import argparse
import glob
import logging
import os
import sys

import yaml
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import (
    ExtensionNotFound,
    SubjectAlternativeName,
    load_pem_x509_csr,
)
from jschon import JSON, JSONSchema, create_catalog

from lib.cert import sign
from lib.chain import write_full_chain
from lib.config import Config
from lib.csr import verify
from lib.events import Eventlog
from lib.keypair import KeyPair
from lib.names import as_dict, generate_basename
from lib.ra import validate
from lib.san import read_generalnames
from lib.util import load_yaml

logging.basicConfig(stream=sys.stdout, level=logging.INFO)
logger = logging.getLogger("sign-cert")


def find_profile(enrollment: dict) -> str:
    """
    Find a match profile for indicted enrollment
    :param enrollment:
    :return: a filename of a matching profile
    :exception ValueError if none or multiple profile matches were found
    """
    create_catalog("2020-12")
    matches = []
    profilefilenames = glob.glob(os.path.join('profiles', '*.yaml'))
    for profilefilename in profilefilenames:
        schema = JSONSchema(load_yaml(profilefilename)['validations'])
        result = schema.evaluate(JSON(enrollment))
        if result.valid:
            matches.append(profilefilename)
    if not matches:
        raise ValueError(f'Certificate profile for {csrfile} not found, please verify manually the CSR')
    if len(matches) > 1:
        raise ValueError(
            f'Multiple certificate profiles found for {csrfile}: {matches}. Please specify the correct profile using the --profile switch. ')
    return matches[0]


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('--issuer-password', action="store", help="Password to decrypt issuer's private key")

    parser.add_argument('--write-enrollment', action="store", help="Convert provided CSRs to enrollment data, and write to specified file. Do not sign a certificate. Use this option to override any subject or subjectAlternateName information in the CSRs by using the --enrollment flag on a second run of sign-cert. Ignores all other arguments. ")

    parser.add_argument('--write-full-chain', action="store_true", help="Write a PEM encoded file containing the entire chain, excluding the root, and write the Root to its own PEM encoded file")
    parser.add_argument('csrs', nargs='+', help="CSRs to process")

    group = parser.add_mutually_exclusive_group()
    group.add_argument('--profile', help="Path to a profile file to sign the CRS with")
    group.add_argument('--enrollment', help="Path to an enrollment file to use in the certificate. Overrides any information in the CSR, except for the public key")

    args = parser.parse_args()

    config = Config.from_file("config.yaml")

    for csrfile in args.csrs:

        logger.info(f"Processing {csrfile}")

        with open(csrfile, "rb") as f:
            csr = load_pem_x509_csr(f.read())

        # Verify the CSR cryptografically
        try:
            verify(csr)
        except InvalidSignature:
            logger.fatal(f"{csrfile} signature is invalid, exiting ❌")
            sys.exit(1)
        except UnsupportedAlgorithm:
            logger.fatal(f"{csrfile} signature algorithm is not supported, exiting ❌")
            sys.exit(1)

        if not args.enrollment:
            # No enrollment file was provided, rebuild from CSR data to allow verification one set of code
            enrollment = {
                'profile': 'tbd',
                'subject': as_dict(csr.subject)
            }

            # If present, rebuild SANs
            try:
                ext = csr.extensions.get_extension_for_class(SubjectAlternativeName)
                enrollment['subjectAltNames'] = read_generalnames(ext.value.public_bytes())
                logger.debug(f"CSR contained {len(enrollment['subjectAltNames'])} SANs.")
            except ExtensionNotFound:
                pass

            # Use or find a matching certificate profile
            enrollment['profile'] = args.profile or find_profile(enrollment)

            if args.write_enrollment:
                # Only write the enrollment file. Don't validate data against the certificate profile as this option
                # may be used to correct an incorrect CSR
                if os.path.isfile(args.write_enrollment):
                    logger.fatal(f"Cannot write enrollment, file {args.write_enrollment} exists. Please remove it first")
                    sys.exit(1)

                with open(args.write_enrollment, "w") as f:
                    yaml.dump(enrollment, f)

                logger.info(f"Wrote enrollment to {args.write_enrollment}")

                continue
        else:
            # Use provided enrollment file
            enrollment = load_yaml(args.enrollment)

        # Validate enrollment
        subject_profile = load_yaml(enrollment['profile'])
        validate(enrollment, subject_profile)

        # load subject public key
        subject_keys = KeyPair.for_filename(csrfile)
        subject_keys.load_from_csr(csr)

        # Load issuer's keys
        issuer_profile = load_yaml(os.path.join('enrollment', subject_profile['issuer']))
        issuer_keys = KeyPair.for_filename(generate_basename(issuer_profile['subject']))
        try:
            issuer_keys.load(password=args.issuer_password)
        except FileNotFoundError:
            logger.fatal(f"Cannot find keys of {issuer_keys} for signing operation, please generate it first")
            sys.exit(1)

        cert = sign(subject_profile, enrollment, issuer_profile, subject_keys, issuer_keys, config)

        # Write issued certificate to disk
        filename = subject_keys.derfile
        with open(filename, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.DER))

        Eventlog(config).log_issued_cert(issuer_keys, subject_keys)

        logger.info(f"Certificate issued and saved to {filename}")

        if args.write_full_chain:
            write_full_chain(subject_keys, subject_profile)
