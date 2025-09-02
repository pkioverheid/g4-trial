import argparse
import glob
import logging
import os
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_csr, SubjectAlternativeName, ExtensionNotFound, DNSName
from jschon import create_catalog, JSON, JSONSchema

from lib.cert import sign, IssuerNotFoundError
from lib.dn import generate_basename
from lib.keypair import KeyPair
from lib.names import as_dict
from lib.ra import validate
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
    parser.add_argument('csrs', nargs='+', help="CSRs to process")

    group = parser.add_mutually_exclusive_group()
    group.add_argument('--profile', help="Path to a profile file to sign the CRS with")
    group.add_argument('--enrollment', help="Path to an enrollment file to use in the certificate. Overrides any information in the CSR, except for the public key")

    args = parser.parse_args()

    config = load_yaml("config.yaml")

    for csrfile in args.csrs:

        logging.info(f"Processing {csrfile}")

        # Rebuild enrollment data to we can verify it
        with open(csrfile, "rb") as f:
            csr = load_pem_x509_csr(f.read())

        # TODO: Verify technically the CSR

        if args.enrollment:
            # Use provided enrollment file
            enrollment = load_yaml(args.enrollment)
        else:
            # Rebuild enrollment from CSR data
            enrollment = {
                'profile': 'tbd',
                'subject': as_dict(csr.subject)
            }
            try:
                ext = csr.extensions.get_extension_for_class(SubjectAlternativeName)
                enrollment['subjectAltNames'] = ext.value.get_values_for_type(DNSName)
                logger.debug(f"CSR contained {len(enrollment['subjectAltNames'])} SANs.")
            except ExtensionNotFound:
                pass
            enrollment['profile'] = args.profile or find_profile(enrollment)

        # Validate
        subject_profile = load_yaml(enrollment['profile'])
        validate(enrollment, subject_profile)

        # load subject public key
        subject_keys = KeyPair.for_filename(csrfile)
        subject_keys.load_from_csr(csr)

        # Load issuer's keys
        issuer_profile = load_yaml(os.path.join('enrollment', subject_profile['issuer']))
        issuer_keys = KeyPair(generate_basename(issuer_profile['subject']))
        try:
            issuer_keys.load()
        except FileNotFoundError as e:
            logger.fatal(f"Cannot find keys of {issuer_keys} for signing operation, please generate it first")
            exit(1)

        cert = sign(subject_profile, enrollment, issuer_profile, subject_keys, issuer_keys, config)

        # Write issued certificate to disk
        filename = subject_keys.certificatefile
        with open(filename, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.DER))

        logger.info(f"Certificate issued and saved to {filename}")
