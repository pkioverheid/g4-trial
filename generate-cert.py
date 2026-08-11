import argparse
import logging
import os
import sys

from cryptography.hazmat.primitives import serialization

from lib import ra
from lib.cert import IssuerNotFoundError, IssueService
from lib.chain import write_full_chain
from lib.config import Config
from lib.events import Eventlog
from lib.keypair import KeyPair
from lib.util import load_yaml

logging.basicConfig(stream=sys.stdout, level=logging.INFO)
logger = logging.getLogger("generate-cert")


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('--profile-override', action="store", help="Override Certificate Profile in enrollments")
    parser.add_argument('--issuer-password', action="store", help="Password to decrypt issuer's private key")
    parser.add_argument('--subject-password', action="store", help="Password to encrypt subject's private key")
    parser.add_argument('--write-full-chain', action="store_true", help="Write a PEM encoded file containing the entire chain, excluding the root, and write the Root to its own PEM encoded file")
    parser.add_argument('enrollments', nargs='+', help="Enrollments to process")
    args = parser.parse_args()

    config = Config.from_file("config.yaml")
    event_log = Eventlog(config)
    issue_service = IssueService(config, event_log)

    for filename in args.enrollments:
        logger.info(f"Processing {filename}")

        subject_keys = KeyPair.for_filename(config.base_dir, filename)
        if subject_keys.exists():
            logger.error(f"Some files already exist for {filename}, skipping")
            continue

        enrollment = load_yaml(filename)
        profile = load_yaml(args.profile_override or enrollment['profile'])

        ra.validate(enrollment, profile)

        # Find issuer keypair by its DN from its enrollment
        issuer_enrollment = load_yaml(os.path.join('enrollment', profile['issuer']))
        issuer_keys = KeyPair.for_filename(config.base_dir, os.path.splitext(profile['issuer'])[0])

        selfsigned = issuer_enrollment['subject'] == enrollment['subject']
        if selfsigned:
            logger.debug("Issuing a self signed certificate")
            try:
                issuer_keys.load()
                print(f"KeyPair for {issuer_keys} already exists, skipping")
            except FileNotFoundError:
                # NOTE: use the subject password as it is used to encrypt the private key
                issuer_keys.generate_private_key(profile, password=args.subject_password)
                subject_keys = issuer_keys
        else:
            try:
                issuer_keys.load(password=args.issuer_password)
            except FileNotFoundError as e:
                raise IssuerNotFoundError(
                    f"Cannot find keys of {issuer_keys} for signing operation, please generate it first") from e

            try:
                subject_keys.load()
            except FileNotFoundError:
                logger.debug("Generating new key pair for subject")
                subject_keys.generate_private_key(profile, password=args.subject_password)

        # Issue the certificate
        cert = issue_service.sign(profile, enrollment, issuer_enrollment, subject_keys, issuer_keys)

        # Write issued certificate to disk
        filename = subject_keys.derfile
        with open(filename, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.DER))

        if args.write_full_chain:
            write_full_chain(subject_keys, profile)

        logger.info(f"Certificate issued and saved to {filename}")
