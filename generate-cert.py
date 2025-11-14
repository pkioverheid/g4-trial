import argparse
import logging
import sys

from lib import cert
from lib.chain import write_full_chain
from lib.keypair import KeyPair
from lib.util import load_yaml

logging.basicConfig(stream=sys.stdout, level=logging.INFO)
logger = logging.getLogger("generate-cert")


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('--profile-override', action="store", help="Override Certificate Profile in enrollments")
    parser.add_argument('--issuer-password', action="store", help="Password to decrypt issuer's private key")
    parser.add_argument('--subject-password', action="store", help="Password to encrypt subject's private key")
    parser.add_argument('--write-full-chain', action="store_true", help="Write a PEM file containing the entire chain, excluding the root")
    parser.add_argument('enrollments', nargs='+', help="Enrollments to process")
    args = parser.parse_args()

    config = load_yaml("config.yaml")

    for filename in args.enrollments:
        logger.info(f"Processing {filename}")

        subject_keys = KeyPair.for_filename(filename)
        if subject_keys.exists():
            logger.error(f"Some files already exist for {filename}, skipping")
            continue

        enrollment = load_yaml(filename)
        leaf_profile = load_yaml(args.profile_override or enrollment['profile'])
        cert.process(leaf_profile, enrollment, subject_keys, config, issuer_password=args.issuer_password, subject_password=args.subject_password)

        if args.write_full_chain:
            write_full_chain(subject_keys, leaf_profile)
