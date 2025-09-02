import argparse
import logging
import sys

from lib import csr
from lib.keypair import KeyPair
from lib.util import load_yaml

logging.basicConfig(stream=sys.stdout, level=logging.INFO)
logger = logging.getLogger("create-csr")

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('--subject-password', action="store", help="Password to encrypt subject's private key")
    parser.add_argument('enrollments', nargs='+', help="Enrollment to create key pairs and Certificate Signing Request for")
    args = parser.parse_args()

    config = load_yaml("config.yaml")

    for filename in args.enrollments:
        logger.info(f"Processing {filename}")

        subject_keys = KeyPair.for_filename(filename)
        if subject_keys.exists():
            logger.error(f"Some files already exist for {filename}, skipping")
            continue

        enrollment = load_yaml(filename)

        csr.process(load_yaml(enrollment['profile']), enrollment, subject_keys, config, subject_password=args.subject_password)
