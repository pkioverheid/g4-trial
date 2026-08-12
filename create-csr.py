import argparse
import logging
import sys

from cryptography.hazmat.primitives import serialization

from lib import ra
from lib.config import Config
from lib.csr import RequestService
from lib.events import Eventlog
from lib.keypair import KeyPair
from lib.util import load_yaml

logging.basicConfig(stream=sys.stdout, level=logging.INFO)
logger = logging.getLogger("create-csr")


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('--subject-password', action="store", help="Password to encrypt subject's private key")
    parser.add_argument('enrollments', nargs='+', help="Enrollment to create key pairs and Certificate Signing Request for")
    args = parser.parse_args()

    config = Config.from_file("config.yaml")
    event_log = Eventlog(config)

    service = RequestService(config, event_log)

    for filename in args.enrollments:
        logger.info(f"Processing {filename}")

        subject_keys = KeyPair.for_filename(filename)
        if subject_keys.exists():
            logger.error(f"Some files already exist for {filename}, skipping")
            continue

        enrollment = load_yaml(filename)
        profile = load_yaml(enrollment['profile'])

        ra.validate(enrollment, profile)

        csr = service.create(profile, enrollment, subject_keys, password=args.subject_password)

        csr_path = f"{subject_keys.basename}.csr"
        with open(csr_path, "wb") as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))

        logger.info(f"Private key written to {subject_keys.privatekeyfile}")
        logger.info(f"CSR written to {csr_path}")
