import argparse
import logging

from lib import csr
from lib.keypair import KeyPair
from lib.util import load_yaml

logger = logging.getLogger("example")
logger.setLevel(logging.INFO)

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('enrollments', nargs='+', help="Enrollment to create key pairs and Certificate Signing Request for")
    args = parser.parse_args()

    config = load_yaml("config.yaml")

    for filename in args.enrollments:
        enrollment = load_yaml(filename)
        profilefilename = enrollment['profile']

        logger.info(f"Processing {filename}")

        keypair = KeyPair.for_filename(filename)

        if keypair.exists():
            logger.error(f"Some files already exist for {filename}, skipping")
            continue

        csr.process(load_yaml(profilefilename), enrollment, keypair, config)
