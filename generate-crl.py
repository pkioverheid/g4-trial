import argparse
import logging
import sys

from lib.config import Config
from lib.crl import CRLService
from lib.events import Eventlog

logging.basicConfig(stream=sys.stdout, level=logging.INFO)
logger = logging.getLogger("generate-crl")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--force', action='store_true', help="If files are absent, generate boilerplate YAML and CRL files")
    parser.add_argument('--issuer-password', action="store", help="Password to decrypt issuer's private key")
    parser.add_argument('revocations', nargs='+', help="Generate CRLs for these files")
    args = parser.parse_args()

    config = Config.from_file("config.yaml")
    event_log = Eventlog(config)

    service = CRLService(config, event_log)

    for filename in args.revocations:
        logger.info(f"Processing {filename}")
        service.process(filename, force=args.force, issuer_password=args.issuer_password)



if __name__ == "__main__":
    main()
