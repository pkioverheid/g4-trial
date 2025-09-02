import argparse
import logging
import sys

from lib.util import load_yaml
from lib import crl

logging.basicConfig(stream=sys.stdout, level=logging.INFO)
logger = logging.getLogger("generate-crl")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--force', action='store_true', help="If files are absent, generate boilerplate YAML and CRL files")
    parser.add_argument('revocations', nargs='+', help="Generate CRLs for these files")
    args = parser.parse_args()

    config = load_yaml("config.yaml")

    for filename in args.revocations:
        logger.info(f"Processing {filename}")
        crl.process(filename, config, args.force)


if __name__ == "__main__":
    main()
