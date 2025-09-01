import argparse

from lib import cert
from lib.keypair import KeyPair
from lib.util import load_yaml

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('--profile-override', action="store", help="Override Certificate Profile in enrollments")
    parser.add_argument('enrollments', nargs='+', help="Enrollments to process")
    args = parser.parse_args()

    config = load_yaml("config.yaml")

    for filename in args.enrollments:
        enrollment = load_yaml(filename)

        profilefilename = args.profile_override or enrollment['profile']

        subject_keys = KeyPair.for_filename(filename)

        try:
            subject_keys.load()
            print(f"Certificate {subject_keys} already exists, skipping")
            continue
        except FileNotFoundError:
            pass

        print(f"Processing {filename}")
        cert.process(load_yaml(profilefilename), enrollment, subject_keys, config)
