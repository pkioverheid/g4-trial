import argparse

from lib.util import load_yaml
from lib import cert

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('--profile-override', action="store", help="Override Certificate Profile in enrollments")
    parser.add_argument('enrollments', nargs='+', help="Enrollments to process")
    args = parser.parse_args()

    config = load_yaml("config.yaml")

    for enrollmentfile in args.enrollments:
        enrollment = load_yaml(enrollmentfile)

        if args.profile_override:
            profilefile = args.profile_override
        else:
            profilefile = enrollment['profile']

        cert.process(load_yaml(profilefile), enrollment, enrollmentfile, config)
