import logging
import sys
from pathlib import Path

from lib import cert, crl
from lib.domains import verify
from lib.keypair import KeyPair
from lib.util import choose, load_config, load_yaml

logging.basicConfig(stream=sys.stdout, level=logging.INFO)
logger = logging.getLogger("create-ca")


def main():
    config = load_config()

    options = load_yaml("domains.yaml")['domains']
    if not verify(options):
        sys.exit(1)

    hierarchy = choose("Choose a domain:", list(options.keys()))

    enrollmentfiles = options[hierarchy]
    revocationfiles = [Path("revocations").joinpath(Path(enrollmentfile).name) for enrollmentfile in enrollmentfiles]

    # Creating a hierarchy is simply creating the certificates and CRLs in sequence
    for enrollmentfile, revocationfile in zip(enrollmentfiles, revocationfiles):
        enrollment = load_yaml(enrollmentfile)
        profile = load_yaml(enrollment['profile'])
        subject_keys = KeyPair.for_filename(enrollmentfile)
        cert.process(profile, enrollment, subject_keys, config)
        crl.process(revocationfile, config, force=True)

    print('To automate this step, run next time:')
    filenames = "\' \'".join(enrollmentfiles)
    print(f'python generate-cert.py \'{filenames}\'')
    filenames = "\' \'".join([str(f) for f in revocationfiles])
    print(f'python generate-crl.py --force \'{filenames}\'')


if __name__ == "__main__":
    main()
