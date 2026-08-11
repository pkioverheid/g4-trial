import logging
import subprocess
import sys
from pathlib import Path

from lib.domains import verify
from lib.util import choose, load_yaml

logging.basicConfig(stream=sys.stdout, level=logging.INFO)
logger = logging.getLogger("create-ca")


def main():
    options = load_yaml("domains.yaml")['domains']
    if not verify(options):
        sys.exit(1)

    hierarchy = choose("Choose a domain:", list(options.keys()))

    enrollmentfiles = options[hierarchy]
    revocationfiles = [Path("revocations").joinpath(Path(enrollmentfile).name) for enrollmentfile in enrollmentfiles]

    gen_certs = ["python", "generate-cert.py"]
    gen_certs.extend(enrollmentfiles)
    subprocess.run(gen_certs, check=True) 

    gen_crls = ["python", "generate-crl.py"]
    gen_crls.extend(revocationfiles)
    subprocess.run(gen_crls, check=True) 
    
    print('\nTo automate this step, run next time:')
    filenames = "\' \'".join(enrollmentfiles)
    print(f'python generate-cert.py \'{filenames}\'')
    filenames = "\' \'".join([str(f) for f in revocationfiles])
    print(f'python generate-crl.py --force \'{filenames}\'')


if __name__ == "__main__":
    main()
