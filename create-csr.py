import argparse
import logging
import sys

from cryptography.hazmat.primitives import serialization

from lib import ra
from lib.config import Config
from lib.csr import RequestService
from lib.events import Eventlog
from lib.keypair import KeyPair
from lib.names import as_dict
from lib.util import load_yaml

logging.basicConfig(stream=sys.stdout, level=logging.INFO)
logger = logging.getLogger("create-csr")


def is_digital_signature(key: str) -> bool:
    """
    Returns true if key type name can be used for digital signatures
    """
    return key in [
        'Ed25519',
        'Ed448',
        'rsaEncryption',
        'DSA',
        'EllipticCurve',
        'ML-DSA-44',
        'ML-DSA-65',
        'ML-DSA-87'
    ]


def load(filename):
    enrollment = load_yaml(filename)
    return enrollment, load_yaml(enrollment["profile"]), filename


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('--subject-password', action="store", help="Password to encrypt subject's private key")
    parser.add_argument('--signer', action="store", help="Enrollment of an existing certificate that will be used to sign the CSR")
    parser.add_argument('enrollments', nargs='+', help="Enrollment to create key pairs and Certificate Signing Request for")
    args = parser.parse_args()

    config = Config.from_file("config.yaml")
    event_log = Eventlog(config)

    service = RequestService(config, event_log)

    has_kem = False
    needs_dn = []

    # The CSR may be signed using a different key (RFC 9883)
    signer_keys = None
    if args.signer:
        signer_keys = KeyPair.for_filename(args.signer)
        if not signer_keys.certificate_exists():
            logger.error(f'Certificate for {args.signer} does not exist. Please request it first from your CA before running this command.')
            sys.exit(2)
        if not signer_keys.private_key_exists():
            logger.error(f'Private key for {args.signer} does not exist. Please generate it first (and request the certificate) before running this command.')
            sys.exit(2)

        # All CSRs for all specified "dual enrollment" will be signed by the indicated signer_keys. Their DNs should match. 
        signer_keys.load()
        expected_dn = as_dict(signer_keys.certificate.subject)
        for enrollment, _, _ in map(load, args.enrollments):
            if enrollment['subject'] != expected_dn:
                logger.error('When using a separate signer to sign the CSRs, all enrollments must specify the same Distinguished Name (DN), and that DN must also match the Distinguished Name in the signer\'s certificate.')
                sys.exit(1)

    else:
        # Check if signer keys must be specified, which is if one of the enrollments uses a public key algorithm that cannot be used for digital signatures
        requires_signer_dn = None
        for enrollment, profile, _ in map(load, args.enrollments):
            if not is_digital_signature(profile['publicKeyAlgorithm']):
                requires_signer_dn = enrollment['subject']
                break

        if requires_signer_dn:
            # Find suitable enrollments for digitalSignatures so that we can help the user point into the right direction. 
            # Additional requirement: the DN of both enrollments
            options = []
            for enrollment, profile, filename in map(load, args.enrollments):
                if enrollment['subject'] == requires_signer_dn and is_digital_signature(profile['publicKeyAlgorithm']):
                    options.append(filename)
                    
            logger.error(f"Enrollment {filename} uses an unsuitable publicKeyAlgorithm {profile['publicKeyAlgorithm']} for digital signatures. Request a certificate with a signature algorithm (for example, ML-DSA, RSA, or ECDSA) and retry this command using that certificate as the signer key.")
            sys.exit(1)

    # Process each enrollment
    for enrollment, profile, filename in map(load, args.enrollments):
        logger.info(f"Processing {filename}")

        subject_keys = KeyPair.for_filename(filename)
        if subject_keys.exists():
            logger.error(f"Some files already exist for {filename}, skipping")
            continue

        enrollment = load_yaml(filename)
        profile = load_yaml(enrollment['profile'])

        ra.validate(enrollment, profile)

        csr = service.create(profile, enrollment, subject_keys, signer_keys=signer_keys, password=args.subject_password)

        csr_path = f"{subject_keys.basename}.csr"
        with open(csr_path, "wb") as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))

        logger.info(f"Private key written to {subject_keys.privatekeyfile}")
        logger.info(f"CSR written to {csr_path}")
