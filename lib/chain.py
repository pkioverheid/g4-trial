import logging
import os

from cryptography.hazmat.primitives import serialization

from .dn import generate_basename
from .keypair import KeyPair
from .util import load_yaml

logger = logging.getLogger(__name__)


def write_full_chain(subject_keys: KeyPair, leaf_profile: dict) -> None:
    """
    Writes the full certificate chain for subject
    :param subject_keys:
    :param leaf_profile:
    :return: None
    """
    with open(subject_keys.pemfile, "wb") as f:
        # First write the leaf
        f.write(subject_keys.certificate.public_bytes(serialization.Encoding.PEM))

        # Then find our way up the hierarchy, excluding the root certificate
        issuer = leaf_profile['issuer']
        for _ in range(10):
            issuer_enrollment = load_yaml(os.path.join('enrollment', issuer))
            issuer_profile = load_yaml(issuer_enrollment['profile'])
            issuer_basename = generate_basename(issuer_enrollment['subject'])

            # Load and write the key pair of the issuer
            issuer_keys = KeyPair(issuer_basename).load()

            if issuer_profile['issuer'] == f'{issuer_basename}.yaml':
                # Write the Root its own PEM file
                with open(issuer_keys.pemfile, "wb") as rf:
                    rf.write(issuer_keys.certificate.public_bytes(serialization.Encoding.PEM))
                break

            f.write(issuer_keys.certificate.public_bytes(serialization.Encoding.PEM))

            # Setup for next iteration
            issuer = issuer_profile['issuer']

    logger.info(f"Certificate chain file saved to {subject_keys.pemfile}")