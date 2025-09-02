import logging
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import CertificateSigningRequestBuilder, SubjectAlternativeName, DNSName

from .keypair import get_hash_algo, KeyPair
from .names import as_name
from .ra import validate
from .util import force_int

logger = logging.getLogger(__name__)


def create_csr(profile: dict, enrollment: dict, subject_keys: KeyPair, password=None):
    if not subject_keys.private_key:
        if os.path.exists(subject_keys.privatekeyfile):
            raise FileExistsError(subject_keys.privatekeyfile)

        if password:
            password.encode("UTF-8")
        subject_keys.generate_private_key(profile, password=password)

    hash_algo = get_hash_algo(profile['hashAlgorithm'])

    builder = CertificateSigningRequestBuilder().subject_name(as_name(enrollment['subject']))

    if 'subjectAltNames' in enrollment:
        sans = [DNSName(item) for item in enrollment['subjectAltNames']]
        san_extension = SubjectAlternativeName(sans)
        builder = builder.add_extension(san_extension, critical=False)

    return builder.sign(subject_keys.private_key,
                        algorithm=hash_algo,
                        rsa_padding=padding.PSS(
                            mgf=padding.MGF1(hash_algo),
                            salt_length=force_int(profile.get('saltLength', 64))
                        ))


def process(profile: dict, enrollment: dict, keypair: KeyPair, config: dict, subject_password=None):
    validate(enrollment, profile)

    csr = create_csr(profile, enrollment, keypair, password=subject_password)

    csr_path = f"{keypair.basename}.csr"
    with open(csr_path, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    logger.info(f"Private key written to {keypair.privatekeyfile}")
    logger.info(f"CSR written to {csr_path}")
