import logging
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, padding, rsa
from cryptography.x509 import CertificateSigningRequestBuilder, SubjectAlternativeName, DNSName, \
    CertificateSigningRequest

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


def verify(csr: CertificateSigningRequest) -> bool:
    pub = csr.public_key()
    sig = csr.signature
    data = csr.tbs_certrequest_bytes
    alg = csr.signature_hash_algorithm

    try:
        if isinstance(pub, rsa.RSAPublicKey):
            pub.verify(sig, data, csr.signature_algorithm_parameters, alg)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(sig, data, ec.ECDSA(alg))
        elif isinstance(pub, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            pub.verify(sig, data)
        else:
            raise Exception("Unsupported signature algorithm")
        return True
    except InvalidSignature:
        return False


def process(profile: dict, enrollment: dict, keypair: KeyPair, config: dict, subject_password=None):
    validate(enrollment, profile)

    csr = create_csr(profile, enrollment, keypair, password=subject_password)

    csr_path = f"{keypair.basename}.csr"
    with open(csr_path, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    logger.info(f"Private key written to {keypair.privatekeyfile}")
    logger.info(f"CSR written to {csr_path}")
