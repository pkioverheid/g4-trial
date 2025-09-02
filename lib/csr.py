from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import CertificateSigningRequestBuilder, SubjectAlternativeName, DNSName

from .keypair import get_hash_algo
from .names import as_name
from .ra import validate
from .util import force_int


def create_csr(profile, enrollment, subject_keys):
    if not subject_keys.private_key:
        try:
            with open(subject_keys.privatekeyfile, "rb") as f:
                subject_keys.private_key = serialization.load_pem_private_key(f.read(), password=None)
        except FileNotFoundError:
            subject_keys.generate_private_key(profile)

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


def process(profile, enrollment, keypair, config):
    validate(enrollment, profile)

    csr_path = f"{keypair.basename}.csr"
    csr = create_csr(profile, enrollment, keypair)

    with open(csr_path, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    print(f"Private key written to {keypair.privatekeyfile}")
    print(f"CSR written to {csr_path}")
