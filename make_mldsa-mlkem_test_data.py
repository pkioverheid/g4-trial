
import datetime

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import (
    mldsa,
    mlkem,
)
from cryptography.x509 import (
    CertificateBuilder,
    CertificateSigningRequestBuilder,
)
from cryptography.x509.name import _ASN1Type

from lib import statement_of_possession
from lib.names import as_name
from lib.statement_of_possession import statementOfPossessionOID

one_day = datetime.timedelta(1, 0, 0)

# make CA
ca_key = mldsa.MLDSA65PrivateKey.generate()
ca_cert = (
    CertificateBuilder()
    .subject_name(as_name({'country': 'NL'}))
    .issuer_name(as_name({'country': 'NL'}))
    .public_key(ca_key.public_key())
    .add_extension(
            x509.BasicConstraints(
                ca=True,
                path_length=0
            ),
            critical=True
        )
    .not_valid_before(datetime.datetime.today() - one_day)
    .not_valid_after(datetime.datetime.today() + (one_day * 30))
    .serial_number(151281543974166114540432905634029587273238573437)
    .sign(ca_key, algorithm=None))

ca_path = "testdata/csr/certs/statement-of-possession-ca.pem"
with open(ca_path, "wb") as f:
    f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

with open("testdata/csr/private/statement-of-possession-ca.key", "wb") as f:
    f.write(ca_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))



# issue digital signature certificate
signature_key = mldsa.MLDSA65PrivateKey.generate()
signature_cert = (
    CertificateBuilder()
    .subject_name(as_name({'country': 'NL'}))
    .issuer_name(ca_cert.subject)
    .public_key(signature_key.public_key())
    .not_valid_before(datetime.datetime.today())
    .not_valid_after(datetime.datetime.today() + (one_day * 29))
    .serial_number(305165262547671163706059072524803971879204169699)
    .sign(ca_key, algorithm=None)
    )

signature_path = "testdata/csr/certs/statement-of-possession-signing.pem"
with open(signature_path, "wb") as f:
    f.write(signature_cert.public_bytes(serialization.Encoding.PEM))
with open("testdata/csr/private/statement-of-possession-signing.key", "wb") as f:
    f.write(signature_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))



# create kem csr
enclosed_key = mlkem.MLKEM768PrivateKey.generate()
csr = (
    CertificateSigningRequestBuilder()
    .subject_name(as_name({'country': 'NL'}))
    .public_key(enclosed_key.public_key())
    .add_attribute(
        statementOfPossessionOID,
        statement_of_possession.serialize(statement_of_possession.build_from(signature_cert.public_bytes(serialization.Encoding.DER)), broken=True),
        _tag=_ASN1Type.Sequence
    )
    .sign(signature_key, algorithm=None)
)

# Write mixed CSR (lean)
csr_path = "testdata/csr/statement-of-possession-csr-lean.pem"
with open(csr_path, "wb") as f:
    f.write(csr.public_bytes(serialization.Encoding.PEM))



# create kem csr
csr = (
    CertificateSigningRequestBuilder()
    .subject_name(as_name({'country': 'NL'}))
    .public_key(enclosed_key.public_key())
    .add_attribute(
        statementOfPossessionOID,
        statement_of_possession.serialize(statement_of_possession.build_from(signature_cert.public_bytes(serialization.Encoding.DER), include_cert=True), broken=True),
        _tag=_ASN1Type.Sequence
    )
    .sign(signature_key, algorithm=None)
)

# Write mixed CSR (full)
csr_path = "testdata/csr/statement-of-possession-csr-full.pem"
with open(csr_path, "wb") as f:
    f.write(csr.public_bytes(serialization.Encoding.PEM))