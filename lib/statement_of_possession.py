from asn1crypto.cms import IssuerAndSerialNumber
from asn1crypto.core import Sequence
from asn1crypto.x509 import Any, Certificate, Name
from cryptography.x509 import ObjectIdentifier
from cryptography.x509.name import _ASN1Type

statementOfPossessionOID = ObjectIdentifier("1.3.6.1.4.1.22112.2.1")

# Attribute is a ASN.1 SEQUENCE, but it missing from the required Enum. Monkey patch for now. 
from aenum import extend_enum

extend_enum(_ASN1Type, 'Sequence', 48)


class PrivateKeyPossessionStatement(Sequence):
    _fields = [ # noqa: RUF012
        ('signer', IssuerAndSerialNumber),
        ('cert', Certificate, {'optional': True})
    ]


class Reconstructor(Sequence):
    _fields = [  # noqa: RUF012
        ('signer', Any),
        ('cert', Any, {'optional': True}),
    ]


def build(issuer: Name, serial_number: int, cert: Certificate | None = None) -> PrivateKeyPossessionStatement:
    """
    Encodes a PrivateKeyPossessionStatement
    """
    return PrivateKeyPossessionStatement({
        'signer': IssuerAndSerialNumber({
            'issuer': issuer,
            'serial_number': serial_number
        }),
        'cert': cert
    })


def build_from(cert_der: bytes, include_cert: bool = False) -> PrivateKeyPossessionStatement:
    """
    Encodes a PrivateKeyPossessionStatement for specified certificate
    """

    # Load the certificate into asn1crypto library
    cert = Certificate.load(cert_der)
    return build(cert.issuer, cert.serial_number, cert if include_cert else None)


def load(der: bytes, broken: bool = False) -> PrivateKeyPossessionStatement:
    """
    Loads a PrivateKeyPossessionStatement from DER-encoded bytes
    """
    if broken:
        # if cryptograghy library is used to read the CSR, the der encoded bytes of the attribute no longer contains the TL of the TLV. 
        # However the bytestream does contain the two SEQUENCEs (`signer` and `cert`) within the SEQUENCE. Reconstruct the outer SEQUENCE 
        # to parse it correctly. 
        signer = Any.load(der)
        
        remainder = len(signer.dump()) - len(der)
        cert = Any.load(der[remainder:]) if remainder else None

        der = Reconstructor({
            'signer': signer,
            'cert': cert
        }).dump()

    return PrivateKeyPossessionStatement.load(der)


def serialize(statement: PrivateKeyPossessionStatement, broken: bool = False):
    """
    Serializes the statement to write to a broken cryptography library
    """

    if broken:
        der = statement['signer'].dump()
        if statement['cert']:
            der = der + statement['cert'].dump()
        return der

    return statement.dump()
