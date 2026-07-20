import hashlib
import re

from cryptography.x509 import Name
from cryptography.x509.oid import NameOID


class OID:
    def __init__(self, short_name, long_name, oid):
        self.short_name = short_name
        self.long_name = long_name
        self.oid = oid

    def names(self):
        return filter(len, [self.short_name, self.long_name, self.oid.dotted_string])

    def __str__(self):
        return f"OID(short_name={self.short_name}, long_name={self.long_name}, oid={self.oid})"


attributes = [
    OID('C', 'country', NameOID.COUNTRY_NAME),
    OID('ST', 'stateOrProvinceName', NameOID.STATE_OR_PROVINCE_NAME),
    OID('L', 'localityName', NameOID.LOCALITY_NAME),
    OID('', 'postalCode', NameOID.POSTAL_CODE),
    OID('', 'streetAddress', NameOID.STREET_ADDRESS),
    OID('O', 'organizationName', NameOID.ORGANIZATION_NAME),
    OID("SN", 'surName', NameOID.SURNAME),
    OID("GN", 'givenName', NameOID.GIVEN_NAME),
    OID("", 'organizationalUnitName', NameOID.ORGANIZATIONAL_UNIT_NAME),
    OID('CN', 'commonName', NameOID.COMMON_NAME),
    OID('', 'organizationIdentifier', NameOID.ORGANIZATION_IDENTIFIER),
    OID('', 'serialNumber', NameOID.SERIAL_NUMBER),
    OID('', 'title', NameOID.TITLE),
]


def as_name(d: dict):
    merged = []
    for attribute in attributes:
        for k, v in d.items():
            if k in attribute.names():
                merged.append(f'{attribute.oid.dotted_string}={v}')

    return Name.from_rfc4514_string(','.join(reversed(merged)))


def generate_basename(dn: dict, fallback=None):
    """
    Compute the default name used for its issuer by EJBCA
    """
    if 'CN' in dn and not dn['CN'].startswith("omit"):
        return re.compile('[^a-zA-Z0-9_]+').sub('', dn['CN'])

    if fallback is not None:
        return fallback

    # Unique hash
    subject_str = str(dn.items())
    return "cert_" + hashlib.sha1(subject_str.encode()).hexdigest()[:8]
