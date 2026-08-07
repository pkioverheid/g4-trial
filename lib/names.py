import hashlib
import re

from asn1crypto.x509 import NameType
from cryptography.x509 import Name
from cryptography.x509.oid import NameOID


class OID:
    def __init__(self, short_name, long_name, oid):
        self.short_name = short_name
        self.long_name = long_name
        self.oid = oid

        # Dynamically locate the snake_name from asn1crypto
        self.snake_name = NameType._map[oid.dotted_string]

    def names(self):
        return filter(len, [self.short_name, self.long_name, self.snake_name, self.oid.dotted_string])

    def __str__(self):
        return f"OID(short_name={self.short_name}, long_name={self.long_name}, snake_name={self.snake_name}, oid={self.oid})"


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


allowed_attributes = []
for attribute in attributes:
    allowed_attributes.extend(attribute.names())


def as_name(d: dict):

    for k in d:
        if k not in allowed_attributes:
            raise ValueError(f'Unknown attribute name: {k}')

    merged = []
    for attribute in attributes:
        for k, v in d.items():
            if k in attribute.names():
                merged.append(f'{attribute.oid.dotted_string}={v}')

    return Name.from_rfc4514_string(','.join(reversed(merged)))


def as_dict(n: Name):
    res = {}
    for attrs in n.rdns:
        for attr in attrs:
            items = [a for a in attributes if a.oid == attr.oid]
            if not items:
                raise AttributeError(f"{attr.oid} has not a defined shortname")
            res[items[0].short_name or items[0].long_name] = attr.value
    return res


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
