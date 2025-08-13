import hashlib
from collections import OrderedDict
import re
import yaml
from cryptography.x509 import Name
from cryptography.x509.oid import NameOID


class OID:
    def __init__(self, short_name, long_name, oid):
        self.short_name = short_name
        self.long_name = long_name
        self.oid = oid


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
    for k, v in d.items():
        for attribute in attributes:
            if k in [attribute.short_name, attribute.long_name, attribute.oid.dotted_string]:
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
