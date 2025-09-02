import hashlib
import re
from collections import Counter

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

def as_dict(n: Name):
    res = {}
    for attrs in n.rdns:
        for attr in attrs:
            items = [a for a in attributes if a.oid == attr.oid]
            if not items:
                raise AttributeError(f"{attr.oid} has not a defined shortname")
            res[items[0].short_name or items[0].long_name] = attr.value
    return res


class BasenameGenerator:
    """
    Utility class to ensure certificate profiles and enrollments are written to an unique filename
    """

    def __init__(self, names):
        # Find for which certificates will have colliding filenames (which we fix when writing files)
        self.duplicates = [k for k, v in Counter([self._generate_basename(name) for name in names]).items() if v > 1]

        # Initialize a counter to increment the filename for each certificate
        self.duplicate_counter = {k: v for v, k in enumerate(self.duplicates, start=1)}

    def get(self, dn: dict):
        basename = self._generate_basename(dn)
        if basename not in self.duplicates:
            return basename

        increment = self.duplicate_counter[basename]
        self.duplicate_counter[basename] = increment + 1
        return f'{basename}-{increment}'

    def _generate_basename(self, dn: dict, fallback=None) -> str:
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

    def __str__(self):
        return f"<lib.names.BasenameGenerator having {len(self.duplicates)} duplicates>"
