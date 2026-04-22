from cryptography import x509
from cryptography.x509.oid import ObjectIdentifier

from asn1crypto import core
from asn1crypto.core import Sequence, UTF8String, IA5String, ObjectIdentifier as Asn1ObjectIdentifier
from asn1crypto.x509 import GeneralNames, AnotherName, EmailAddress, DNSName

from typing import Any


def build_san_extension(subjectAltNames: list[dict[str,Any] | str], config) -> list[x509.GeneralName]:
    """
    Encodes SubjectAlternateNames
    """

    sans = []

    for name in subjectAltNames:

        if isinstance(name, str):
            if '@' in name:
                # Assume rfc822Name (emailaddres)
                general_name = x509.RFC822Name(name)
            else:
                # Assume dNSName
                general_name = x509.DNSName(name)

        elif 'assigner' in name and 'identifierValue' in name:
            # Existence of these attributes indicate an OtherName of type AnotherName containing a PermanentIdentifier

            class PermanentIdentifier(Sequence):
                _fields = [
                    ('identifierValue', UTF8String),
                    ('assigner', Asn1ObjectIdentifier)
                ]

            permanent_identifier = PermanentIdentifier({
                'identifierValue': name['identifierValue'],
                'assigner': Asn1ObjectIdentifier(name['assigner'])
            })

            # The default PermanentIdentifier OID may be overwritten by the enrollment
            typeId = ObjectIdentifier('1.3.6.1.5.5.7.8.3')
            if 'type-id' in name:
                typeId = ObjectIdentifier(name['type-id'])
            
            general_name = x509.OtherName(typeId, permanent_identifier.dump())

        elif 'type-id' in name:
            # is an OtherName of type AnotherName (but not a PermanentIdentifier)
            typeId = ObjectIdentifier(name['type-id'])

            # Encoding of the value depends on the indicated type-id so bail if not recognized
            encodings = {
                'UTF8': UTF8String,
                'IA5': IA5String,
            }

            if name['encoding'] not in encodings:
                raise NotImplementedError(f"Encoding {name['encoding']} is currently not supported. Please open a Github issue. ")

            value = encodings[name['encoding']](name['value'])

            general_name = x509.OtherName(typeId, value.dump())

        else:
            raise NotImplementedError(f"Handling of SAN {name} is currently not supported. Please open a Github issue. ")
        
        sans.append(general_name)

    return sans


class PermanentIdentifier(Sequence):
    """
    Define PermanentIdentifier structure according to RFC 4043
    """
    _fields = [
        ("identifier_value", UTF8String, {"optional": True}),
        ("assigner", Asn1ObjectIdentifier, {"optional": True}),
    ]


# Monkey patch to enable deep parsing of AnotherNames
Asn1ObjectIdentifier._map = {
    "1.3.6.1.5.5.7.8.3": 'permanent_identifier',
    "1.3.6.1.4.1.311.20.2.3": 'MSUPN',  
    "2.5.5.5": 'IA5',
    "1.3.6.1.4.1.1466.115.121.1.26": 'IA5',
}
AnotherName._oid_pair = ('type_id', 'value')
AnotherName._oid_specs = {
    'permanent_identifier': PermanentIdentifier,
    'MSUPN': core.UTF8String,
    'IA5': core.IA5String
}


def read_generalnames(names_raw: bytes):
    """
    Parses GeneralNames as DER and returns a list of included alternate names
    """

    results:list[str | dict] = []

    names = GeneralNames.load(names_raw)

    for name in names:

        if isinstance(name.chosen, (EmailAddress, DNSName)):
            # This type is added directly  as string
            results.append(name.chosen.contents.decode())

        elif isinstance(name.chosen, AnotherName):
            result = {
                'type-id': name.chosen['type_id'].dotted
            }

            value = name.chosen['value']
            if isinstance(value, UTF8String):
                result['encoding'] = 'UTF8'
                result['value'] = value.native
            elif isinstance(value, IA5String):
                result['encoding'] = 'IA5'
                result['value'] = value.native
            elif isinstance(value, PermanentIdentifier):
                if "identifier_value" in value:
                    result["identifierValue"] = value["identifier_value"].contents.decode("UTF8")
                if "assigner" in value:
                    result["assigner"] = value["assigner"].dotted
            else:
                raise NotImplementedError(f"Unsupported type {name} for AnotherName. Please open a Github issue. ")

            results.append(result)

    return results

            

            





