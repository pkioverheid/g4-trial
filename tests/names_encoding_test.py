import unittest

from cryptography import x509
from cryptography.x509.oid import NameOID

from lib.names import as_dict, as_name


class TestLiteralNameValues(unittest.TestCase):
    def test_reserved_and_unicode_values_survive_der_roundtrip(self):
        values = [
            'Example Research, Development and Services',
            'Example,O=Injected', 'Example+OU=Injected', 'A+B', 'A=B',
            'A"B', 'A\\B', 'A;B', 'A<B>', '#ABCD', ' leading', 'trailing ',
            ' both ', 'München – café', '組織', 'e\u0301', 'é',
            r'literal\2Cescape', 'A\x00B', 'A\nB',
        ]
        for value in values:
            with self.subTest(value=value):
                name = as_name({'CN': value, 'C': 'NL', 'O': value})
                expected = x509.Name([
                    x509.NameAttribute(NameOID.COUNTRY_NAME, 'NL'),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, value),
                    x509.NameAttribute(NameOID.COMMON_NAME, value),
                ])
                self.assertEqual(name.public_bytes(), expected.public_bytes())
                self.assertEqual(len(name.rdns), 3)
                self.assertTrue(all(len(rdn) == 1 for rdn in name.rdns))
                self.assertEqual(as_dict(name), {'C': 'NL', 'O': value, 'CN': value})

    def test_aliases_keep_existing_attribute_order(self):
        names = as_name({'common_name': 'A,B', '2.5.4.10': 'A+B', 'country': 'NL'})
        self.assertEqual([a.oid for a in names], [
            NameOID.COUNTRY_NAME, NameOID.ORGANIZATION_NAME, NameOID.COMMON_NAME])
        self.assertEqual([a.value for a in names], ['NL', 'A+B', 'A,B'])

    def test_invalid_attributes_and_types_are_rejected(self):
        for subject in [{'unknown': 'value'}, {'': 'value'}, {'C': 'NLD'}, {'CN': None}, {'CN': 123}]:
            with self.subTest(subject=subject):
                with self.assertRaises((TypeError, ValueError)):
                    as_name(subject)

    def test_aliases_for_same_oid_remain_separate_rdns(self):
        name = as_name({'CN': 'One, literal', 'common_name': 'Two+literal'})
        self.assertEqual(len(name.rdns), 2)
        self.assertTrue(all(len(rdn) == 1 for rdn in name.rdns))
        self.assertEqual([a.value for a in name], ['One, literal', 'Two+literal'])
