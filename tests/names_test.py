import unittest

from cryptography import x509
from cryptography.x509.oid import NameOID

from lib.names import as_name


class TestDNFunctions(unittest.TestCase):

    def test_as_name(self):
        # Some random input
        dn_input = {
            'C': 'NL',
            'O': 'Organization',
            'organizationIdentifier': '12345',
            '2.5.4.3': 'Test User',
        }

        actual = as_name(dn_input)
        expected = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, 'NL'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Organization'),
            x509.NameAttribute(NameOID.COMMON_NAME, 'Test User'),
            x509.NameAttribute(NameOID.ORGANIZATION_IDENTIFIER, '12345'),
        ])

        self.assertEqual(actual, expected)
        self.assertEqual(actual.rfc4514_string(), '2.5.4.97=12345,CN=Test User,O=Organization,C=NL')

    def test_incorrect_name(self):
        dn_input = {
            'C': 'NL',
            'unknown': 'Organization',
        }

        with self.assertRaises(ValueError):
            as_name(dn_input)


if __name__ == '__main__':
    unittest.main()
