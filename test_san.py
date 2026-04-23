#!/usr/bin/env python3
import unittest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import ObjectIdentifier, RFC822Name, OtherName, DNSName, load_pem_x509_csr, SubjectAlternativeName
from cryptography.hazmat.primitives import hashes

from lib.san import build_san_extension, read_generalnames


class TestSANFunctions(unittest.TestCase):

    def test_build_and_read_san_extension(self):
        """Test building SAN extension and reading it back"""

        inputdata = [
            "dik.trom@companyname.com",  # Email
            "companyname.com",           # DNS
            {
                "type-id": "1.3.6.1.4.1.311.20.2.3",
                "encoding": "UTF8",
                "value": "ABCD001@0.1.2.3.4"
            },  # MSUPN
            {
                "type-id": "1.3.6.1.4.1.1466.115.121.1.26",
                "encoding": "IA5",
                "value": "0.1.2.3.4-diktrom"
            },  # IA5String
            {
                "type-id": "1.3.6.1.5.5.7.8.3",
                "identifierValue": "diktrom",
                "assigner": "0.1.2.3.4"
            }  # PermanentIdentifier
        ]

        # Build the SAN extension
        actual = build_san_extension(inputdata, config={})
        expected = [
                RFC822Name("dik.trom@companyname.com"),
                DNSName('companyname.com'),
                OtherName(type_id=ObjectIdentifier("1.3.6.1.4.1.311.20.2.3"), value=b'\x0c\x11ABCD001@0.1.2.3.4'),
                OtherName(type_id=ObjectIdentifier("1.3.6.1.4.1.1466.115.121.1.26"), value=b'\x16\x110.1.2.3.4-diktrom'),
                OtherName(type_id=ObjectIdentifier("1.3.6.1.5.5.7.8.3"), value=b'0\x0f\x0c\x07diktrom\x06\x04\x01\x02\x03\x04'),
            ]

        self.assertEqual(actual, expected)

    def test_read_generalnames(self):

        csrfile = "testdata/csr_with_sans.csr"
        with open(csrfile, "rb") as f:
            csr = load_pem_x509_csr(f.read())

            ext = csr.extensions.get_extension_for_class(SubjectAlternativeName)

            actual = read_generalnames(ext.value.public_bytes())
            expected = [
                "dik.trom@companyname.com",
                {
                    "type-id": "1.3.6.1.4.1.311.20.2.3",
                    "encoding": "UTF8",
                    "value": "ABCD001@0.1.2.3.4"
                },
                {
                    "type-id": "1.3.6.1.4.1.1466.115.121.1.26",
                    "encoding": "IA5",
                    "value": "0.1.2.3.4-diktrom"
                },
                {
                    "type-id": "1.3.6.1.5.5.7.8.3",
                    "identifierValue": "diktrom",
                    "assigner": "0.1.2.3.4"
                }
            ]

            self.assertEqual(actual, expected)

    def test_unrecognized_encoding(self):
        """Test unrecognized encoding raises NotImplementedError"""
        subjectAltNames = [
            {
                "type-id": "1.3.6.1.4.1.311.20.2.3",
                "encoding": "UNSUPPORTED",
                "value": "test"
            }
        ]

        with self.assertRaises(NotImplementedError):
            build_san_extension(subjectAltNames, config={})

    def test_unrecognized_oid(self):
        """Test unrecognized OID containing a 'value' should still be parsed"""
        subjectAltNames = [
            {
                "type-id": "0.1.2.3.4.1", 
                "encoding": "UTF8", 
                "value": "test"
            },
            {
                "type-id": "0.1.2.3.4.2", 
                "encoding": "IA5", 
                "value": "test"
            }
        ]

        actual = build_san_extension(subjectAltNames, config={})
        expected = [
            OtherName(type_id=ObjectIdentifier("0.1.2.3.4.1"), value=b'\x0c\x04test'),
            OtherName(type_id=ObjectIdentifier("0.1.2.3.4.2"), value=b'\x16\x04test'),
            ]
        self.assertEqual(actual, expected)


if __name__ == '__main__':
    unittest.main()