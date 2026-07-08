import unittest

from asn1crypto import pem
from asn1crypto.cms import IssuerAndSerialNumber
from asn1crypto.x509 import Certificate, Name
from cryptography.x509 import load_pem_x509_csr

from lib import statement_of_possession
from lib.statement_of_possession import (
    PrivateKeyPossessionStatement,
    statementOfPossessionOID,
)

unittest.TestCase.maxDiff = None


class TestPOP(unittest.TestCase):
    
    def test_load_from_csr_full(self):
        """
        Loads a CSR containing the posession statement (including the certificate) and verifies correct loading
        """

        # open the CSR from RFC 9883
        with open('testdata/csr/statement-of-possession-csr-full.pem', 'rb') as f:
            csr = load_pem_x509_csr(f.read())

            attr = csr.attributes.get_attribute_for_oid(statementOfPossessionOID)

            actual = statement_of_possession.load(attr.value, broken=True)

            # Load separately the public key, with which private key the CSR was signed
            with open('testdata/csr/certs/statement-of-possession-signing.pem', 'rb') as f:
                _, _, der_bytes = pem.unarmor(f.read())
                cert = Certificate.load(der_bytes)

            expected = PrivateKeyPossessionStatement({
                'signer': IssuerAndSerialNumber({
                    'issuer': Name.build({'country_name': 'NL'}, use_printable=True),
                    'serial_number': 305165262547671163706059072524803971879204169699
                }),
                'cert': cert
            })

            # Regardless of internal structure, the actual DER should match
            self.assertEqual(expected.dump(), actual.dump())

    def test_load_from_csr_lean(self):
        """
        Loads a CSR containing the posession statement (excluding the certificate) and verifies correct loading
        """

        # open the CSR from RFC 9883
        with open('testdata/csr/statement-of-possession-csr-lean.pem', 'rb') as f:
            csr = load_pem_x509_csr(f.read())

            attr = csr.attributes.get_attribute_for_oid(statementOfPossessionOID)

            actual = statement_of_possession.load(attr.value, broken=True)

            expected = PrivateKeyPossessionStatement({
                'signer': IssuerAndSerialNumber({
                    'issuer': Name.build({'country_name': 'NL'}),
                    'serial_number': 305165262547671163706059072524803971879204169699
                })
            })

            # Regardless of internal structure, the actual DER should match
            self.assertEqual(expected.dump(), actual.dump())

    def test_build_from_cert(self):
        """
        Builds a possession statement from a certificate and verifies that it gets generated correctly
        """

        with open('testdata/csr/certs/statement-of-possession-signing.pem', 'rb') as f:
            _, _, cert_der = pem.unarmor(f.read())

        actual = statement_of_possession.build_from(cert_der, include_cert=True)

        expected = PrivateKeyPossessionStatement({
            'signer': IssuerAndSerialNumber({
                'issuer': Name.build({'country_name': 'NL'}, use_printable=True),
                'serial_number': 305165262547671163706059072524803971879204169699
            }),
            'cert': Certificate.load(cert_der)
        })


        self.assertEqual(expected['signer']['issuer'],actual['signer']['issuer'])
        self.assertEqual(expected['signer']['serial_number'],actual['signer']['serial_number'])

        # Actually compare output DER
        self.assertEqual(expected['cert'].dump(),actual['cert'].dump())
        self.assertEqual(expected.dump(), actual.dump())

