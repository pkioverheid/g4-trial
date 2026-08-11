import tempfile
import unittest
from pathlib import Path

from cryptography.x509 import AccessDescription, AuthorityInformationAccess, AuthorityKeyIdentifier, BasicConstraints, CRLDistributionPoints, DNSName, DistributionPoint, ExtendedKeyUsage, GeneralNames, KeyUsage, Name, ObjectIdentifier, PolicyInformation, SubjectAlternativeName, SubjectKeyIdentifier, UniformResourceIdentifier
import yaml

from lib.cert import sign
from lib.config import Config
from lib.keypair import KeyPair


class TestCert(unittest.TestCase):

    def test_sign(self):

        config = Config()

        with open('testdata/G4TRIALEEEUTLGSigsLP2025_profile.yaml') as f:
            profile = yaml.safe_load(f)

        with open('testdata/G4TRIALEEEUTLGSigsLP2025_enrollment.yaml') as f:
            enrollment = yaml.safe_load(f)
        
        subject_keys = KeyPair('test').generate_private_key(profile)
        issuer_keys = subject_keys

        cert = sign(profile, enrollment, enrollment, subject_keys, issuer_keys, config)

        self.assertEqual(cert.public_key(), subject_keys.public_key)
        self.assertEqual(cert.subject, Name.from_rfc4514_string('2.5.4.5=00000099999999910000,2.5.4.97=NTRNL-99999991,CN=TRIAL Company name,O=TRIAL Company name,C=NL'))


        ext = cert.extensions.get_extension_for_class(BasicConstraints).value
        self.assertEqual(ext, BasicConstraints(False, None))

        ext = cert.extensions.get_extension_for_class(AuthorityKeyIdentifier).value
        self.assertIsNotNone(ext)
        self.assertNotEqual(ext, 'match_issuer')

        ext = cert.extensions.get_extension_for_class(AuthorityInformationAccess).value
        self.assertEqual(ext, 
                        AuthorityInformationAccess(
                            [
                                AccessDescription(
                                    access_method=ObjectIdentifier('1.3.6.1.5.5.7.48.2'), 
                                    access_location=UniformResourceIdentifier(value='http://cert.pkioverheid.nl/test.cer'))
                            ]
                            )
                        )

        
        #ext = cert.extensions.get_extension_for_class(PolicyInformation).value
        #self.assertIsNotNone(ext)

        ext = cert.extensions.get_extension_for_class(ExtendedKeyUsage).value
        self.assertEqual(ext, ExtendedKeyUsage([ObjectIdentifier('1.3.6.1.4.1.311.10.3.12'), ObjectIdentifier('1.3.6.1.5.5.7.3.36')]))
        
        ext = cert.extensions.get_extension_for_oid(ObjectIdentifier("1.3.6.1.5.5.7.1.3")).value
        self.assertEqual(len(ext.value), 129)

        ext = cert.extensions.get_extension_for_class(CRLDistributionPoints).value
        self.assertEqual(ext, CRLDistributionPoints([DistributionPoint(
            [UniformResourceIdentifier('http://crl.pkioverheid.nl/test.crl')], None, None, None)]))     
        
        ext = cert.extensions.get_extension_for_class(SubjectKeyIdentifier).value
        self.assertEqual(len(ext.digest), 20)    

        ext = cert.extensions.get_extension_for_class(KeyUsage).value
        self.assertEqual(ext, KeyUsage(True, True, False, False, False, False, False, False, False))

        ext = cert.extensions.get_extension_for_class(SubjectAlternativeName).value
        self.assertEqual(ext, SubjectAlternativeName(general_names=GeneralNames([DNSName('example.com')])) )






