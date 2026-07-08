import os
import unittest
from cryptography.hazmat.primitives import serialization
from asn1crypto.x509 import Name
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import (
    mldsa,
    mlkem,
    rsa,
)
from cryptography.x509 import (
    CertificateSigningRequestBuilder,
    SignatureAlgorithmOID,
    load_pem_x509_csr,
)
from cryptography.x509.name import _ASN1Type

from lib import statement_of_possession
from lib.config import Config
from lib.csr import RequestService
from lib.events import Eventlog
from lib.keypair import KeyPair
from lib.names import as_name
from lib.statement_of_possession import statementOfPossessionOID


class TestCreateCsr(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        cls.subject_keys = KeyPair(
            private_key=cls.private_key,
            public_key=cls.private_key.public_key(),
            certificate=None,
        )

        cls.profile = {
            "hashAlgorithm": "sha256",
            "signatureAlgorithm": 'rsassaPss'
        }

        cls.enrollment = {
            "subject": {
                "commonName": "Test Subject",
            },
        }

        config = Config()
        cls.service = RequestService(config, Eventlog(config))

    def test_creates_csr(self):
        csr = self.service.create(
            self.profile,
            self.enrollment,
            self.subject_keys,
        )

        self.assertIsInstance(
            csr,
            x509.CertificateSigningRequest,
        )

        self.assertTrue(csr.is_signature_valid)

        self.assertEqual(
            csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value,
            "Test Subject",
        )

        self.assertEqual(
            csr.public_key().public_numbers(),
            self.private_key.public_key().public_numbers(),
        )

    def test_without_subject_alt_names(self):
        csr = self.service.create(
            self.profile,
            self.enrollment,
            self.subject_keys,
        )

        with self.assertRaises(x509.ExtensionNotFound):
            csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)

    def test_subject_alt_names(self):
        enrollment = {
            "subject": {
                "commonName": "Test Subject",
            },
            "subjectAltNames": [
                "test.example.com",
            ],
        }

        csr = self.service.create(
            self.profile,
            enrollment,
            self.subject_keys,
        )

        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)

        self.assertFalse(san.critical)

        self.assertEqual(
            san.value.get_values_for_type(x509.DNSName),
            ["test.example.com"],
        )

    def test_algorithm(self):
        csr = self.service.create(
            {
                "hashAlgorithm": "sha256",
                "saltLength": 32,
                "signatureAlgorithm": 'rsassaPss'
            },
            self.enrollment,
            self.subject_keys,
        )

        self.assertIsInstance(
            csr.signature_hash_algorithm,
            hashes.SHA256,
        )

        self.assertEqual(
            csr.signature_algorithm_oid,
            x509.ObjectIdentifier("1.2.840.113549.1.1.10"),
        )

        self.assertEqual(
            csr.signature_algorithm_parameters._salt_length,
            32,
        )

    def test_generate_mixed_mldsa_mlkem(self):
        """
        Generate a CSR containing a ML-KEM public key and signed by an ML-DSA private key
        """

        config = Config()
        event_log = Eventlog(config)
        service = RequestService(config, event_log)

        profile = {
            'publicKeyAlgorithm': 'ML-KEM-768',
            'signatureAlgorithm': 'ML-DSA-65'
        }

        enrollment = {
            'subject': {
                'country': 'US'
            }
        }

        subject_keys = KeyPair.for_filename("test_generate_mixed_mldsa_mlkem-subject")
        subject_keys.basedir = 'testdata/csr'
        subject_keys.generate_private_key(profile)

        signer_keys = KeyPair.for_filename("statement-of-possession-signing")
        signer_keys.basedir = 'testdata/csr'
        signer_keys.load()
        
        csr = service.create(profile, enrollment, subject_keys, signer_keys=signer_keys)

        self.assertEqual(csr.attributes.get_attribute_for_oid(statementOfPossessionOID).value, b"0%0\r1\x0b0\t\x06\x03U\x04\x06\x13\x02NL\x02\x145t\x15iz\xdfAW}\x9f\xb1\x19\xf4\xbf\x17\xd4\x06\x0e'\xe3")

        self.assertIsInstance(csr.public_key(), mlkem.MLKEM768PublicKey)
        self.assertEqual(csr.public_key(), subject_keys.public_key)
        
        self.assertEqual(csr.signature_algorithm_oid, SignatureAlgorithmOID.ML_DSA_65);


    def test_verify_csr_mixed_ok(self):
        """
        Tests loading a CSR containing an ML-KEM public key and signed by a ML-DSA private key
        """

        # Load CSR
        csrfile = os.path.join('testdata', 'csr', 'statement-of-possession-csr-lean.pem')
        with open(csrfile, "rb") as f:
            csr = load_pem_x509_csr(f.read())

        self.assertEqual(csr.subject, as_name({'country': 'NL'}))

        # Verify algorithms
        self.assertIsInstance(csr.public_key(), mlkem.MLKEM768PublicKey)
        self.assertEqual(csr.signature_algorithm_oid, SignatureAlgorithmOID.ML_DSA_65);

        # Load signer certificate
        signing_keys = KeyPair.for_filename('statement-of-possession-signing', )
        signing_keys.basedir = os.path.join('testdata', 'csr')
        signing_keys._load_certificate()
        
        # Verify the CSR using the known signer
        csr.verify_directly_signed_by(signing_keys.public_key)

        # Build the CA checking logging
        issuer_keys = KeyPair.for_filename('statement-of-possession-ca')
        issuer_keys.basedir = os.path.join('testdata', 'csr')
        issuer_keys._load_certificate()
        
        # Then do the full check
        config = Config()
        event_log = Eventlog(config)
        service = RequestService(config, event_log)

        service.verify_proof_of_possession(signing_keys, issuer_keys, csr)
