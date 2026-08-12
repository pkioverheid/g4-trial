import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

from lib.csr import create_csr
from lib.keypair import KeyPair


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
        }

        cls.enrollment = {
            "subject": {
                "commonName": "Test Subject",
            },
        }

    def test_creates_csr(self):
        csr = create_csr(
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
        csr = create_csr(
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

        csr = create_csr(
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
        csr = create_csr(
            {
                "hashAlgorithm": "sha256",
                "saltLength": 32,
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
