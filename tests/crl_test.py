import unittest
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

from lib.config import Config
from lib.crl import CRLService
from lib.events import Eventlog
from lib.keypair import KeyPair


class TestGenerateCrl(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        cls.subject = x509.Name(
            [
                x509.NameAttribute(
                    x509.oid.NameOID.COMMON_NAME,
                    "Test CA",
                ),
            ]
        )

        cls.certificate = (
            x509.CertificateBuilder()
            .subject_name(cls.subject)
            .issuer_name(cls.subject)
            .public_key(cls.private_key.public_key())
            .serial_number(1)
            .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .sign(cls.private_key, hashes.SHA256())
        )

        cls.ca_keys = KeyPair(
            private_key=cls.private_key,
            public_key=cls.private_key.public_key(),
            certificate=cls.certificate,
        )

        config = Config()
        cls.service = CRLService(config, Eventlog(config))

    def test_empty_revocations(self):
        crl = self.service.generate(
            revocations=[],
            ca_keys=self.ca_keys,
        )

        self.assertIsInstance(
            crl,
            x509.CertificateRevocationList,
        )
        self.assertEqual(
            crl.issuer,
            self.certificate.subject,
        )
        self.assertEqual(
            len(crl),
            0,
        )

    def test_crl_number(self):
        crl = self.service.generate(
            revocations=[],
            ca_keys=self.ca_keys,
            crl_number=42,
        )

        extension = crl.extensions.get_extension_for_class(
            x509.CRLNumber,
        )

        self.assertEqual(
            extension.value.crl_number,
            42,
        )

    def test_renewal_period(self):
        crl = self.service.generate(
            revocations=[],
            ca_keys=self.ca_keys,
            renewal_hours=48,
        )

        last_update = crl.last_update_utc
        next_update = crl.next_update_utc

        self.assertAlmostEqual(
            (next_update - last_update).total_seconds(),
            48 * 60 * 60,
            delta=1,
        )

    def test_revoked_certificate(self):
        crl = self.service.generate(
            revocations=[
                {
                    "serialNumber": "1234",
                },
            ],
            ca_keys=self.ca_keys,
        )

        self.assertEqual(len(crl), 1)

        revoked = crl[0]

        self.assertEqual(
            revoked.serial_number,
            1234,
        )

    def test_revocation_date_as_datetime(self):
        revocation_date = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

        crl = self.service.generate(
            revocations=[
                {
                    "serialNumber": "1234",
                    "date": revocation_date,
                },
            ],
            ca_keys=self.ca_keys,
        )

        revoked = crl[0]

        self.assertEqual(
            revoked.revocation_date_utc,#.replace(tzinfo=None),
            revocation_date,
        )

    def test_revocation_date_as_string(self):
        revocation_date = "2026-01-01T12:00:00"

        crl = self.service.generate(
            revocations=[
                {
                    "serialNumber": "1234",
                    "date": revocation_date,
                },
            ],
            ca_keys=self.ca_keys,
        )

        revoked = crl[0]

        self.assertEqual(
            revoked.revocation_date_utc.replace(tzinfo=None),
            datetime.fromisoformat(revocation_date),
        )

    def test_default_revocation_reason(self):
        crl = self.service.generate(
            revocations=[
                {
                    "serialNumber": "1234",
                },
            ],
            ca_keys=self.ca_keys,
        )

        reason = crl[0].extensions.get_extension_for_class(
            x509.CRLReason,
        )

        self.assertEqual(
            reason.value.reason,
            x509.ReasonFlags.cessation_of_operation,
        )

    def test_revocation_reason(self):
        crl = self.service.generate(
            revocations=[
                {
                    "serialNumber": "1234",
                    "reason": "keyCompromise",
                },
            ],
            ca_keys=self.ca_keys,
        )

        reason = crl[0].extensions.get_extension_for_class(
            x509.CRLReason,
        )

        self.assertEqual(
            reason.value.reason,
            x509.ReasonFlags.key_compromise,
        )

    def test_multiple_revocations(self):
        crl = self.service.generate(
            revocations=[
                {"serialNumber": "1"},
                {"serialNumber": "2"},
                {"serialNumber": "3"},
            ],
            ca_keys=self.ca_keys,
        )

        self.assertEqual(len(crl), 3)
        self.assertEqual(
            [entry.serial_number for entry in crl],
            [1, 2, 3],
        )

    def test_authority_key_identifier(self):
        crl = self.service.generate(
            revocations=[],
            ca_keys=self.ca_keys,
        )

        aki = crl.extensions.get_extension_for_class(
            x509.AuthorityKeyIdentifier,
        )

        expected = x509.AuthorityKeyIdentifier.from_issuer_public_key(
            self.ca_keys.public_key,
        )

        self.assertEqual(
            aki.value.key_identifier,
            expected.key_identifier,
        )

    def test_crl_is_signed_by_ca(self):
        crl = self.service.generate(
            revocations=[],
            ca_keys=self.ca_keys,
        )

        self.ca_keys.public_key.verify(
            crl.signature,
            crl.tbs_certlist_bytes,
            padding=self.certificate.signature_algorithm_parameters,
            algorithm=self.certificate.signature_hash_algorithm,
        )
