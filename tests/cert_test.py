import unittest
from datetime import datetime, timedelta, timezone

import yaml
from cryptography.x509 import (
    AccessDescription,
    AuthorityInformationAccess,
    AuthorityKeyIdentifier,
    BasicConstraints,
    CertificatePolicies,
    CRLDistributionPoints,
    DistributionPoint,
    DNSName,
    ExtendedKeyUsage,
    GeneralNames,
    KeyUsage,
    Name,
    ObjectIdentifier,
    PolicyInformation,
    SubjectAlternativeName,
    SubjectKeyIdentifier,
    UniformResourceIdentifier,
)

from lib.cert import _parse_date_str, _parse_not_after, sign
from lib.config import Config
from lib.keypair import KeyPair


class TestCert(unittest.TestCase):

    def test_sign(self):

        config = Config()

        with open("testdata/G4TRIALEEEUTLGSigsLP2025_profile.yaml") as f:
            profile = yaml.safe_load(f)

        with open("testdata/G4TRIALEEEUTLGSigsLP2025_enrollment.yaml") as f:
            enrollment = yaml.safe_load(f)

        subject_keys = KeyPair.for_filename("test").generate_private_key(profile)
        issuer_keys = subject_keys

        cert = sign(profile, enrollment, enrollment, subject_keys, issuer_keys, config)

        self.assertEqual(cert.public_key(), subject_keys.public_key)
        self.assertEqual(
            cert.subject,
            Name.from_rfc4514_string(
                "2.5.4.5=00000099999999910000,2.5.4.97=NTRNL-99999991,CN=TRIAL Company name,O=TRIAL Company name,C=NL"
            ),
        )

        ext = cert.extensions.get_extension_for_class(BasicConstraints).value
        self.assertEqual(ext, BasicConstraints(False, None))

        ext = cert.extensions.get_extension_for_class(AuthorityKeyIdentifier).value
        self.assertIsNotNone(ext)
        self.assertNotEqual(ext, "match_issuer")

        ext = cert.extensions.get_extension_for_class(AuthorityInformationAccess).value
        self.assertEqual(
            ext,
            AuthorityInformationAccess(
                [
                    AccessDescription(
                        access_method=ObjectIdentifier("1.3.6.1.5.5.7.48.2"),
                        access_location=UniformResourceIdentifier(
                            value="http://cert.pkioverheid.nl/test.cer"
                        ),
                    )
                ]
            ),
        )

        ext = cert.extensions.get_extension_for_class(CertificatePolicies).value
        policies = [
            PolicyInformation(
                policy_identifier=ObjectIdentifier("0.4.0.2042.1.2"),
                policy_qualifiers=None,
            ),
            PolicyInformation(
                policy_identifier=ObjectIdentifier("0.4.0.194112.1.3"),
                policy_qualifiers=None,
            ),
            PolicyInformation(
                policy_identifier=ObjectIdentifier("2.16.528.1.1003.1.2.41.14.25.5"),
                policy_qualifiers=None,
            ),
        ]
        self.assertEqual(ext, CertificatePolicies(policies))

        ext = cert.extensions.get_extension_for_class(ExtendedKeyUsage).value
        self.assertEqual(
            ext,
            ExtendedKeyUsage(
                [
                    ObjectIdentifier("1.3.6.1.4.1.311.10.3.12"),
                    ObjectIdentifier("1.3.6.1.5.5.7.3.36"),
                ]
            ),
        )

        ext = cert.extensions.get_extension_for_oid(
            ObjectIdentifier("1.3.6.1.5.5.7.1.3")
        ).value
        self.assertEqual(len(ext.value), 129)

        ext = cert.extensions.get_extension_for_class(CRLDistributionPoints).value
        self.assertEqual(
            ext,
            CRLDistributionPoints(
                [
                    DistributionPoint(
                        [
                            UniformResourceIdentifier(
                                "http://crl.pkioverheid.nl/test.crl"
                            )
                        ],
                        None,
                        None,
                        None,
                    )
                ]
            ),
        )

        ext = cert.extensions.get_extension_for_class(SubjectKeyIdentifier).value
        self.assertEqual(len(ext.digest), 20)

        ext = cert.extensions.get_extension_for_class(KeyUsage).value
        self.assertEqual(
            ext, KeyUsage(True, True, False, False, False, False, False, False, False)
        )

        ext = cert.extensions.get_extension_for_class(SubjectAlternativeName).value
        self.assertEqual(
            ext,
            SubjectAlternativeName(
                general_names=GeneralNames([DNSName("example.com")])
            ),
        )


class TestParseDateStr(unittest.TestCase):

    def test_datetime_input(self):
        value = datetime(2026, 8, 12, 10, 30, tzinfo=timezone.UTC)
        result = _parse_date_str(value)
        self.assertIs(result, value)

    def test_now(self):
        before = datetime.now(timezone.UTC)

        result = _parse_date_str("now")

        after = datetime.now(timezone.UTC)

        self.assertIsInstance(result, datetime)
        self.assertGreaterEqual(result, before)
        self.assertLessEqual(result, after)

    def test_iso_datetime_string(self):
        value = "2026-08-12T10:30:00+00:00"

        result = _parse_date_str(value)

        self.assertEqual(
            result,
            datetime(2026, 8, 12, 10, 30, tzinfo=timezone.UTC),
        )

    def test_iso_datetime_string_without_timezone(self):
        value = "2026-08-12T10:30:00"

        result = _parse_date_str(value)

        self.assertEqual(
            result,
            datetime(2026, 8, 12, 10, 30, tzinfo=timezone.UTC),
        )

    def test_invalid_date_string(self):
        with self.assertRaises(ValueError):
            _parse_date_str("not-a-date")


class TestParseNotAfter(unittest.TestCase):

    def setUp(self):
        self.not_before = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.UTC)
        self.issuer_not_after = datetime(
            2027, 1, 1, 12, 0, tzinfo=timezone.UTC
        )

    def test_datetime_input(self):
        value = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.UTC)

        result = _parse_not_after(
            value,
            self.not_before,
            self.issuer_not_after,
        )

        self.assertIs(result, value)

    def test_issuer_relative_days(self):
        result = _parse_not_after(
            "issuer10d",
            self.not_before,
            self.issuer_not_after,
        )

        expected = (
            self.issuer_not_after
            + timedelta(days=10, seconds=-1)
        )

        self.assertEqual(result, expected)

    def test_issuer_relative_negative_days(self):
        result = _parse_not_after(
            "issuer-10d",
            self.not_before,
            self.issuer_not_after,
        )

        expected = (
            self.issuer_not_after
            + timedelta(days=-10, seconds=-1)
        )

        self.assertEqual(result, expected)

    def test_relative_zero_days(self):
        result = _parse_not_after(
            "0d",
            self.not_before,
            self.issuer_not_after,
        )

        expected = self.not_before - timedelta(seconds=1)

        self.assertEqual(result, expected)

    def test_iso_datetime_string(self):
        value = "2026-06-01T12:00:00+00:00"

        result = _parse_not_after(
            value,
            self.not_before,
            self.issuer_not_after,
        )

        expected = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.UTC)

        self.assertEqual(result, expected)

    def test_invalid_dependency(self):
        with self.assertRaises(ValueError):
            _parse_not_after(
                "issuer-1d",
                self.not_before,
                None,
            )

    def test_invalid_string(self):
        with self.assertRaises(ValueError):
            _parse_not_after(
                "not-a-date",
                self.not_before,
                self.issuer_not_after,
            )