import unittest
from datetime import datetime, timedelta, timezone

from lib.dates import parse_date_str, parse_not_after


class TestParseDateStr(unittest.TestCase):

    def test_datetime_input(self):
        value = datetime(2026, 8, 12, 10, 30, tzinfo=timezone.utc)
        result = parse_date_str(value)
        self.assertIs(result, value)

    def test_now(self):
        before = datetime.now(timezone.utc)

        result = parse_date_str("now")

        after = datetime.now(timezone.utc)

        self.assertIsInstance(result, datetime)
        self.assertGreaterEqual(result, before)
        self.assertLessEqual(result, after)

    def test_iso_datetime_string(self):
        value = "2026-08-12T10:30:00+00:00"

        result = parse_date_str(value)

        self.assertEqual(
            result,
            datetime(2026, 8, 12, 10, 30, tzinfo=timezone.utc),
        )

    def test_iso_datetime_string_without_timezone(self):
        value = "2026-08-12T10:30:00"

        result = parse_date_str(value)

        self.assertEqual(
            result,
            datetime(2026, 8, 12, 10, 30, tzinfo=timezone.utc),
        )

    def test_invalid_date_string(self):
        with self.assertRaises(ValueError):
            parse_date_str("not-a-date")


class TestParseNotAfter(unittest.TestCase):

    def setUp(self):
        self.not_before = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
        self.issuer_not_after = datetime(2027, 1, 1, 12, 0, tzinfo=timezone.utc)

    def test_datetime_input(self):
        value = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)

        result = parse_not_after(
            value,
            self.not_before,
            self.issuer_not_after,
        )

        self.assertIs(result, value)

    def test_issuer_relative_days(self):
        result = parse_not_after(
            "issuer10d",
            self.not_before,
            self.issuer_not_after,
        )

        expected = self.issuer_not_after + timedelta(days=10, seconds=-1)

        self.assertEqual(result, expected)

    def test_issuer_relative_negative_days(self):
        result = parse_not_after(
            "issuer-10d",
            self.not_before,
            self.issuer_not_after,
        )

        expected = self.issuer_not_after + timedelta(days=-10, seconds=-1)

        self.assertEqual(result, expected)

    def test_relative_zero_days(self):
        result = parse_not_after(
            "0d",
            self.not_before,
            self.issuer_not_after,
        )

        expected = self.not_before - timedelta(seconds=1)

        self.assertEqual(result, expected)

    def test_iso_datetime_string(self):
        value = "2026-06-01T12:00:00+00:00"

        result = parse_not_after(
            value,
            self.not_before,
            self.issuer_not_after,
        )

        expected = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)

        self.assertEqual(result, expected)

    def test_invalid_dependency(self):
        with self.assertRaises(ValueError):
            parse_not_after(
                "issuer-1d",
                self.not_before,
                None,
            )

    def test_invalid_string(self):
        with self.assertRaises(ValueError):
            parse_not_after(
                "not-a-date",
                self.not_before,
                self.issuer_not_after,
            )
