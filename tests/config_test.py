import tempfile
import unittest
from pathlib import Path

import yaml

from lib.config import Config, PDSLocation


class TestPDSLocation(unittest.TestCase):

    def test_create(self):
        pds = PDSLocation(
            url="https://example.com",
            language="en",
        )

        self.assertEqual(pds.url, "https://example.com")
        self.assertEqual(pds.language, "en")

    def test_from_dict(self):
        data = {
            "url": "https://example.com",
            "language": "nl",
        }

        pds = PDSLocation.from_dict(data)

        self.assertEqual(
            pds,
            PDSLocation(
                url="https://example.com",
                language="nl",
            ),
        )

    def test_as_dict(self):
        pds = PDSLocation(
            url="https://example.com",
            language="en",
        )

        self.assertEqual(
            pds.as_dict(),
            {
                "url": "https://example.com",
                "language": "en",
            },
        )

    def test_is_frozen(self):
        pds = PDSLocation(
            url="https://example.com",
            language="en",
        )

        with self.assertRaises(AttributeError):
            pds.url = "https://other.example.com"


class TestConfig(unittest.TestCase):

    def test_default_values(self):
        config = Config()

        self.assertEqual(config.log_filename, "ca/events.txt")
        self.assertEqual(
            config.ca_issuers_base_url,
            "http://cert.pkioverheid.nl",
        )
        self.assertEqual(
            config.crl_distribution_points_base_url,
            "http://crl.pkioverheid.nl",
        )
        self.assertEqual(config.crl_renewal_hours, 48)
        self.assertEqual(
            config.pds_location,
            PDSLocation(
                url="https://www.github.com/pkioverheid/g4-trial",
                language="en",
            ),
        )

    def test_as_dict(self):
        config = Config(
            log_filename="test-ca/events.txt",
            ca_issuers_base_url="https://cert.example.com",
            crl_distribution_points_base_url="https://crl.example.com",
            crl_renewal_hours=24,
            pds_location=PDSLocation(
                url="https://example.com/pds",
                language="nl",
            ),
        )

        self.assertEqual(
            config.as_dict(),
            {
                "logFilename": "test-ca/events.txt",
                "caIssuersBaseUrl": "https://cert.example.com",
                "cRLDistributionPointsBaseUrl": "https://crl.example.com",
                "crlRenewalHours": 24,
                "pdsLocation": {
                    "url": "https://example.com/pds",
                    "language": "nl",
                },
            },
        )

    def test_from_yaml(self):
        yaml_data = {
            "logFilename": "test-ca/events.txt",
            "caIssuersBaseUrl": "https://cert.example.com",
            "cRLDistributionPointsBaseUrl": "https://crl.example.com",
            "crlRenewalHours": 24,
            "pdsLocation": {
                "url": "https://example.com/pds",
                "language": "nl",
            },
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)
            yaml_file = temp_dir / "config.yaml"

            yaml_file.write_text(
                yaml.safe_dump(yaml_data),
                encoding="utf-8",
            )

            config = Config.from_yaml(str(yaml_file))

            self.assertEqual(
                config.log_filename,
                "test-ca/events.txt",
            )
            self.assertEqual(
                config.ca_issuers_base_url,
                "https://cert.example.com",
            )
            self.assertEqual(
                config.crl_distribution_points_base_url,
                "https://crl.example.com",
            )
            self.assertEqual(config.crl_renewal_hours, 24)
            self.assertEqual(
                config.pds_location,
                PDSLocation(
                    url="https://example.com/pds",
                    language="nl",
                ),
            )

    def test_yaml_round_trip(self):
        original = Config(
            log_filename="test-ca/events.txt",
            ca_issuers_base_url="https://cert.example.com",
            crl_distribution_points_base_url="https://crl.example.com",
            crl_renewal_hours=24,
            pds_location=PDSLocation(
                url="https://example.com/pds",
                language="nl",
            ),
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)
            yaml_file = temp_dir / "config.yaml"

            yaml_file.write_text(
                yaml.safe_dump(original.as_dict()),
                encoding="utf-8",
            )

            # from_yaml() invokes init()
            loaded_data = yaml.safe_load(yaml_file.read_text())
            yaml_file.write_text(
                yaml.safe_dump(loaded_data),
                encoding="utf-8",
            )

            loaded = Config.from_yaml(str(yaml_file))

            self.assertEqual(loaded.log_filename, original.log_filename)
            self.assertEqual(
                loaded.ca_issuers_base_url,
                original.ca_issuers_base_url,
            )
            self.assertEqual(
                loaded.crl_distribution_points_base_url,
                original.crl_distribution_points_base_url,
            )
            self.assertEqual(
                loaded.crl_renewal_hours,
                original.crl_renewal_hours,
            )
            self.assertEqual(
                loaded.pds_location,
                original.pds_location,
            )

