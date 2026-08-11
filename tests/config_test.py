from pathlib import Path
import tempfile
import unittest

from lib.config import Config, PDSLocation


class TestConfig(unittest.TestCase):

    def test_default_values(self):
        config = Config()

        self.assertEqual(config.base_dir, "ca")
        self.assertEqual(config.log_filename, "events.txt")
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
            base_dir="test-ca",
            log_filename="events.txt",
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
                "baseDir": "test-ca",
                "logFilename": "events.txt",
                "caIssuersBaseUrl": "https://cert.example.com",
                "cRLDistributionPointsBaseUrl": "https://crl.example.com",
                "crlRenewalHours": 24,
                "pdsLocation": {
                    "url": "https://example.com/pds",
                    "language": "nl",
                },
            },
        )

    def test_init_creates_directories(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            base_dir = Path(temp_dir) / "ca"

            config = Config(
                base_dir=str(base_dir),
                log_filename=str(base_dir / "events.txt"),
            )

            result = config.init()

            self.assertIs(result, config)

            self.assertTrue(base_dir.is_dir())
            self.assertTrue((base_dir / "private").is_dir())
            self.assertTrue((base_dir / "certs").is_dir())
            self.assertTrue((base_dir / "crl").is_dir())

    def test_init_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            base_dir = Path(temp_dir) / "ca"

            config = Config(base_dir=str(base_dir))

            config.init()
            config.init()

            self.assertTrue(base_dir.is_dir())
            self.assertTrue((base_dir / "private").is_dir())
            self.assertTrue((base_dir / "certs").is_dir())
            self.assertTrue((base_dir / "crl").is_dir())

    def test_from_yaml(self):
        yaml_data = """
baseDir: superca
logFilename: events.txt
caIssuersBaseUrl: https://cert.example.com
cRLDistributionPointsBaseUrl: https://crl.example.com
crlRenewalHours: 24
pdsLocation: 
    url: https://example.com/pds
    language: nl
"""

        config = Config.from_yaml(yaml_data)

        self.assertEqual(
            config.base_dir,
            "superca",
        )

        self.assertEqual(
            config.log_filename,
            "events.txt",
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
