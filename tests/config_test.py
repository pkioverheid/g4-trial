import unittest

from lib.config import Config, PDSLocation


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
        yaml_data = """
logFilename: test-ca/events.txt
caIssuersBaseUrl: https://cert.example.com
cRLDistributionPointsBaseUrl: https://crl.example.com
crlRenewalHours: 24
pdsLocation: 
    url: https://example.com/pds
    language: nl
"""

        config = Config.from_yaml(yaml_data)

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
