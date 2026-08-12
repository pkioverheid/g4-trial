import unittest

from lib.config import Config, PDSLocation
from lib.qc_statements import (
    PdsLocations,
    QCStatements,
    QcTypeSyntax,
    build_qc_statements_extension,
)


class TestBuildQcStatementsExtension(unittest.TestCase):

    def setUp(self):
        self.config = Config(
            ca_issuers_base_url="https://ca.example.com",
            crl_distribution_points_base_url="https://crl.example.com",
            crl_renewal_hours=48,
            pds_location=PDSLocation("https://example.com/pds", "en"),
        )

    def test_encode(self):
        """
        Verifies encoding qcStatements from our internal representation
        """
        qc_data = {
            "value": [
                {
                    "name": "id-etsi-qcs-QcType",
                    "oid": "0.4.0.1862.1.1",
                    "value": "0.4.0.1862.1.6",
                },
                {
                    "name": "id-etsi-qcs-QcPDS",
                    "oid": "0.4.0.1862.1.5",
                    "value": {
                        "url": "{}",
                        "language": "{}",
                    },
                },
                {
                    "name": "id-qcs-pkixQCSyntax-v2",
                    "oid": "1.3.6.1.5.5.7.11.2",
                    "value": "0.4.0.1862.1.3",
                },
                {
                    "name": "unknown",
                    "oid": "1.2.3.4",
                    "value": "ignored",
                },
            ]
        }

        der = build_qc_statements_extension(qc_data, self.config)
        result = QCStatements.load(der)

        self.assertEqual(len(result), 4)

        self.assertEqual(result[0]["statementId"].native, "0.4.0.1862.1.1")
        self.assertEqual(
            result[0]["statementInfo"].parse(QcTypeSyntax)[0].native, "0.4.0.1862.1.6"
        )

        self.assertEqual(result[1]["statementId"].native, "0.4.0.1862.1.5")
        location = result[1]["statementInfo"].parse(PdsLocations)[0]
        self.assertEqual(location["url"].native, "https://example.com/pds")
        self.assertEqual(location["language"].native, "en")

        self.assertEqual(result[2]["statementId"].native, "1.3.6.1.5.5.7.11.2")
        self.assertEqual(
            result[2]["statementInfo"].parse(QcTypeSyntax)[0].native, "0.4.0.1862.1.3"
        )

        self.assertEqual(result[3]["statementId"].native, "1.2.3.4")
        self.assertEqual(result[3]["statementInfo"].native, None)
