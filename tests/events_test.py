import os
import unittest

from lib.config import Config
from lib.events import Eventlog


class TestEventlog(unittest.TestCase):

    def setUp(self):
        config = Config(log_filename="unittest.log")
        self.log = Eventlog(config)

        return super().setUp()

    def tearDown(self):
        if os.path.isfile("ca/unittest.log"):
            os.remove("ca/unittest.log")
        return super().tearDown()

    def test_lookup_found(self):
        self.log._log_issued_cert("my_ca", "2.5.4.97=NTRNL-99999990,CN=TRIAL My TSP - G4 PKIo Priv G-TLS SYS - 2026,O=TRIAL My TSP - not for Production use,C=NL", "SOMEAKI", 12345, "myenrollmentfile1")
        self.log._log_issued_cert("my_ca", "2.5.4.97=NTRNL-99999990,CN=TRIAL My TSP - G4 PKIo Priv G-TLS SYS - 2026,O=TRIAL My TSP - not for Production use,C=NL", "SOMEAKI", 67890, "myenrollmentfile2")
        self.log._log_issued_cert("my_ca", "2.5.4.97=NTRNL-99999990,CN=TRIAL My TSP - G4 PKIo Priv G-TLS SYS - 2026,O=TRIAL My TSP - not for Production use,C=NL", "SOMEAKI", 14725, "myenrollmentfile3")
        self.log._log_issued_cert("my_ca", "2.5.4.97=NTRNL-99999990,CN=TRIAL My TSP - G4 PKIo Priv G-TLS SYS - 2026,O=TRIAL My TSP - not for Production use,C=NL", "SOMEAKI", 25836, "myenrollmentfile4")

        issuer,name = self.log.lookup("2.5.4.97=NTRNL-99999990,CN=TRIAL My TSP - G4 PKIo Priv G-TLS SYS - 2026,O=TRIAL My TSP - not for Production use,C=NL", 14725)

        self.assertEqual(issuer, "my_ca")
        self.assertEqual(name, "myenrollmentfile3")

    def test_lookup_not_found(self):
        self.log._log_issued_cert("my_ca", "2.5.4.97=NTRNL-99999990,CN=TRIAL My TSP - G4 PKIo Priv G-TLS SYS - 2026,O=TRIAL My TSP - not for Production use,C=NL", "SOMEAKI", 12345, "myenrollmentfile1")

        with self.assertRaises(ValueError):
            self.log.lookup("C=NL", 1)
