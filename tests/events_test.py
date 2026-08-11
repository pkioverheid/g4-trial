import os
import unittest

from lib.config import Config
from lib.events import Eventlog

config = Config(log_filename="unittest.log")


class TestEventlog(unittest.TestCase):

    def tearDown(self):
        if os.path.isfile("unittest.log"):
            os.remove("unittest.log")
        return super().tearDown()

    def test_lookup_found(self):
        log = Eventlog(config)

        log._log_issued_cert("my_ca", "2.5.4.97=NTRNL-99999990,CN=TRIAL My TSP - G4 PKIo Priv G-TLS SYS - 2026,O=TRIAL My TSP - not for Production use,C=NL", "SOMEAKI", 12345, "myenrollmentfile1")
        log._log_issued_cert("my_ca", "2.5.4.97=NTRNL-99999990,CN=TRIAL My TSP - G4 PKIo Priv G-TLS SYS - 2026,O=TRIAL My TSP - not for Production use,C=NL", "SOMEAKI", 67890, "myenrollmentfile2")
        log._log_issued_cert("my_ca", "2.5.4.97=NTRNL-99999990,CN=TRIAL My TSP - G4 PKIo Priv G-TLS SYS - 2026,O=TRIAL My TSP - not for Production use,C=NL", "SOMEAKI", 14725, "myenrollmentfile3")
        log._log_issued_cert("my_ca", "2.5.4.97=NTRNL-99999990,CN=TRIAL My TSP - G4 PKIo Priv G-TLS SYS - 2026,O=TRIAL My TSP - not for Production use,C=NL", "SOMEAKI", 25836, "myenrollmentfile4")

        issuer,name = log.lookup("2.5.4.97=NTRNL-99999990,CN=TRIAL My TSP - G4 PKIo Priv G-TLS SYS - 2026,O=TRIAL My TSP - not for Production use,C=NL", 14725)

        self.assertEqual(issuer, "my_ca")
        self.assertEqual(name, "myenrollmentfile3")

    def test_lookup_not_found(self):
        log = Eventlog(config)
        log._log_issued_cert("my_ca", "2.5.4.97=NTRNL-99999990,CN=TRIAL My TSP - G4 PKIo Priv G-TLS SYS - 2026,O=TRIAL My TSP - not for Production use,C=NL", "SOMEAKI", 12345, "myenrollmentfile1")

        with self.assertRaises(ValueError):
            log.lookup("C=NL", 1)
