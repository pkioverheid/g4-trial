import logging
import unittest

from lib.ca import lookup

from lib.events import _log_issued_cert, configure_logger


class TestCA(unittest.TestCase):

    logfile = 'ca_test.txt'

    def setUp(self):
        logging.basicConfig(
            level=logging.DEBUG,
            force=True,
        )
        self.log = logging.getLogger('test')
        configure_logger(self.log, log_filename=self.logfile)

    def tearDown(self):
        logging.shutdown()

        # Clean up the test log file after each test
        import os
        if os.path.exists(self.logfile):
            os.remove(self.logfile)

    def test_lookup_found(self):
        _log_issued_cert("my_ca", "2.5.4.97=NTRNL-99999990,CN=TRIAL My TSP - G4 PKIo Priv G-TLS SYS - 2026,O=TRIAL My TSP - not for Production use,C=NL", "SOMEAKI", 12345, "myenrollmentfile1", eventlog=self.log)
        _log_issued_cert("my_ca", "2.5.4.97=NTRNL-99999990,CN=TRIAL My TSP - G4 PKIo Priv G-TLS SYS - 2026,O=TRIAL My TSP - not for Production use,C=NL", "SOMEAKI", 67890, "myenrollmentfile2", eventlog=self.log)
        _log_issued_cert("my_ca", "2.5.4.97=NTRNL-99999990,CN=TRIAL My TSP - G4 PKIo Priv G-TLS SYS - 2026,O=TRIAL My TSP - not for Production use,C=NL", "SOMEAKI", 14725, "myenrollmentfile3", eventlog=self.log)
        _log_issued_cert("my_ca", "2.5.4.97=NTRNL-99999990,CN=TRIAL My TSP - G4 PKIo Priv G-TLS SYS - 2026,O=TRIAL My TSP - not for Production use,C=NL", "SOMEAKI", 25836, "myenrollmentfile4", eventlog=self.log)

        issuer,name = lookup("2.5.4.97=NTRNL-99999990,CN=TRIAL My TSP - G4 PKIo Priv G-TLS SYS - 2026,O=TRIAL My TSP - not for Production use,C=NL", 14725, self.logfile)

        self.assertEqual(issuer, "my_ca")
        self.assertEqual(name, "myenrollmentfile3")

    def test_lookup_not_found(self):
        _log_issued_cert("my_ca", "2.5.4.97=NTRNL-99999990,CN=TRIAL My TSP - G4 PKIo Priv G-TLS SYS - 2026,O=TRIAL My TSP - not for Production use,C=NL", "SOMEAKI", 12345, "myenrollmentfile1", eventlog=self.log)

        with self.assertRaises(ValueError):
            lookup("C=NL", 1, self.logfile)
