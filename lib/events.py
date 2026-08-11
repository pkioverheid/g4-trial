import csv
import datetime

from cryptography import x509
from cryptography.x509.extensions import AuthorityKeyIdentifier

from .config import Config
from .keypair import KeyPair


class Eventlog:

    def __init__(self, config: Config):
        self.config = config

    def log(self, msg: str) -> None:
        with open(self.config.log_filename, "a") as log:
            str = '%(asctime)s;%(name)s;%(levelname)s;%(message)s\n' % { #noqa: UP031
                'asctime': datetime.datetime.now(datetime.timezone.utc),
                'name': 'events',
                'levelname': 'INFO', 
                'message': msg
            }
            log.write(str)
            log.flush()

    def _log_issued_cert(self, issuer_enrollment: str, issuer_dn: str, aki: str, cert_serial_number: int, enrollment: str) -> None:
        self.log(f"issued;{issuer_enrollment};{issuer_dn};{aki};{cert_serial_number};{enrollment}")


    def log_issued_cert(self, issuer: KeyPair, subject: KeyPair) -> None:
        cert = subject.certificate
        aki = cert.extensions.get_extension_for_class(AuthorityKeyIdentifier).value.key_identifier.hex()
        self._log_issued_cert(issuer.basename, issuer.certificate.subject.rfc4514_string(), aki, cert.serial_number, subject.basename)


    def log_signed_crl(self, crl: x509.CertificateRevocationList) -> None:
        aki = crl.extensions.get_extension_for_class(AuthorityKeyIdentifier).value.key_identifier.hex()
        crl_number = crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
        self.log(f"crl;{aki};{crl_number}")


    def lookup(self, issuer_dn: str, serial_number: int) -> str:
        """
        Looks up the basename of a certificate by its issuer DN and serial number in the event log file.
        """
        with open(self.config.log_filename, encoding="utf-8") as f:
            for row in csv.reader(f, delimiter=";"):
                if row[3] != "issued":
                    continue
                if row[5] == issuer_dn and row[7] == str(serial_number):
                    return row[4],row[8]

        raise ValueError(f"Certificate with serial number {serial_number} issued by {issuer_dn} not found")
