import csv
import logging
import os

from cryptography import x509
from cryptography.x509.extensions import AuthorityKeyIdentifier

from .config import BASEDIR
from .keypair import KeyPair

LOG_FILENAME = os.path.join(BASEDIR, 'events.txt')

# Ensure our output directories exist
for dir in [BASEDIR, os.path.join(BASEDIR, 'private'), os.path.join(BASEDIR, 'certs')]:
    if not os.path.isdir(dir):
        os.mkdir(dir)


def configure_logger(logger, log_filename=LOG_FILENAME):
    file_handler = logging.FileHandler(filename=log_filename)
    formatter = logging.Formatter('%(asctime)s;%(name)s;%(levelname)s;%(message)s')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)


eventlog = logging.getLogger('events')
configure_logger(eventlog)


def log(msg: str, eventlog=eventlog) -> None:
    eventlog.info(msg)


def _log_issued_cert(issuer_enrollment: str, issuer_dn: str, aki: str, cert_serial_number: int, enrollment: str, eventlog=eventlog) -> None:
    log(f"issued;{issuer_enrollment};{issuer_dn};{aki};{cert_serial_number};{enrollment}", eventlog=eventlog)


def log_issued_cert(issuer: KeyPair, subject: KeyPair, eventlog=eventlog) -> None:
    cert = subject.certificate
    aki = cert.extensions.get_extension_for_class(AuthorityKeyIdentifier).value.key_identifier.hex()
    _log_issued_cert(issuer.basename, issuer.certificate.subject.rfc4514_string(), aki, cert.serial_number, subject.basename, eventlog=eventlog)


def log_signed_crl(crl: x509.CertificateRevocationList, eventlog=eventlog) -> None:
    aki = crl.extensions.get_extension_for_class(AuthorityKeyIdentifier).value.key_identifier.hex()
    crl_number = crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
    log(f"crl;{aki};{crl_number}", eventlog=eventlog)


def lookup(issuer_dn: str, serial_number: int, logfile=LOG_FILENAME) -> str:
    """
    Looks up the basename of a certificate by its issuer DN and serial number in the event log file.
    """
    with open(logfile, encoding="utf-8") as f:
        for row in csv.reader(f, delimiter=";"):
            if row[3] != "issued":
                continue

            if row[5] == issuer_dn and row[7] == str(serial_number):
                return row[4],row[8]

    raise ValueError(f"Certificate with serial number {serial_number} issued by {issuer_dn} not found")
