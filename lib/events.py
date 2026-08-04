import logging
import os

from cryptography import x509
from cryptography.x509.extensions import AuthorityKeyIdentifier

from lib.keypair import KeyPair

if not os.path.isdir('ca'):
    os.mkdir('ca')

LOG_FILENAME = os.path.join('ca', 'events.txt')

def configure_logger(logger, log_filename=LOG_FILENAME):
    file_handler = logging.FileHandler(filename=log_filename)
    formatter = logging.Formatter('%(asctime)s;%(name)s;%(levelname)s;%(message)s')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)


eventlog = logging.getLogger('events')
configure_logger(eventlog)


def log(msg: str, eventlog=eventlog):
    eventlog.info(msg)


def _log_issued_cert(issuer_dn: str, aki: str, serial_number: int, enrollment: str, eventlog=eventlog):
    log(f"issued;{issuer_dn};{aki};{serial_number};{enrollment}", eventlog=eventlog)


def log_issued_cert(issuer: KeyPair, subject: KeyPair, eventlog=eventlog):
    cert = subject.certificate
    aki = cert.extensions.get_extension_for_class(AuthorityKeyIdentifier).value.key_identifier.hex()
    _log_issued_cert(issuer.certificate.subject.rfc4514_string(), aki, cert.serial_number, subject.basename, eventlog=eventlog)


def log_signed_crl(crl: x509.CertificateRevocationList, eventlog=eventlog):
    aki = crl.extensions.get_extension_for_class(AuthorityKeyIdentifier).value.key_identifier.hex()
    crl_number = crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
    log(f"crl;{aki};{crl_number}", eventlog=eventlog)
