import logging
import os

from cryptography import x509
from cryptography.x509.extensions import AuthorityKeyIdentifier

if not os.path.isdir('ca'):
    os.mkdir('ca')

eventlog = logging.getLogger('events')
file_handler = logging.FileHandler(filename=os.path.join('ca', 'events.txt'))
formatter = logging.Formatter('%(asctime)s;%(name)s;%(levelname)s;%(message)s')
file_handler.setFormatter(formatter)
eventlog.addHandler(file_handler)


def log(msg: str):
    eventlog.info(msg)


def log_issued_cert(cert: x509.Certificate):
    aki = cert.extensions.get_extension_for_class(AuthorityKeyIdentifier).value.key_identifier.hex()
    log(f"issued;{aki};{cert.serial_number}")


def log_signed_crl(crl: x509.CertificateRevocationList):
    aki = crl.extensions.get_extension_for_class(AuthorityKeyIdentifier).value.key_identifier.hex()
    crl_number = crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
    log(f"crl;{aki};{crl_number}")
