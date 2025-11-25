import logging
import os
import pathlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import load_der_x509_certificate, CertificateSigningRequest

from .util import force_int

logger = logging.getLogger(__name__)


def get_hash_algo(name):
    return {
        'sha512': hashes.SHA512(),
        'sha384': hashes.SHA384(),
        'sha256': hashes.SHA256(),
    }[name.lower()]


class KeyPair:

    BASEDIR = 'ca'

    privatekeyfile = property(lambda self: os.path.join(self.BASEDIR, 'private', f'{self.basename}.key'))
    derfile = property(lambda self: os.path.join(self.BASEDIR, 'certs', f'{self.basename}.cer'))
    pemfile = property(lambda self: os.path.join(self.BASEDIR, 'certs', f'{self.basename}.pem'))

    def __init__(self, basename):
        self.basename = basename
        self.certificate = None
        self.private_key = None
        self.public_key = None

    @classmethod
    def for_filename(cls, filename):
        return cls(pathlib.Path(filename).stem)

    def exists(self):
        return os.path.isfile(self.privatekeyfile) or os.path.isfile(self.derfile)

    def load(self, password=None):
        if self.public_key:
            logger.debug(f"Public Key already loaded")
        else:
            if not self.private_key:
                with open(self.privatekeyfile, "rb") as f:
                    if password:
                        password = password.encode("utf-8")
                    self.private_key = serialization.load_pem_private_key(f.read(), password=password)
            if not self.certificate:
                with open(self.derfile, "rb") as f:
                    # Load the certificate and extract the public key
                   self.certificate = load_der_x509_certificate(f.read())
                   self.public_key = self.certificate.public_key()

            logger.debug(f"Loaded private key and certificate files")
        return self

    def generate_private_key(self, profile:dict, password=None):
        logger.info(f"Generating keypair")
        self.private_key = rsa.generate_private_key(
            public_exponent=force_int(profile['exponent']),
            key_size=force_int(profile['publicKeyLength'])
        )
        self.public_key = self.private_key.public_key()

        newpath = os.path.join(self.BASEDIR, 'private')
        if not os.path.exists(newpath):
            os.makedirs(newpath)

        newpath = os.path.join(self.BASEDIR, 'certs')
        if not os.path.exists(newpath):
            os.makedirs(newpath)

        logger.debug(f"Saving private key to {self.privatekeyfile}")

        if password:
            encryption = serialization.BestAvailableEncryption(password.encode("utf-8"))
        else:
            encryption = serialization.NoEncryption()

        with open(self.privatekeyfile, "wb") as f:
            f.write(self.private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=encryption
            ))

    def load_from_csr(self, csr: CertificateSigningRequest):
        if self.private_key or self.public_key:
            raise ValueError(f'Some keys are already loaded, not overriding them from CSR.')
        self.public_key = csr.public_key()
        logger.info(f"Loaded public key from CSR")

    def __str__(self):
        p_loaded = ""
        if self.private_key:
            p_loaded = " (loaded)"
        c_loaded = ""
        if self.certificate:
            c_loaded = " (loaded)"

        return f'KeyPair<Private Key={self.privatekeyfile}{p_loaded}, Certificate={self.derfile}{c_loaded}>'
