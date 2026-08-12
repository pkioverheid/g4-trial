import logging
import os
import pathlib
from enum import StrEnum

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import (
    CertificateSigningRequest,
    load_der_x509_certificate,
    load_pem_x509_certificate,
)

from lib.config import BASEDIR
from lib.util import force_int


class Crypto(StrEnum):
    RSA = "rsaEncryption"


logger = logging.getLogger(__name__)


def get_hash_algo(name):
    return {
        'sha512': hashes.SHA512(),
        'sha384': hashes.SHA384(),
        'sha256': hashes.SHA256(),
    }[name.lower()]


class KeyPair:

    privatekeyfile = property(lambda self: os.path.join(self.basedir, 'private', f'{self.basename}.key'))
    derfile = property(lambda self: os.path.join(self.basedir, 'certs', f'{self.basename}.cer'))
    pemfile = property(lambda self: os.path.join(self.basedir, 'certs', f'{self.basename}.pem'))

    def __init__(self, private_key, public_key, certificate):
        self.basedir = BASEDIR
        self.private_key = private_key
        self.public_key = public_key
        self.certificate = certificate

    @classmethod
    def for_filename(cls, filename) -> "KeyPair":
        instance = cls(None, None, None)
        instance.basename = pathlib.Path(filename).stem
        return instance

    def exists(self) -> bool:
        return self.private_key_exists() or self.certificate_exists()

    def private_key_exists(self) -> bool:
        return os.path.isfile(self.privatekeyfile)

    def certificate_exists(self) -> bool:
        return os.path.isfile(self.derfile) or os.path.isfile(self.pemfile)

    def load(self, password=None) -> "KeyPair":
        if self.public_key:
            logger.debug("Public Key already loaded")

        if not self.private_key:
            self._load_private_key(password)

        if not self.certificate:
            self._load_certificate()

        logger.debug("Loaded private key and certificate files")

        return self

    def _load_private_key(self, password: str | None = None) -> "KeyPair":
        with open(self.privatekeyfile, "rb") as f:
            if password:
                password = password.encode("utf-8")
            self.private_key = serialization.load_pem_private_key(f.read(), password=password)
        return self

    def _load_certificate(self) -> "KeyPair":
        # Load the certificate and extract the public key
        try:
            with open(self.derfile, "rb") as f:
                self.certificate = load_der_x509_certificate(f.read())
        except FileNotFoundError:
            with open(self.pemfile, "rb") as f:
                self.certificate = load_pem_x509_certificate(f.read())

        self.public_key = self.certificate.public_key()
        return self

    def generate_private_key(self, profile:dict, password=None) -> "KeyPair":
        publicKeyAlgorithm = profile['publicKeyAlgorithm']
        
        match publicKeyAlgorithm:
            case Crypto.RSA:
                self.private_key = rsa.generate_private_key(
                    public_exponent=force_int(profile['exponent']),
                    key_size=force_int(profile['publicKeyLength'])
                )
            case _:
                raise UnsupportedAlgorithm(f"Unsupported publicKeyAlgorithm {publicKeyAlgorithm}")

        logger.info(f"Generated keypair using {publicKeyAlgorithm}")
        
        self.public_key = self.private_key.public_key()

        logger.debug(f"Saving private key to {self.privatekeyfile}")

        if password:
            encryption = serialization.BestAvailableEncryption(password.encode("utf-8"))
        else:
            encryption = serialization.NoEncryption()

        with open(self.privatekeyfile, "wb") as f:
            f.write(self.private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption
            ))

        return self

    def load_from_csr(self, csr: CertificateSigningRequest) -> "KeyPair":
        if self.private_key or self.public_key:
            raise ValueError('Some keys are already loaded, not overriding them from CSR.')

        self.public_key = csr.public_key()

        logger.info("Loaded public key from CSR")

        return self

    def __str__(self):
        p_loaded = ""
        if self.private_key:
            p_loaded = " (loaded)"
        c_loaded = ""
        if self.certificate:
            c_loaded = " (loaded)"

        return f'KeyPair<Private Key={self.privatekeyfile}{p_loaded}, Certificate={self.derfile}{c_loaded}>'

    def __eq__(self, value):
        return self.basename == value
