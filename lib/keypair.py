import os
import logging
import pathlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509 import load_der_x509_certificate, CertificateSigningRequestBuilder, CertificateSigningRequest

from .util import force_int


class KeyPair:

    BASEDIR = 'ca'

    privatekeyfile = property(lambda self: os.path.join(self.BASEDIR, 'private', f'{self.basename}.key'))
    certificatefile = property(lambda self: os.path.join(self.BASEDIR, 'certs', f'{self.basename}.cer'))

    def __init__(self, basename):
        self.basename = basename
        self.certificate = None
        self.private_key = None
        self.public_key = None

    @classmethod
    def for_filename(cls, filename):
        return cls(pathlib.Path(filename).stem)

    def exists(self):
        return os.path.isfile(self.privatekeyfile) or os.path.isfile(self.certificatefile)

    def load(self):
        with open(self.privatekeyfile, "rb") as f:
            self.private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(self.certificatefile, "rb") as f:
            # Load the certificate and extract the public key
            self.certificate = load_der_x509_certificate(f.read())
            self.public_key = self.certificate.public_key()
        return self

    def generate_private_key(self, config):
    def generate_private_key(self, profile):
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

        with open(self.privatekeyfile, "wb") as f:
            f.write(self.private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            ))

    def __str__(self):
        p_loaded = ""
        if self.private_key:
            p_loaded = " (loaded)"
        c_loaded = ""
        if self.certificate:
            c_loaded = " (loaded)"

        return f'KeyPair<Private Key={self.privatekeyfile}{p_loaded}, Certificate={self.certificatefile}{c_loaded}>'
