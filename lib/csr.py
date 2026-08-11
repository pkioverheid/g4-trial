import logging
import os

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import (
    CertificateSigningRequest,
    CertificateSigningRequestBuilder,
    ExtensionNotFound,
    SubjectAlternativeName,
)

from lib.keypair import KeyPair, get_hash_algo
from lib.names import as_dict, as_name
from lib.san import build_san_extension, read_generalnames
from lib.util import force_int

logger = logging.getLogger(__name__)


class RequestService:

    def __init__(self, config, event_log):
        self.config = config
        self.event_log = event_log

    def create(self, profile: dict, enrollment: dict, subject_keys: KeyPair, password=None) -> CertificateSigningRequest:
        if not subject_keys.private_key:
            if os.path.exists(subject_keys.privatekeyfile):
                raise FileExistsError(subject_keys.privatekeyfile)

            if password:
                password.encode("UTF-8")

            subject_keys.generate_private_key(profile, password=password)

        hash_algo = get_hash_algo(profile['hashAlgorithm'])

        builder = (
            CertificateSigningRequestBuilder()
            .subject_name(as_name(enrollment['subject']))
            )

        if 'subjectAltNames' in enrollment:
            builder = builder.add_extension(
                    x509.SubjectAlternativeName(
                    build_san_extension(enrollment['subjectAltNames'])
                ),
                critical=False
            )

        return builder.sign(subject_keys.private_key,
                            algorithm=hash_algo,
                            rsa_padding=padding.PSS(
                                mgf=padding.MGF1(hash_algo),
                                salt_length=force_int(profile.get('saltLength', 64))
                            ))

    def verify(csr: CertificateSigningRequest) -> None:
        """
        Verifies whether the CSR is acceptable to us. Raises an
        exception if it fails. 
        """
        if not csr.is_signature_valid:
            raise InvalidSignature()

    def rebuild_enrollment(self, csr: CertificateSigningRequest) -> dict:
        """
        From specified CSR, attempt to rebuild the enrollment data.
        """

        enrollment = {
            'subject': as_dict(csr.subject)
        }

        # If present, rebuild internal representation of the included SAN
        try:
            ext = csr.extensions.get_extension_for_class(SubjectAlternativeName)
            enrollment['subjectAltNames'] = read_generalnames(ext.value.public_bytes())
            logger.debug(f"CSR contained {len(enrollment['subjectAltNames'])} SANs.")
        except ExtensionNotFound:
            pass

        return enrollment
