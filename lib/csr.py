import logging
import os

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import (
    padding,
)
from cryptography.x509 import (
    CertificateSigningRequest,
    CertificateSigningRequestBuilder,
    ExtensionNotFound,
    SubjectAlternativeName,
)
from cryptography.x509.name import _ASN1Type

from lib import statement_of_possession
from lib.events import Eventlog
from lib.keypair import KeyPair, get_hash_algo
from lib.names import as_dict, as_name
from lib.san import build_san_extension, read_generalnames
from lib.statement_of_possession import (
    statementOfPossessionOID,
)
from lib.util import force_int

logger = logging.getLogger(__name__)


class RequestService:

    def __init__(self, config, event_log):
        self.config = config
        self.event_log = event_log

    def create(self, profile: dict, enrollment: dict, subject_keys: KeyPair, signer_keys=None, password=None) -> CertificateSigningRequest:
        if not subject_keys.private_key:
            if os.path.exists(subject_keys.privatekeyfile):
                raise FileExistsError(subject_keys.privatekeyfile)

            if password:
                password.encode("UTF-8")

            subject_keys.generate_private_key(profile, password=password)

        builder = (
            CertificateSigningRequestBuilder()
            .subject_name(as_name(enrollment['subject']))
            .public_key(subject_keys.public_key)
        )

        # Only embed SANs in the CSRs
        if 'subjectAltNames' in enrollment:
            builder = builder.add_extension(
                    x509.SubjectAlternativeName(
                    build_san_extension(enrollment['subjectAltNames'])
                ),
                critical=False
            )

        # A different key pair will be used to sign the CSR: add the statement of possession attribute (RFC 9883)
        if signer_keys and subject_keys != signer_keys:
            builder = builder.add_attribute(
                statementOfPossessionOID,
                statement_of_possession.serialize(
                    statement_of_possession.build_from(
                        signer_keys.certificate.public_bytes(serialization.Encoding.DER), include_cert=False), 
                        broken=True),
                _tag=_ASN1Type.Sequence
            )
        else:
            signer_keys = subject_keys

        hash_algo = None
        rsa_padding = None
        if profile['signatureAlgorithm'] == 'rsassaPss':
            hash_algo = get_hash_algo(profile['hashAlgorithm'])
            rsa_padding = padding.PSS(
                                mgf=padding.MGF1(hash_algo),
                                salt_length=force_int(profile.get('saltLength', 64))
                            )

        return builder.sign(signer_keys.private_key,
                            algorithm=hash_algo,
                            rsa_padding=rsa_padding)


    def verify(self, csr: CertificateSigningRequest) -> None:

        signer_pub_key = None
        
        # Was this CSR signed by another private key?
        try:
            attr = csr.attributes.get_attribute_for_oid(statementOfPossessionOID)
            statement = statement_of_possession.load(attr.value, broken=True)

            # Lookup indicated certificate by issuer and serial number (always ignore the included certificate as it's optional)
            
            # Did we issue the certificate that was used for this CSR?
            ca_dn = as_name(statement['signer']['issuer'].native).rfc4514_string()
            issuer_enrollment, signing_enrollment = self.event_log.lookup(ca_dn, statement['signer']['serial_number'].native)
            signing_keys = KeyPair.for_filename(signing_enrollment)._load_certificate()
            issuer_keys = KeyPair.for_filename(issuer_enrollment)._load_certificate()

            # Verify match between the digital signature certificate and this CSR
            self.verify_proof_of_possession(signing_keys, issuer_keys, csr)

            signer_pub_key = signing_keys.public_key

        except x509.AttributeNotFound:
            # Recoverable exception: this CSR is self-signed, verify signature using the public key in the CSR
            signer_pub_key = csr.public_key()

        csr.verify_directly_signed_by(signer_pub_key)

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

    def verify_proof_of_possession(self, signing_keys: KeyPair, issuer_keys: KeyPair, csr: CertificateSigningRequest) -> None:

        # 1. Path validation
        signing_keys.certificate.verify_directly_issued_by(issuer_keys.certificate)

        # 2. Verify DN match between signer and CSR (let's do a MUST instead of a SHOULD)
        if signing_keys.certificate.subject != csr.subject:
            raise ValueError(f"CSR subject {csr.subject} does not match signer certificate subject {signing_keys.certificate.subject}")

        # 3. Verify SANs
        # ignore for now, as the SANs in the CSR are not necessarily the same as in the signing cert
