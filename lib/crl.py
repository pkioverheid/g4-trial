import logging
import os
from datetime import datetime, timedelta, timezone

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import (
    CertificateRevocationList,
    ReasonFlags,
    load_der_x509_crl,
)
from cryptography.x509.extensions import BasicConstraints
from jschon import JSON, JSONSchema, create_catalog

from lib.config import Config
from lib.events import Eventlog

from .keypair import KeyPair
from .util import force_int, load_yaml, output_errors

logger = logging.getLogger(__name__)


catalog = create_catalog("2020-12")
schema = JSONSchema.loadf(os.path.join('schema', 'revocations.json'))

reason_map = {
    "unspecified": ReasonFlags.unspecified,
    "keyCompromise": ReasonFlags.key_compromise,
    "CACompromise": ReasonFlags.ca_compromise,
    "affiliationChanged": ReasonFlags.affiliation_changed,
    "superseded": ReasonFlags.superseded,
    "cessationOfOperation": ReasonFlags.cessation_of_operation,
    "certificateHold": ReasonFlags.certificate_hold,
    "removeFromCRL": ReasonFlags.remove_from_crl,
    "privilegeWithdrawn": ReasonFlags.privilege_withdrawn,
    "AACompromise": ReasonFlags.aa_compromise,
}


def parse_serial_number(input):
    if isinstance(input, str) and ':' in input:
        # Assume openSSL output, e.g. '78:74:17:c2:a6:23:5f:55:57:ac:38:5e:e3:4d:6e:82:b4:fd:07:eb'
        return int(input.replace(':', ''), 16)
    return force_int(input)


class CRLService:

    def __init__(self, config: Config, event_log: Eventlog):
        self.config = config
        self.event_log = event_log

    def generate(self, revocations: list, ca_keys: KeyPair, crl_number=1, renewal_hours=48) -> CertificateRevocationList:

        # Build CRL
        now = datetime.now(timezone.utc)
        crl_builder = (
            x509.CertificateRevocationListBuilder()
                .issuer_name(ca_keys.certificate.subject)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_keys.public_key), critical=False)
                .add_extension(x509.CRLNumber(crl_number), critical=False)
                .last_update(now)
                .next_update(now + timedelta(hours=renewal_hours))
        )

        # Create revoked certificate entries
        for revoked_cert in revocations:
            date = revoked_cert.get('date', datetime.now(timezone.utc))
            if isinstance(date, str):
                date = datetime.fromisoformat(date)
            crl_reason = reason_map.get(revoked_cert.get('reason', 'cessationOfOperation'), ReasonFlags.cessation_of_operation)
            revoked_cert = (
                x509.RevokedCertificateBuilder()
                    .serial_number(parse_serial_number(revoked_cert['serialNumber']))
                    .revocation_date(date)
                    .add_extension(x509.CRLReason(crl_reason), critical=False)
                    .build()
            )
            crl_builder = crl_builder.add_revoked_certificate(revoked_cert)

        # Sign the CRL (use the same parameters as the signature of the CA's certificate)
        crl = crl_builder.sign(
            private_key=ca_keys.private_key,
            algorithm=ca_keys.certificate.signature_hash_algorithm,
            rsa_padding=ca_keys.certificate.signature_algorithm_parameters
        )

        return crl
    
    def process(self, revocationfile: str, force: bool = False, issuer_password: str|None = None) -> CertificateRevocationList:

        # Find keys
        ca_keys = (
            KeyPair
            .for_filename(revocationfile)
            .load(password=issuer_password)
            )

        # Check must be a CA
        basic_constraints = ca_keys.certificate.extensions.get_extension_for_class(BasicConstraints).value
        if not basic_constraints.ca:
            logger.fatal('Cannot create a CRL for non-CA certificates. Skipping')
            raise TypeError('Issuer is not a CA')

        # If absent YAML, create a boilerplate file
        if force and not os.path.exists(revocationfile):
            # Write a boilerplate YAML
            logger.debug(f"Revocation file {revocationfile} not found, writing boilerplate file")

            d = {'revocations': []}
            with open(revocationfile, 'w') as outfile:
                yaml.dump(d, outfile, default_flow_style=False, explicit_start=True)

        # Validate input
        revocations = load_yaml(revocationfile)
        instance = JSON(revocations)
        result = schema.evaluate(instance)
        if not result.valid:
            logger.fatal(f"{revocationfile} is invalid to generate a CRL ❌")
            output_errors(result.output("detailed")["errors"])
            raise ValueError('Invalid revocations')

        filename = os.path.join(ca_keys.basedir, 'crl', f"{ca_keys.basename}.crl")

        current_crl_number = 0
        try:
            # Attempt to load existing CRL to extract cRLNumber
            with open(filename, 'rb') as f:
                crl = load_der_x509_crl(f.read())
                current_crl_number = crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
                logger.debug(f"Current cRLNumber is {current_crl_number}")
        except FileNotFoundError:
            # Safely ignore, as this would be the first CRL for this CA
            pass

        # Generate CRL
        crl = self.generate(revocations['revocations'], ca_keys, crl_number=current_crl_number+1, renewal_hours=self.config.crl_renewal_hours)

        self.event_log.log_signed_crl(crl)

        # Write to disk
        with open(filename, "wb") as f:
            f.write(crl.public_bytes(serialization.Encoding.DER))

        logger.info(f"Signed CRL with number {current_crl_number+1} containing {len(revocations['revocations'])} revocations and saved to {filename}")

        return crl
