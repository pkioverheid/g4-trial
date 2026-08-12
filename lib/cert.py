import logging
import os
import re
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import UnrecognizedExtension
from cryptography.x509.oid import ObjectIdentifier

from .config import Config
from .events import Eventlog
from .keypair import KeyPair, get_hash_algo
from .names import as_name
from .qc_statements import build_qc_statements_extension
from .ra import validate
from .san import build_san_extension
from .util import force_int, keys_exist, load_yaml

logger = logging.getLogger(__name__)


class IssuerNotFoundError(Exception):
    pass


def handle_extensions(builder, ext, enrollment, subject_keys, ca_keys, config):
    if 'basicConstraints' in ext:
        builder = builder.add_extension(
            x509.BasicConstraints(
                ca=ext['basicConstraints']['cA'],
                path_length=ext['basicConstraints'].get('pathLenConstraint')
            ),
            critical=ext['basicConstraints'].get('critical', True)
        )

    if 'authorityKeyIdentifier' in ext:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_keys.public_key),
            critical=ext['authorityKeyIdentifier'].get('critical', False)
        )

    if 'authorityInfoAccess' in ext:
        aia = ext['authorityInfoAccess']
        access_descriptions = []
        if 'caIssuers' in aia:
            access_descriptions.append(x509.AccessDescription(
                x509.AuthorityInformationAccessOID.CA_ISSUERS,
                x509.UniformResourceIdentifier(aia['caIssuers'])
            ))
            builder = builder.add_extension(
                x509.AuthorityInformationAccess(access_descriptions),
                critical=aia.get('critical', False)
            )

    if 'certificatePolicies' in ext:
        policies = []
        for policy in ext['certificatePolicies']['value']:
            policies.append(x509.PolicyInformation(
                policy_identifier=ObjectIdentifier(policy['oid']),
                policy_qualifiers=None
            ))
        builder = builder.add_extension(
            x509.CertificatePolicies(policies),
            critical=ext['certificatePolicies'].get('critical', False)
        )

    if 'extendedKeyUsage' in ext:
        ekus = []
        for entry in ext['extendedKeyUsage']['value']:
            oid = entry.get('oid') if isinstance(entry, dict) else entry
            ekus.append(ObjectIdentifier(oid))
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(ekus),
            critical=ext['extendedKeyUsage'].get('critical', False)
        )

    if 'qcStatements' in ext:
        qc_ext = UnrecognizedExtension(
            ObjectIdentifier(ext['qcStatements']['oid']),  # id-pe-qcStatements
            build_qc_statements_extension(ext['qcStatements'], config)
        )
        builder = builder.add_extension(qc_ext, critical=ext['qcStatements'].get('critical', False))

    if 'cRLDistributionPoints' in ext:
        uris = ext['cRLDistributionPoints'].get('value', [])
        points = [
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier(uri)],
                relative_name=None,
                reasons=None,
                crl_issuer=None
            )
            for uri in uris
        ]
        builder = builder.add_extension(
            x509.CRLDistributionPoints(points),
            critical=ext['cRLDistributionPoints'].get('critical', False)
        )

    if 'subjectKeyIdentifier' in ext:
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(subject_keys.public_key),
            critical=ext['subjectKeyIdentifier'].get('critical', False)
        )

    if 'keyUsage' in ext:
        usage_flags = ext['keyUsage']['value']
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature='digitalSignature' in usage_flags,
                content_commitment='nonRepudiation' in usage_flags,
                key_encipherment='keyEncipherment' in usage_flags,
                data_encipherment='dataEncipherment' in usage_flags,
                key_agreement='keyAgreement' in usage_flags,
                key_cert_sign='keyCertSign' in usage_flags,
                crl_sign='cRLSign' in usage_flags,
                encipher_only='encipherOnly' in usage_flags,
                decipher_only='decipherOnly' in usage_flags
            ),
            critical=ext['keyUsage'].get('critical', True)
        )

    if 'subjectAltNames' in enrollment:
        builder = builder.add_extension(
                x509.SubjectAlternativeName(
                build_san_extension(enrollment['subjectAltNames'], config)
            ),
            critical=ext.get('subjectAltNames', {}).get('critical', False)
        )

    return builder


def sign(profile:dict, enrollment:dict, issuer_enrollment:dict, subject_keys:KeyPair, issuer_keys:KeyPair, config:Config) -> x509.Certificate:

    issuer_name = issuer_keys.certificate.subject if issuer_keys.certificate is not None else as_name(issuer_enrollment['subject'])
    
    logger.debug(f"Signing certificate {as_name(enrollment['subject']).rfc4514_string()} using {issuer_name.rfc4514_string()}")

    # Replace placeholders with actual values
    replacements = config.as_dict()
    replacements['issuerBaseName'] = issuer_keys.basename
    if keys_exist(profile, ['extensions', 'authorityInfoAccess', 'caIssuers']):
        profile['extensions']['authorityInfoAccess']['caIssuers'] = profile['extensions']['authorityInfoAccess']['caIssuers'] % replacements
    if keys_exist(profile, ['extensions', 'cRLDistributionPoints', 'value']):
        profile['extensions']['cRLDistributionPoints']['value'] = [value % replacements for value in profile['extensions']['cRLDistributionPoints']['value']]

    # Validity
    if isinstance(profile['validity']['notBefore'], datetime):
        # Absolute date
        not_before = profile['validity']['notBefore']
    elif profile['validity']['notBefore'] == 'now':
        not_before = datetime.now(UTC)
    else:  # assume date time format as string
        not_before = datetime.fromisoformat(profile['validity']['notBefore'])

    if isinstance(profile['validity']['notAfter'], datetime):
        # Absolute date
        not_after = profile['validity']['notAfter']
    else:
        match = re.match("^issuer([0-9-+]+)d$", profile['validity']['notAfter'])
        if match:
            # Is a period relative to the issuer's notAfter. NOTE: last second is inclusive, therefore substract one second
            not_after = issuer_keys.certificate.not_valid_after_utc + timedelta(days=int(match.group(1)), seconds=-1)
        else:
            match = re.match("^([0-9]+)d$", profile['validity']['notAfter'])
            if match:
                # Relative date into the future
                not_after = not_before + timedelta(days=int(match.group(1)), seconds=-1)
            else:
                # assume date time format as string
                not_after = datetime.fromisoformat(profile['validity']['notAfter'])

    # Generate a random Serial number (20 octets)
    serial_number = int.from_bytes(os.urandom(20), "big") >> 1

    # Certificate Builder
    builder = (
        x509.CertificateBuilder()
        .subject_name(as_name(enrollment['subject']))
        .issuer_name(issuer_name)
        .public_key(subject_keys.public_key)
        .serial_number(serial_number)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    
    # Build extensions
    builder = handle_extensions(builder, profile['extensions'], enrollment, subject_keys, issuer_keys, config)

    # Crypto parameter selection
    hash_algo = None
    rsa_padding = None
    if profile['signatureAlgorithm'] == 'rsassaPss':
        hash_algo = get_hash_algo(profile['hashAlgorithm'])
        rsa_padding = padding.PSS(
                            mgf=padding.MGF1(hash_algo),
                            salt_length=force_int(profile.get('saltLength', 64))
                        )
        
    # Sign certificate
    cert = builder.sign(
        private_key=issuer_keys.private_key,
        algorithm=hash_algo,
        rsa_padding=rsa_padding
    )

    subject_keys.certificate = cert

    return cert


def process(profile: dict, enrollment: dict, subject_keys: KeyPair, config: Config, issuer_password=None, subject_password=None) -> None:
    validate(enrollment, profile)

    # Find issuer keypair by its DN from its enrollment
    issuer = load_yaml(os.path.join('enrollment', profile['issuer']))
    issuer_keys = KeyPair.for_filename(os.path.splitext(profile['issuer'])[0])

    selfsigned = issuer['subject'] == enrollment['subject']
    if selfsigned:
        logger.debug("Issuing a self signed certificate")
        try:
            issuer_keys.load()
            print(f"KeyPair for {issuer_keys} already exists, skipping")
            return
        except FileNotFoundError:
            # NOTE: use the subject password as it is used to encrypt the private key
            issuer_keys.generate_private_key(profile, password=subject_password)
            subject_keys = issuer_keys
    else:
        try:
            issuer_keys.load(password=issuer_password)
        except FileNotFoundError as e:
            raise IssuerNotFoundError(
                f"Cannot find keys of {issuer_keys} for signing operation, please generate it first") from e

        try:
            subject_keys.load()
        except FileNotFoundError:
            logger.debug("Generating new key pair for subject")
            subject_keys.generate_private_key(profile, password=subject_password)

    cert = sign(profile, enrollment, issuer, subject_keys, issuer_keys, config)

    # Write issued certificate to disk
    filename = subject_keys.derfile
    with open(filename, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.DER))

    log = Eventlog(Config.from_file("config.yaml"))
    log.log_issued_cert(issuer_keys, subject_keys)

    logger.info(f"Certificate issued and saved to {filename}")
