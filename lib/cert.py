import os
import pathlib
import re
from datetime import datetime, timedelta

from asn1crypto.core import Sequence, ObjectIdentifier as Asn1OID, SequenceOf
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import UnrecognizedExtension
from cryptography.x509.oid import ObjectIdentifier
from jschon import create_catalog, JSON, JSONSchema

from .dn import as_name, generate_basename
from .keypair import KeyPair
from .util import load_yaml, force_int, output_errors, keys_exist


def get_hash_algo(name):
    return {
        'sha512': hashes.SHA512(),
        'sha384': hashes.SHA384(),
        'sha256': hashes.SHA256(),
    }[name.lower()]


def build_qc_statements_extension(qc_data):
    """
    Encodes a single QCStatement with a statementId and statementInfo (OID).
    """

    class SemanticsInformation(Sequence):
        _fields = [
            ('semanticsIdentifier', Asn1OID)
        ]

    class QCStatement(Sequence):
        _fields = [
            ('statementId', Asn1OID),
            ('statementInfo', SemanticsInformation)
        ]

    class QCStatements(SequenceOf):
        _child_spec = QCStatement

    semantics_oid = qc_data['value']['value'].split()[0]  # Strip description
    qc = QCStatements([
        QCStatement({
            'statementId': qc_data['value']['oid'],
            'statementInfo': SemanticsInformation({'semanticsIdentifier': semantics_oid})
        })
    ])

    # Return as UnrecognizedExtension to include it
    return UnrecognizedExtension(
        ObjectIdentifier('1.3.6.1.5.5.7.1.3'),  # id-pe-qcStatements
        qc.dump()
    )


def handle_extensions(builder, ext, enrollment, subject_keys, ca_keys):

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
        qc_ext = build_qc_statements_extension(ext['qcStatements'])
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
        # SANs are define in the enrollment data
        dns_names = [x509.DNSName(name) for name in enrollment['subjectAltNames']]
        builder = builder.add_extension(
            x509.SubjectAlternativeName(dns_names),
            critical=ext['subjectAltNames'].get('critical', False)
        )

    return builder


def sign(profile, enrollment, subject_keys, issuer_keys):

    # Validity
    if profile['validity']['notBefore'] == 'now':
        not_before = datetime.now()
    else:  # assume date time format
        not_before = datetime.fromisoformat(profile['validity']['notBefore'])

    match = re.match("^([0-9]+)d$", profile['validity']['notAfter'])
    if match:
        # last second is inclusive, therefore substract one second
        not_after = not_before + timedelta(days=int(match.group(1))) - timedelta(seconds=1)
    else:  # assume date time format
        not_after = datetime.fromisoformat(profile['validity']['not_after'])

    # Generate a random Serial number
    serial_number = int.from_bytes(os.urandom(20), "big") >> 1

    # Hash algorithm
    hash_algo = get_hash_algo(profile['hashAlgorithm'])

    # Certificate Builder
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(as_name(enrollment['subject']))
    builder = builder.issuer_name(as_name(profile['issuer']))
    builder = builder.public_key(subject_keys.public_key)
    builder = builder.serial_number(serial_number)
    builder = builder.not_valid_before(not_before)
    builder = builder.not_valid_after(not_after)

    # Build Extensions
    builder = handle_extensions(builder, profile['extensions'], enrollment, subject_keys, issuer_keys)

    # Sign certificate
    cert = builder.sign(
        private_key=issuer_keys.private_key,
        algorithm=hash_algo,
        rsa_padding=padding.PSS(
            mgf=padding.MGF1(hash_algo),
            salt_length=force_int(profile.get('saltLength', 64))
        )
    )

    subject_keys.certificate = cert

    return cert


def process(profile, enrollment, enrollmentfile, config):

    # Validate CSR against the certificate profile
    create_catalog("2020-12")
    schema = JSONSchema(profile['validations'])
    result = schema.evaluate(JSON(enrollment))
    if not result.valid:
        print(f"Enrollment {enrollmentfile} is invalid for specified certificate profile ❌")
        output_errors(result.output("detailed")["errors"])
        exit(1)

    selfsigned = profile['issuer'] == enrollment['subject']

    # Find issuer keypair by name
    issuer_name = generate_basename(profile['issuer'])
    issuer_keys = KeyPair(issuer_name)

    if not selfsigned and not os.path.exists(issuer_keys.certificatefile):
        # If keys for a self-signed do not exist, we'll create them later
        print(f"Cannot find keys of {issuer_keys} for signing operation, please generate it first")
        return

    try:
        issuer_keys.load()
    except FileNotFoundError:
        issuer_keys.generate_private_key(profile)

    if selfsigned:
        subject_keys = issuer_keys

        if os.path.exists(subject_keys.certificatefile):
            print(f"Certificate {subject_keys.basename} already exists, skipping")
            return

    else:
        # Find cert private key - use the same name as the input YAML file
        basename = pathlib.Path(enrollmentfile).stem
        subject_keys = KeyPair(basename)

        if os.path.exists(subject_keys.certificatefile):
            print(f"Certificate {basename} already exists, skipping")
            return

        try:
            subject_keys.load()
        except FileNotFoundError:
            subject_keys.generate_private_key(profile)

    # Some proposed certificate values contain placeholders, replace them here to keep the sign funcion clean
    if keys_exist(profile, ['extensions', 'authorityInfoAccess', 'caIssuers']):
        profile['extensions']['authorityInfoAccess']['caIssuers'] = profile['extensions']['authorityInfoAccess']['caIssuers'] % config['caIssuersBaseUrl']
    if keys_exist(profile, ['extensions', 'cRLDistributionPoints', 'value']):
        profile['extensions']['cRLDistributionPoints']['value'] = [value % config['cRLDistributionPointsBaseUrl'] for value in profile['extensions']['cRLDistributionPoints']['value']]

    cert = sign(profile, enrollment, subject_keys, issuer_keys)

    # Write issued certificate to disk
    filename = subject_keys.certificatefile
    with open(filename, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.DER))

    print(f"Certificate issued and saved to {filename}")
