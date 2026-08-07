from asn1crypto.core import (
    Any,
    IA5String,
    ObjectIdentifier,
    PrintableString,
    Sequence,
    SequenceOf,
)


class SemanticsInformation(Sequence):
    _fields = [('semanticsIdentifier', ObjectIdentifier)] # noqa: RUF012


class QCStatement(Sequence):
    _fields = [ # noqa: RUF012
        ('statementId', ObjectIdentifier),
        ('statementInfo', Any, {'optional': True})
    ]


class QCStatements(SequenceOf):
    _child_spec = QCStatement


class QcTypeSyntax(SequenceOf):
    _child_spec = ObjectIdentifier


class PdsLocation(Sequence):
    _fields = [  # noqa: RUF012
        ('url', IA5String),
        ('language', PrintableString)
    ]


class PdsLocations(SequenceOf):
    _child_spec = PdsLocation


def build_qc_statements_extension(qc_data, config):
    """
    Encodes QCStatements with a statementId and statementInfo (OID).
    """

    qc_statements = []

    for item in qc_data['value']:
        oid = ObjectIdentifier(item['oid'])

        match item['name']:
            case 'id-etsi-qcs-QcType':
                qc_statements.append(QCStatement({
                    'statementId': oid,
                    'statementInfo': QcTypeSyntax([ObjectIdentifier(item['value'].split(' ')[0])])
                }))
            case 'id-etsi-qcs-QcPDS':
                loc = config.get('pdsLocation')

                url = item['value']['url'].format(loc.get('url'))
                language = item['value']['language'].format(loc.get('language'))

                pds_loc = PdsLocations([
                    PdsLocation({'url': url, 'language': language})
                ])
                qc_statements.append(QCStatement({
                    'statementId': oid,
                    'statementInfo': pds_loc
                }))
            case 'id-qcs-pkixQCSyntax-v2':
                qc_statements.append(QCStatement({
                    'statementId': oid,
                    'statementInfo': SemanticsInformation({'semanticsIdentifier': ObjectIdentifier(item['value'].split(' ')[0])})
                }))
            case _:
                qc_statements.append(QCStatement({'statementId': oid}))

    return QCStatements(qc_statements).dump()
