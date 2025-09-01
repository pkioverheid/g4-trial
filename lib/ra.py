from jschon import create_catalog, JSON, JSONSchema

from .util import output_errors


def validate(enrollment: dict, profile: dict):
    """
    Validate CSR against the certificate profile
    :param enrollment:
    :param profile:
    :return:
    """
    create_catalog("2020-12")
    schema = JSONSchema(profile['validations'])
    result = schema.evaluate(JSON(enrollment))
    if not result.valid:
        print(f"Enrollment is invalid for specified certificate profile ❌")
        output_errors(result.output("detailed")["errors"])
        exit(1)
