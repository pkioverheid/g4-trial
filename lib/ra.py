import logging

from jschon import JSON, JSONSchema, create_catalog

from .util import output_errors

logger = logging.getLogger(__name__)


def validate(enrollment: dict, profile: dict) -> None:
    """
    Validate CSR against the certificate profile. Raises exception
    if validation fails. 
    :param enrollment:
    :param profile:
    """
    create_catalog("2020-12")
    schema = JSONSchema(profile['validations'])
    result = schema.evaluate(JSON(enrollment))
    if not result.valid:
        logger.fatal("Enrollment is invalid for specified certificate profile ❌")
        output_errors(result.output("detailed")["errors"])
        raise ValueError("Enrollment is invalid for specified certificate profile")
