import re
from datetime import datetime, timedelta, timezone


def parse_date_str(input: str | datetime) -> datetime:
    if isinstance(input, datetime):
        # Absolute date in the correct type
        return input
    elif input == "now":
        return datetime.now(timezone.utc)

    # assume date time format as string: parse
    d = datetime.fromisoformat(input)

    # If no timezone was included, assume UTC
    if d.tzinfo is None or d.tzinfo.utcoffset(d) is None:
        return d.replace(tzinfo=timezone.utc)

    return d


def parse_not_after(
    input: str | datetime,
    not_before: datetime,
    issuer_not_valid_after: datetime | None,
) -> datetime:
    if isinstance(input, datetime):
        # Absolute date
        return input

    match = re.match("^issuer([0-9-+]+)d$", input)
    if match:
        if not issuer_not_valid_after:
            raise ValueError(
                "Certificate notAfter date depends on issuer, but has not been defined"
            )

        # Is a period relative to the issuer's notAfter. NOTE: last second is inclusive, therefore substract one second
        return issuer_not_valid_after + timedelta(days=int(match.group(1)), seconds=-1)

    match = re.match("^([0-9]+)d$", input)
    if match:
        # Relative date into the future
        return not_before + timedelta(days=int(match.group(1)), seconds=-1)

    # Assume date time formated as string
    return parse_date_str(input)
