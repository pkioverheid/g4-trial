import os
import sys

import yaml
from jschon import create_catalog, JSONSchema, JSON


def force_int(value):
    if isinstance(value, int):
        return value
    elif isinstance(value, str):
        first = value.split(" ")[0]
        if first.startswith('0x'):
            return int(first, 16)
        return int(first)
    return value


def load_yaml(filename):
    with open(filename, 'r') as f:
        return yaml.safe_load(f)


def keys_exist(d, path):
    """
    Recursively checks if a sequence of nested keys exists in a dictionary.

    :param d: The dictionary to check.
    :param path: A list of keys representing the nested path.
    :return: True if all keys exist in sequence, False otherwise.
    """
    if not path:  # Base case: if no keys are left to check, return True
        return True
    if not isinstance(d, dict) or path[0] not in d:
        return False
    # Recursive call for the next level, passing the rest of the keys
    return keys_exist(d[path[0]], path[1:])


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def output_errors(errors):
    for error in errors:
        # print(error)
        if 'error' in error:
            print(f"- {error['instanceLocation']}: {error['error']}")
        else:
            output_errors(error['errors'])


def choose(prompt, options):
    print(prompt)
    for i, option in enumerate(options, 1):
        if isinstance(option, dict):
            print(f"\t{i}. {option.get('label', str(option))}")
        else:
            print(f"\t{i}. {option}")

    while True:
        choice = input("Enter the number of your choice: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(options):
            return options[int(choice) - 1]
        else:
            print("Invalid choice. Try again.")


def load_config():
    filename = "config.yaml"

    try:
        config = load_yaml(filename) or {}
    except FileNotFoundError:
        config = {}

    defaults = {
        "caIssuersBaseUrl": "http://cert.pkioverheid.nl",
        "cRLDistributionPointsBaseUrl": "http://crl.pkioverheid.nl",
        "crlRenewalHours": 48,
        "pdsLocation": {
            "url": "https://www.github.com/pkioverheid/g4-trial",
            "language": "en",
        },
    }
    defaults.update(config)
    config = defaults

    create_catalog("2020-12")
    schema = JSONSchema.loadf(os.path.join('schema', 'config.json'))

    instance = JSON(config)
    result = schema.evaluate(instance)
    if not result.valid:
        print(f"Configuration file {filename} is invalid: ")
        output_errors(result.output("detailed")["errors"])
        exit(1)

    # Only write file if validation passed, to avoid overwriting with invalid data
    with open(filename, "w") as f:
        yaml.safe_dump(config, f, sort_keys=False)

    return config
