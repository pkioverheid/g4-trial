import os

from lib.util import load_yaml


def verify(data):
    missing = []
    for enrollmentfiles in data.values():
        for enrollmentfile in enrollmentfiles:
            # Verify existance of enrollment
            if not os.path.isfile(enrollmentfile):
                missing.append(enrollmentfile)

            # Verify existance of profile referenced in enrollment
            enrollment = load_yaml(enrollmentfile)
            if not os.path.isfile(enrollment['profile']):
                missing.append(f'{enrollment['profile']} (referenced in {enrollmentfile})')

    for path in missing:
        print(f'MISSING: {path}')

    if missing:
        print(f'\n{len(missing)} files missing.')

    return not missing
