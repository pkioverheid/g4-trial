import os


def verify(data):

    def collect_file_paths(data):
        paths = []

        for domain, content in data.items():
            # Check hierarchy items
            for item in content.get('hierarchy', []):
                for key in ('profile', 'enrollment', 'revocations'):
                    if key in item:
                        paths.append(item[key])

            # Check endentity items
            for item in content.get('endentity', []):
                if 'profile' in item:
                    paths.append(item['profile'])

        return paths

    paths = collect_file_paths(data)

    missing = []
    for path in paths:
        if not os.path.isfile(path):
            print(f'MISSING: {path}')
            missing.append(path)

    if missing:
        print(f'\n{len(missing)} files missing.')
    return len(missing) == 0
