import os

BASEDIR = 'ca'

# Ensure our output directories exist
for dir in [BASEDIR, os.path.join(BASEDIR, 'private'), os.path.join(BASEDIR, 'certs')]:
    if not os.path.isdir(dir):
        os.mkdir(dir)
