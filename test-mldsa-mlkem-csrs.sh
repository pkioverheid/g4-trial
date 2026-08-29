
export OPENSSL_DIR=/opt/conda/pkgs/openssl-3.5.5-h1b28b03_0/
export LD_LIBRARY_PATH=/opt/conda/lib

# Create PQC TLS
echo 6 | python create-ca.py

# Create PQC Other
echo 7 | python create-ca.py

# Should fail as no ML-DSA exists yet to sign the CSR (TypeError)
python create-csr.py examples/enrollment/G4-PQC-Private-G-Other-LP-Confidentiality.yaml

# So: create a ML-DSA/ML-DSA CSR first
python create-csr.py examples/enrollment/G4-PQC-Private-G-TLS-SYS.yaml

# Sign it
python sign-cert.py --profile 'profiles/G4TRIALPQCEEPrivGTLSSYS2026.yaml' G4-PQC-Private-G-TLS-SYS.csr 

# Create the CSR for ML-KEM again (fails using the master branch, but works with my PR)
python create-csr.py --signer examples/enrollment/G4-PQC-Private-G-TLS-SYS.yaml examples/enrollment/G4-PQC-Private-G-Other-LP-Confidentiality.yaml

# Sign the ML-KEM CSR
python sign-cert.py --profile 'profiles/G4TRIALPQCEEPrivGOtherLPConfidentiality2026.yaml' G4-PQC-Private-G-Other-LP-Confidentiality.csr 
