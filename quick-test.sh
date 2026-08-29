python create-csr.py enrollment/TRIALMyTSPG4PKIoPrivGTLSSYS2025.yaml
python generate-cert.py "enrollment/TRIALPKIoverheidG4RootPrivGTLS2024.yaml" "enrollment/TRIALPKIoverheidG4IntmPrivGTLSSYS2024.yaml"
python generate-crl.py "revocations/TRIALPKIoverheidG4RootPrivGTLS2024.yaml" "revocations/TRIALPKIoverheidG4IntmPrivGTLSSYS2024.yaml"
python sign-cert.py --profile profiles/G4TRIALPKIoPrivGTLSSYS2025.yaml TRIALMyTSPG4PKIoPrivGTLSSYS2025.csr