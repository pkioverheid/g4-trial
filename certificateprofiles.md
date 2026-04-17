As this repository contains many different certificate profiles for several hierarchies, this document contains an overview of the relationships displayed in "tree" format. 

## G4 Private TLS Generic Devices

Currently only one end entity certificate profile for private TLS is included, decending from a single Root. 

```
G4TRIALRootPrivGTLS2024.yaml
`-- G4TRIALIntmPrivGTLSSYS2024.yaml
    `-- G4TRIALPKIoPrivGTLSSYS2025.yaml
        `-- G4TRIALEEPrivGTLSSYS2025.yaml
```

## G4 Private Other Generic Natural Persons and G4 Private Other Generic Legal Persons

Both Natural Persons (NP) and Legal Persons (LP) end entity certificates are issued from a common Root certificate. The distinction is made on the CAs issued by the root. 

```
G4TRIALRootPrivGOther2024.yaml
|-- G4TRIALIntmPrivGOtherNP2024.yaml
|   |-- G4TRIALEEPrivGOtherNP2025IndividualValidated.yaml
|   |-- G4TRIALEEPrivGOtherNP2025RegulatedProfession.yaml
|   |-- G4TRIALEEPrivGOtherNP2025RegulatedProfessionwithSponsorValidation.yaml
|   `-- G4TRIALEEPrivGOtherNP2025SponsorValidated.yaml
`-- G4TRIALIntmPrivGOtherLP2024.yaml
    `-- G4TRIALEEPrivGOtherLP2025.yaml
```

## G4 EUTL Signatures Generic Natural Persons and G4 EUTL Signatures Generic Legal Persons

Both Natural Persons (NP) and Legal Persons (LP) end entity certificates are issued from a common Root certificate. The distinction is made on the CAs issued by the root. 

```
G4TRIALRootEUTLGSigs2024.yaml
|-- G4TRIALIntmEUTLGSigsNP2024.yaml
|   |-- G4TRIALEEEUTLGSigsNP2025IndividualValidated.yaml
|   |-- G4TRIALEEEUTLGSigsNP2025IndividualValidatedSection513.yaml
|   |-- G4TRIALEEEUTLGSigsNP2025RegulatedProfession.yaml
|   |-- G4TRIALEEEUTLGSigsNP2025RegulatedProfessionwithSponsorValidation.yaml
|   `-- G4TRIALEEEUTLGSigsNP2025SponsorValidated.yaml
`-- G4TRIALIntmEUTLGSigsLP2024.yaml
    `-- G4TRIALEEEUTLGSigsLP2025.yaml
```