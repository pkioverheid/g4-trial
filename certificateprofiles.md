As this repository contains many different certificate profiles for several hierarchies, this document contains an overview of the relationships displayed in "tree" format. 

## G4 Private TLS Generic Devices

Currently only one end entity certificate profile for private TLS is included, decending from a single Root. 

```
G4TRIALRootPrivGTLS2024.yaml               -- Certificate profile for "TRIAL PKIoverheid - G4 Root Priv G-TLS"
`-- G4TRIALIntmPrivGTLSSYS2024.yaml        -- Certificate profile for "TRIAL PKIoverheid - G4 Intm Priv G-TLS SYS"
    `-- G4TRIALPKIoPrivGTLSSYS2025.yaml    -- Certificate profile for "TRIAL My TSP - G4 PKIo Priv G-TLS SYS"
        `-- G4TRIALEEPrivGTLSSYS2025.yaml  -- Profile for TLS end entity certificates
```

## G4 Private Other Generic Natural Persons and G4 Private Other Generic Legal Persons

Both Natural Persons (NP) and Legal Persons (LP) end entity certificates are issued from a common Root certificate. The distinction is made on the CAs issued by the root. Several certificateprofiles have been defined for Natural Persons, dependant on validation type. For Legal Persons, only one certificate profile has been defined. 

```
G4TRIALRootPrivGOther2024.yaml                                                     -- Certificate profile for "TRIAL PKIoverheid - G4 Root Priv G-Other"
|-- G4TRIALIntmPrivGOtherNP2024.yaml                                               -- Certificate profile for "TRIAL PKIoverheid - G4 Intm Priv G-Other NP"
|   |-- TRIALMyTSPG4PKIoPrivGOtherNP2025.yaml                                      -- Certificate profile for "TRIAL My TSP - G4 PKIo Priv G-Other NP"
|   |   |-- G4TRIALEEPrivGOtherNP2025IndividualValidated.yaml                      -- Profile for certificates issued to individuals (citizen)
|   |   |-- G4TRIALEEPrivGOtherNP2025RegulatedProfession.yaml                      -- Profile for certificates issued to regulated professions
|   |   |-- G4TRIALEEPrivGOtherNP2025RegulatedProfessionwithSponsorValidation.yaml -- Profile for certificates issued to regulated professions with sponsor validated
|   |   `-- G4TRIALEEPrivGOtherNP2025SponsorValidated.yaml                         -- Profile for certificates issued to sponsor validated individuals
`-- G4TRIALIntmPrivGOtherLP2024.yaml                                               -- Certificate profile for "TRIAL PKIoverheid - G4 Intm Priv G-Other LP"
    |-- TRIALMyTSPG4PKIoPrivGOtherLP2025.yaml                                      -- Certificate profile for "TRIAL My TSP - G4 PKIo Priv G-Other LP"
    |   `-- G4TRIALEEPrivGOtherLP2025.yaml                                         -- Profile for certificates issued to legal persons
```

## G4 EUTL Signatures Generic Natural Persons and G4 EUTL Signatures Generic Legal Persons

Both Natural Persons (NP) and Legal Persons (LP) end entity certificates are issued from a common Root certificate. The distinction is made on the CAs issued by the root. Several certificateprofiles have been defined for Natural Persons, dependant on validation type. For Legal Persons, only one certificate profile has been defined. 

```
G4TRIALRootEUTLGSigs2024.yaml                                                      -- Certificate profile for "TRIAL PKIoverheid - G4 Root EUTL G-Sigs"
|-- G4TRIALIntmEUTLGSigsNP2024.yaml                                                -- Certificate profile for "TRIAL PKIoverheid - G4 Intm EUTL G-Sigs NP"
|   |-- TRIALMyTSPG4PKIoEUTLGSigsNP2025.yaml                                       -- Certificate profile for "TRIAL My TSP - G4 PKIo EUTL G-Sigs NP"
|   |   |-- G4TRIALEEEUTLGSigsNP2025IndividualValidated.yaml                       -- Profile for eSignature certificates issued to individuals (citizen)
|   |   |-- G4TRIALEEEUTLGSigsNP2025IndividualValidatedSection513.yaml             -- Profile for eSignature certificates issued to individuals (citizen). Certificate contains a serial number conforming to a specific format
|   |   |-- G4TRIALEEEUTLGSigsNP2025RegulatedProfession.yaml                       -- Profile for eSignature certificates issued to regulated professions
|   |   |-- G4TRIALEEEUTLGSigsNP2025RegulatedProfessionwithSponsorValidation.yaml  -- Profile for eSignature certificates issued to regulated professions with sponsor validated
|   |   `-- G4TRIALEEEUTLGSigsNP2025SponsorValidated.yaml                          -- Profile for eSignature certificates issued to sponsor validated individuals
`-- G4TRIALIntmEUTLGSigsLP2024.yaml                                                -- Certificate profile for "TRIAL PKIoverheid - G4 Intm EUTL G-Sigs LP"
    `-- G4TRIALMyTSPEUTLGSigsLP2025.yaml                                           -- Certificate profile for "TRIAL My TSP - G4 PKIo EUTL G-Sigs LP"
        `-- G4TRIALEEEUTLGSigsLP2025.yaml                                          -- Profile for eSeal certificates issued to legal persons 
```