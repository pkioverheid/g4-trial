# Table of Contents

- [Overview](#overview)
- [Major changes from G3 to G4](#major-changes-from-g3-to-g4)
- [Certificate profiles](#certificate-profiles)
- [Limitations](#limitations)
- [Usage](#usage)
- [Requirements](#requirements)
- [Support & Contributing](#support--contributing)
- [Disclaimer](#disclaimer)

# Overview

This is version 2 of the G4 TRIAL tool. Version 1 can be found at https://github.com/pkioverheid/g4-trial/tree/v1.0. 

This tool allows you to generate TRIAL (test) certificates for the PKIoverheid G4 hierarchies yourself. It generates a complete hierarchy of certificates resembling a chosen G4 hierarchy. For more information on these hierarchies, please refer to the [PKIoverheid CPS, Section 1.1](https://cps.pkioverheid.nl/pkioverheid-cps-unified-v5.4.html#id__11-overview). 

Use the self-signed certificates to test your own and relying party's readiness for the production PKIoverheid G4 certificates issued by PKIoverheid TSPs. 

For the G3 certificate hierarchy some PKIoverheid TSPs offer TRIAL certificates. However, the G4 hierarchies consists of many different types of certificates, increasing implementation costs for TSPs. Therefore it was deemed most effective for users to be able to generate their own test certificates using a publicly available tool.

# Target audience

Software developers creating applications either using PKIoverheid certificates, or validating signatures created with PKIoverheid certificates, will be the primary audience of the PKIoverheid TRIAL certificates. However, organizations using *commercial off the shelf* (COTS) software in combination with PKIoverheid certificates or signatures created using them, may also wish to test their software stack with the PKIoverheid TRIAL certificates.

# Major changes from G3 to G4

There have been a number of changes from G3 to G4, which you need to be aware of. In depth technical changes are described in the [PKIoverheid CPS](https://cps.pkioverheid.nl) and [Certificate Policy/Programme of Requirements PKIoverheid](https://cp.pkioverheid.nl/), while the functional changes are:  

- Instead of one certificate root, the PKIoverheid G4 consists of multiple Certificate Roots, depending on its trust type (Public, Mandated (eIDAS) and Private). Since Privately trusted roots may be used separately within a specific domain, several Privately trusted Certificate Roots are created. Relying parties should only trust the appropriate Certificate Roots. Please see [https://cert.pkioverheid.nl/](https://cert.pkioverheid.nl/) for details;
- Many more certificate types are available for the G4 than G3, the certificate Common Names reflect this accordingly;
- Intermediate CAs are based upon Subject Type (Natural Persons, Legal Entities or Devices), rather than a validation type, for example the G3's "Organisatie Persoon";
- G3 certificates used a limited number of Policy OIDs, this has been expanded significantly for the G4. This allows the relying party to pinpoint exactly which type of certificate and validation was performed; 
- G4 makes a distinction between Authenticity and Authentication certificates, while G3 only defined Authenticity for both use cases. Confidentiality usage for certificates is deemed an edge case and is disasbled by default in the G4 TRIAL;
- Previously two variants existed of G1 Private Services Server certificate (OID: 2.16.528.1.1003.1.2.8.6). One containing one or more domain names and one without. This has been changed in G4. A "G4 Private Other Generic Legal Persons Organization Validated Authentication" does not contain any domains and is used only for `clientAuth`. A "G4 Private TLS Generic Devices Organization Validated Server" contains one or more domains and can be used for both `clientAuth` and `serverAuth`. 
- G3 certificates were allowed to have IP addresses as Subject Alternate Names. The G4 prohibits this.  
- Signature algorithm `RSASSA‐PKCS1‐v1_5` has been designated as legacy by the SOG-IS Crypto Evaluation Scheme and is replaced by `RSASSA-PSS`. This algorithm is used for certificates and CRLs. 

# Certificate profiles

The PKIoverheid G4 hierarchies offer many different types of certificates, each for a different purpose. Please refer to the factsheet [Wees voorbereid de nieuwe generatie pkioverheidcertificaten komen eraan](https://www.logius.nl/onze-dienstverlening/domeinen/toegang/pkioverheid/wees-voorbereid-de-nieuwe-generatie-pkioverheidcertificaten-komen-eraan) (Dutch) or [New generation of PKIoverheid Certificates](https://www.logius.nl/english/pkioverheid/new-generation-pkioverheid-certificates) (English) for details. 

The included profiles are compliant with:

* [ETSI EN 319 412-1 V1.6.1](https://portal.etsi.org/webapp/workprogram/Report_WorkItem.asp?WKI_ID=69996) (Overview and common data structures)
* [ETSI EN 319 412-2 V2.4.1](https://portal.etsi.org/webapp/workprogram/Report_WorkItem.asp?WKI_ID=73460) (Certificate profile for certificates issued to natural persons)
* [ETSI EN 319 412-3 V1.3.1](https://portal.etsi.org/webapp/workprogram/Report_WorkItem.asp?WKI_ID=68498) (Certificate profile for certificates issued to legal persons)
* [ETSI EN 319 412-4 V1.4.1](https://portal.etsi.org/webapp/workprogram/Report_WorkItem.asp?WKI_ID=73791) (Certificate profile for web site certificates)
* [Certification Practice Statement Policy Authority PKIoverheid Unified v5.5](https://cps.pkioverheid.nl/pkioverheid-cps-unified-v5.5.html)
* [PKIoverheid Programme of Requirements v5.2](https://cp.pkioverheid.nl/pkioverheid-por-v5.2.html)

Please be aware certificates generated by this tooling differ from their production counterparts in some aspects: 

- There is no Certificate Policy document and as such these certificates provide no trust whatsoever
- **Serial Numbers** are not generated using a CSPRNG.
- **Issuer** and **Subject** fields do not mention "Staat der Nederlanden" or any of the participating TSPs. Instead, "TRIAL PKIoverheid" and "My TSP" are used. Nevertheless, relying parties should not rely on Subject and Issuer for trust. 
- **Validity** range for end entity certificates defaults to 365 days, which may be different from production certificates;
- **crlDistributionPoints** and **caIssuers** point to `localhost` for TRIAL certificates by default, for the Production environment these point to http://crl.pkioverheid.nl and http://cert.pkioverheid.nl respectively. File names are generated based on the Common Name of the CA certificates.
- **Policy Identifiers** are defined by the [differentation model](https://oid.pkioverheid.nl/) and differ slightly between TRIAL and Production, for example:
    | Certificate type                      | TRIAL                               | Production                          |
    |---------------------------------------|-------------------------------------|-------------------------------------|
    | System Organization Validation Server | `2.16.528.1.1003.1.2.*41*.15.39.10` | `2.16.528.1.1003.1.2.*44*.15.39.10` | 
- There may be some minor (non-security) differences between these TRIAL certificates and certificates offered by the different PKIoverheid TSPs. Most notably the value of the `subject.commonName` field and the ASN.1 encoding of some `subject` fields may be different. 

# Limitations

All G4 TRIAL certificates are self issued and must not be used for any production purpose and should only be used for testing purposes.

Currently, only the following [G4 Domains](https://cp.pkioverheid.nl/pkioverheid-por-v5.1.html#id__11-overview) have been included:

- G4 Private TLS Generic Devices
- G4 Private Other Generic Natural Persons
- G4 Private Other Generic Legal Persons

If you require any other G4 Domain, please open a Github issue in this repository. 

# Usage

## Installation

1. Clone this repository locally
2. You will need Python >3.7 installed. If not already installed, please follow the instructions for your operating system at https://www.python.org;
3. To be able to install additional libraries, you will need to install `pip`. For instructions please refer to https://packaging.python.org/en/latest/tutorials/installing-packages/;
4. (optional) create and activate a virtualenv, see previous hyperlink;
5. Install the packages this repository requires: 
   ```bash
   pip install -r requirements.txt
   ```

## Create top level hierarchy

First create the top three layers of the CA hierarchy for a [G4 Domain](https://cp.pkioverheid.nl/pkioverheid-por-v5.1.html#id__11-overview). These are the self-signed Root CA, Domain CA and Issuing (TSP) CA. This command will prompt which for which PKIoverheid G4 domain you'd like to create the private key, certificate and its (empty) Certificate Revocation List (CSR). 

```bash
python create-ca.py
```

## Create end entity certificates

Each end entity certificate requires subject information to be provided separately from the certificate profile. This information is provided using an "enrollment" YAML file. Please see any of the files in the `examples/enrollment` directory. The filename will indicate the certificate type. Please see the "G1/G3 to G4 mapping table" on the logius.nl website for information which certificate type you need for your use case. 

Enrollment files will need to be modified for your own use cases. An example enrollment file would be:

```yaml
---
profile: profiles/G4TRIALEEPrivGTLSSYS2025.yaml
subject:
  C: NL
  CN: Bedrijfsnaam TLS
  O: Bedrijfsnaam
  organizationIdentifier: NTRNL-99999991
subjectAltNames:
  - example.com
  - www.example.com
```

The file indicates which certificate profile is to be used, provides `subject` information and (in this case) two FQDNs to be included in the certificate. For each end entity certificate you want to create, copy the enrollment file and modify it according to your needs. Then run:

```bash
python generate-cert.py <one or more enrollment files>
```

Example enrollment files can be used directly, e.g. the following command will create an end entity certificate to secure a TLS endpoint.

```bash
python generate-cert.py examples/enrollment/G4-Private-G-TLS-SYS-WithOrganizationIdentifier.yaml
```

Prior to generating the certificate, the script will validate your enrollment file against the requirements for the selected hierarchy and output any discrepancies. Please note that no validations are performed on the actual contents of each attribute, please refer to the documents listed under [Certificate Profiles](#certificate-profiles) to determine what information should be included in each field. 

The filenames of the newly generated private and public keys will match the filename of the enrollment file. They will be placed in the `ca/private` and the `ca/certs` directories. The command will not overwrite any preexisting files. 

## Revocations

When CA certificates are created, an associated Certificate Revocation List (CRL) is automatically created. By default no certificates are revoked. However, to test revocation checking, you may want to generate some certificates and revoke them. 

Each CA certificate will have a corresponding file in the `revocations` directory. For example:

```yaml
---
revocations:
  - serialNumber: '78:74:17:c2:a6:23:5f:55:57:ac:38:5e:e3:4d:6e:82:b4:fd:07:eb'
    reason: superseded
    date: "2025-08-08 00:00:00"
  - serialNumber: '75:13:8e:39:29:93:c5:23:62:9f:bb:4c:24:dd:28:6b:41:11:52:c7'
    reason: superseded
    date: "2025-08-10 10:02:00"
```

Only three values are needed per revocation:

* `serialNumber` of the certificate must indicated in hexadecimal format separated by colons (openSSL format);
* `reason` for revocation must be one listed in [Programme of Requirements Section 7.2 CRL profile](https://cp.pkioverheid.nl/pkioverheid-por-v5.2.html#id__7222-tbscertlistrevokedcertificatescrlentryextensionsextensions); 
* `date` is the date of revocation. For production uses this date is the actual date of revocation, however for the G4 TRIAL this date is unbounded. 

After modification of the revocations file, create a new CRL by executing:

```shell
python generate-crl.py <revocation file>
```

Please do not rename the created CRL file(s) as they are referenced by other certificates (see below) and are used to increment the `cRLNumber` included within each CRL. Publish the CRL file accordingly (see below). 

The Programme of Requirements dictates that CRLs must be renewed (regenerated) at least each 48 hours, and this has been set as default. When publishing the CRL, you may wish to setup a cronjob that automatically recreates the CRL. For testing purposes you may change this setting in `config.yaml` (see below).

## Certificate Status Service

If you'd like to host the CA certificates (as specified in the certificate's `authorityInfoAccess` extension) and CRLs (as specified in the `crlDistributionPoints` extension) on your local machine, you can start a minimal webserver:

```bash
bash start-server.sh
```

If desired, these files can be hosted using other webservers on other domains (see below). 

# Customizing

## Issuing certificates and CRL locations

If you intend to host the certificates and CRLs on another domain modify the `config.yaml` file by modifing the `caIssuersBaseUrl` and `cRLDistributionPointsBaseUrl` parameters. You must recreate all certificates for these values to be used. An example configuration could be: 

```yaml
caIssuersBaseUrl: http://cert.mydomain.com
cRLDistributionPointsBaseUrl: http://crl.mydomain.com
crlRenewalHours: 48
```

The parameter `crlRenewalHours` indicates the lifespan of a CRL, i.e. the difference between `thisUpdate` and `nextUpdate`. The default is 48 hours, but can be modified for testing purposes. 

# File list

| Filename           | Description                                                             |
|--------------------|-------------------------------------------------------------------------|
| `create_ca.py`     | Script to create the top level CA private keys and certificates         |
| `generate-cert.py` | Script to create any number of end entity private keys and certificates |
| `generate-crl.py`  | Script to create CRLs for a CA                                          |
| `start_server.sh`  | A minimal webserver to host generated certificates and CRLs             |
| `ca/private/*.key` | Generated private keys                                                  |
| `ca/certs/*.pem`   | Issued certificates                                                     |
| `ca/crl/*.crl`     | CRLs for the generated CA certificates                                  |
| `examples`         | Example files to create end entity certificates and revocation lists    |

# Requirements

- Python >3.7 

# Support & Contributing

These files are provided as-is and no warranty or support is given. However, you may create a Github issue to discuss issues and enhancements.

# Roadmap

Based on user input, other G4 hierarchies will be added in future releases.

# Disclaimer

This project is provided as-is, without any express or implied warranties, including but not limited to merchantability, fitness for a particular purpose, or non-infringement. Use generated self-signed certificate hierarchies is at your own risk, and the maintainers are not responsible for any security issues, misconfigurations, or unintended consequences. External systems, applications and entities must not trust certificates generated by this tooling. 
