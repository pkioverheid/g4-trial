#!/bin/bash

# A POSIX variable
OPTIND=1         # Reset in case getopts has been used previously in the shell.

# Initialize defaults
country="NL"
organization="Bedrijfsnaam"
commonname="End Entity"
san="URI:www.example.com"
issuingbasename="TRIALMyTSPG4PKIoPrivGTLSSYS2024"

usage() { echo "Usage: $0 [-c Two letter country code] [-o Subject Organization name] [-n Subject Common Name]" 1>&2; exit 1; }

while getopts "h?c:o:n:s:" opt; do
  case "$opt" in
    h|\?)
      usage
      exit 0
      ;;
    c)  country=$OPTARG
        if (( ${#country} != 2)); then
            usage && exit 0
        fi
      ;;
    o)  organization=$OPTARG
      ;;
    n)  commonname=$OPTARG
      ;;
    s)  san=$OPTARG
      ;;
  esac
done

shift $((OPTIND-1))

[ "${1:-}" = "--" ] && shift

if ! test -f "ca/certs/$issuingbasename.pem"; then
  echo "Issuing certificate does not exists. Create it first using create_ca.sh" && exit 1
fi

if ! test -f "ca/private/$issuingbasename.key"; then
  echo "Issuing private key does not exist. Create it first using create_ca.sh" && exit 1
fi

basename=$(echo "$commonname" | tr -d ' -.')

if test -f "ca/private/$basename.key"; then
  echo "Private key file exists. Choose a different Common Name" && exit 1
fi

if test -f "ca/$basename.csr"; then
  echo "Certificate Signing Request file exists. Choose a different Common Name" && exit 1
fi

if test -f "ca/certs/$basename.pem"; then
   echo "Certificate file exists. Choose a different Common Name" && exit 1
fi

dn="/C=${country}/O=${organization}/CN=${commonname}"

. .includes

# Generate and issue end entity key
# -----------------------------------------
export SAN=$san
openssl genpkey ${genpkeyopt} -out ca/private/$basename.key
openssl req ${reqopt} -key ca/private/$basename.key -out ca/$basename.csr -subj "${dn}"
openssl ca ${caopt} -days ${eedays} -extensions v3_end_entity -in ca/$basename.csr -out ca/certs/$basename.pem -cert ca/certs/$issuingbasename.pem -keyfile ca/private/$issuingbasename.key
openssl x509 -in ca/certs/$basename.pem -noout -text > ca/certs/$basename.txt

echo "Successfully created private key and issued test certificate:"
echo " keyfile: ca/private/$basename.key"
echo " certificate file: ca/certs/$basename.pem"
