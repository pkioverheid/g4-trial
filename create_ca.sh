#!/bin/bash

if test -e "ca"; then
  echo "Previous test CA already exists, if you'd like to start fresh, remove the ca directory and run this command again" && exit 1
fi

if [ "$#" -ne 1 ] || [ "$1" != "G4 Private TLS Generic Devices" ]; then
    echo 'Please specify a CA domain to create a test CA for. Options are: "G4 Private TLS Generic Devices" ' >&2
    exit 1
fi

# Commands to create the CA structure and certificates:
mkdir -p ca/{certs,crl,newcerts,private}
touch ca/index.txt
echo 1000 > ca/serial

. .includes

# Generate Root CA key and certificate
# -----------------------------------------
openssl genpkey ${genpkeyopt} -out ca/private/ca.key
openssl req ${reqopt} -x509 -key ca/private/ca.key -out ca/certs/cacert.pem -extensions v3_ca

rootbasename=$(openssl x509 -in ca/certs/cacert.pem -noout -subject -nameopt multiline | grep commonName | cut -d '=' -f2 | tr -d ' -.')
mv ca/private/ca.key ca/private/$rootbasename.key
mv ca/certs/cacert.pem ca/certs/$rootbasename.pem

openssl x509 -in ca/certs/$rootbasename.pem -noout -text > ca/certs/$rootbasename.txt

openssl ca ${crlopt} -out ca/crl/$rootbasename.crl
openssl crl -in ca/crl/$rootbasename.crl -noout -text > ca/crl/$rootbasename.txt

# Generate and issue Intermediate CA
# -----------------------------------------
openssl genpkey ${genpkeyopt} -out ca/private/intermediate.key
openssl req ${reqopt} -section req_intermediate -key ca/private/intermediate.key -out ca/intermediate.csr

intermediatebasename=$(openssl req -in ca/intermediate.csr -noout -subject -nameopt multiline | grep commonName | cut -d '=' -f2 | tr -d ' -.')
mv ca/private/{intermediate,$intermediatebasename}.key
mv ca/{intermediate,$intermediatebasename}.csr

openssl ca ${caopt} -extensions v3_intermediate_ca -in ca/$intermediatebasename.csr -out ca/certs/$intermediatebasename.pem
openssl x509 -in ca/certs/$intermediatebasename.pem -noout -text > ca/certs/$intermediatebasename.txt

openssl ca ${crlopt} -out ca/crl/$intermediatebasename.crl
openssl crl -in ca/crl/$intermediatebasename.crl -noout -text > ca/crl/$intermediatebasename.txt

# Generate and issue Second-Level Intermediate CA
# -----------------------------------------
openssl genpkey ${genpkeyopt} -out ca/private/issuing.key
openssl req ${reqopt} -section req_issuing -key ca/private/issuing.key -out ca/issuing.csr

issuingbasename=$(openssl req -in ca/issuing.csr -noout -subject -nameopt multiline | grep commonName | cut -d '=' -f2 | tr -d ' -.')
mv ca/private/{issuing,$issuingbasename}.key
mv ca/{issuing,$issuingbasename}.csr

openssl ca ${caopt} -extensions v3_issuing_ca -in ca/$issuingbasename.csr -out ca/certs/$issuingbasename.pem -cert ca/certs/$intermediatebasename.pem -keyfile ca/private/$intermediatebasename.key
openssl x509 -in ca/certs/$issuingbasename.pem -noout -text > ca/certs/$issuingbasename.txt

openssl ca ${crlopt} -out ca/crl/$issuingbasename.crl
openssl crl -in ca/crl/$issuingbasename.crl -noout -text > ca/crl/$issuingbasename.txt

echo "Created test CA. Now create as many end entity certificates as needed using create_entity.sh"