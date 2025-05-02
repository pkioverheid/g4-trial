#!/bin/bash

if test -e "ca"; then
  echo "Previous test CA already exists, if you'd like to start fresh, remove the ca directory and run this command again" && exit 1
fi

echo "Create a test CA for the following domain:"
. .prompt


# Commands to create the CA structure and certificates:
mkdir -p ca/{certs,crl,newcerts,private,csr}
touch ca/index.txt
echo 1000 > ca/serial

. .includes

# Generate Root CA key and certificate
# -----------------------------------------
openssl genpkey ${genpkeyopt} -out "$PRIVATE_DIR/ca.key"
openssl req ${reqopt} -x509 -key "$PRIVATE_DIR/ca.key" -out "$CERT_DIR/cacert.pem" -extensions v3_ca

rootbasename=$(openssl x509 -in "$CERT_DIR/cacert.pem" -noout -subject -nameopt multiline | grep commonName | cut -d '=' -f2 | tr -d ' -.')
mv "$PRIVATE_DIR/ca.key" "$PRIVATE_DIR/$rootbasename.key"
mv "$CERT_DIR/cacert.pem" "$CERT_DIR/$rootbasename.pem"

openssl x509 -in "$CERT_DIR/$rootbasename.pem" -noout -text > $CERT_DIR/$rootbasename.txt

openssl ca ${crlopt} -days ${rootdays} -out "$CRL_DIR/$rootbasename.crl"
openssl crl -in "$CRL_DIR/$rootbasename.crl" -noout -text > "$CRL_DIR/$rootbasename.txt"

# Generate and issue Intermediate CA
# -----------------------------------------
openssl genpkey ${genpkeyopt} -out "$PRIVATE_DIR/intermediate.key"
openssl req ${reqopt} -section req_intermediate -key "$PRIVATE_DIR/intermediate.key" -out "$CSR_DIR/intermediate.csr"

intermediatebasename=$(openssl req -in $CSR_DIR/intermediate.csr -noout -subject -nameopt multiline | grep commonName | cut -d '=' -f2 | tr -d ' -.')
mv $PRIVATE_DIR/{intermediate,$intermediatebasename}.key
mv $CSR_DIR/{intermediate,$intermediatebasename}.csr

openssl ca ${caopt} -days ${intermediatedays} -extensions v3_intermediate_ca -in "$CSR_DIR/$intermediatebasename.csr" -out "$CERT_DIR/$intermediatebasename.pem"
openssl x509 -in "$CERT_DIR/$intermediatebasename.pem" -noout -text > "$CERT_DIR/$intermediatebasename.txt"

openssl ca ${crlopt} -out "$CRL_DIR/$intermediatebasename.crl"
openssl crl -in "$CRL_DIR/$intermediatebasename.crl" -noout -text > "$CRL_DIR/$intermediatebasename.txt"

# Generate and issue Second-Level Intermediate CA
# -----------------------------------------
openssl genpkey ${genpkeyopt} -out $PRIVATE_DIR/issuing.key
openssl req ${reqopt} -section req_issuing -key $PRIVATE_DIR/issuing.key -out $CSR_DIR/issuing.csr

issuingbasename=$(openssl req -in "$CSR_DIR/issuing.csr" -noout -subject -nameopt multiline | grep commonName | cut -d '=' -f2 | tr -d ' -.')
mv $PRIVATE_DIR/{issuing,$issuingbasename}.key
mv $CSR_DIR/{issuing,$issuingbasename}.csr

openssl ca ${caopt} -days ${issuingdays} -extensions v3_issuing_ca -in "$CSR_DIR/$issuingbasename.csr" -out "$CERT_DIR/$issuingbasename.pem" -cert "$CERT_DIR/$intermediatebasename.pem" -keyfile "$PRIVATE_DIR/$intermediatebasename.key"
openssl x509 -in "$CERT_DIR/$issuingbasename.pem" -noout -text > "$CERT_DIR/$issuingbasename.txt"

openssl ca ${crlopt} -out "$CRL_DIR/$issuingbasename.crl"
openssl crl -in "$CRL_DIR/$issuingbasename.crl" -noout -text > "$CRL_DIR/$issuingbasename.txt"

echo "Created test CA. Now create as many end entity certificates as needed using create_endentity.sh"