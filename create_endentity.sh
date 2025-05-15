#!/bin/bash

usage() { echo "Usage: $0 [-f input file]" 1>&2; exit 1; }

inputfile=endentitycerts.txt

while getopts "h?f:" opt; do
  case "$opt" in
    h|\?)
      usage
      exit 0
      ;;
    f)  inputfile=$OPTARG
      ;;
  esac
done

if ! test -f "$inputfile"; then
  echo "End entity input file $inputfile not found" && usage && exit 1
fi

echo Using "$inputfile"

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

echo "Specify the domain for which you want to create End Entity certificates:"
. "$SCRIPT_DIR"/.prompt

. "$SCRIPT_DIR"/.includes

. .includes

issuingbasenames=( "blank" "TRIALMyTSPG4PKIoPrivGTLSSYS2024" )
issuingbasename=${issuingbasenames[$((catype))]}

policies=( "blank" "policy_g4privatetls" )
policy=${policies[$((catype))]}

# Validate CA status and inputs
if ! test -f "$CERT_DIR/$issuingbasename.pem"; then
  echo "Issuing certificate does not exists. Create it first using create_ca.sh" && exit 1
fi

if ! test -f "$PRIVATE_DIR/$issuingbasename.key"; then
  echo "Issuing private key does not exist. Create it first using create_ca.sh" && exit 1
fi

while IFS=, read country organization commonname san
do

  basename=$(echo "$commonname" | tr -d ' -.')

  file="$PRIVATE_DIR/$basename.key"

  if test -f "$file"; then
    echo "Private key file $file exists. Choose a different Common Name" && exit 1
  fi

  file="$CSR_DIR/$basename.csr"
  if test -f "$file"; then
    echo "Certificate Signing Request file $file exists. Choose a different Common Name" && exit 1
  fi

  file="$CERT_DIR/$basename.pem"
  if test -f "$file"; then
     echo "Certificate file $file exists. Choose a different Common Name" && exit 1
  fi
done < <(grep -Ev '^#' "$inputfile")  

# Parse the input file and create the end entity certificates
echo "Creating certificates from file $inputfile"

. .includes

unset outfiles

while IFS=, read country organization commonname san
do

  basename=$(echo "$commonname" | tr -d ' -.')
  dn="/C=${country}/O=${organization}/CN=${commonname}"

  # Generate and issue end entity key
  # -----------------------------------------
  export SAN=$san
  openssl genpkey ${genpkeyopt} -out "$PRIVATE_DIR/$basename.key"
  openssl req ${reqopt} -key "$PRIVATE_DIR/$basename.key" -out "$CSR_DIR/$basename.csr" -subj "${dn}"
  openssl ca ${caopt} -days ${eedays} -extensions v3_end_entity -policy ${policy} -in "$CSR_DIR/$basename.csr" -out "$CERT_DIR/$basename.pem" -cert "$CERT_DIR/$issuingbasename.pem" -keyfile "$PRIVATE_DIR/$issuingbasename.key"
  openssl x509 -in "$CERT_DIR/$basename.pem" -noout -text > "$CERT_DIR/${basename}_text.txt"

  outfiles+=("$basename")
done < <(grep -Ev '^#' "$inputfile")

echo
echo "Successfully created private keys and issued test certificates:"
for basename in "${outfiles[@]}"
do
   echo " keyfile: $PRIVATE_DIR/$basename.key"
   echo " certificate file: $CERT_DIR/$basename.pem"
done


