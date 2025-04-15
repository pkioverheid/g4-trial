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

echo "Specify the domain for which you want to create End Entity certificates:"
. .prompt

issuingbasenames=( "blank" "TRIALMyTSPG4PKIoPrivGTLSSYS2024" )
issuingbasename=${issuingbasenames[$((catype))]}

policies=( "blank" "policy_g4privatetls" )
policy=${policies[$((catype))]}

if ! test -f "ca/certs/$issuingbasename.pem"; then
  echo "Issuing certificate does not exists. Create it first using create_ca.sh" && exit 1
fi

if ! test -f "ca/private/$issuingbasename.key"; then
  echo "Issuing private key does not exist. Create it first using create_ca.sh" && exit 1
fi

while IFS=, read country organization commonname san
do

  basename=$(echo "$commonname" | tr -d ' -.')

  file="ca/private/$basename.key"

  if test -f "$file"; then
    echo "Private key file $file exists. Choose a different Common Name" && exit 1
  fi

  file="ca/$basename.csr"
  if test -f "$file"; then
    echo "Certificate Signing Request file $file exists. Choose a different Common Name" && exit 1
  fi

  file="ca/certs/$basename.pem"
  if test -f "$file"; then
     echo "Certificate file $file exists. Choose a different Common Name" && exit 1
  fi
done < <(grep -Ev '^#' "$inputfile")  

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
  openssl genpkey ${genpkeyopt} -out ca/private/$basename.key
  openssl req ${reqopt} -key ca/private/$basename.key -out ca/$basename.csr -subj "${dn}"
  openssl ca ${caopt} -days ${eedays} -extensions v3_end_entity -policy ${policy} -in ca/$basename.csr -out ca/certs/$basename.pem -cert ca/certs/$issuingbasename.pem -keyfile ca/private/$issuingbasename.key
  openssl x509 -in ca/certs/$basename.pem -noout -text > ca/certs/$basename.txt

  outfiles+=("$basename")
done < <(grep -Ev '^#' "$inputfile")

echo
echo "Successfully created private keys and issued test certificates:"
for basename in "${outfiles[@]}"
do
   echo " keyfile: ca/private/$basename.key"
   echo " certificate file: ca/certs/$basename.pem"
done


