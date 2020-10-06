#!/bin/bash

# DO NOT RUN THIS SCRIPT IN PRODUCTION 
# This scripts attempts to cross sign intermediate CA Certificates using pki/sign-self-issued

### Certs
export CommonName="hashidemos.io"
export InterCommonName="inter.hashidemos.io"
export Root_CA_ttl="730h"
export Inter_CA_ttl="380h"
export Cert_ttl="8h"

echo "WARNING: this script will over-write previous pki mounts at root_ca1, root_ca2 and inter_ca1, interca_2, is this OK? "
echo "Enter yes to continue: "
read x

if [ $x != "yes" ]; then
  echo "Please type yes to continue, exiting."
  exit
fi

## Go to working directory
mkdir -p certs && cd certs

# Mount Root CA and generate certs:
for i in {1..2}
do
  export name="root_ca$i"
  echo "Mounting Root CA at path: ${name}"
  vault secrets disable ${name}
  vault secrets enable -path ${name} pki
  vault secrets tune -max-lease-ttl=${Root_CA_ttl} ${name}
  vault write -format=json ${name}/root/generate/internal \
    common_name="${CommonName}" ttl=${Root_CA_ttl} | tee \
      >(jq -r .data.certificate > ${name}.pem) \
      >(jq -r .data.issuing_ca > ${name}-issuing_ca.pem)
done


# Mount Intermmediate CAs, generate CSR and sign certificates:
for i in {1..2}
do
  export name="inter_ca$i"
  echo "Mounting Intemmediate CA at path: ${name}"
  vault secrets disable ${name}
  vault secrets enable -path ${name} pki
  vault secrets tune -max-lease-ttl=${Inter_CA_ttl} ${name}

  # Generate CSR
  vault write -format=json ${name}/intermediate/generate/internal \
    common_name="${InterCommonName}" ttl=${Inter_CA_ttl} | tee \
    >(jq -r .data.csr > ${name}.csr)
  
  # Sign CSR
  root_path="root_ca$i"
  echo "Signing Intermmediate with with ${root_path}"
  vault write -format=json $root_path/root/sign-intermediate \
    csr=@${name}.csr \
    common_name="${InterCommonName}" ttl=${Inter_CA_ttl} | tee \
      >(jq -r .data.certificate > ${name}.pem) \
      >(jq -r .data.issuing_ca > ${name}_issuing_ca.pem)

  # Set signed cert
  vault write ${name}/intermediate/set-signed certificate=@${name}.pem

  # Display signed cert
  echo "Displaying cert for ${name}"
  openssl x509 -in ${name}.pem -text -noout

done

echo "Displaying all pki secret engines"
vault secrets list | grep pki

# This function uses $root_ca/sign-self-issued to sign $inter_ca
# Set $root_ca and $inter_ca paths before calling this function
crosssign_inter() {
  echo "Crossign: ${inter_ca} with ${root_ca}"

  curl --header "X-Vault-Token: $(vault print token)" \
    -s ${VAULT_ADDR}/v1/${inter_ca}/ca/pem > ${inter_ca}-ca.pem
  # Remove line breaks
  # https://serverfault.com/questions/466683/can-an-ssl-certificate-be-on-a-single-line-in-a-file-no-line-breaks
  awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' ${inter_ca}-ca.pem \
    | tee ${inter_ca}-ca-singleline.pem 

# Create payload
cat <<EOF >payload.json
{
  "certificate": "$(cat ${inter_ca}-ca-singleline.pem)"
}
EOF

  # Cross sign with the root CA
  curl --header "X-Vault-Token: $(vault print token)" \
    --request POST --data @payload.json \
	-s ${VAULT_ADDR}/v1/${root_ca}/root/sign-self-issued > ${inter_ca}-crosssign.json

   # Inspect response from sign-self-issued
   echo "*** Received response from sign-self-issued: $(cat ${inter_ca}-crosssign.json) ***"
   cert=$(cat ${inter_ca}-crosssign.json | jq -r .data.certificate)

  # Display cert if valid
  if [ ! -z "${cert}" ] && [ "${cert}" != "null" ]; then
      # View cross signed certificate
      echo "Displaying Crosssigned certificate"
      openssl x509 -in $cert -text -noout
  else
      echo "Cross-signing failed, please inspect for errors."
  fi
}

# Cross-sign inter_ca2 with root_ca1
export root_ca=root_ca1
export inter_ca=inter_ca2
crosssign_inter

# Cross-sign inter_ca1 with root_ca2
export root_ca=root_ca2
export inter_ca=inter_ca1
crosssign_inter