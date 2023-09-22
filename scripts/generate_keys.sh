#!/bin/sh

###########################################################
#
### generate_keys.sh
#
#   Utility to generate RSA keys
#
#   INPUT PARAMTERS:
#
#       KEY_ID_PREFIX - FQDN of the SF ORG which will use
#                       generated keys.
#
###########################################################

KEY_ID_PREFIX=${1:?KEY_ID_PREFIX (SF ORG FQDN) is a mandatory parameter}
KEY_SIZE=${2:-2048}
APPID=${3:-SFAPP}

UUID=$(uuidgen)


keyName() {
    local suffix=$1

    echo "${KEY_ID_PREFIX}-${APPID}-${UUID}-${suffix}"
}

PRIVATE_KEY_FILE=$(keyName "private.pem")
PUBLIC_KEY_FILE=$(keyName "public.pem")

#
# --- Private key generation
#
openssl genpkey -algorithm RSA -out $PRIVATE_KEY_FILE -pkeyopt rsa_keygen_bits:$KEY_SIZE

#
# --- Public key generation
#
openssl rsa -in $PRIVATE_KEY_FILE -pubout -out $PUBLIC_KEY_FILE

chmod 400 $PRIVATE_KEY_FILE
chmod 400 $PUBLIC_KEY_FILE

#
# --- Modulus, and public/private exponents to be used in Apex
#
./prep_modulus_exponents.sh $PRIVATE_KEY_FILE
