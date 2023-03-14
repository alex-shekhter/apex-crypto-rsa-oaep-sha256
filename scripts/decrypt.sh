#!/bin/sh

##############################################################
#
#### decrypts string using public key
#
##############################################################

PRIVATEKEY_FILE="${1:?Private key file mandatory}"
CYPHER_TXT="${2:?Cypher text to be decrypted mandatory}"

echo "PRIVATEKEY: $PRIVATEKEY_FILE"
echo "Cypher text: $CYPHER_TXT\n\n"

RES=$( \
    echo $CYPHER_TXT | \
    base64 -d | \
    openssl pkeyutl -decrypt -inkey $PRIVATEKEY_FILE \
       -pkeyopt rsa_padding_mode:oaep \
       -pkeyopt rsa_oaep_md:sha256 \
       -pkeyopt rsa_mgf1_md:sha256 \
)

echo "DECRYPTED: [$RES]"
