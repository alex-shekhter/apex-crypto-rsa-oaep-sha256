#!/bin/sh

##############################################################
#
#### encrypts string using public key
#
##############################################################

PUBKEY_FILE="${1:?Public key file mandatory}"
CLEAR_TXT="${2:?Clear text to be encrypted}"

echo "Encrypting PUBKEY: $PUBKEY_FILE."
echo "Clear text: $CLEAR_TXT\n\n"

RES=$( \
    echo "${CLEAR_TXT}" | \
    openssl pkeyutl -encrypt -pubin -inkey $PUBKEY_FILE \
       -pkeyopt rsa_padding_mode:oaep \
       -pkeyopt rsa_oaep_md:sha256 \
       -pkeyopt rsa_mgf1_md:sha256 | \
    base64 \
)

echo "ENCRYPTED: [$RES]"
