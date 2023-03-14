#!/bin/sh

###########################################################
#
### cat_mod_exponents.sh
#
#   Utility to show modulus, exponents of the private key
#
#   INPUT PARAMTERS:
#
#       NAME_OF_THE_PRIVATE_KEY_FILE (by default private.pem)
#
###########################################################

PRIVATE_KEY_FILE=${1:-private.pem}

openssl rsa -in $PRIVATE_KEY_FILE -noout -text
