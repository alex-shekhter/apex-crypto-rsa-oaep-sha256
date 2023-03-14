#!/bin/sh

###########################################################
#
### prep_modulus_exponents.sh
#
#   Utility to extract modulus and exponent from the private
#   key to be used inside custom setting and/or Apex for
#   encryption
#
#   INPUT PARAMTERS:
#
#       NAME_OF_THE_PRIVATE_KEY_FILE (by default private.pem)
#
###########################################################

PRIVATE_KEY_FILE=${1:-private.pem}

#
# --- Modulus, and public/private exponents to be used in Apex
#
openssl rsa -in $PRIVATE_KEY_FILE -noout -text | \
awk '
BEGIN {
    parts[ "modulus:" ] = ""
    parts[ "publicExponent:" ] = ""
    parts[ "privateExponent:" ] = ""
    curr = ""
    isStop = 0
}
/^prime1:/ {
    isStop = 1
}
{
    if ( $1 in parts ) {
        curr = $1 
        if ( curr == "publicExponent:" ) {
            parts[ curr ] = $3
            gsub( /^\(0x/, "", parts[ curr ] )
            gsub( /\)$/, "", parts[ curr ] ) 
        }
    }
    else if ( curr > "" && isStop == 0 ) {
        gsub( /[ \t:]/, "" )
        parts[ curr ] = parts[ curr ] $0 
    }
}
END {
    print "MODULUS:" 
    print parts[ "modulus:" ]
    print "PUBLIC_EXPONENT:" 
    print parts[ "publicExponent:" ]
    print "PRIVATE_EXPONENT:" 
    print parts[ "privateExponent:" ]
}
'
