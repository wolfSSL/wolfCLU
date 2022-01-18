#!/bin/bash

if [ ! -d ./certs/ ]; then
    #return 77 to indicate to automake that the test was skipped
    exit 77
fi

run() {
    RESULT=`./wolfssl $1`
    if [ $? != 0 ]; then
        echo "Failed on test \"./wolfssl $1\""
        exit 99
    fi
}

run_fail() {
    RESULT=`./wolfssl $1`
    if [ $? == 0 ]; then
        echo "Failed on test \"./wolfssl $1\""
        exit 99
    fi
}

run "ecparam -genkey -name secp384r1 -out ecparam.key"
run "ecparam -text -in ecparam.key"
EXPECTED="Curve Name : SECP384R1
-----BEGIN EC PARAMETERS-----
BgUrgQQAIg==
-----END EC PARAMETERS-----"
if [ "$RESULT" != "$EXPECTED" ]; then
    echo "unexpected text output found"
    echo "$RESULT"
    exit 99
fi
rm -f ecparam.key

run "ecparam -text -in ./certs/ecc-key.pem"
EXPECTED="Curve Name : SECP256R1
-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----"
if [ "$RESULT" != "$EXPECTED" ]; then
    echo "unexpected text output found"
    echo "$RESULT"
    exit 99
fi

# pem -> der
run "ecparam -in certs/ecc-key.pem -out ecc-key.der -outform der"

# not yet supported reading only parameters with no key
run_fail "ecparam -in ecc-key.der -inform der -out ecc-key.pem -outform pem"
rm -f ecc-key.der

run "ecparam -genkey -out ecc-key.der -outform der"

run_fail "ecparam -in certs/ca-key.pem -text"

echo "Done"
exit 0

