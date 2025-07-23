#!/bin/bash

if [ ! -d ./certs/ ]; then
    #return 77 to indicate to automake that the test was skipped
    exit 77
fi

# Skip test if filesystem disabled
FILESYSTEM=`cat config.log | grep "disable\-filesystem"`
if [ "$FILESYSTEM" != "" ]
then
    exit 77
fi

# Is this a FIPS build?
IS_FIPS=0
if ./wolfssl -v 2>&1 | grep -q FIPS; then
    IS_FIPS=1
fi

RESULT=`./wolfssl pkcs8 -in certs/server-keyEnc.pem -passin pass:yassl123 2>&1`
echo "$RESULT" | grep "Recompile wolfSSL with PKCS8 support"
if [ $? == 0 ]; then
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

if [ ${IS_FIPS} != "1" ]; then
    # Can only decrypt server-keyEnc.pem using DES if not a FIPS build
    run "pkcs8 -in certs/server-keyEnc.pem -passin pass:yassl123 -outform DER -out keyEnc.der"
    run "pkcs8 -in keyEnc.der -inform DER -outform PEM -out key.pem"
else
    run "pkcs8 -in certs/server-key.pem  -outform PEM -out key.pem"
fi

run "pkcs8 -in key.pem -topk8 -nocrypt"

run "pkcs8 -in key.pem -traditional -out pkcs1.pem"

diff "./certs/server-key.pem" "./pkcs1.pem" &> /dev/null
if [ $? != 0 ]; then
    echo "server-key.pem -traditional check failed"
    exit 99
fi

rm -rf pkcs1.pem
rm -rf key.pem
rm -rf keyEnc.der

if [ ${IS_FIPS} != "1" ]; then
    #check stdin input
    RESULT=`cat certs/server-keyEnc.pem | ./wolfssl pkcs8 -passin pass:yassl123`
    echo $RESULT | grep "BEGIN PRIVATE"
    if [ $? != 0 ]; then
        echo "Couldn't parse PKCS8 from stdin"
        exit 99
    fi

    run_fail "pkcs8 -in certs/server-cert.pem -passin pass:yassl123"

    run_fail "pkcs8 -in certs/server-keyEnc.pem -passin pass:wrongPass"

    run_fail "pkcs8 -in certs/server-keyEnc.pem -inform DER -passin pass:yassl123"
fi

echo "Done"
exit 0
