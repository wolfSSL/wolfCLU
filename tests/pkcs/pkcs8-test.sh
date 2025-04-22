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

run "pkcs8 -in certs/server-keyEnc.pem -passin pass:yassl123 -outform DER -out keyEnc.der"

run "pkcs8 -in keyEnc.der -inform DER -outform PEM -out key.pem"

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

#check stdin input
RESULT=`cat certs/server-keyEnc.pem | ./wolfssl pkcs8 -passin pass:yassl123`
echo $RESULT | grep "BEGIN PRIVATE"
if [ $? != 0 ]; then
    echo "Couldn't parse PKCS8 from stdin"
    exit 99
fi

echo "Done"
exit 0
