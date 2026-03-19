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

RESULT=`./wolfssl base64 -in certs/server-key.der 2>&1`
echo "$RESULT" | grep "No coding support"
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

#test encode
run "base64 -in certs/server-key.der"

if ! grep -F "$RESULT" certs/server-key.pem; then
    echo "server-key.der base64 conversion failed"
    exit 99
fi

#test decode
run "base64 -d -in certs/signed.p7s -out testp7.der"

run "base64 -in testp7.der"

if ! grep -F "$RESULT" certs/signed.p7s; then
    echo "signed.p7s der base64 conversion failed"
    exit 99
fi

rm -rf testp7.der

# base64 encode round-trip test
run "base64 -in certs/server-key.der -out test-b64-encoded.b64"
run "base64 -d -in test-b64-encoded.b64 -out test-b64-decoded.der"
diff certs/server-key.der test-b64-decoded.der > /dev/null 2>&1
if [ $? != 0 ]; then
    echo "base64 encode/decode round-trip failed"
    rm -f test-b64-encoded.b64 test-b64-decoded.der
    exit 99
fi
rm -f test-b64-encoded.b64 test-b64-decoded.der

#check stdin input
RESULT=`cat certs/signed.p7b | ./wolfssl base64`
if [ $? != 0 ]; then
    echo "Couldn't parse input from stdin"
    exit 99
fi

echo "Done"
exit 0
