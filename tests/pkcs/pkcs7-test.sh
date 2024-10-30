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

RESULT=`./wolfssl pkcs7 -inform DER -in signed.p7b`
echo "$RESULT" | grep "Recompile wolfSSL with PKCS7 support"
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

run "pkcs7 -inform DER -print_certs -in signed.p7b"

#check that certs were printed
echo $RESULT | grep "CERTIFICATE"
if [ $? != 0 ]; then
    echo "ERROR didn't find cert with -print_certs option"
    exit 99
fi

#check der to pem
run "pkcs7 -inform DER -in signed.p7b -outform PEM"

echo $RESULT | grep "BEGIN PKCS7"
if [ $? != 0 ]; then
    echo "ERROR didn't PKCS7 PEM header in output"
    exit 99
fi

#check pem to der
run "pkcs7 -inform PEM -in signed.p7s -outform DER"

echo "Done"
exit 0
