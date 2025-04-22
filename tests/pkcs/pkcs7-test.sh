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

RESULT=`./wolfssl pkcs7 -inform DER -in certs/signed.p7b 2>&1`
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

run "pkcs7 -inform DER -print_certs -in certs/signed.p7b"

#check that certs were printed
echo $RESULT | grep "CERTIFICATE"
if [ $? != 0 ]; then
    echo "ERROR didn't find cert with -print_certs option"
    exit 99
fi

#check der to pem
run "pkcs7 -inform DER -in certs/signed.p7b -outform PEM"

echo $RESULT | grep "BEGIN PKCS7"
if [ $? != 0 ]; then
    echo "ERROR didn't PKCS7 PEM header in output"
    exit 99
fi

#check pem to der
run "pkcs7 -inform PEM -in certs/signed.p7s -outform DER"

#check stdin input
RESULT=`cat certs/signed.p7b | ./wolfssl pkcs7 -inform DER`
echo $RESULT | grep "BEGIN PKCS7"
if [ $? != 0 ]; then
    echo "Couldn't parse PKCS7 from stdin"
    exit 99
fi

echo "Done"
exit 0
