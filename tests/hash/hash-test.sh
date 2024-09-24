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

run_success() {
    RESULT=`./wolfssl $1`
    if [ $? != 0 ]; then
        echo "Failed on test \"$1\""
        exit 99
    fi
}

run_fail() {
    RESULT=`./wolfssl $1`
    if [ $? == 0 ]; then
        echo "Failed on test \"$1\""
        exit 99
    fi
}

run_success "-hash sha -in certs/ca-cert.pem -base64enc"
EXPECTED=`cat tests/hash/sha-expect.hex`
if [ "$RESULT" != "$EXPECTED" ]
then
    echo "found unexpected output 1"
    exit 99
fi

run_success "-hash sha256 -in certs/ca-cert.pem"
EXPECTED=`cat tests/hash/sha256-expect.hex`
if [ "$RESULT" != "$EXPECTED" ]
then
    echo "found unexpected output 2"
    exit 99
fi

run_success "-hash sha384 -in certs/ca-cert.pem"
EXPECTED=`cat tests/hash/sha384-expect.hex`
if [ "$RESULT" != "$EXPECTED" ]
then
    echo "found unexpected output 3"
    exit 99
fi

run_success "-hash sha512 -in certs/ca-cert.pem"
EXPECTED=`cat tests/hash/sha512-expect.hex`
if [ "$RESULT" != "$EXPECTED" ]
then
    echo "found unexpected output"
    exit 99
fi


run_success "md5 certs/ca-cert.pem"
EXPECTED=`cat tests/hash/md5-expect.hex`
if [ "$RESULT" != "$EXPECTED" ]
then
    echo "found unexpected output"
    exit 99
fi

run_success "sha256 certs/ca-cert.pem"
EXPECTED=`cat tests/hash/sha256-expect.hex`
if [ "$RESULT" != "$EXPECTED" ]
then
    echo "found unexpected output"
    exit 99
fi

run_success "sha384 certs/ca-cert.pem"
EXPECTED=`cat tests/hash/sha384-expect.hex`
if [ "$RESULT" != "$EXPECTED" ]
then
    echo "found unexpected output"
    exit 99
fi

run_success "sha512 certs/ca-cert.pem"
EXPECTED=`cat tests/hash/sha512-expect.hex`
if [ "$RESULT" != "$EXPECTED" ]
then
    echo "found unexpected output"
    exit 99
fi


echo "Done"
exit 0
