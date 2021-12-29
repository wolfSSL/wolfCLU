#!/bin/bash

if [ ! -d ./certs/ ]; then
    #return 77 to indicate to automake that the test was skipped
    exit 77
fi

run() {
    RESULT=`eval $1`
    if [ $? != 0 ]; then
        echo "Failed on test \"$1\""
        exit 99
    fi
}

run_fail() {
    RESULT=`eval $1`
    if [ $? == 0 ]; then
        echo "Failed on test \"$1\""
        exit 99
    fi
}


run "./wolfssl enc -d -aes-256-cbc -nosalt -k '' -in certs/crl.der.enc -out test-dec.der"
diff "./certs/crl.der" "./test-dec.der" &> /dev/null
if [ $? != 0 ]; then
    echo "issue with decryption"
    exit 99
fi
rm -f test-dec.der

run "./wolfssl enc -base64 -d -aes-256-cbc -nosalt -k '' -in certs/crl.der.enc.base64 -out test-dec.der"
diff "./certs/crl.der" "./test-dec.der" &> /dev/null
if [ $? != 0 ]; then
    echo "issue with decryption"
    exit 99
fi
rm -f test-dec.der


# check fail cases
run_fail "./wolfssl enc -base64 -d -aes-256-cbc -nosalt -k '' -in certs/file-does-not-exist -out test-dec.der"

echo "Done"
exit 0
