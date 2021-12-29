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


# encrypt and then test decrypt
run "./wolfssl enc -base64 -aes-256-cbc -k 'test password' -in certs/crl.der -out test-enc.der"
run_fail "./wolfssl enc -base64 -d -aes-256-cbc -k 'bad password' -in test-enc.der -out test-dec.der"
run "./wolfssl enc -base64 -d -aes-256-cbc -k 'test password' -in test-enc.der -out test-dec.der"
diff "./certs/crl.der" "./test-dec.der" &> /dev/null
if [ $? != 0 ]; then
    echo "issue with decryption"
    exit 99
fi
rm -f test-dec.der
rm -f test-enc.der



# interoperability testing
openssl enc --help
if [ $? == 0 ]; then
    run "openssl enc -base64 -aes-256-cbc -k 'test password' -in certs/crl.der -out test-enc.der"
    run "./wolfssl enc -base64 -d -aes-256-cbc -k 'test password' -in test-enc.der -out test-dec.der"
    diff "./certs/crl.der" "./test-dec.der" &> /dev/null
    if [ $? != 0 ]; then
        echo "issue openssl enc and wolfssl dec"
        exit 99
    fi
    rm -f test-dec.der
    rm -f test-enc.der

    run "./wolfssl enc -base64 -aes-256-cbc -k 'test password' -in certs/crl.der -out test-enc.der"
    run "openssl enc -base64 -d -aes-256-cbc -k 'test password' -in test-enc.der -out test-dec.der"
    diff "./certs/crl.der" "./test-dec.der" &> /dev/null
    if [ $? != 0 ]; then
        echo "issue wolfssl enc and openssl dec"
        exit 99
    fi
    rm -f test-dec.der
    rm -f test-enc.der

    # now try with -pbkdf2
    run "openssl enc -base64 -pbkdf2 -aes-256-cbc -k 'test password' -in certs/crl.der -out test-enc.der"
    run "./wolfssl enc -base64 -d -pbkdf2 -aes-256-cbc -k 'test password' -in test-enc.der -out test-dec.der"
    diff "./certs/crl.der" "./test-dec.der" &> /dev/null
    if [ $? != 0 ]; then
        echo "issue openssl enc and wolfssl dec pbkdf2"
        exit 99
    fi
    rm -f test-dec.der
    rm -f test-enc.der

    run "./wolfssl enc -base64 -pbkdf2 -aes-256-cbc -k 'test password' -in certs/crl.der -out test-enc.der"
    run "openssl enc -base64 -d -pbkdf2 -aes-256-cbc -k 'test password' -in test-enc.der -out test-dec.der"
    diff "./certs/crl.der" "./test-dec.der" &> /dev/null
    if [ $? != 0 ]; then
        echo "issue wolfssl enc and openssl dec pbkdf2"
        exit 99
    fi
    rm -f test-dec.der
    rm -f test-enc.der
fi

echo "Done"
exit 0
