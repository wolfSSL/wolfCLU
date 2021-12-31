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

run "dgst -sha256 -verify ./certs/server-keyPub.pem -signature ./tests/dgst/sha256-rsa.sig ./certs/server-key.der"

run "dgst -md5 -verify ./certs/server-keyPub.pem -signature ./tests/dgst/md5-rsa.sig ./certs/server-key.der"

run "dgst -sha256 -verify ./certs/ecc-keyPub.pem -signature ./tests/dgst/sha256-ecc.sig ./certs/server-key.der"

run_fail "dgst -sha256 -verify ./certs/ecc-keyPub.pem -signature ./tests/dgst/sha256-rsa.sig ./certs/server-key.der"

run_fail "dgst -sha256 -verify ./certs/ca-key.pem -signature ./tests/dgst/sha256-rsa.sig ./certs/server-key.der"

run_fail "dgst -sha256 -verify ./certs/server-key.pem -signature ./tests/dgst/sha256-rsa.sig ./certs/server-key.der"

run_fail "dgst -md5 -verify ./certs/server-keyPub.pem -signature ./tests/dgst/sha256-rsa.sig ./certs/server-key.der"


echo "Doing large file test"
# recreate large file and test
rm -f large-test.txt
for i in {1..5000}; do
    cat ./certs/server-key.der >> large-test.txt
done
run "dgst -sha256 -verify ./certs/server-keyPub.pem -signature ./tests/dgst/5000-server-key.sig ./large-test.txt"
rm -f large-test.txt

echo "Done"
exit 0
