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

run "pkey -pubin -in ./certs/ecc-keyPub.pem"
EXPECTED="-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEuzOsTCdQSsZKpQTDPN6fNttyLc6U
6iv6yyAJOSwW6GEC6a9N0wKTmjFbl5Ihf/DPGNqREQI0huggWDMLgDSJ2A==
-----END PUBLIC KEY-----"
if [ "$RESULT" != "$EXPECTED" ]; then
    echo "unexpected text output found"
    echo "$RESULT"
    exit 99
fi
run_fail "pkey -pubin -in ./certs/ecc-key.pem"

# pem -> der -> pem
run "pkey -pubin -in ./certs/ecc-keyPub.pem -outform der -out ecc.der"
run "pkey -pubin -in ecc.der -inform der -outform pem -out ecc.pem"
run "pkey -pubin -in ecc.pem"
EXPECTED="-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEuzOsTCdQSsZKpQTDPN6fNttyLc6U
6iv6yyAJOSwW6GEC6a9N0wKTmjFbl5Ihf/DPGNqREQI0huggWDMLgDSJ2A==
-----END PUBLIC KEY-----"
if [ "$RESULT" != "$EXPECTED" ]; then
    echo "unexpected text output found"
    echo "$RESULT"
    exit 99
fi

echo "Done"
exit 0

