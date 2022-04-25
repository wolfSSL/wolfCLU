#!/bin/bash

if [ ! -d ./certs/ ]; then
    #return 77 to indicate to automake that the test was skipped
    exit 77
fi

run_success() {
    RESULT=`./wolfssl $1`
    if [ $? != 0 ]; then
        echo "Fail on ./wolfssl $1"
        exit 99
    fi
}

run_fail() {
    RESULT=`./wolfssl $1`
    if [ $? == 0 ]; then
        echo "Fail on ./wolfssl $1"
        exit 99
    fi
}


# Test if CRL compiled in
RESULT=`./wolfssl crl -CAfile ./certs/ca-cert.pem -in ./certs/crl.pem 2>&1`
echo $RESULT | grep "recompile wolfSSL with CRL support"
if [ $? == 0 ]; then
    #return 77 to indicate to automake that the test was skipped
    exit 77
fi


# check that the CRL was printed out
run_success "crl -CAfile ./certs/ca-cert.pem -in ./certs/crl.pem"
echo $RESULT | grep BEGIN
if [ $? != 0 ]; then
    echo "CRL not printed when should have been"
    exit 99
fi


# check that the CRL was not printed out
run_success "crl -noout -CAfile ./certs/ca-cert.pem -in ./certs/crl.pem"
echo $RESULT | grep "BEGIN X509 CRL"
if [ $? == 0 ]; then
    echo "CRL printed when should not have been"
    exit 99
fi

# check that CRL is printed on fail to parse CRL
run_success "crl -inform DER -outform PEM -in ./certs/ca-cert.der"
echo $RESULT | grep BEGIN
if [ $? != 0 ]; then
    echo "CRL "
    exit 99
fi

run_success "req -new -days 3650 -key ./certs/server-key.pem -subj O=wolfSSL/C=US/ST=WA/L=Seattle/CN=wolfSSL/OU=org-unit -out client.pem -x509"
run_success "crl -noout -CAfile client.pem -in ./certs/crl.pem"
if [ $? != 0 ]; then
    echo "CRL should work even when verification fails"
    exit 99
fi
rm -rf client.pem

# fail to load
run_fail "crl -noout -CAfile ./certs/ca-cer.pem -in ./certs/crl.pem"
run_fail "crl -noout -CAfile ./certs/ca-cert.pem -in ./certs/cl.pem"

# fail to verify
run_fail "crl -noout -CAfile ./certs/client-cert.pem -in ./certs/crl.pem"

run_success "crl -inform DER -outform PEM -in ./certs/crl.der -out ./test-crl.pem"
run_success "crl -noout -CAfile ./certs/ca-cert.pem -in ./test-crl.pem"
run_success "crl -inform DER -outform PEM -in ./certs/ca-cert.der -out test.crl.pem"
rm -f test-crl.pem

echo "Done"
exit 0

