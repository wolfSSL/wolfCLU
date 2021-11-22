#!/bin/sh

if [ ! -d ./certs/ ]; then
    #return 77 to indicate to automake that the test was skipped
    exit 77
fi

RESULT=`./wolfssl verify -CAfile ./certs/ca-cert.pem ./certs/server-cert.pem`
if [ $? != 0 ]; then
    echo "Failed on test \"./wolfssl verify -CAfile ./certs/ca-cert.pem ./certs/server-cert.pem\""
    exit 99
fi

RESULT=`./wolfssl verify -CAfile ./certs/ca-cert.pem ./certs/server-ecc.pem`
if [ $? == 0 ]; then
    echo "Failed on test \"./wolfssl verify -CAfile ./certs/ca-cert.pem ./certs/server-ecc.pem\""
    exit 99
fi

RESULT=`./wolfssl verify -CAfile ./certs/ca-ecc-cert.pem ./certs/server-ecc.pem`
if [ $? != 0 ]; then
    echo "Failed on test \"./wolfssl verify -CAfile ./certs/ca-ecc-cert.pem ./certs/server-ecc.pem\""
    exit 99
fi

RESULT=`./wolfssl verify -CAfile ./certs/ca-cert.pem -crl_check ./certs/server-cert.pem | grep "recompile wolfSSL with CRL"`
HAVE_CRL=$?

#if the return value of the grep is success (0) then CRL not compiled in
if [ $HAVE_CRL != 0 ]; then
    RESULT=`./wolfssl verify -CAfile ./certs/ca-cert.pem -crl_check ./certs/server-cert.pem`
    if [ $? == 0 ]; then
        echo "Failed on test \"./wolfssl verify -CAfile ./certs/ca-cert.pem -crl_check ./certs/server-cert.pem\""
        exit 99
    fi

    RESULT=`./wolfssl verify -CAfile ./certs/crl-chain.pem -crl_check ./certs/server-cert.pem`
    if [ $? != 0 ]; then
        echo "Failed on test \"./wolfssl verify -CAfile ./certs/crl-chain.pem -crl_check ./certs/server-cert.pem\""
        exit 99
    fi

    RESULT=`./wolfssl verify -CAfile ./certs/crl-chain.pem -crl_check ./certs/server-revoked-cert.pem`
    if [ $? == 0 ]; then
        echo "Failed on test \"./wolfssl verify -CAfile ./certs/crl-chain.pem -crl_check ./certs/server-revoked-cert.pem\""
        exit 99
    fi
else
    echo "Skipping CRL tests..."
fi

exit 0
