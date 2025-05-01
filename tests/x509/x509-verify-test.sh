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

RESULT=`./wolfssl verify ./certs/server-cert.pem 2>&1`
if [ $? == 0 ]; then
    echo "Failed on test \"./wolfssl verify ./certs/server-cert.pem\""
    exit 99
fi
echo "$RESULT" | grep "Err (20): unable to get local issuer certificate"
if [ $? != 0 ]; then
    echo "Unexpected error result on test \"./wolfssl verify ./certs/server-cert.pem\""
    exit 99
fi

RESULT=`./wolfssl verify ./certs/ca-cert.pem 2>&1`
if [ $? == 0 ]; then
    echo "Failed on test \"./wolfssl verify ./certs/ca-cert.pem\""
    exit 99
fi
echo "$RESULT" | grep "Err (18): self-signed certificate in certificate chain"
if [ $? != 0 ]; then
    echo "Unexpected error result on test \"./wolfssl verify ./certs/ca-cert.pem\""
    exit 99
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

RESULT=`./wolfssl verify -CAfile ./certs/ca-cert.pem ./certs/server-cert.pem`
if [ $? != 0 ]; then
    echo "Failed on test \"./wolfssl verify -CAfile ./certs/ca-cert.pem ./certs/server-cert.pem\""
    exit 99
fi

RESULT=`./wolfssl verify -CAfile ./certs/server-cert.pem ./certs/server-cert.pem`
if [ $? == 0 ]; then
    echo "Failed on test \"./wolfssl verify -CAfile ./certs/server-cert.pem ./certs/server-cert.pem\""
    exit 99
fi

RESULT=`./wolfssl verify -partial_chain -CAfile ./certs/server-cert.pem ./certs/server-cert.pem`
if [ $? != 0 ]; then
    echo "Failed on test \"./wolfssl verify -partial_chain -CAfile ./certs/server-cert.pem ./certs/server-cert.pem\""
    exit 99
fi

RESULT=`./wolfssl verify -CAfile ./certs/ca-cert.pem -crl_check ./certs/server-cert.pem 2>&1 | grep "recompile wolfSSL with CRL"`
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

# Test verifying along a chain of certificates
RESULT=`./wolfssl verify -CAfile ./certs/ca-int-cert.pem ./certs/ca-int2-cert.pem`
if [ $? == 0 ]; then
    echo "Should have failed to verify ca-int2-cert.pem with ca-int-cert.pem"
    exit 99
fi
RESULT=`./wolfssl verify -partial_chain -CAfile ./certs/ca-int-cert.pem ./certs/ca-int2-cert.pem`
if [ $? != 0 ]; then
    echo "Failed to verify ca-int2-cert.pem with ca-int-cert.pem"
    exit 99
fi
RESULT=`./wolfssl verify -partial_chain -CAfile ./certs/ca-int2-cert.pem ./certs/client-int-cert.pem`
if [ $? != 0 ]; then
    echo "Failed to verify client-int-cert.pem with ca-int2-cert.pem"
    exit 99
fi
RESULT=`./wolfssl verify -CAfile ./certs/ca-cert.pem -untrusted ./certs/ca-int-cert.pem ./certs/ca-int2-cert.pem`
if [ $? != 0 ]; then
    echo "Failed to verify ca-int2-cert.pem with ca-cert.pem and ca-int-cert.pem"
    exit 99
fi

exit 0
