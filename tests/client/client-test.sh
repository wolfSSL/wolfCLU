#!/bin/bash


echo | ./wolfssl s_client -connect www.wolfssl.com:443 | ./wolfssl x509 -outform pem -out tmp.crt

RESULT=`./wolfssl x509 -in tmp.crt`

echo $RESULT | grep -e "-----BEGIN CERTIFICATE-----"
if [ $? != 0 ]; then
    echo "Expected x509 input not found"
    exit 99
fi

rm tmp.crt

echo "Done"
exit 0
