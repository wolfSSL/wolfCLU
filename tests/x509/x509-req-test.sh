#!/bin/bash

if [ ! -d ./certs/ ]; then
    #return 77 to indicate to automake that the test was skipped
    exit 77
fi

run_success() {
    if [ -z "$2" ]; then
        RESULT=`./wolfssl $1`
    else
        RESULT=`echo "$2" | ./wolfssl $1`
    fi
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


cat << EOF >> test.conf
[ req ]
distinguished_name =req_distinguished_name
attributes =req_attributes
prompt =no
x509_extensions = v3_req
req_extensions = v3_req
[ req_distinguished_name ]
countryName =US
stateOrProvinceName =Montana
localityName =Bozeman
organizationName =wolfSSL
commonName = testing
[ req_attributes ]
[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names
[ v3_alt_ca ]
basicConstraints = CA:TRUE
keyUsage = digitalSignature
subjectAltName = @alt_names
[alt_names]
DNS.1 = extraName
DNS.2 = alt-name
DNS.3 = thirdName
IP.1 = 2607:f8b0:400a:80b::2004
DNS.4 = 2607:f8b0:400a:80b::2004 (google.com)
IP.2 = 127.0.0.1
EOF


run_success "req -new -days 3650 -key ./certs/server-key.pem -subj O=wolfSSL/C=US/ST=WA/L=Seattle/CN=wolfSSL/OU=org-unit -out tmp.cert -x509"

SUBJECT=`./wolfssl x509 -in tmp.cert -text | grep Subject:`
if [ "$SUBJECT" != "        Subject: /O=wolfSSL/C=US/ST=WA/L=Seattle/CN=wolfSSL/OU=org-unit" ]
then
    echo "found unexpected $SUBJECT"
    exit 99
fi
rm -f tmp.cert

# no parameter -conf
#run_fail "req -new -key ./certs/server-key.pem -conf ./test.conf -out tmp.csr"

run_success "req -new -key ./certs/server-key.pem -config ./test.conf -out tmp.csr"
run_success "req -text -in tmp.csr"

run_success "req -new -extensions v3_alt_ca -key ./certs/server-key.pem -config ./test.conf -x509 -out alt.crt"
run_success "x509 -in alt.crt -text -noout"
echo "$RESULT" | grep "CA:TRUE"
if [ $? != 0 ]; then
    echo "was expecting alt extensions to have CA set"
    exit 99
fi

# test pem to der and back again
run_success "req -inform pem -outform der -in tmp.csr -out tmp.csr.der"
run_success "req -inform der -outform pem -in tmp.csr.der -out tmp.csr.pem"
diff tmp.csr.pem tmp.csr
if [ $? != 0 ]; then
    echo "transforming from der and back to pem mismatch"
    echo "tmp.csr != tmp.csr.pem"
    exit 99
fi
rm -f tmp.csr.pem
rm -f tmp.csr.der
rm -f tmp.csr

run_success "req -new -key ./certs/server-key.pem -config ./test.conf -x509 -out tmp.cert"
SUBJECT=`./wolfssl x509 -in tmp.cert -text | grep Subject:`
if [ "$SUBJECT" != "        Subject: /C=US/ST=Montana/L=Bozeman/O=wolfSSL/CN=testing" ]
then
    echo "found unexpected $SUBJECT"
    exit 99
fi
rm -f tmp.cert

run_success "req -new -newkey rsa:2048 -config ./test.conf -x509 -out tmp.cert" "test"
echo $RESULT | grep "ENCRYPTED"
if [ $? -ne 0 ]; then
    echo "no encrypted key found in result"
    exit 99
fi
rm -f tmp.cert

run_success "req -new -newkey rsa:2048 -keyout new-key.pem -config ./test.conf -x509 -out tmp.cert" "test"
rm -f tmp.cert
rm -f new-key.pem
rm -f test.conf
echo "Done"
exit 0


