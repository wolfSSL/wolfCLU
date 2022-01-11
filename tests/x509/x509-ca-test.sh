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


cat << EOF >> ca.conf
[ ca ]
default_ca = CA_default

[ usr_cert ]

basicConstraints=CA:FALSE
nsComment            = "wolfSSL Generated Certificate using wolfSSL command line utility."
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer

[ CA_default ]

dir = ./certs
database = ./index.txt
new_certs_dir = ./

certificate = \$dir/ca-cert.pem
private_key = \$dir/ca-key.pem
rand_serial = yes

default_days = 365
default_md = sha256

policy = policy_any

[ policy_any]
countryName            = supplied
stateOrProvinceName    = optional
organizationName       = optional
organizationalUnitName = optional
commonName             = supplied
emailAddress           = optional
EOF


touch index.txt
run_success "ca -h"
run_success "ca -help"
run_success "req -key ./certs/server-key.pem -subj O=wolfSSL/C=US/ST=MT/L=Bozeman/CN=wolfSSL/OU=org-unit -out tmp-ca.csr"

# create a certificate and then verify it
run_success "ca -config ca.conf -in tmp-ca.csr -out test.pem"
run_success "verify -CAfile ./certs/ca-cert.pem test.pem"

# override almost all info from config file
run_success "ca -config ca.conf -in tmp-ca.csr -out test.pem -extensions usr_cert -md sha512 -days 3650 -cert ./certs/ca-ecc-cert.pem -keyfile ./certs/ecc-key.pem"
rm -f test.pem

# test key missmatch
run_fail "ca -config ca.conf -in tmp-ca.csr -out test.pem -keyfile ./certs/ecc-key.pem"

rm -f tmp-ca.csr
rm -f ca.conf
rm -f index.txt

echo "Done"
exit 0



