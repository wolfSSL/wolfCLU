#!/bin/bash

# for interop testing create signatures using OpenSSL
openssl dgst -sign ../../certs/server-key.pem -sha256 -out sha256-rsa.sig ../../certs/server-key.der

openssl dgst -sign ../../certs/server-key.pem -md5 -out md5-rsa.sig ../../certs/server-key.der

openssl dgst -sign ../../certs/ecc-key.pem -sha256 -out sha256-ecc.sig ../../certs/server-key.der

