

if [ -z $1 ]; then
    echo "run with path to certs <./renew.sh /path/to/wolfssl/certs>"
    exit 1
fi


CERTS_DIR=$1

echo "Creating CRL test certificates and chains"
cat $CERTS_DIR/crl/crl.pem $CERTS_DIR/ca-cert.pem > crl-chain.pem
cp  $CERTS_DIR/server-revoked-cert.pem .

echo "Copy over CRLs"
cp  $CERTS_DIR/crl/crl.pem .
cp  $CERTS_DIR/crl/crl.der .

echo "Copy over test keys"
cp  $CERTS_DIR/server-key.pem .
cp  $CERTS_DIR/server-key.der .
cp  $CERTS_DIR/server-keyEnc.pem .
cp  $CERTS_DIR/server-keyPub.pem .
cp  $CERTS_DIR/ecc-key.pem .
cp  $CERTS_DIR/ecc-keyPub.pem .
cp  $CERTS_DIR/ca-ecc-key.pem .
cp  $CERTS_DIR/ca-key.pem .

echo "Copy over test certificates and chains"
cp  $CERTS_DIR/server-cert.pem .
cp  $CERTS_DIR/server-ecc.pem .
cp  $CERTS_DIR/ca-cert.pem .
cp  $CERTS_DIR/ca-ecc-cert.pem .
cp  $CERTS_DIR/ca-cert.der .

echo "Copy over pkcs12 test bundles"
cp  $CERTS_DIR/test-servercert.p12 .

echo "Copy over certificates for longer chain"
cp  $CERTS_DIR/intermediate/ca-int-cert.pem .
cp  $CERTS_DIR/intermediate/ca-int2-cert.pem .
cp  $CERTS_DIR/intermediate/client-int-cert.pem .

echo "Additional update of client example source code"
cp $CERTS_DIR/../examples/client/client.c ../src/client/client.c
sed -i '' "s/examples\/client\//wolfclu\//" ../src/client/client.c

echo "Recreate expected encrypted data with new files"
openssl enc -aes-256-cbc -nosalt -in ./crl.der -out ./crl.der.enc -k ""
openssl enc -base64 -aes-256-cbc -nosalt -in ./crl.der -out ./crl.der.enc.base64 -k ""

echo "Recreating expected hash values"
cat ./ca-cert.pem | openssl dgst -sha1 -r | awk '{print $1}' > ../tests/hash/sha-expect.hex
cat ./ca-cert.pem | openssl dgst -sha256 -r | awk '{print $1}' > ../tests/hash/sha256-expect.hex
cat ./ca-cert.pem | openssl dgst -sha384 -r | awk '{print $1}' > ../tests/hash/sha384-expect.hex
cat ./ca-cert.pem | openssl dgst -sha512 -r | awk '{print $1}' > ../tests/hash/sha512-expect.hex
cat ./ca-cert.pem | openssl dgst -md5 -r | awk '{print $1}' > ../tests/hash/md5-expect.hex

echo "Recreating expected cert values"
openssl x509 -in ./server-cert.pem -modulus -noout > ../tests/x509/expect-modulus.txt
openssl x509 -in ./server-cert.pem -subject -noout -nameopt compat | sed 's/^subject=//' > ../tests/x509/expect-subject.txt
openssl x509 -in ./server-cert.pem -issuer -noout -nameopt compat | sed 's/^issuer=//' > ../tests/x509/expect-issuer.txt
openssl x509 -in ./ca-cert.pem -serial -noout > ../tests/x509/expect-ca-serial.txt
openssl x509 -in ./server-cert.pem -serial -noout > ../tests/x509/expect-server-serial.txt
openssl x509 -in ./server-cert.pem -dates -noout > ../tests/x509/expect-dates.txt
openssl x509 -in ./server-cert.pem -email -noout > ../tests/x509/expect-email.txt
openssl x509 -in ./server-cert.pem -fingerprint -noout | sed 's/^SHA1 Fingerprint=//' | tr -d ':' > ../tests/x509/expect-fingerprint.txt
openssl x509 -in ./server-cert.pem -hash -noout > ../tests/x509/expect-hash.txt

#Simply cannot make openssl purpose match wolfssl purpose programatically
../wolfssl x509 -in ./server-cert.pem -purpose -noout > ../tests/x509/expect-purpose.txt

echo "Recreate test signatures with new files, may take some time..."
cd ../tests/dgst/
./create-test-sigs.sh
cd ../../certs

echo "Done"
exit 0
