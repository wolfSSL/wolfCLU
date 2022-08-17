

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

echo "Additional update of client example source code"
cp $CERTS_DIR/../examples/client/client.c ../src/client/client.c
sed -i '' "s/examples\/client\//wolfclu\//" ../src/client/client.c

echo "Done"
exit 0
