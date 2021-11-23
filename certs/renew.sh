

if [ -z $1 ]; then
    echo "run with path to certs <./renew.sh /path/to/wolfssl/certs>"
    exit 1
fi


CERTS_DIR=$1

echo "Creating CRL test certificates and chains"
cat $CERTS_DIR/crl/crl.pem $CERTS_DIR/ca-cert.pem > crl-chain.pem
cp  $CERTS_DIR/server-revoked-cert.pem .

echo "Copy over test certificates and chains"
cp  $CERTS_DIR/server-cert.pem .
cp  $CERTS_DIR/server-ecc.pem .
cp  $CERTS_DIR/ca-cert.pem .
cp  $CERTS_DIR/ca-ecc-cert.pem .

echo "Copy over pkcs12 test bundles"
cp  $CERTS_DIR/test-servercert.p12 .

echo "Done"
exit 0
