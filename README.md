# wolfCLU

This is the wolfSSL Command Line Utility (wolfCLU).

## wolfSSL Installation

Configure and install wolfSSL with the following commands:

```
./autogen.sh # only needed if source pulled from GitHub
./configure --enable-wolfclu
make
make check
sudo make install
```

## wolfCLU Installation

After wolfSSL is installed, install wolfCLU from the wolfCLU root directory:

```
./autogen.sh # only needed if source pulled from GitHub
./configure
make
make check
sudo make install
```

If wolfSSL was recently installed run `sudo ldconfig` to update the linker cache.

Now, you should be able to use wolfCLU:

```
wolfssl -h
```

If everything worked, you should see the wolfCLU help message.

## Examples

### Base64

#### Encode

```
wolfssl -hash base64enc -in README.md > README_encrypted.md
```

#### Decode

```
wolfssl -hash base64dec -in README_encrypted.md
```

### X509

```
wolfssl -x509 -inform pem -in testing-certs/ca-cert.pem -outform der -out outputfilename.der
wolfssl -x509 -inform der -in testing-certs/ca-cert.der -outform pem -out outputfilename.pem
```

### RSA Signature Generation and Verification

#### Hash

```
wolfssl -hash sha256 -in README.md -out README.md.sha256
```

#### Sign

```
wolfssl -rsa -sign -inkey ../certs/client-key.der -in README.md.sha256  -out README.md.signed
```

#### Verify

```
wolfssl -rsa -verify -inkey ../certs/client-keyPub.der -sigfile README.md.signed -out README.md.verify -pubin
```

At this point, the contents of `README.md.sha256` and `README.md.verify` should be the same.

## Contacts

Please contact support@wolfssl.com with any questions or comments.

## License

Copyright (c) 2006-2021 wolfSSL Inc.
