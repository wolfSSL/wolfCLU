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

For instuctions on how to build windows, see [here](ide/winvs/README.md).

## Examples

### Key Generation

The command below generates an RSA public/private key pair in PEM form.
```
wolfssl genkey rsa -size 2048 -out mykey -outform pem -output KEY
```
Resulting files mykey.priv and mykey.pub can be seen below.
```
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAvCjQxgLC0QT3m2KCBRGF9inN3xKzTd9Aht2i3on5th1gFTmh
0X9M8MFoOnXrzAuTTq/rjR1OLJCBJkB029zoXkbGMN/D0KCXRNl1SRTH+Z5lL6ZG
88ckhMYoAk96FDZq83WCEL/UnAkL/U1IRSHmCzmQdYSMkO4+7upvipEjwe3yP1DN
w/Dx72fMRKagkbjAujETzVRn17kEe4uENBOX/hFPjjVf+7ie+AgY6UAxWaDt46IC
Y0c/PisP+aSj5+yLDGHcGOrgRIt4lJ8NQXvmQtyH6lfLomOobGJMbrAmy68fmCzR
y8lfaxS05SnsUIHulotxZgZ0ZFhPB7q8EAsRKQIDAQABAoIBAG8KV0rDzlyz5bwZ
gkmjcb84JHqE+rP2EIqGudtC6c8DvvRHsquDyNA8E1qMxL8CBcjmIMiChuPd05nT
aCNoVulsMwIcy96PJzZGbuTWEr3JMEXShwTOfUqt9maGqLDM/Ij4y+0+iCYdYKn3
tbK2sp/lNM9ljd7p+tHcID9SMBv9YIP3XwEPHxPDXcHEah5G9eNTOYpZvNCZf0pO
ShKTDfRi/DYm6gOYMca9hiJANoG7LfkcXRDpmPYC6wzJZSN0SBNn27I9A9JkwoPQ
/vLi9782TyNM/ncurFIiRi7vJho398WPNf0lOI+8kjvH9OPI87usYNjLAo3CXZS+
bow7kFECgYEA7tn2yrZHfoA526mWRkkf7I9B+c/7YA++8hyt2XiDPIGMsa78yae1
MBn9SgF/bAdYq/aazGMPKtENIF2vHEfEH9W5Kqgp9qW/emqvU9Rj6CDyznhXcwN8
uGIPow+uSN5bPysmFp/wjg8AM9SryRaVWgkykaLvhALcTVjH8Lwv8psCgYEAyask
4XO22NieX/v6v6uVwaVGH6Uo5uHNbu7p0SuvEQMXWEIQKB3vHdtR3XE6sH+E6rX3
5KgxqPzbodLXd2PV15VWwTTb+/jrJkWN9Ix0nbez4eP7MrSUJjtrXKk8+1VQKCPn
wbwsw1jsAj2DuDyqXbcnEY5t1rhY5z1JCE+89YsCgYA3Xw5IdjNizyUamFj/GEqv
U5Ku8BlNbrkMdbuT081QxJOySWfO8/McIJpIgspgZ9+VlgjS4xAMFASgATfsLXL5
Elnn2q5HwKsAHSViILW8hY7kcJ+NSTyrnggT/DmiKPIsVbtxuUhSFoYsfdwJNRQQ
mFtBye0OxH7/61oGpAnViwKBgF5lMXomA6w0mM0s0Q3ubsaZad1eHWsUvmfyhJdX
7zXzUHYLViyw9j/vbL5ORb5fsgN68XGiGLyUvulcG2bS4EFssZL1/xJOTSM4411Y
cS1x000kvWvago3yuipBPT4XjNF9HPnd7sXxVWcnDASswMHk/PCGznr3BwYV9Z1i
VXxJAoGAN6ZLY3Ol+CxSICNe5RZM7ZTs9GadgN7jSYqFUpZQX6nMZxaftNdhVIum
K9jchl6IVIZVOyNE0yX02oj1tUUruhC3pdSg8NQSVoYonNFvJwKzBOgVqJKsNjrF
I+sL/vVEOzji/VePapveVG5yGDiAT1FKg6MDHJ8U+H5j+Go3bmI=
-----END RSA PRIVATE KEY-----
```
```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvCjQxgLC0QT3m2KCBRGF
9inN3xKzTd9Aht2i3on5th1gFTmh0X9M8MFoOnXrzAuTTq/rjR1OLJCBJkB029zo
XkbGMN/D0KCXRNl1SRTH+Z5lL6ZG88ckhMYoAk96FDZq83WCEL/UnAkL/U1IRSHm
CzmQdYSMkO4+7upvipEjwe3yP1DNw/Dx72fMRKagkbjAujETzVRn17kEe4uENBOX
/hFPjjVf+7ie+AgY6UAxWaDt46ICY0c/PisP+aSj5+yLDGHcGOrgRIt4lJ8NQXvm
QtyH6lfLomOobGJMbrAmy68fmCzRy8lfaxS05SnsUIHulotxZgZ0ZFhPB7q8EAsR
KQIDAQAB
-----END PUBLIC KEY-----
```
### Certification Generation

This command generates an X509 certificate using the private key created above.
```
wolfssl req -new -days 3650 -key mykey.priv -out test.cert -x509
```
The resulting file test.cert can be seen below.
```
-----BEGIN CERTIFICATE-----
MIICiDCCAXCgAwIBAgIQUxgFCkVR/08kI3nA38BsLTANBgkqhkiG9w0BAQsFADAA
MB4XDTIyMDIxODIwMzUwMFoXDTMyMDIxNjIwMzUwMFowADCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBALwo0MYCwtEE95tiggURhfYpzd8Ss03fQIbdot6J
+bYdYBU5odF/TPDBaDp168wLk06v640dTiyQgSZAdNvc6F5GxjDfw9Cgl0TZdUkU
x/meZS+mRvPHJITGKAJPehQ2avN1ghC/1JwJC/1NSEUh5gs5kHWEjJDuPu7qb4qR
I8Ht8j9QzcPw8e9nzESmoJG4wLoxE81UZ9e5BHuLhDQTl/4RT441X/u4nvgIGOlA
MVmg7eOiAmNHPz4rD/mko+fsiwxh3Bjq4ESLeJSfDUF75kLch+pXy6JjqGxiTG6w
JsuvH5gs0cvJX2sUtOUp7FCB7paLcWYGdGRYTwe6vBALESkCAwEAATANBgkqhkiG
9w0BAQsFAAOCAQEAHHX+4PTg1nv8Bo0LgLqmx0YtG08Ye8IvPLRNIePSYRdVwToW
MRPOvUU2/VQ41ro+iqlvopb2wX+gNz2K89EU3PQ6tVXxj0JiVB7DpXm/8lMklf3v
0DGAJrvK3dEPbTvb71JG5qkwcBaS8jARKXOkuyW2D9yVSVKT/CkylpanRfXuU4NL
adaA+l398KpM0c0XT7Fl4ylSeZLLi5CSObu1kkPpYqjAGyI+y0EW79btz88U2QmB
uqGDApXWYuBdjheL4Ysoq6YXtt6dnm8DkBVrnt+gAMCBFbBNPXxy2MODBDqya907
iky6IRTUzkBy1fssv3Gr/jOsyN8J565NST3RpQ==
-----END CERTIFICATE-----
```
### DGST Sign and Verify

The commands below sign this README then verify it with the resulting signature.
```
wolfssl dgst -sha256 -sign mykey.priv -out readme.sig ./README.md
wolfssl dgst -sha256 -verify mykey.pub -signature readme.sig ./README.md
```

### Creating a Certificate Authority (CA) to sign other certificates using ECC signing/verification

The following demonstrates how to create a root CA and use it to sign other certificates. This example uses ECC, but steps are similar for RSA.

In this scenario there are three entities A, B, and C, where A is meant to function as a root CA. 

The following steps demonstrate how to generate keys and certificates for A, B, and C, where A is self-signed and B and C are signed by A

1. Create private ECC keys for A, B, and C (to create RSA keys instead use `wolfssl -genkey rsa`)
```
wolfssl -genkey ecc -out ecc-key-A -output priv -outform PEM
wolfssl -genkey ecc -out ecc-key-B -output priv -outform PEM
wolfssl -genkey ecc -out ecc-key-C -output priv -outform PEM
```

2. Create a self-signed certificate for A, which will function as our CA
```
wolfssl req -new -key ecc-key-A.priv -subj O=org-A/C=US/ST=WA/L=Seattle/CN=A/OU=org-unit-A -x509 -out A.cert -outform PEM
```

3. Create certificates for B and C signed by A
```
# first create a certificate signing request (CSR) for B and C
wolfssl req -new -key ecc-key-B.priv -subj O=org-B/C=US/ST=WA/L=Seattle/CN=B/OU=org-unit-B -out B.csr -outform PEM
wolfssl req -new -key ecc-key-C.priv -subj O=org-C/C=US/ST=WA/L=Seattle/CN=C/OU=org-unit-C -out C.csr -outform PEM

# now have our CA (A) sign the CSR's of B and C to generate their certificates
wolfssl ca -in B.csr -keyfile ecc-key-A.priv -cert A.cert -out B.cert
wolfssl ca -in C.csr -keyfile ecc-key-A.priv -cert A.cert -out C.cert
```

We can now verify certs B and C using our CA cert A using the following command:
```
wolfssl verify -CAfile A.cert B.cert
wolfssl verify -CAfile A.cert C.cert
```

## Contacts

Please contact support@wolfssl.com with any questions or comments.

## License

Copyright (c) 2006-2021 wolfSSL Inc.
