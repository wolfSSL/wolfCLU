#ifndef _WIN_USER_SETTINGS_H_
#define _WIN_USER_SETTINGS_H_

/* Verify this is Windows */
#ifndef _WIN32
#error This user_settings.h header is only designed for Windows
#endif

#define WC_RSA_BLINDING
#define NO_MULTIBYTE_PRINT
#define WC_NO_HARDEN

/* wolfSSL's default Windows XINET_PTON casts to PCWSTR which breaks
 * with narrow char* strings.  Use the narrow-string InetPtonA instead. */
#define XINET_PTON(a,b,c) InetPtonA((a),(b),(c))

#define WOLFSSL_KEY_GEN
#define WOLFSSL_CERT_GEN
#define WOLFSSL_CERT_REQ
#define WOLFSSL_CERT_EXT
#define HAVE_ECC
#define HAVE_DH
#define HAVE_ED25519
#define WOLFSSL_AES_COUNTER
#define WOLFSSL_AES_DIRECT
#define HAVE_AESGCM
#define HAVE_CAMELLIA
#define WOLFSSL_SHA224
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512

#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE128
#define WOLFSSL_SHAKE256
#define HAVE_DILITHIUM
#define WOLFSSL_WC_DILITHIUM
#define WOLFSSL_EXPERIMENTAL_SETTINGS
#define WOLFSSL_DUAL_ALG_CERTS

#define HAVE_TLS_EXTENSIONS
#define HAVE_SNI
#define WOLFSSL_TLS13
#define HAVE_HKDF
#define WC_RSA_PSS
#define HAVE_SUPPORTED_CURVES
#define HAVE_FFDHE_2048
#define OPENSSL_ALL
#define OPENSSL_EXTRA
#define HAVE_PKCS7
#define HAVE_PKCS12
#define HAVE_CRL
#define HAVE_OCSP
#define HAVE_OCSP_RESPONDER

#endif /* _WIN_USER_SETTINGS_H_ */
