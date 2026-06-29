/* clu_dgst_setup.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#include <wolfclu/clu_error_codes.h>
#include <wolfclu/clu_header_main.h>
#include <wolfclu/clu_log.h>
#include <wolfclu/clu_optargs.h>
#include <wolfclu/sign-verify/clu_sign.h>
#include <wolfclu/sign-verify/clu_verify.h>
#include <wolfclu/sign-verify/clu_sign_verify_setup.h>
#include <wolfclu/pkey/clu_pkey.h>
#include <wolfclu/x509/clu_cert.h>    /* PER_FORM/DER_FORM */
#include <wolfssl/openssl/bio.h>
#include <wolfssl/openssl/compat_types.h>
#include <wolfssl/openssl/hmac.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifndef WOLFCLU_NO_FILESYSTEM

static const struct option dgst_options[] = {

    {"-md5",       no_argument,       0, WOLFCLU_MD5        },
    {"-sha",       no_argument,       0, WOLFCLU_CERT_SHA   },
    {"-sha224",    no_argument,       0, WOLFCLU_CERT_SHA224},
    {"-sha256",    no_argument,       0, WOLFCLU_CERT_SHA256},
    {"-sha384",    no_argument,       0, WOLFCLU_CERT_SHA384},
    {"-sha512",    no_argument,       0, WOLFCLU_CERT_SHA512},

    {"-hmac",     no_argument      , 0, WOLFCLU_HMAC       },
    {"-mackey",   required_argument, 0, WOLFCLU_HMAC_KEY   },

    {"-inform",    required_argument, 0, WOLFCLU_INFORM    },
    {"-out",       required_argument, 0, WOLFCLU_OUTFILE   },
    {"-signature", required_argument, 0, WOLFCLU_INFILE    },
    {"-verify",    required_argument, 0, WOLFCLU_VERIFY    },
    {"-sign",     required_argument, 0, WOLFCLU_SIGN      },
    {"-h",        no_argument,       0, WOLFCLU_HELP      },
    {"-help",     no_argument,       0, WOLFCLU_HELP      },

    {0, 0, 0, 0} /* terminal element */
};


static void wolfCLU_dgstHelp(void)
{
    WOLFCLU_LOG(WOLFCLU_L0, "dgst: (Data can be passed in via stdin or via "
        "a file as the last argument)");
    WOLFCLU_LOG(WOLFCLU_L0, "Hash algos supported:");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-md5");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-sha");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-sha224");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-sha256");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-sha384");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-sha512");
    WOLFCLU_LOG(WOLFCLU_L0, "General Parameters:");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-out    output file for signature\n");
    WOLFCLU_LOG(WOLFCLU_L0, "Parameters sign/verify:");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-signature file containing the signature");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-inform pem or der in format");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-verify key used to verify the signature");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-sign   private key used to create the "
                                        "signature\n");

    WOLFCLU_LOG(WOLFCLU_L0, "Parameters hmac:");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-hmac       Must be passed to enable hmac "
                                            "functionality");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-mackey     key:value for plain text "
                                        "hexkey:value to have value encoded\n");


    WOLFCLU_LOG(WOLFCLU_L0, "Example sign/verify:");
    WOLFCLU_LOG(WOLFCLU_L0, "\twolfssl dgst -signature test.sig -verify key.pem test");
    WOLFCLU_LOG(WOLFCLU_L0, "Example hmac:");
    WOLFCLU_LOG(WOLFCLU_L0, "\twolfssl dgst -sha256 -hmac -mackey "
            "hexkey:0b0b0b0b0b0b0b inputfile.txt");
}


/* return WOLFCLU_SUCCESS on success */
static int ExtractKey(void* key, WOLFSSL_EVP_PKEY* pkey, int* keySz,
        enum wc_SignatureType* sigType, int signing)
{
    ecc_key* ecc = NULL;
    RsaKey*  rsa = NULL;
    byte* der = NULL;
    int   derSz = 0;
    int ret = WOLFCLU_SUCCESS;
    word32 idx = 0;

    if (signing == 0) { /* expecting public key */
        derSz = wolfCLU_pKeytoPubKey(pkey, &der);
    }
    else { /* expecting private key */
        derSz = wolfCLU_pKeytoPriKey(pkey, &der);
    }
    if (derSz <= 0) {
        wolfCLU_LogError("Unable to extract der key");
        ret = WOLFCLU_FATAL_ERROR;
    }

    switch (wolfSSL_EVP_PKEY_id(pkey)) {
        case EVP_PKEY_RSA:
            *keySz   = (int)sizeof(RsaKey);
            *sigType = WC_SIGNATURE_TYPE_RSA_W_ENC;
            rsa = (RsaKey*)key;

            if (wc_InitRsaKey(rsa, NULL) != 0) {
                wolfCLU_LogError("Unable to initialize rsa key");
                ret = WOLFCLU_FATAL_ERROR;
            }

            /* expecting public key */
            if (ret == WOLFCLU_SUCCESS && signing == 0 &&
                    wc_RsaPublicKeyDecode(der, &idx, rsa, derSz) != 0) {
                wolfCLU_LogError("Error decoding public rsa key");
                ret = WOLFCLU_FATAL_ERROR;
            }

            /* expecting private key */
            if (ret == WOLFCLU_SUCCESS && signing == 1 &&
                    wc_RsaPrivateKeyDecode(der, &idx, rsa, derSz) != 0) {
                wolfCLU_LogError("Error decoding public rsa key");
                ret = WOLFCLU_FATAL_ERROR;
            }
            break;

        case EVP_PKEY_EC:
            *keySz   = (int)sizeof(ecc_key);
            *sigType = WC_SIGNATURE_TYPE_ECC;
            ecc = (ecc_key*)key;

            if (wc_ecc_init(ecc) != 0) {
                wolfCLU_LogError("Error initializing ecc key");
                ret = WOLFCLU_FATAL_ERROR;
            }

            /* expecting public key */
            if (ret == WOLFCLU_SUCCESS && signing == 0 &&
                    wc_EccPublicKeyDecode(der, &idx, ecc, derSz) != 0) {
                wolfCLU_LogError("Error decoding public ecc key");
                ret = WOLFCLU_FATAL_ERROR;
            }

            /* expecting private key */
            if (ret == WOLFCLU_SUCCESS && signing == 1 &&
                    wc_EccPrivateKeyDecode(der, &idx, ecc, derSz) != 0) {
                wolfCLU_LogError("Error decoding private ecc key");
                ret = WOLFCLU_FATAL_ERROR;
            }
            break;

        default:
            wolfCLU_LogError("Key type not yet supported");
            ret = WOLFCLU_FATAL_ERROR;
    }

    if (der != NULL)
        XFREE(der, NULL, DYNAMIC_TYPE_OPENSSL);

    return ret;
}


/* compute an HMAC over the data in dataBio and output the resulting MAC. When
 * outFile is set the raw MAC bytes are written there, otherwise the MAC is
 * printed to stdout as hex.
 * return WOLFCLU_SUCCESS on success */
static int wolfCLU_dgstHmac(WOLFSSL_BIO* dataBio, char* hmacKey,
        enum wc_HashType hashType, char* outFile)
{
    WOLFSSL_HMAC_CTX* hmacCtx = NULL;
    byte digest[WC_MAX_DIGEST_SIZE];
    word32 digestSz = sizeof(digest);
    byte*  keyBin = NULL;
    word32 keyBinSz = 0;
    int ret = WOLFCLU_SUCCESS;
    char* macKeyVal= NULL;
    char* sep;
    byte hex = 0;

    if (hmacKey == NULL) {
        wolfCLU_LogError("No HMAC key provided");
        return WOLFCLU_FATAL_ERROR;
    }

    /* Split the key on the FIRST ':' only, so a plaintext value may itself
     * contain ':' (matching OpenSSL's key:/hexkey: forms). Everything before
     * the colon is the type, everything after is the verbatim value. */
    sep = XSTRSTR(hmacKey, ":");
    if (sep == NULL) {
        wolfCLU_LogError("Malformed Hmac key %s", hmacKey);
        ret = WOLFCLU_FATAL_ERROR;
    }
    else {
        macKeyVal = sep + 1; /* value is the remainder, ':' included */

        if (XSTRNCMP(hmacKey, "hexkey:", 7) == 0) {
            hex = 1;
        }
        else if (XSTRNCMP(hmacKey, "key:", 4) != 0) {
            wolfCLU_LogError("Invalid key type must be 'hexkey' or "
                    "'key' %s", hmacKey);
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* an empty value (e.g. "key:") is not a usable key */
    if (ret == WOLFCLU_SUCCESS && *macKeyVal == '\0') {
        wolfCLU_LogError("No HMAC key value provided after '%s:'", hmacKey);
        ret = WOLFCLU_FATAL_ERROR;
    }

    /* The key is supplied as a hex string (matching OpenSSL's "hexkey:"
     * form), so decode it to raw bytes before keying the HMAC. Using the
     * ASCII text directly would key with the wrong bytes and length. */
    if (ret == WOLFCLU_SUCCESS) {
        if (hex) {
            ret = wolfCLU_hexToBin(macKeyVal, &keyBin, &keyBinSz,
                    NULL, NULL, NULL,
                    NULL, NULL, NULL,
                    NULL, NULL, NULL);
            if (ret != WOLFCLU_SUCCESS) {
                wolfCLU_LogError("Invalid hex key value passed to -mackey %s",
                        macKeyVal);
            }
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        hmacCtx = wolfSSL_HMAC_CTX_new();
        if (hmacCtx == NULL) {
            wolfCLU_LogError("Unable to create HMAC context");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        if (keyBin != NULL) {
            ret = wolfCLU_hmacHash(hmacCtx, keyBin, keyBinSz, hashType, dataBio,
                    digest, &digestSz);
        }
        else {
            ret = wolfCLU_hmacHash(hmacCtx, macKeyVal,
                    (word32)XSTRLEN(macKeyVal),
                    hashType, dataBio, digest, &digestSz);
        }
    }

    /* output the resulting MAC */
    if (ret == WOLFCLU_SUCCESS) {
        WOLFSSL_BIO* outBio = NULL;

        if (outFile != NULL) {
            outBio = wolfSSL_BIO_new_file(outFile, "wb");
        }
        else {
            outBio = wolfSSL_BIO_new_fp(stdout, WOLFSSL_BIO_NOCLOSE);
        }

        if (outBio == NULL) {
            wolfCLU_LogError("Unable to open output for HMAC");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            if (outFile != NULL) {
                if (wolfSSL_BIO_write(outBio, digest, digestSz) <= 0) {
                    wolfCLU_LogError("Error writing out HMAC");
                    ret = WOLFCLU_FATAL_ERROR;
                }
            }
            else {
                word32 i;
                for (i = 0; i < digestSz; i++)
                    wolfSSL_BIO_printf(outBio, "%02x", digest[i]);
                wolfSSL_BIO_printf(outBio, "\n");
            }
        }
        if (outBio != NULL) {
            wolfSSL_BIO_free(outBio);
        }
    }

    /* clean up */
    if (hmacCtx != NULL) {
        wolfSSL_HMAC_CTX_cleanup(hmacCtx);
        wolfSSL_HMAC_CTX_free(hmacCtx);
    }
    /* wolfCLU_hexToBin allocates keyBin with a NULL heap hint; zero the
     * key material and free it with the matching hint. */
    if (keyBin != NULL) {
        wc_ForceZero(keyBin, keyBinSz);
        XFREE(keyBin, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    return ret;
}


/* create or verify a signature over the data in dataBio using the key in
 * pubKeyBio. When signing the signature is written to outFile, otherwise the
 * signature is read from sigFile and verified.
 * return WOLFCLU_SUCCESS on success */
static int wolfCLU_dgstSignVerify(WOLFSSL_BIO* dataBio, WOLFSSL_BIO* pubKeyBio,
        char* sigFile, char* outFile, enum wc_HashType hashType, int inForm,
        byte signing)
{
    ecc_key ecc;
    RsaKey  rsa;
    WOLFSSL_BIO* sigBio = NULL;
    WOLFSSL_EVP_PKEY* pkey = NULL;
    void* key  = NULL;
    byte* sig  = NULL;
    byte digest[MAX_DER_DIGEST_SZ];
    word32 digestSz = 0;
    word32 sigSz  = 0;
    int keySz  = 0;
    int ret = WOLFCLU_SUCCESS;
    enum wc_SignatureType sigType = WC_SIGNATURE_TYPE_NONE;

    XMEMSET(&ecc, 0, sizeof(ecc));
    XMEMSET(&rsa, 0, sizeof(rsa));

    /* Stream the data file through a hash to produce a digest, then pass
     * the digest to wc_Signature{Generate,Verify}Hash below. */
    if (ret == WOLFCLU_SUCCESS) {
        digestSz = MAX_DER_DIGEST_SZ;
        ret = wolfCLU_streamHashBio(dataBio, hashType, digest, &digestSz);
    }

    if (ret == WOLFCLU_SUCCESS && signing == 0) {
        sigBio = wolfSSL_BIO_new_file(sigFile, "rb");

        if (sigBio == NULL) {
            wolfCLU_LogError("Unable to read signature file %s", sigFile);
            ret = WOLFCLU_FATAL_ERROR;
        }

        if (ret == WOLFCLU_SUCCESS) {
            ret = wolfSSL_BIO_get_len(sigBio);
            if (ret <= 0) {
                wolfCLU_LogError("Unable to get signature size");
                ret = WOLFCLU_FATAL_ERROR;
            }
            else {
                sigSz = (word32)ret;
                ret = WOLFCLU_SUCCESS;
            }
        }
    }

    if (ret == WOLFCLU_SUCCESS && signing == 0) {
        sig = (byte*)XMALLOC(sigSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (sig == NULL) {
            ret = MEMORY_E;
        }
        else {
            if (wolfSSL_BIO_read(sigBio, sig, sigSz) <= 0) {
                wolfCLU_LogError("Error reading sig");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
    }

    /* get type of key and size of structure */
    if (ret == WOLFCLU_SUCCESS && signing == 0) {
        if (inForm == PEM_FORM) {
            pkey = wolfSSL_PEM_read_bio_PUBKEY(pubKeyBio, NULL, NULL, NULL);
        }
        else {
            pkey = wolfSSL_d2i_PUBKEY_bio(pubKeyBio, NULL);
        }

        if (pkey == NULL) {
            wolfCLU_LogError("Unable to decode public key");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS && signing == 1) {
        if (inForm == PEM_FORM) {
            pkey = wolfSSL_PEM_read_bio_PrivateKey(pubKeyBio, NULL, NULL, NULL);
        }
        else {
            pkey = wolfSSL_d2i_PrivateKey_bio(pubKeyBio, NULL);
        }
        if (pkey == NULL) {
            wolfCLU_LogError("Unable to decode private key");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        switch (wolfSSL_EVP_PKEY_id(pkey)) {
            case EVP_PKEY_RSA:
                key = (void*)&rsa;
                break;

            case EVP_PKEY_EC:
                key = (void*)&ecc;
                break;
        }

        if (ExtractKey(key, pkey, &keySz, &sigType, signing) !=
                WOLFCLU_SUCCESS) {
            wolfCLU_LogError("Unable to extract key");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* For RSA with PKCS#1 v1.5 encoding, wc_Signature{Generate,Verify}Hash
     * expect the digest already wrapped in DER. The non-Hash variants did
     * this internally. ECC signs the raw digest, so no wrap. */
#ifndef NO_RSA
    if (ret == WOLFCLU_SUCCESS && sigType == WC_SIGNATURE_TYPE_RSA_W_ENC) {
        int oid = wc_HashGetOID(hashType);
        word32 enc;
        if (oid < 0) {
            wolfCLU_LogError("Unable to get hash OID for DER encoding");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            byte encodedDigest[MAX_DER_DIGEST_SZ + 256];
            enc = wc_EncodeSignature(encodedDigest, digest, digestSz, oid);
            if (enc == 0 || enc > (word32)MAX_DER_DIGEST_SZ) {
                wolfCLU_LogError("Unable to DER-encode digest");
                ret = WOLFCLU_FATAL_ERROR;
            }
            else {
                XMEMCPY(digest, encodedDigest, enc); /* copy before zero */
                digestSz = enc;
                wc_ForceZero(digest + enc, (word32)MAX_DER_DIGEST_SZ - enc);
            }
            wc_ForceZero(encodedDigest, sizeof(encodedDigest));
        }
    }
#endif

    /* if not signing then do verification */
    if (ret == WOLFCLU_SUCCESS && signing == 0) {
        int verifyRet = wc_SignatureVerifyHash(hashType, sigType,
                    digest, digestSz, (const byte*)sig, sigSz,
                    key, keySz);
        if (verifyRet == 0) {
            WOLFCLU_LOG(WOLFCLU_L0, "Verify OK");
        }
        else {
            wolfCLU_LogError("Verification failure");
            if (hashType == WC_HASH_TYPE_MD5 && verifyRet == BAD_FUNC_ARG) {
                WOLFCLU_LOG(WOLFCLU_L0,
                    "Note: MD5 below default min sig hash on wolfSSL > 5.9.1");
            }
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* create the signature if requested */
    if (ret == WOLFCLU_SUCCESS && signing == 1) {
        WC_RNG rng;
        XMEMSET(&rng, 0, sizeof(rng));

        if (wc_InitRng(&rng) != 0) {
            wolfCLU_LogError("Error initializing RNG");
            ret = WOLFCLU_FATAL_ERROR;
        }

        /* get expected signature size */
        if (ret == WOLFCLU_SUCCESS) {
            ret = wc_SignatureGetSize(sigType, key, keySz);
            if (ret <= 0) {
                wolfCLU_LogError("Error getting signature size");
                ret = WOLFCLU_FATAL_ERROR;
            }
            else {
                sigSz = (word32)ret;
                ret = WOLFCLU_SUCCESS;
            }
        }

        if (ret == WOLFCLU_SUCCESS) {
            sig = (byte*)XMALLOC(sigSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            if (sig == NULL) {
                ret = MEMORY_E;
            }
        }

        if (ret == WOLFCLU_SUCCESS) {
            int signRet = wc_SignatureGenerateHash(hashType, sigType,
                    digest, digestSz, sig, &sigSz, key, keySz, &rng);
            if (signRet != 0) {
                wolfCLU_LogError("Error getting signature");
                if (hashType == WC_HASH_TYPE_MD5 && signRet == BAD_FUNC_ARG) {
                    WOLFCLU_LOG(WOLFCLU_L0,
                        "Note: MD5 below default min sig hash on wolfSSL > 5.9.1");
                }
                ret = WOLFCLU_FATAL_ERROR;
            }
        }

        /* write out the signature */
        if (ret == WOLFCLU_SUCCESS) {
            sigBio = wolfSSL_BIO_new_file(outFile, "wb");
            if (sigBio == NULL) {
                wolfCLU_LogError("Unable to create signature file %s",
                        outFile);
                ret = WOLFCLU_FATAL_ERROR;
            }
        }

        if (ret == WOLFCLU_SUCCESS &&
                wolfSSL_BIO_write(sigBio, sig, sigSz) <= 0) {
            wolfCLU_LogError("Error writing out signature");
            ret = WOLFCLU_FATAL_ERROR;
        }
        wc_FreeRng(&rng);
    }

    /* if any key size has been set then try to free the key struct */
    if (keySz > 0) {
        switch (sigType) {
            case WC_SIGNATURE_TYPE_RSA:
            case WC_SIGNATURE_TYPE_RSA_W_ENC:
                wc_FreeRsaKey(&rsa);
                break;

            case WC_SIGNATURE_TYPE_ECC:
                wc_ecc_free(&ecc);
                break;

            case WC_SIGNATURE_TYPE_NONE:
                FALL_THROUGH;

            default:
                wolfCLU_LogError("Key type not yet supported");
                ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (sig != NULL)
        XFREE(sig, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

    wolfSSL_EVP_PKEY_free(pkey);
    wolfSSL_BIO_free(sigBio);
    return ret;
}
#endif /* !WOLFCLU_NO_FILESYSTEM */

/* return WOLFCLU_SUCCESS on success */
int wolfCLU_dgst_setup(int argc, char** argv)
{
#ifndef WOLFCLU_NO_FILESYSTEM
    WOLFSSL_BIO *pubKeyBio = NULL;
    WOLFSSL_BIO *dataBio = NULL;
    int     ret = WOLFCLU_SUCCESS;
    char* sigFile = NULL;
    char* outFile = NULL;
    int option;
    int longIndex = 2;
    byte signing = 0;
    byte hmac    = 0;
    char* hmacKey = NULL;
    int inForm = PEM_FORM;

    enum wc_HashType hashType = WC_HASH_TYPE_NONE;

    /* Last arg is input data if there otherwise we look at stdin */
    if ((XSTRNCMP("-h", argv[argc-1], 2) == 0 && argv[argc-1][2] == '\0') ||
            (XSTRNCMP("-help", argv[argc-1], 5) == 0
             && argv[argc-1][5] == '\0')) {
        wolfCLU_dgstHelp();
        return WOLFCLU_SUCCESS;
    }
    else {
        /* check that last arg file is unique and not a flag or flag arg */
        char* lastArg = argv[argc-1];
        int isPositional = 1;
        int j;

        for (j = 0; dgst_options[j].name != NULL; j++) {
            if (XSTRCMP(lastArg, dgst_options[j].name) == 0) {
                isPositional = 0; /* last token is itself an option */
                break;
            }
            if (argc >= 2 && dgst_options[j].has_arg == required_argument &&
                    XSTRCMP(argv[argc-2], dgst_options[j].name) == 0) {
                isPositional = 0; /* last token is that option's value */
                break;
            }
        }

        if (isPositional) {
            dataBio = wolfSSL_BIO_new_file(lastArg, "rb");
            if (dataBio == NULL) {
                wolfCLU_LogError("Unable to open data file %s", lastArg);
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
        else {
            dataBio = wolfSSL_BIO_new_fp(stdin, WOLFSSL_BIO_NOCLOSE);
        }
    }

    opterr = 0; /* do not display unrecognized options */
    optind = 0; /* start at indent 0 */
    while ((option = wolfCLU_GetOpt(argc, argv, "",
                   dgst_options, &longIndex )) != -1) {

        switch (option) {

            case WOLFCLU_MD5:
                hashType = WC_HASH_TYPE_MD5;
                break;

            case WOLFCLU_CERT_SHA:
                hashType = WC_HASH_TYPE_SHA;
                break;

            case WOLFCLU_CERT_SHA224:
                hashType = WC_HASH_TYPE_SHA224;
                break;

            case WOLFCLU_CERT_SHA256:
                hashType = WC_HASH_TYPE_SHA256;
                break;

            case WOLFCLU_CERT_SHA384:
                hashType = WC_HASH_TYPE_SHA384;
                break;

            case WOLFCLU_CERT_SHA512:
                hashType = WC_HASH_TYPE_SHA512;
                break;

            case WOLFCLU_HMAC:
                hmac = 1;
                break;

            case WOLFCLU_HMAC_KEY:
                if (optarg != NULL) {
                    hmacKey = optarg;
                }
                else {
                    wolfCLU_LogError("No Key passed to -mackey");
                    ret = WOLFCLU_FATAL_ERROR;
                }
                break;

            case WOLFCLU_SIGN:
                signing = 1;
                FALL_THROUGH;
            case WOLFCLU_VERIFY:
                pubKeyBio = wolfSSL_BIO_new_file(optarg, "rb");
                if (pubKeyBio == NULL) {
                    wolfCLU_LogError("Unable to open key file %s",
                            optarg);
                    ret = WOLFCLU_FATAL_ERROR;
                }
                break;

            case WOLFCLU_INFILE:
                sigFile = optarg;
                break;

            case WOLFCLU_OUTFILE:
                outFile = optarg;
                break;

            case WOLFCLU_INFORM:
                inForm = wolfCLU_checkInform(optarg);
                if (inForm < 0) {
                    wolfCLU_LogError("bad inform");
                    ret = USER_INPUT_ERROR;
                }
                break;

            case ':':
            case '?':
                break;

            default:
                /* do nothing. */
                (void)ret;
        }
    }

    if (ret == WOLFCLU_SUCCESS && dataBio == NULL) {
        wolfCLU_LogError("error with reading signature or data");
        ret = WOLFCLU_FATAL_ERROR;
    }

    /* the sign/verify paths need a file to read/write; validate before
     * dispatch so a NULL is never handed to wolfSSL_BIO_new_file/LogError.
     * Also check that we have a pubkey*/
    if (ret == WOLFCLU_SUCCESS && hmac == 0) {
        if (pubKeyBio == NULL) {
            wolfCLU_LogError("No key provided, use -sign <key> or -verify <key>");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else if (signing == 0 && sigFile == NULL) {
            wolfCLU_LogError("No signature file provided, use -signature");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else if (signing == 1 && outFile == NULL) {
            wolfCLU_LogError("No output file provided, use -out");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* dispatch to the HMAC or sign/verify handler */
    if (ret == WOLFCLU_SUCCESS) {
        if (hmac == 1) {
            ret = wolfCLU_dgstHmac(dataBio, hmacKey, hashType, outFile);
        }
        else {
            ret = wolfCLU_dgstSignVerify(dataBio, pubKeyBio, sigFile, outFile,
                    hashType, inForm, signing);
        }
    }

    wolfSSL_BIO_free(pubKeyBio);
    wolfSSL_BIO_free(dataBio);

    return ret;
#else
    (void)argc;
    (void)argv;
    WOLFCLU_LOG(WOLFCLU_E0, "No filesystem support");
    return WOLFCLU_FATAL_ERROR;
#endif
}

