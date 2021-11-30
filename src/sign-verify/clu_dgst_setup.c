/* clu_dgst_setup.c
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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

#include <wolfclu/clu_header_main.h>
#include <wolfclu/clu_log.h>
#include <wolfclu/clu_optargs.h>
#include <wolfclu/sign-verify/clu_sign.h>
#include <wolfclu/sign-verify/clu_verify.h>
#include <wolfclu/sign-verify/clu_sign_verify_setup.h>

static const struct option dgst_options[] = {

    {"md5",       no_argument,       0, WOLFCLU_MD5        },
    {"sha",       no_argument,       0, WOLFCLU_CERT_SHA   },
    {"sha224",    no_argument,       0, WOLFCLU_CERT_SHA224},
    {"sha256",    no_argument,       0, WOLFCLU_CERT_SHA256},
    {"sha384",    no_argument,       0, WOLFCLU_CERT_SHA384},
    {"sha512",    no_argument,       0, WOLFCLU_CERT_SHA512},

    {"signature", required_argument, 0, WOLFCLU_INFILE    },
    {"verify",    required_argument, 0, WOLFCLU_VERIFY    },
    {"h",        no_argument,       0, WOLFCLU_HELP      },
    {"help",     no_argument,       0, WOLFCLU_HELP      },

    {0, 0, 0, 0} /* terminal element */
};


static void wolfCLU_dgstHelp(void)
{
    WOLFCLU_LOG(WOLFCLU_L0, "dgst: (the last argument is the data that was signed)");
    WOLFCLU_LOG(WOLFCLU_L0, "Hash algos supported:");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-md5");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-sha");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-sha224");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-sha256");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-sha384");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-sha512");
    WOLFCLU_LOG(WOLFCLU_L0, "Parameters:");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-signature file containing the signature");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-verify key used to verify the signature");
    WOLFCLU_LOG(WOLFCLU_L0, "Example:");
    WOLFCLU_LOG(WOLFCLU_L0, "\twolfssl dgst -signature test.sig -verify key.pem test");
}


/* return WOLFCLU_SUCCESS on success */
int wolfCLU_dgst_setup(int argc, char** argv)
{
    WOLFSSL_BIO *sigBio = NULL;
    WOLFSSL_BIO *pubKeyBio = NULL;
    WOLFSSL_BIO *dataBio = NULL;
    WOLFSSL_EVP_PKEY *pkey;
    int     ret = WOLFCLU_SUCCESS;
    char* sig  = NULL;
    char* data = NULL;
    void* key  = NULL;
    int derSz  = 0;
    int dataSz = 0;
    int sigSz  = 0;
    int keySz  = 0;
    int option;
    int longIndex = 2;

    unsigned char* der = NULL;
    ecc_key ecc;
    RsaKey  rsa;
    word32 idx = 0;

    enum wc_HashType      hashType = WC_HASH_TYPE_NONE;
    enum wc_SignatureType sigType  = WC_SIGNATURE_TYPE_NONE;

    opterr = 0; /* do not display unrecognized options */
    optind = 0; /* start at indent 0 */
    while ((option = getopt_long_only(argc, argv, "",
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

            case WOLFCLU_VERIFY:
                pubKeyBio = wolfSSL_BIO_new_file(optarg, "rb");
                if (pubKeyBio == NULL) {
                    WOLFCLU_LOG(WOLFCLU_L0, "unable to open public key file %s", optarg);
                    ret = WOLFCLU_FATAL_ERROR;
                }
                break;

            case WOLFCLU_INFILE:
                sigBio = wolfSSL_BIO_new_file(optarg, "rb");
                if (sigBio == NULL) {
                    WOLFCLU_LOG(WOLFCLU_L0, "unable to signature file %s", optarg);
                    ret = WOLFCLU_FATAL_ERROR;
                }
                break;

            case WOLFCLU_HELP:
                wolfCLU_dgstHelp();
                return WOLFCLU_SUCCESS;

            case ':':
            case '?':
                break;

            default:
                /* do nothing. */
                (void)ret;
        }
    }

    /* signed file should be the last arg */
    if (ret == WOLFCLU_SUCCESS) {
        dataBio = wolfSSL_BIO_new_file(argv[argc-1], "rb");
        if (dataBio == NULL) {
            WOLFCLU_LOG(WOLFCLU_L0, "unable to open data file %s", argv[argc-1]);
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        if (dataBio == NULL || sigBio == NULL) {
            WOLFCLU_LOG(WOLFCLU_L0, "error with reading signature or data");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        dataSz = wolfSSL_BIO_get_len(dataBio);
        sigSz  = wolfSSL_BIO_get_len(sigBio);
        if (dataSz <= 0 || sigSz <= 0) {
            WOLFCLU_LOG(WOLFCLU_L0, "no signature or data");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* create buffers and fill them */
    if (ret == WOLFCLU_SUCCESS) {
        data = (char*)XMALLOC(dataSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (data == NULL) {
            ret = MEMORY_E;
        }
        else {
            if (wolfSSL_BIO_read(dataBio, data, dataSz) <= 0) {
                WOLFCLU_LOG(WOLFCLU_L0, "error reading data");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        sig = (char*)XMALLOC(sigSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (sig == NULL) {
            ret = MEMORY_E;
        }
        else {
            if (wolfSSL_BIO_read(sigBio, sig, sigSz) <= 0) {
                WOLFCLU_LOG(WOLFCLU_L0, "error reading sig");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
    }

    /* get type of key and size of structure */
    if (ret == WOLFCLU_SUCCESS) {
        pkey = wolfSSL_PEM_read_bio_PUBKEY(pubKeyBio, NULL, NULL, NULL);
        if (pkey == NULL) {
            WOLFCLU_LOG(WOLFCLU_L0, "unable to decode public key");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        switch (wolfSSL_EVP_PKEY_id(pkey)) {
            case EVP_PKEY_RSA:
                keySz   = sizeof(RsaKey);
                sigType = WC_SIGNATURE_TYPE_RSA_W_ENC;

                key = (void*)&rsa;
                if (wc_InitRsaKey(&rsa, NULL) != 0) {
                    WOLFCLU_LOG(WOLFCLU_L0, "unable to initialize rsa key");
                    ret = WOLFCLU_FATAL_ERROR;
                }

                if (ret == WOLFCLU_SUCCESS) {
                    derSz = wolfSSL_i2d_PUBKEY(pkey, &der);
                    if (derSz <= 0) {
                        WOLFCLU_LOG(WOLFCLU_L0, "error converting pkey to der");
                        ret = WOLFCLU_FATAL_ERROR;
                    }
                }

                if (ret == WOLFCLU_SUCCESS &&
                    wc_RsaPublicKeyDecode(der, &idx, &rsa, derSz) != 0) {
                    WOLFCLU_LOG(WOLFCLU_L0, "error decoding public rsa key");
                    ret = WOLFCLU_FATAL_ERROR;
                }

                break;

            case EVP_PKEY_EC:
                keySz   = sizeof(ecc_key);
                sigType = WC_SIGNATURE_TYPE_ECC;

                key = (void*)&ecc;
                if (wc_ecc_init(&ecc) != 0) {
                    WOLFCLU_LOG(WOLFCLU_L0, "error initializing ecc key");
                    ret = WOLFCLU_FATAL_ERROR;
                }

                if (ret == WOLFCLU_SUCCESS) {
                    derSz = wolfSSL_i2d_PUBKEY(pkey, &der);
                    if (derSz <= 0) {
                        WOLFCLU_LOG(WOLFCLU_L0, "error converting pkey to der");
                        ret = WOLFCLU_FATAL_ERROR;
                    }
                }

                if (ret == WOLFCLU_SUCCESS &&
                        wc_EccPublicKeyDecode(der, &idx, &ecc, derSz) != 0) {
                    WOLFCLU_LOG(WOLFCLU_L0, "error decoding public ecc key");
                    ret = WOLFCLU_FATAL_ERROR;
                }

                break;

            default:
                WOLFCLU_LOG(WOLFCLU_L0, "key type not yet supported");
                ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        if (wc_SignatureVerify(hashType, sigType, (const byte*)data, dataSz,
                    (const byte*)sig, sigSz, key, keySz) == 0) {
            WOLFCLU_LOG(WOLFCLU_L0, "Verify OK");
        }
        else {
            WOLFCLU_LOG(WOLFCLU_L0, "Verification failure");
            ret = WOLFCLU_FATAL_ERROR;
        }
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
                WOLFCLU_LOG(WOLFCLU_L0, "key type not yet supported");
                ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (data != NULL)
        XFREE(data, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (sig != NULL)
        XFREE(sig, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

    wolfSSL_BIO_free(sigBio);
    wolfSSL_BIO_free(pubKeyBio);
    wolfSSL_BIO_free(dataBio);

    return ret;
}

