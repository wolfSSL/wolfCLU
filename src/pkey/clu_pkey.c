/* clu_pkey_setup.c
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
#include <wolfclu/pkey/clu_pkey.h>
#include <wolfclu/x509/clu_cert.h>
#include <wolfclu/x509/clu_parse.h>

static const struct option pkey_options[] = {
    {"in",        required_argument, 0, WOLFCLU_INFILE    },
    {"out",       required_argument, 0, WOLFCLU_OUTFILE   },
    {"inform",    required_argument, 0, WOLFCLU_INFORM    },
    {"pubout",    no_argument,       0, WOLFCLU_PUBOUT    },
    {"help",      no_argument,       0, WOLFCLU_HELP      },
    {"h",         no_argument,       0, WOLFCLU_HELP      },

    {0, 0, 0, 0} /* terminal element */
};


static void wolfCLU_pKeyHelp(void)
{
    WOLFCLU_LOG(WOLFCLU_L0, "./wolfssl pkey");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-in file input for key to read");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-out file to output to (default stdout)");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-pubout output the public key");
}


/* helper function for ECC EVP_PKEY
 * return WOLFSSL_SUCCESS on success */
static int _ECCpKeyPEMtoKey(WOLFSSL_BIO* bio, WOLFSSL_EVP_PKEY* pkey,
        int isPrivate)
{
    int ret;
    WOLFSSL_EVP_PKEY *tmpPkey = NULL;
    WOLFSSL_EC_KEY *key;

    key = wolfSSL_EVP_PKEY_get0_EC_KEY(pkey);
    if (key == NULL) {
        unsigned char *der = NULL;
        int derSz;

        if (isPrivate) {
            derSz = wolfSSL_i2d_PrivateKey(pkey, &der);
        }
        else {
            derSz = wolfSSL_i2d_PublicKey(pkey, &der);
        }

        if (derSz >= 0) {
            if (isPrivate) {
                tmpPkey = wolfSSL_d2i_PrivateKey_EVP(NULL, &der, derSz);
            }
            else {
                const unsigned char *p = der;
                tmpPkey = wolfSSL_d2i_PUBKEY(NULL, &p, derSz);
            }

            key = wolfSSL_EVP_PKEY_get0_EC_KEY(tmpPkey);
        }

        if (der != NULL) {
            wolfCLU_ForceZero(der, derSz);
            XFREE(der, NULL, DYNAMIC_TYPE_OPENSSL);
        }
    }

    if (isPrivate) {
        ret = wolfSSL_PEM_write_bio_ECPrivateKey(bio, key, NULL, NULL, 0, NULL,
                NULL);
    }
    else {
        ret = wolfSSL_PEM_write_bio_EC_PUBKEY(bio, key);
    }

    if (tmpPkey != NULL) {
        wolfSSL_EVP_PKEY_free(tmpPkey);
    }

    return ret;
}


/* print out PEM public key
 * returns WOLFCLU_SUCCESS on success other return values are considered
 * 'not success'
 */
static int wolfCLU_pKeyPEMtoPubKey(WOLFSSL_BIO* bio, WOLFSSL_EVP_PKEY* pkey)
{
    int type;
    int ret = WOLFCLU_FAILURE;

    type = wolfSSL_EVP_PKEY_id(pkey);
    switch (type) {
        case EVP_PKEY_RSA:
            ret = wolfSSL_PEM_write_bio_RSA_PUBKEY(bio,
                    wolfSSL_EVP_PKEY_get0_RSA(pkey));
            break;
        case EVP_PKEY_EC:
            ret = _ECCpKeyPEMtoKey(bio, pkey, 0);
            break;

        case EVP_PKEY_DSA:
            FALL_THROUGH;
        default:
            WOLFCLU_LOG(WOLFCLU_E0, "unknown / unsupported key type");
    }

    if (ret == WOLFSSL_SUCCESS) {
        return WOLFCLU_SUCCESS;
    }
    else {
        return WOLFCLU_FATAL_ERROR;
    }
}


/* print out PEM private key
 * returns WOLFCLU_SUCCESS on success other return values are considered
 * 'not success'
 */
int wolfCLU_pKeyPEMtoPriKey(WOLFSSL_BIO* bio, WOLFSSL_EVP_PKEY* pkey)
{
    int type;
    int ret = WOLFCLU_FAILURE;

    type = wolfSSL_EVP_PKEY_id(pkey);
    switch (type) {
        case EVP_PKEY_RSA:
            ret = wolfSSL_PEM_write_bio_RSAPrivateKey(bio,
                    wolfSSL_EVP_PKEY_get0_RSA(pkey), NULL, NULL, 0, NULL, NULL);
            break;
        case EVP_PKEY_EC:
            ret = _ECCpKeyPEMtoKey(bio, pkey, 1);
            break;

        case EVP_PKEY_DSA:
            FALL_THROUGH;
        default:
            WOLFCLU_LOG(WOLFCLU_E0, "unknown / unsupported key type");
    }

    if (ret == WOLFSSL_SUCCESS) {
        return WOLFCLU_SUCCESS;
    }
    else {
        return WOLFCLU_FATAL_ERROR;
    }
}

/* return key size on success */
static int wolfCLU_pKeyToKeyECC(WOLFSSL_EVP_PKEY* pkey, unsigned char** out,
        int isPrivateKey)
{
    int ret   = 0;
    int derSz = 0;
    unsigned char *der = NULL;
    WOLFSSL_EC_KEY *ec = NULL;

    ec = wolfSSL_EVP_PKEY_get0_EC_KEY(pkey);
    if (ec == NULL) {
        WOLFCLU_LOG(WOLFCLU_E0, "No ecc key found in pkey");
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        if (isPrivateKey) {
            derSz = wc_EccKeyDerSize((ecc_key*)ec->internal, 1);
        }
        else {
            derSz = wc_EccPublicKeyDerSize((ecc_key*)ec->internal, 1);
        }

        if (derSz < 0) {
            WOLFCLU_LOG(WOLFCLU_E0, "Unable to get ecc der size");
            ret = BAD_FUNC_ARG;
        }
    }

    if (ret == 0) {
        der = (unsigned char*)XMALLOC(derSz, HEAP_HINT,
                DYNAMIC_TYPE_TMP_BUFFER);
        if (der == NULL) {
            WOLFCLU_LOG(WOLFCLU_E0, "Unable to malloc der buffer");
            ret = MEMORY_E;
        }
    }

    if (ret == 0) {
        if (isPrivateKey) {
            ret = wc_EccPrivateKeyToDer((ecc_key*)ec->internal, der, derSz);
        }
        else {
            ret = wc_EccPublicKeyToDer((ecc_key*)ec->internal, der, derSz, 1);

        }

        if (ret > 0) {
            ret    = derSz;
            *out   = der;
        }
        else {
            ret = BAD_FUNC_ARG;
            WOLFCLU_LOG(WOLFCLU_E0,
                    "Decoding der from internal structure failed");
        }
    }

    if (ret < 0 && der != NULL) {
        wolfCLU_ForceZero(der, derSz);
        XFREE(der, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        *out = NULL;
    }

    return ret;
}


/* creates an out buffer containing only the public key from the pkey
 * returns size of buffer on success
 */
static int wolfCLU_pKeytoPubKey(WOLFSSL_EVP_PKEY* pkey, unsigned char** out)
{
    int type;
    int ret = 0;

    type   = wolfSSL_EVP_PKEY_id(pkey);
    switch (type) {
        case EVP_PKEY_RSA:
            ret = wolfSSL_i2d_RSAPublicKey(
                    wolfSSL_EVP_PKEY_get0_RSA(pkey), out);
            break;

        case EVP_PKEY_DSA:
            WOLFCLU_LOG(WOLFCLU_E0, "DSA key not yet supported");
            ret = USER_INPUT_ERROR;
            break;

        case EVP_PKEY_EC:
            ret = wolfCLU_pKeyToKeyECC(pkey, out, 0);
            break;

        default:
            WOLFCLU_LOG(WOLFCLU_E0, "unknown / unsupported key type");
            ret = USER_INPUT_ERROR;
    }

    return ret;
}


/* creates an out buffer containing the private key from the pkey
 * returns size of buffer on success
 */
static int wolfCLU_pKeytoPriKey(WOLFSSL_EVP_PKEY* pkey, unsigned char** out)
{
    int type;
    int ret = 0;

    type   = wolfSSL_EVP_PKEY_id(pkey);
    switch (type) {
        case EVP_PKEY_RSA:
            ret = wolfSSL_i2d_RSAPrivateKey(
                    wolfSSL_EVP_PKEY_get0_RSA(pkey), out);
            break;

        case EVP_PKEY_DSA:
            WOLFCLU_LOG(WOLFCLU_E0, "DSA key not yet supported");
            ret = USER_INPUT_ERROR;
            break;

        case EVP_PKEY_EC:
            ret = wolfCLU_pKeyToKeyECC(pkey, out, 1);
            break;

        default:
            WOLFCLU_LOG(WOLFCLU_E0, "unknown / unsupported key type");
            ret = USER_INPUT_ERROR;
    }

    return ret;
}


int wolfCLU_pKeySetup(int argc, char** argv)
{
    int ret    = WOLFCLU_SUCCESS;
    int inForm = PEM_FORM;
    int pubOut = 0;
    int option;
    int longIndex = 1;
    WOLFSSL_EVP_PKEY *pkey = NULL;
    WOLFSSL_BIO *bioIn  = NULL;
    WOLFSSL_BIO *bioOut = NULL;

    opterr = 0; /* do not display unrecognized options */
    optind = 0; /* start at indent 0 */
    while ((option = getopt_long_only(argc, argv, "",
                   pkey_options, &longIndex )) != -1) {
        switch (option) {
            case WOLFCLU_PUBOUT:
                pubOut = 1;
                break;

            case WOLFCLU_INFILE:
                bioIn = wolfSSL_BIO_new_file(optarg, "rb");
                if (bioIn == NULL) {
                    WOLFCLU_LOG(WOLFCLU_E0, "Unable to open public key file %s",
                            optarg);
                    ret = WOLFCLU_FATAL_ERROR;
                }
                break;

            case WOLFCLU_OUTFILE:
                bioOut = wolfSSL_BIO_new_file(optarg, "wb");
                if (bioOut == NULL) {
                    WOLFCLU_LOG(WOLFCLU_E0, "Unable to open output file %s",
                            optarg);
                    ret = WOLFCLU_FATAL_ERROR;
                }
                break;

            case WOLFCLU_INFORM:
                inForm = wolfCLU_checkInform(optarg);
                break;

            case WOLFCLU_HELP:
                wolfCLU_pKeyHelp();
                return WOLFCLU_SUCCESS;

            case ':':
            case '?':
                break;

            default:
                /* do nothing. */
                (void)ret;
        }
    }


    if (ret == WOLFCLU_SUCCESS && bioIn != NULL) {
        if (inForm == PEM_FORM) {
            pkey = wolfSSL_PEM_read_bio_PrivateKey(bioIn, NULL, NULL, NULL);
        }
        else {
            pkey = wolfSSL_d2i_PrivateKey_bio(bioIn, NULL);
        }
        if (pkey == NULL) {
            WOLFCLU_LOG(WOLFCLU_E0, "Error reading key from file");
            ret = USER_INPUT_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS && bioOut == NULL) {
        bioOut = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
        if (bioOut == NULL) {
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            if (wolfSSL_BIO_set_fp(bioOut, stdout, BIO_NOCLOSE)
                    != WOLFSSL_SUCCESS) {
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
    }

    /* print out the public key only */
    if (ret == WOLFCLU_SUCCESS && pubOut == 1) {
        if (pkey != NULL) {
            if (inForm == PEM_FORM) {
                ret = wolfCLU_pKeyPEMtoPubKey(bioOut, pkey);
                if (ret != WOLFCLU_SUCCESS) {
                    WOLFCLU_LOG(WOLFCLU_E0,
                            "Error getting pubkey from pem key");
                }
            }
            else {
                unsigned char *der = NULL;
                int derSz = 0;

                if ((derSz = wolfCLU_pKeytoPubKey(pkey, &der)) <= 0) {
                    WOLFCLU_LOG(WOLFCLU_E0,
                            "Error converting der found to public key");
                    ret = WOLFCLU_FATAL_ERROR;
                }
                else {
                    if (wolfCLU_printDerPubKey(bioOut, der, derSz) !=
                            WOLFCLU_SUCCESS) {
                        WOLFCLU_LOG(WOLFCLU_E0, "Error printing out pubkey");
                        ret = WOLFCLU_FATAL_ERROR;
                    }
                    free(der);
                }
            }
        }
    }

    /* print out the private key */
    if (ret == WOLFCLU_SUCCESS && pubOut == 0) {
        if (pkey != NULL) {
            if (inForm == PEM_FORM) {
                ret = wolfCLU_pKeyPEMtoPriKey(bioOut, pkey);
                if (ret != WOLFCLU_SUCCESS) {
                    WOLFCLU_LOG(WOLFCLU_E0,
                            "Error getting pubkey from pem key");
                    ret = WOLFCLU_FATAL_ERROR;
                }
            }
            else {
                unsigned char *der = NULL;
                int derSz = 0;
                int keyType;

                switch (wolfSSL_EVP_PKEY_id(pkey)) {
                    case EVP_PKEY_RSA: keyType = RSA_TYPE; break;
                    case EVP_PKEY_DSA: keyType = DSA_TYPE; break;
                    case EVP_PKEY_EC:  keyType = ECC_TYPE; break;
                    default:
                        /* keep generic PRIVATEKEY_TYPE as type */
                        keyType = PRIVATEKEY_TYPE;
                }

                if ((derSz = wolfCLU_pKeytoPriKey(pkey, &der)) <= 0) {
                    WOLFCLU_LOG(WOLFCLU_E0,
                            "Error converting der found to public key");
                    ret = WOLFCLU_FATAL_ERROR;
                }
                else {
                    if (wolfCLU_printDerPriKey(bioOut, der, derSz, keyType) !=
                            WOLFCLU_SUCCESS) {
                        WOLFCLU_LOG(WOLFCLU_E0, "Error printing out pubkey");
                        ret = WOLFCLU_FATAL_ERROR;
                    }
                    free(der);
                }
            }
        }
    }

    wolfSSL_BIO_free(bioIn);
    wolfSSL_BIO_free(bioOut);
    wolfSSL_EVP_PKEY_free(pkey);

    return ret;
}

