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

static struct option pkey_options[] = {
    {"in",        required_argument, 0, WOLFCLU_INFILE    },
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
    WOLFCLU_LOG(WOLFCLU_L0, "\t-pubout output the public key");
}


/* print out PEM public key
 * returns 0 on success other return values are considered 'not success'
 */
static int wolfCLU_pKeyPEMtoPubKey(WOLFSSL_BIO* bio, WOLFSSL_EVP_PKEY* pkey)
{
    int type;
    int ret = WOLFSSL_FAILURE;

    type = wolfSSL_EVP_PKEY_id(pkey);
    switch (type) {
        case EVP_PKEY_RSA:
            ret = wolfSSL_PEM_write_bio_RSA_PUBKEY(bio,
                    wolfSSL_EVP_PKEY_get0_RSA(pkey));
            break;
        case EVP_PKEY_EC:
            ret = wolfSSL_PEM_write_bio_EC_PUBKEY(bio,
                    wolfSSL_EVP_PKEY_get0_EC_KEY(pkey));
            break;
        case EVP_PKEY_DSA:
            FALL_THROUGH;
        default:
            WOLFCLU_LOG(WOLFCLU_L0, "unknown / unsupported key type");
    }

    if (ret == WOLFSSL_SUCCESS) {
        return 0;
    }
    else {
        return FATAL_ERROR;
    }
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
            WOLFCLU_LOG(WOLFCLU_L0, "DSA key not yet supported");
            ret = USER_INPUT_ERROR;
            break;

        case EVP_PKEY_EC:
            {
                int derSz = 0;
                unsigned char *der = NULL;
                WOLFSSL_EC_KEY *ec = NULL;

                ec = wolfSSL_EVP_PKEY_get0_EC_KEY(pkey);
                if (ec == NULL) {
                    WOLFCLU_LOG(WOLFCLU_L0, "no ecc key found in pkey");
                    ret = BAD_FUNC_ARG;
                }

                if (ret == 0) {
                    derSz = wc_EccPublicKeyDerSize((ecc_key*)ec->internal, 1);
                    if (derSz < 0) {
                        WOLFCLU_LOG(WOLFCLU_L0, "unable to get ecc der size");
                        ret = BAD_FUNC_ARG;
                    }
                }

                if (ret == 0) {
                     der = (unsigned char*)XMALLOC(derSz, HEAP_HINT,
                             DYNAMIC_TYPE_TMP_BUFFER);
                     if (der == NULL) {
                         WOLFCLU_LOG(WOLFCLU_L0, "unable to malloc der buffer");
                         ret = MEMORY_E;
                     }
                }

                if (ret == 0) {
                     ret = wc_EccPublicKeyToDer((ecc_key*)ec->internal, der,
                             derSz, 1);
                     if (ret > 0) {
                         ret    = derSz;
                         *out   = der;
                     }
                     else {
                        ret = BAD_FUNC_ARG;
                        WOLFCLU_LOG(WOLFCLU_L0, "decoding der from internal structure failed");
                     }
                }

                if (der != NULL)
                    XFREE(der, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            }
            break;

        default:
            WOLFCLU_LOG(WOLFCLU_L0, "unknown / unsupported key type");
            ret = USER_INPUT_ERROR;
    }

    return ret;
}


int wolfCLU_pKeySetup(int argc, char** argv)
{
    int ret    = 0;
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
                    WOLFCLU_LOG(WOLFCLU_L0, "unable to open public key file %s", optarg);
                    ret = FATAL_ERROR;
                }
                break;

            case WOLFCLU_INFORM:
                inForm = wolfCLU_checkInform(optarg);
                break;

            case WOLFCLU_HELP:
                wolfCLU_pKeyHelp();
                return 0;

            case ':':
            case '?':
                break;

            default:
                /* do nothing. */
                (void)ret;
        }
    }


    if (ret == 0 && bioIn != NULL) {
        if (inForm == PEM_FORM) {
            pkey = wolfSSL_PEM_read_bio_PrivateKey(bioIn, NULL, NULL, NULL);
        }
        else {
            pkey = wolfSSL_d2i_PrivateKey_bio(bioIn, NULL);
        }
        if (pkey == NULL) {
            WOLFCLU_LOG(WOLFCLU_L0, "error reading key from file");
            ret = USER_INPUT_ERROR;
        }
    }

    if (ret == 0) {
        bioOut = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
        if (bioOut == NULL) {
            ret = FATAL_ERROR;
        }
        else {
            if (wolfSSL_BIO_set_fp(bioOut, stdout, BIO_NOCLOSE)
                    != WOLFSSL_SUCCESS) {
                ret = FATAL_ERROR;
            }
        }
    }

    if (ret == 0 && pubOut == 1) {
        if (pkey != NULL) {
            if (inForm == PEM_FORM) {
                ret = wolfCLU_pKeyPEMtoPubKey(bioOut, pkey);
                if (ret != 0) {
                    WOLFCLU_LOG(WOLFCLU_L0, "error getting pubkey from pem key");
                }
            }
            else {
                unsigned char *der = NULL;
                int derSz = 0;

                if ((derSz = wolfCLU_pKeytoPubKey(pkey, &der)) <= 0) {
                    WOLFCLU_LOG(WOLFCLU_L0, "error converting der found to public key");
                    ret = FATAL_ERROR;
                }
                else {
                    if (wolfCLU_printDerPubKey(bioOut, der, derSz) != 0) {
                        WOLFCLU_LOG(WOLFCLU_L0, "error printing out pubkey");
                        ret = FATAL_ERROR;
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



