/* clu_request_setup.c
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
#include <wolfclu/x509/clu_request.h>
#include <wolfclu/x509/clu_cert.h>
#include <wolfclu/certgen/clu_certgen.h>

static struct option req_options[] = {

    {"sha",       no_argument,       0, WOLFCLU_CERT_SHA   },
    {"sha224",    no_argument,       0, WOLFCLU_CERT_SHA224},
    {"sha256",    no_argument,       0, WOLFCLU_CERT_SHA256},
    {"sha384",    no_argument,       0, WOLFCLU_CERT_SHA384},
    {"sha512",    no_argument,       0, WOLFCLU_CERT_SHA512},
    {"rsa",       no_argument,       0, WOLFCLU_RSA       },
    {"ecc",       no_argument,       0, WOLFCLU_ECC       },
    {"ed25519",   no_argument,       0, WOLFCLU_ED25519   },

    {"in",        required_argument, 0, WOLFCLU_INFILE    },
    {"out",       required_argument, 0, WOLFCLU_OUTFILE   },
    {"key",       required_argument, 0, WOLFCLU_KEY       },
    {"new",       no_argument,       0, WOLFCLU_NEW       },
    {"inkey",     required_argument, 0, WOLFCLU_INKEY     },
    {"inform",    required_argument, 0, WOLFCLU_INFORM    },
    {"outform",   required_argument, 0, WOLFCLU_OUTFORM   },
    {"config",    required_argument, 0, WOLFCLU_CONFIG },
    {"days",      required_argument, 0, WOLFCLU_DAYS },
    {"x509",      no_argument,       0, WOLFCLU_X509 },

    {0, 0, 0, 0} /* terminal element */
};


/* return WOLFCLU_SUCCESS on success */
int wolfCLU_requestSetup(int argc, char** argv)
{
#ifndef WOLFSSL_CERT_REQ
    WOLFCLU_LOG(WOLFCLU_L0, "wolfSSL not compiled with --enable-certreq");
    return NOT_COMPILED_IN;
#else
    WOLFSSL_BIO *bioOut = NULL;
    WOLFSSL_BIO *bioIn  = NULL;
    WOLFSSL_X509 *x509  = NULL;
    const WOLFSSL_EVP_MD *md  = NULL;
    WOLFSSL_EVP_PKEY *pkey = NULL;

    int     ret = WOLFCLU_SUCCESS;
    char*   in  = NULL;
    char*   out = NULL;
    char*   config = NULL;

    int     algCheck =   0;     /* algorithm type */
    int     oid      =   0;
    int     outForm = PEM_FORM; /* default to PEM format */
    int     inForm;
    int     option;
    int     longIndex = 1;
    int     days = 0;
    int     genX509 = 0;


    opterr = 0; /* do not display unrecognized options */
    optind = 0; /* start at indent 0 */
    while ((option = getopt_long_only(argc, argv, "", req_options,
                    &longIndex )) != -1) {

        switch (option) {
            case WOLFCLU_INFILE:
            case WOLFCLU_KEY:
                in = optarg;
                bioIn = wolfSSL_BIO_new_file(optarg, "rb");
                if (bioIn == NULL) {
                    WOLFCLU_LOG(WOLFCLU_L0, "unable to open public key file %s", optarg);
                    ret = WOLFCLU_FATAL_ERROR;
                }
                break;

            case WOLFCLU_OUTFILE:
                out = optarg;
                bioOut = wolfSSL_BIO_new_file(optarg, "wb");
                if (bioOut == NULL) {
                    WOLFCLU_LOG(WOLFCLU_L0, "unable to open output file %s", optarg);
                    ret = WOLFCLU_FATAL_ERROR;
                }
                break;

            case WOLFCLU_INFORM:
                inForm = wolfCLU_checkInform(optarg);
                (void)inForm; /* for future use */
                break;

            case WOLFCLU_OUTFORM:
                outForm = wolfCLU_checkOutform(optarg);
                break;

            case WOLFCLU_HELP:
                wolfCLU_certgenHelp();
                return WOLFCLU_SUCCESS;

            case WOLFCLU_RSA:
                algCheck = 1;
                break;

            case WOLFCLU_ECC:
                algCheck = 3;
                break;

            case WOLFCLU_ED25519:
                algCheck = 2;
                break;

            case WOLFCLU_CONFIG:
                config = optarg;
                break;

            case WOLFCLU_DAYS:
                days = XATOI(optarg);
                break;

            case WOLFCLU_CERT_SHA:
                md  = wolfSSL_EVP_sha1();
                oid = SHA_HASH;
                break;

            case WOLFCLU_CERT_SHA224:
                md  = wolfSSL_EVP_sha224();
                oid = SHA_HASH224;
                break;

            case WOLFCLU_CERT_SHA256:
                md  = wolfSSL_EVP_sha256();
                oid = SHA_HASH256;
                break;

            case WOLFCLU_CERT_SHA384:
                md  = wolfSSL_EVP_sha384();
                oid = SHA_HASH384;
                break;

            case WOLFCLU_CERT_SHA512:
                md  = wolfSSL_EVP_sha512();
                oid = SHA_HASH512;
                break;

            case WOLFCLU_X509:
                genX509 = 1;
                break;

            case ':':
            case '?':
                break;

            default:
                /* do nothing. */
                (void)ret;
        }
    }

    /* default to sha256 if not set */
    if (md == NULL) {
        md  = wolfSSL_EVP_sha256();
        oid = SHA_HASH256;
    }

    x509 = wolfSSL_X509_new();
    if (x509 == NULL) {
        WOLFCLU_LOG(WOLFCLU_L0, "issue creating structure to use");
        ret = MEMORY_E;
    }

    if (ret == WOLFCLU_SUCCESS && days > 0) {
        WOLFSSL_ASN1_TIME *notBefore, *notAfter;
        time_t t;

        t = time(NULL);
        notBefore = wolfSSL_ASN1_TIME_adj(NULL, t, 0, 0);
        notAfter = wolfSSL_ASN1_TIME_adj(NULL, t, days, 0);
        if (notBefore == NULL || notAfter == NULL) {
            WOLFCLU_LOG(WOLFCLU_L0, "error creating not before/after dates");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            wolfSSL_X509_set_notBefore(x509, notBefore);
            wolfSSL_X509_set_notAfter(x509, notAfter);
        }

        wolfSSL_ASN1_TIME_free(notBefore);
        wolfSSL_ASN1_TIME_free(notAfter);
    }


    if (ret == WOLFCLU_SUCCESS && bioIn != NULL) {
        pkey = wolfSSL_PEM_read_bio_PrivateKey(bioIn, NULL, NULL, NULL);
        if (pkey == NULL) {
            WOLFCLU_LOG(WOLFCLU_L0, "error reading key from file");
            ret = USER_INPUT_ERROR;
        }

        if (ret == WOLFCLU_SUCCESS &&
                wolfSSL_X509_set_pubkey(x509, pkey) != WOLFSSL_SUCCESS) {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }
    else {
        WOLFCLU_LOG(WOLFCLU_L0, "Please specify a -key <key> option when "
               "generating a certificate.");
        wolfCLU_certgenHelp();
        ret = USER_INPUT_ERROR;
    }

    if (ret == WOLFCLU_SUCCESS) {
        if (config != NULL) {
            ret = wolfCLU_readConfig(x509, config, (char*)"req");
        }
        else {
            /* if no configure is passed in then get input from command line */
            WOLFSSL_X509_NAME *name;

            name = wolfSSL_X509_NAME_new();
            if (name == NULL) {
                ret = MEMORY_E;
            }
            else {
                wolfCLU_CreateX509Name(name);
                wolfSSL_X509_REQ_set_subject_name(x509, name);
            }
        }
    }

    if (ret == WOLFSSL_SUCCESS) {
        ret = wolfSSL_X509_set_version(x509, WOLFSSL_X509_V3);
    }

    if (ret == WOLFCLU_SUCCESS && bioOut == NULL) {
        /* output to stdout if no output is provided */
        bioOut = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
        if (bioOut != NULL) {
            if (wolfSSL_BIO_set_fp(bioOut, stdout, BIO_NOCLOSE)
                    != WOLFSSL_SUCCESS) {
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        if (algCheck == 3) {
            ret = make_self_signed_ecc_certificate(in, out, oid);
        }
        else {
            /* sign the req/cert */
            if (genX509) {
                ret = wolfSSL_X509_sign(x509, pkey, md);
                if (ret > 0)
                    ret = WOLFSSL_SUCCESS;
            }
            else {
                ret = wolfSSL_X509_REQ_sign(x509, pkey, md);
            }
            if (ret != WOLFSSL_SUCCESS) {
                WOLFCLU_LOG(WOLFCLU_L0, "error %d signing", ret);
            }

            if (ret == WOLFSSL_SUCCESS) {
                if (outForm == DER_FORM) {
                    if (genX509) {
                        ret = wolfSSL_i2d_X509_bio(bioOut, x509);
                    }
                    else {
                        ret = wolfSSL_i2d_X509_REQ_bio(bioOut, x509);
                    }
                }
                else {
                    if (genX509) {
                        ret = wolfSSL_PEM_write_bio_X509(bioOut, x509);
                    }
                    else {
                        ret = wolfSSL_PEM_write_bio_X509_REQ(bioOut, x509);
                    }
                }

                if (ret != WOLFSSL_SUCCESS) {
                    WOLFCLU_LOG(WOLFCLU_L0, "error %d writing out cert req", ret);
                    ret = WOLFCLU_FATAL_ERROR;
                }
                else {
                    /* set WOLFSSL_SUCCESS case to success value */
                    ret = WOLFCLU_SUCCESS;
                }
            }
        }
    }

    wolfSSL_BIO_free(bioIn);
    wolfSSL_BIO_free(bioOut);
    wolfSSL_X509_free(x509);
    wolfSSL_EVP_PKEY_free(pkey);
    return ret;
#endif
}


