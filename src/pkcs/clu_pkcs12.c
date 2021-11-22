/* clu_pkcs12.c
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

static const struct option pkcs12_options[] = {
    {"nodes",     no_argument, 0, WOLFCLU_NODES   },
    {"nocerts",   no_argument, 0, WOLFCLU_NOCERTS },
    {"nokeys",    no_argument, 0, WOLFCLU_NOKEYS  },
    {"passin",    required_argument, 0, WOLFCLU_PASSWORD     },
    {"passout",   required_argument, 0, WOLFCLU_PASSWORD_OUT },
    {"in",        required_argument, 0, WOLFCLU_INFILE       },
    {"help",      no_argument, 0, WOLFCLU_HELP},
    {"h",         no_argument, 0, WOLFCLU_HELP},

    {0, 0, 0, 0} /* terminal element */
};


static void wolfCLU_pKeyHelp(void)
{
    WOLFCLU_LOG(WOLFCLU_L0, "./wolfssl pkcs12");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-in file input for pkcs12 bundle");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-nodes no DES encryption");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-nocerts no certificate output");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-nokeys no key output");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-passin source to get password from");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-passout source to output password to");
}

#define MAX_PASSWORD_SIZE 256

int wolfCLU_PKCS12(int argc, char** argv)
{
#ifdef HAVE_PKCS12
    char password[MAX_PASSWORD_SIZE];
    int passwordSz = MAX_PASSWORD_SIZE;
    int ret    = WOLFCLU_SUCCESS;
    int inForm = PEM_FORM;
    int useDES = 1;     /* default to yes */
    int printCerts = 1; /* default to yes*/
    int printKeys  = 1; /* default to yes*/
    int option;
    int longIndex = 1;
    WOLFSSL_EVP_PKEY *pkey = NULL;
    WOLFSSL_X509     *cert = NULL;
    WC_PKCS12        *pkcs12 = NULL;
    WOLF_STACK_OF(WOLFSSL_X509) *extra = NULL;
    WOLFSSL_BIO *bioIn  = NULL;
    WOLFSSL_BIO *bioOut = NULL;

    opterr = 0; /* do not display unrecognized options */
    optind = 0; /* start at indent 0 */
    while ((option = getopt_long_only(argc, argv, "",
                   pkcs12_options, &longIndex )) != -1) {
        switch (option) {
            case WOLFCLU_NODES:
                useDES = 0;
                break;

            case WOLFCLU_NOCERTS:
                printCerts = 0;
                break;

            case WOLFCLU_NOKEYS:
                printKeys = 0;
                break;

            case WOLFCLU_PASSWORD:
                XMEMSET(password, 0, MAX_PASSWORD_SIZE);
                if (XSTRNCMP(optarg, "stdin", 5) == 0) {
                    if (XFGETS(password, MAX_PASSWORD_SIZE, stdin) == NULL) {
                        WOLFCLU_LOG(WOLFCLU_L0, "error getting password");
                        ret = WOLFCLU_FATAL_ERROR;
                    }
                    if (ret == WOLFCLU_SUCCESS) {
                        size_t idx = 0;
                        passwordSz = (int)XSTRLEN(password);

                        /* span the string up to the first return line and chop
                         * it off */
                        if (XSTRSTR(password, "\r\n")) {
                            idx = strcspn(password, "\r\n");
                            if ((int)idx > passwordSz) {
                                ret = WOLFCLU_FATAL_ERROR;
                            }
                            else {
                                password[idx] = '\0';
                            }
                        }

                        if (XSTRSTR(password, "\n")) {
                            idx = strcspn(password, "\n");
                            if ((int)idx > passwordSz) {
                                ret = WOLFCLU_FATAL_ERROR;
                            }
                            else {
                                password[idx] = '\0';
                            }
                        }

                        passwordSz = (int)XSTRLEN(password);
                    }
                }
                else if (XSTRNCMP(optarg, "pass:", 5) == 0) {
                    XSTRNCPY(password, optarg + 5, MAX_PASSWORD_SIZE);
                    if (ret == WOLFCLU_SUCCESS) {
                        passwordSz = (int)XSTRLEN(password);
                    }
                }
                else {
                    WOLFCLU_LOG(WOLFCLU_L0, "not supported password in type %s",
                            optarg);
                    ret = WOLFCLU_FATAL_ERROR;
                }
                break;

            case WOLFCLU_PASSWORD_OUT:
                break;

            case WOLFCLU_INFILE:
                printf("bioin = %s\n", optarg);
                bioIn = wolfSSL_BIO_new_file(optarg, "rb");
                if (bioIn == NULL) {
                    WOLFCLU_LOG(WOLFCLU_L0, "unable to open pkcs12 file %s",
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


    if (ret == WOLFCLU_SUCCESS) {
        pkcs12 = wolfSSL_d2i_PKCS12_bio(bioIn, NULL);
        if (pkcs12 == NULL) {
            WOLFCLU_LOG(WOLFCLU_L0, "error reading pkcs12 file");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        if (wolfSSL_PKCS12_parse(pkcs12, password, &pkey, &cert, &extra)
                != WOLFSSL_SUCCESS) {
            WOLFCLU_LOG(WOLFCLU_L0, "error parsing pkcs12 file");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* setup output bio to stdout for now */
    if (ret == WOLFCLU_SUCCESS) {
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

    /* print out the certificate */
    if (ret == WOLFCLU_SUCCESS && cert != NULL && printCerts) {
        if (wolfSSL_PEM_write_bio_X509(bioOut, cert) != WOLFSSL_SUCCESS) {
            WOLFCLU_LOG(WOLFCLU_L0, "error printing cert file");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* print out the certificate list */
    if (ret == WOLFCLU_SUCCESS && extra != NULL && printCerts) {
        WOLFSSL_X509 *x509;
        int i;

        for (i = 0; i < wolfSSL_sk_X509_num(extra); i++) {
            x509 = wolfSSL_sk_X509_value(extra, i);
            if (wolfSSL_PEM_write_bio_X509(bioOut, x509) != WOLFSSL_SUCCESS) {
                WOLFCLU_LOG(WOLFCLU_L0, "error printing cert file");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
    }

    /* print out the key */
    if (ret == WOLFCLU_SUCCESS && pkey != NULL && printKeys) {
        ret = wolfCLU_pKeyPEMtoPriKey(bioOut, pkey);
        if (ret != WOLFCLU_SUCCESS) {
            WOLFCLU_LOG(WOLFCLU_L0, "error getting pubkey from pem key");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    wolfSSL_BIO_free(bioIn);
    wolfSSL_BIO_free(bioOut);
    wolfSSL_EVP_PKEY_free(pkey);
    wc_PKCS12_free(pkcs12);

    return ret;
#else
    WOLFCLU_LOG(WOLFCLU_L0, "Recompile wolfSSL with PKCS12 support");
    return WOLFCLU_FATAL_ERROR;
#endif
}

