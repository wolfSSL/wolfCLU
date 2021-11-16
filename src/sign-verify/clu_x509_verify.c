/* clu_x509_verify.c
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
#include <wolfclu/sign-verify/clu_verify.h>
#include <wolfclu/x509/clu_cert.h>

static struct option pkey_options[] = {
    {"CAfile",    required_argument, 0, WOLFCLU_INFILE    },
    {"crl_check", no_argument,       0, WOLFCLU_CHECK_CRL },
    {"help",      no_argument,       0, WOLFCLU_HELP      },
    {"h",         no_argument,       0, WOLFCLU_HELP      },

    {0, 0, 0, 0} /* terminal element */
};


static void wolfCLU_x509VerifyHelp(void)
{
    WOLFCLU_LOG(WOLFCLU_L0, "./wolfssl verify -CAfile <ca file name> [-crl_check] <cert to verify>");
}


int wolfCLU_x509Verify(int argc, char** argv)
{
    int ret    = WOLFCLU_SUCCESS;
    int inForm = PEM_FORM;
    int crlCheck = 0;
    int longIndex = 1;
    int option;
    WOLFSSL_EVP_PKEY *CAkey = NULL;
    WOLFSSL_BIO *bioIn  = NULL;
    WOLFSSL_BIO *bioCA  = NULL;
    WOLFSSL_X509 *x509  = NULL;
    WOLFSSL_X509 *ca    = NULL;

    /* last parameter is the certificate to verify */
    bioIn = wolfSSL_BIO_new_file(argv[argc-1], "rb");
    if (bioIn == NULL) {
        WOLFCLU_LOG(WOLFCLU_L0, "unable to open certificate file %s",
                argv[argc-1]);
        ret = WOLFCLU_FATAL_ERROR;
    }

    if (ret == WOLFCLU_SUCCESS) {
        WOLFCLU_LOG(WOLFCLU_L0, "verifying certificate file %s", argv[argc-1]);

        opterr = 0; /* do not display unrecognized options */
        optind = 0; /* start at indent 0 */
        while ((option = getopt_long_only(argc - 1, argv, "",
                       pkey_options, &longIndex )) != -1) {
            switch (option) {
                case WOLFCLU_CHECK_CRL:
                    crlCheck = 1;
                    break;

                case WOLFCLU_INFILE:
                    WOLFCLU_LOG(WOLFCLU_L0, "using CA file %s", optarg);
                    bioCA = wolfSSL_BIO_new_file(optarg, "rb");
                    if (bioCA == NULL) {
                        WOLFCLU_LOG(WOLFCLU_L0, "unable to open CA file %s",
                                optarg);
                        ret = WOLFCLU_FATAL_ERROR;
                    }
                    break;

                case WOLFCLU_INFORM:
                    inForm = wolfCLU_checkInform(optarg);
                    break;

                case WOLFCLU_HELP:
                    wolfCLU_x509VerifyHelp();
                    return WOLFCLU_SUCCESS;

                case ':':
                case '?':
                    break;

                default:
                    /* do nothing. */
                    (void)ret;
            }
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        if (inForm == PEM_FORM) {
            ca = wolfSSL_PEM_read_bio_X509(bioCA, NULL, NULL, NULL);
        }
        else {
            ca = wolfSSL_d2i_X509_bio(bioCA, NULL);
        }
        if (ca == NULL) {
            WOLFCLU_LOG(WOLFCLU_L0, "unable to parse CA file");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        if (inForm == PEM_FORM) {
            x509 = wolfSSL_PEM_read_bio_X509(bioIn, NULL, NULL, NULL);
        }
        else {
            x509 = wolfSSL_d2i_X509_bio(bioIn, NULL);
        }
        if (x509 == NULL) {
            WOLFCLU_LOG(WOLFCLU_L0, "unable to parse certificate file");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* get the CAs public key */
    if (ret == WOLFCLU_SUCCESS) {
        CAkey = wolfSSL_X509_get_pubkey(ca);
        if (CAkey == NULL) {
            WOLFCLU_LOG(WOLFCLU_L0, "error reading key from CA");
            ret = WOLFCLU_FATAL_ERROR;

        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        if ((ret = wolfSSL_X509_verify(x509, CAkey)) != WOLFSSL_SUCCESS) {
            WOLFCLU_LOG(WOLFCLU_L0, "Verification Failed");
        }
        else {
            WOLFCLU_LOG(WOLFCLU_L0, "OK");
        }
    }

    wolfSSL_X509_free(ca);
    wolfSSL_X509_free(x509);
    wolfSSL_EVP_PKEY_free(CAkey);
    wolfSSL_BIO_free(bioIn);
    wolfSSL_BIO_free(bioCA);

    return ret;
}

