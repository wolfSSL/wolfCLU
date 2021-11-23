/* clu_crl_verify.c
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
#include <wolfclu/x509/clu_parse.h>
#include <wolfclu/x509/clu_cert.h>

#ifdef HAVE_CRL
static const struct option crl_options[] = {
    {"in",        required_argument, 0, WOLFCLU_INFILE    },
    {"out",       required_argument, 0, WOLFCLU_OUTFILE   },
    {"inform",    required_argument, 0, WOLFCLU_INFORM    },
    {"outform",   required_argument, 0, WOLFCLU_OUTFORM   },
    {"CAfile",    required_argument, 0, WOLFCLU_CAFILE    },
    {"noout",     no_argument,       0, WOLFCLU_NOOUT     },
    {"help",      no_argument,       0, WOLFCLU_HELP      },
    {"h",         no_argument,       0, WOLFCLU_HELP      },

    {0, 0, 0, 0} /* terminal element */
};


static void wolfCLU_CRLVerifyHelp(void)
{
    WOLFCLU_LOG(WOLFCLU_L0, "./wolfssl crl\n"
            "-CAfile <ca file name>\n"
            "-inform pem or der in format");
    WOLFCLU_LOG(WOLFCLU_L0,
            "-in the file to read from\n"
            "-outform pem or der out format");
    WOLFCLU_LOG(WOLFCLU_L0,
            "-out output file to write to\n"
            "-noout do not print output if set");
}
#endif


int wolfCLU_CRLVerify(int argc, char** argv)
{
#ifdef HAVE_CRL
    int ret     = WOLFCLU_SUCCESS;
    int inForm  = PEM_FORM;
    int outForm = PEM_FORM;
    int output = 1;
    int longIndex = 1;
    int option;
    byte* der   = NULL;
    int   derSz = 0;
    char* caCert     = NULL;
    WOLFSSL_BIO* bioIn  = NULL;
    WOLFSSL_BIO* bioOut = NULL;

    opterr = 0; /* do not display unrecognized options */
    optind = 0; /* start at indent 0 */
    while ((option = getopt_long_only(argc, argv, "", crl_options,
                    &longIndex )) != -1) {
        switch (option) {
            case WOLFCLU_OUTFILE:
                bioOut = wolfSSL_BIO_new_file(optarg, "wb");
                if (bioOut == NULL) {
                    WOLFCLU_LOG(WOLFCLU_L0, "unable to open output file %s",
                            optarg);
                    ret = WOLFCLU_FATAL_ERROR;
                }
                break;

            case WOLFCLU_INFILE:
                bioIn = wolfSSL_BIO_new_file(optarg, "rb");
                if (bioIn == NULL) {
                    WOLFCLU_LOG(WOLFCLU_L0, "unable to open input file %s",
                            optarg);
                    ret = WOLFCLU_FATAL_ERROR;
                }
                break;

            case WOLFCLU_OUTFORM:
                outForm = wolfCLU_checkInform(optarg);
                break;

            case WOLFCLU_INFORM:
                inForm = wolfCLU_checkInform(optarg);
                break;

            case WOLFCLU_CAFILE:
                caCert = optarg;
                break;

            case WOLFCLU_NOOUT:
                output = 0;
                break;

            case WOLFCLU_HELP:
                wolfCLU_CRLVerifyHelp();
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
        int len;

        if (inForm == PEM_FORM) {
            byte* pem = NULL;
            DerBuffer* pDer = NULL;

            len = wolfSSL_BIO_get_len(bioIn);
            pem = (byte*)XMALLOC(len, HEAP_HINT, DYNAMIC_TYPE_CRL);
            if (pem == NULL) {
                ret = WOLFCLU_FATAL_ERROR;
            }

            if (ret == WOLFCLU_SUCCESS) {
                if (wolfSSL_BIO_read(bioIn, pem, len) != len) {
                    ret = WOLFCLU_FATAL_ERROR;
                }
            }

            if (ret == WOLFCLU_SUCCESS) {
                if (wc_PemToDer(pem, len, CRL_TYPE, &pDer, NULL, NULL, NULL)
                        != 0) {
                    ret = WOLFCLU_FATAL_ERROR;
                }
            }

            if (ret == WOLFCLU_SUCCESS) {
                derSz = pDer->length;
                der   = (byte*)XMALLOC(derSz, HEAP_HINT, DYNAMIC_TYPE_CRL);
                if (der == NULL) {
                    ret = WOLFCLU_FATAL_ERROR;
                }
                else {
                    XMEMCPY(der, pDer->buffer, derSz);
                }
                wc_FreeDer(&pDer);
            }

            if (pem != NULL) {
                XFREE(pem, HEAP_HINT, DYNAMIC_TYPE_CRL);
            }
        }
        else { /* handle input as DER */
            len = wolfSSL_BIO_get_len(bioIn);
            der = (byte*)XMALLOC(len, HEAP_HINT, DYNAMIC_TYPE_CRL);
            if (der == NULL) {
                ret = WOLFCLU_FATAL_ERROR;
            }
            else {
                derSz = len;
                wolfSSL_BIO_read(bioIn, der, derSz);
            }
        }
    }

    /* print the output CRL */
    if (ret == WOLFCLU_SUCCESS && output != 0) {
        /* set to stdout if no output is set */
        if (bioOut == NULL) {
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
    }

    if (ret == WOLFCLU_SUCCESS && output != 0) {
        if (outForm == DER_FORM) {
            wolfSSL_BIO_write(bioOut, der, derSz);
        }
        else {
            ret = wolfCLU_printDer(bioOut, der, derSz, CRL_TYPE,
                    DYNAMIC_TYPE_CRL);
        }
    }

    /* if a CA was set then verify the input CRL */
    if (ret == WOLFCLU_SUCCESS && caCert != NULL) {
        WOLFSSL_CERT_MANAGER* cm;

        cm = wolfSSL_CertManagerNew();
        if (wolfSSL_CertManagerLoadCA(cm, caCert, NULL) != WOLFSSL_SUCCESS) {
            WOLFCLU_LOG(WOLFCLU_L0, "Unable to open CA file");
            ret = WOLFCLU_FATAL_ERROR;
        }

        if (ret == WOLFCLU_SUCCESS) {
            if (wolfSSL_CertManagerEnableCRL(cm, WOLFSSL_CRL_CHECKALL)
                    != WOLFSSL_SUCCESS) {
                WOLFCLU_LOG(WOLFCLU_L0, "Failed to enable CRL use");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }

        if (ret == WOLFCLU_SUCCESS) {
            int err;

            if ((err = wolfSSL_CertManagerLoadCRLBuffer(cm, der, derSz,
                            WOLFSSL_FILETYPE_ASN1)) == WOLFSSL_SUCCESS) {
                WOLFCLU_LOG(WOLFCLU_L0, "OK");
            }
            else {
                WOLFCLU_LOG(WOLFCLU_L0, "Verification failed");
                WOLFCLU_LOG(WOLFCLU_L0, "Err (%d) : %s",
                    err, wolfSSL_ERR_reason_error_string(err));
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
        wolfSSL_CertManagerFree(cm);
    }

    if (der != NULL) {
        XFREE(der, HEAP_HINT, DYNAMIC_TYPE_CRL);
    }
    wolfSSL_BIO_free(bioIn);
    wolfSSL_BIO_free(bioOut);
    return ret;
#else
    (void)argc;
    (void)argv;
    WOLFCLU_LOG(WOLFCLU_L0, "recompile wolfSSL with CRL support");
    return WOLFCLU_FATAL_ERROR;
#endif
}


