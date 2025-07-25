/* clu_pkcs7.c
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

#include <wolfclu/clu_header_main.h>
#include <wolfclu/clu_log.h>
#include <wolfclu/clu_optargs.h>
#include <wolfclu/pkey/clu_pkey.h>
#include <wolfclu/x509/clu_cert.h>
#include <wolfclu/x509/clu_parse.h>

#if defined(HAVE_PKCS7) && !defined(WOLFCLU_NO_FILESYSTEM)

static const struct option pkcs7_options[] = {
    {"-print_certs",  no_argument,       0, WOLFCLU_CERTFILE  },
    {"-in",           required_argument, 0, WOLFCLU_INFILE    },
    {"-out",          required_argument, 0, WOLFCLU_OUTFILE   },
    {"-inform",       required_argument, 0, WOLFCLU_INFORM    },
    {"-outform",      required_argument, 0, WOLFCLU_OUTFORM   },
    {"-help",         no_argument,       0, WOLFCLU_HELP      },
    {"-h",            no_argument,       0, WOLFCLU_HELP      },

    {0, 0, 0, 0} /* terminal element */
};


static void wolfCLU_pKeyHelp(void)
{
    WOLFCLU_LOG(WOLFCLU_L0, "./wolfssl pkcs7");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-in file input for pkcs7");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-out file to write results to (default stdout)");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-inform pem/der");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-outform pem/der");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-print_certs output certificates");
}
#endif

int wolfCLU_PKCS7(int argc, char** argv)
{
#if defined(HAVE_PKCS7) && !defined(WOLFCLU_NO_FILESYSTEM)
    int ret    = WOLFCLU_SUCCESS;
    int printCerts = 0; /* default to no */
    int option;
    int longIndex = 1;
    int inForm  = PEM_FORM;
    int outForm = PEM_FORM;
    PKCS7 pkcs7;
    WOLFSSL_BIO *bioIn  = NULL;
    WOLFSSL_BIO *bioOut = NULL;
    DerBuffer* derObj = NULL;
    byte* buf = NULL;
    byte* derContent = NULL;
    int   bufSz = MAX_STDINSZ;
    int   derContentSz = 0;
    int   freePkcs7 = 0;

    opterr = 0; /* do not display unrecognized options */
    optind = 0; /* start at indent 0 */
    while ((option = wolfCLU_GetOpt(argc, argv, "",
                   pkcs7_options, &longIndex )) != -1) {
        switch (option) {
            case WOLFCLU_CERTFILE:
                printCerts = 1;
                break;

            case WOLFCLU_INFILE:
                bioIn = wolfSSL_BIO_new_file(optarg, "rb");
                if (bioIn == NULL) {
                    wolfCLU_LogError("Unable to open pkcs7 file %s",
                            optarg);
                    ret = WOLFCLU_FATAL_ERROR;
                }
                break;

            case WOLFCLU_OUTFILE:
                bioOut = wolfSSL_BIO_new_file(optarg, "wb");
                if (bioOut == NULL) {
                    wolfCLU_LogError("Unable to open output file %s",
                            optarg);
                    ret = WOLFCLU_FATAL_ERROR;
                }
                break;

            case WOLFCLU_INFORM:
                inForm = wolfCLU_checkInform(optarg);
                break;

            case WOLFCLU_OUTFORM:
                outForm = wolfCLU_checkOutform(optarg);
                break;

            case WOLFCLU_HELP:
                wolfCLU_pKeyHelp();
                return WOLFCLU_SUCCESS;

            case ':':
            case '?':
                wolfCLU_LogError("Bad argument found");
                wolfCLU_pKeyHelp();
                ret = WOLFCLU_FATAL_ERROR;
                break;

            default:
                /* do nothing. */
                (void)ret;
        }
    }

    /* currently only supporting PKCS7 parsing, input is expected */
    if (ret == WOLFCLU_SUCCESS && bioIn == NULL) {
        bioIn = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
        wolfSSL_BIO_set_fp(bioIn, stdin, BIO_NOCLOSE);
    }

    /* read the input bio to a temporary buffer and convert to PKCS7 */
    if (ret == WOLFCLU_SUCCESS) {
        buf = (byte*)XMALLOC(bufSz, HEAP_HINT, DYNAMIC_TYPE_PKCS);
        if (buf == NULL) {
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            /* reading the full file into a buffer */
            bufSz = wolfSSL_BIO_read(bioIn, buf, bufSz);
            freePkcs7 = 1;

            if (wc_PKCS7_Init(&pkcs7, HEAP_HINT, INVALID_DEVID)) {
                wolfCLU_LogError("Error on pkcs init");
                ret = WOLFCLU_FATAL_ERROR;
            }
            if (ret == WOLFCLU_SUCCESS &&
                    wc_PKCS7_InitWithCert(&pkcs7, HEAP_HINT, 0)) {
                wolfCLU_LogError("Error on pkcs initWithCert");
                ret = WOLFCLU_FATAL_ERROR;
            }

            if (ret == WOLFCLU_SUCCESS && inForm == PEM_FORM) {
                if (wc_PemToDer(buf, bufSz, PKCS7_TYPE, &derObj,
                            HEAP_HINT, NULL, NULL) == 0) {
                    derContent   = derObj->buffer;
                    derContentSz = derObj->length;

                }
                else {
                    ret = WOLFCLU_FATAL_ERROR;
                }
            }
            else if (ret == WOLFCLU_SUCCESS) {
                derContent   = buf;
                derContentSz = bufSz;
            }

            if (ret == WOLFCLU_SUCCESS && wc_PKCS7_VerifySignedData(
                        &pkcs7, derContent, derContentSz)) {
                wolfCLU_LogError("Error reading pkcs7 file");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
    }


    /* setup output bio to stdout if not already set */
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

    /* print out the certificates */
    if (ret == WOLFCLU_SUCCESS && printCerts) {
        for (int i = 0; i < MAX_PKCS7_CERTS; i++) {
            if (pkcs7.certSz[i] > 0) {
                wolfCLU_printDer(bioOut, pkcs7.cert[i],pkcs7.certSz[i],
                        CERT_TYPE, DYNAMIC_TYPE_TMP_BUFFER);
            }
            else {
                break;
            }
        }
    }
    else if (ret == WOLFCLU_SUCCESS && outForm == PEM_FORM) {
        ret = wolfCLU_printDer(bioOut, derContent, derContentSz, PKCS7_TYPE,
                DYNAMIC_TYPE_TMP_BUFFER);
    }
    else if (ret == WOLFCLU_SUCCESS && outForm == DER_FORM) {
        if (wolfSSL_BIO_write(bioOut, derContent, derContentSz) <= 0) {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    wolfSSL_BIO_free(bioIn);
    wolfSSL_BIO_free(bioOut);

    if (freePkcs7)
        wc_PKCS7_Free(&pkcs7);

    if (derObj != NULL)
        wc_FreeDer(&derObj);

    if (buf != NULL)
        XFREE(buf, HEAP_HINT, DYNAMIC_TYPE_PKCS);

    return ret;
#else
    (void)argc;
    (void)argv;
#ifndef HAVE_PKCS7
    wolfCLU_LogError("Recompile wolfSSL with PKCS7 support");
#endif
#ifdef WOLFCLU_NO_FILESYSTEM
    wolfCLU_LogError("No filesystem support");
#endif
    return WOLFCLU_FATAL_ERROR;
#endif
}

