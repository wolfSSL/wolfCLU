/* clu_base64.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

static const struct option base64_options[] = {
    {"-in",           required_argument, 0, WOLFCLU_INFILE    },
    {"-out",          required_argument, 0, WOLFCLU_OUTFILE   },
    {"-d",            no_argument,       0, 'd'               },
    {"-help",         no_argument,       0, WOLFCLU_HELP      },
    {"-h",            no_argument,       0, WOLFCLU_HELP      },

    {0, 0, 0, 0} /* terminal element */
};

/* base64 help function */
static void wolfCLU_Base64Help(void)
{
    WOLFCLU_LOG(WOLFCLU_L0, "wolfssl base64 [options]");
    WOLFCLU_LOG(WOLFCLU_L0, "Base64 encode/decode data");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-in file       Input file to encode/decode");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-out file      Output file for encoded/decoded data");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-d             Decode data");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-help          Display this message");
}

/* base64 setup function */
int wolfCLU_Base64Setup(int argc, char** argv)
{
#if !defined(WOLFCLU_NO_FILESYSTEM) && !defined(NO_CODING)
    WOLFSSL_BIO *bioIn = NULL;
    WOLFSSL_BIO *bioOut = NULL;
    byte* input = NULL;
    byte* output = NULL;
    int ret = WOLFCLU_SUCCESS;
    int decode = 0;
    int isPEM = 0;
    word32 inputSz = 8000;
    word32 outputSz = 0;
    int option;
    int longIndex = 1;
#ifdef WOLFSSL_PEM_TO_DER
    DerBuffer* der = NULL;
#endif

    opterr = 0; /* do not display unrecognized options */
    optind = 0; /* start at indent 0 */
    while ((option = wolfCLU_GetOpt(argc, argv, "",
                   base64_options, &longIndex )) != -1) {
        switch (option) {
            case WOLFCLU_INFILE:
                bioIn = wolfSSL_BIO_new_file(optarg, "rb");
                if (bioIn == NULL) {
                    wolfCLU_LogError("unable to open file %s", optarg);
                    ret = WOLFCLU_FATAL_ERROR;
                }
                break;

            case WOLFCLU_OUTFILE:
                bioOut = wolfSSL_BIO_new_file(optarg, "wb");
                if (bioOut == NULL) {
                    wolfCLU_LogError("unable to open output file %s",
                            optarg);
                    if (bioIn != NULL) {
                        wolfSSL_BIO_free(bioIn);
                    }
                    ret = WOLFCLU_FATAL_ERROR;
                }
                break;

            case 'd':
                decode = 1;
                break;

            case WOLFCLU_HELP:
                wolfCLU_Base64Help();
                return WOLFCLU_SUCCESS;

            case ':':
            case '?':
                wolfCLU_LogError("Bad argument found");
                wolfCLU_Base64Help();
                ret = WOLFCLU_FATAL_ERROR;
                break;

            default:
                /* do nothing. */
                (void)ret;
        }
    }

    if (ret == WOLFCLU_SUCCESS && bioIn == NULL) {
        bioIn = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
        if (bioIn != NULL)
            wolfSSL_BIO_set_fp(bioIn, stdin, BIO_NOCLOSE);
    }
    else if (ret == WOLFCLU_SUCCESS) {
        /* get data size using raw FILE pointer and seek */
        XFILE f;
        if (wolfSSL_BIO_get_fp(bioIn, &f) != WOLFSSL_SUCCESS) {
            wolfCLU_LogError("Unable to get raw file pointer");
            ret = WOLFCLU_FATAL_ERROR;
        }

        if (ret == WOLFCLU_SUCCESS && XFSEEK(f, 0, XSEEK_END) != 0) {
            wolfCLU_LogError("Unable to seek end of file");
            ret = WOLFCLU_FATAL_ERROR;
        }

        if (ret == WOLFCLU_SUCCESS) {
            inputSz = (word32)XFTELL(f);
            wolfSSL_BIO_reset(bioIn);
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        input = (byte*)XMALLOC(inputSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (input == NULL) {
            wolfCLU_LogError("Memory allocation error for input buffer");
            ret = MEMORY_E;
        }
        else {
            inputSz = wolfSSL_BIO_read(bioIn, input, inputSz);

            /* For decoding, check if input is in PEM format */
            if (decode && inputSz > 11) {
                /* Check if the input starts with a PEM header */
                if (XMEMCMP(input, "-----BEGIN", 10) == 0) {
                    isPEM = 1;
                }
            }
        }
    }

    /* Perform encoding/decoding */
    if (ret == WOLFCLU_SUCCESS && decode) {
        if (isPEM) {
#ifdef WOLFSSL_PEM_TO_DER
            /* Try different PEM types */
            ret = wc_PemToDer(input, (long)inputSz, PRIVATEKEY_TYPE,
                                &der, NULL, NULL, NULL);
            if (ret < 0) {
                /* Try other types if PRIVATEKEY_TYPE fails */
                ret = wc_PemToDer(input, (long)inputSz, CERT_TYPE,
                                    &der, NULL, NULL, NULL);
                if (ret < 0) {
                    ret = wc_PemToDer(input, (long)inputSz, CERTREQ_TYPE,
                                        &der, NULL, NULL, NULL);
                    if (ret < 0) {
                        wolfCLU_LogError("PEM to DER conversion failed: %d",
                                ret);
                        ret = WOLFCLU_FATAL_ERROR;
                    }
                }
            }

            if (ret == 0) {
                ret = WOLFCLU_SUCCESS;
                /* Allocate a new buffer and copy the DER data */
                output = (byte*)XMALLOC(der->length, HEAP_HINT,
                            DYNAMIC_TYPE_TMP_BUFFER);
                if (output == NULL) {
                    wolfCLU_LogError("Memory allocation error for output"
                           " buffer");
                    ret = MEMORY_E;
                }
                else {
                    XMEMCPY(output, der->buffer, der->length);
                    outputSz = der->length;
                }
            }
#else
            wolfCLU_LogError("PEM to DER conversion not supported");
            ret = WOLFCLU_FATAL_ERROR;
#endif
        }
        else {
            /* For regular base64 decoding */
            /* Calculate output size */
            outputSz = (inputSz * 3) / 4 + 1;

            /* Allocate output buffer */
            output = (byte*)XMALLOC(outputSz, HEAP_HINT,
                    DYNAMIC_TYPE_TMP_BUFFER);
            if (output == NULL) {
                wolfCLU_LogError("Memory allocation error for output buffer");
                ret = MEMORY_E;
            }
            else {
                /* Decode base64 data */
                ret = Base64_Decode(input, inputSz, output, &outputSz);
                if (ret < 0) {
                    if (ret == ASN_INPUT_E) {
                        wolfCLU_LogError("Base64 decode failed: Input is not in"
                               " valid base64 format");
                    }
                    else {
                        wolfCLU_LogError("Base64 decode failed: %d", ret);
                    }
                    ret = WOLFCLU_FATAL_ERROR;
                }
                else {
                    ret = WOLFCLU_SUCCESS;
                }
            }
        }
    }
    else if (ret == WOLFSSL_SUCCESS) {
        /* For encoding */
        /* Calculate output size */
        if (Base64_Encode(input, inputSz, NULL, &outputSz) != LENGTH_ONLY_E) {
            wolfCLU_LogError("Failed to calculate base64 encode length");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            /* Allocate output buffer */
            output = (byte*)XMALLOC(outputSz, HEAP_HINT,
                    DYNAMIC_TYPE_TMP_BUFFER);
            if (output == NULL) {
                wolfCLU_LogError("Memory allocation error for output buffer");
                ret = MEMORY_E;
            }
        }

        if (ret == WOLFCLU_SUCCESS) {
            if (Base64_Encode(input, inputSz, output, &outputSz) < 0) {
                wolfCLU_LogError("Base64 encode failed: %d", ret);
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
    }

    if (ret == WOLFCLU_SUCCESS && bioOut != NULL) {
        /* Write output */
        ret = wolfSSL_BIO_write(bioOut, output, outputSz);
        if (ret <= 0) {
            wolfCLU_LogError("Failed to write output data: %d", ret);
            ret = WOLFCLU_FATAL_ERROR;
        }
    }
    else if (ret == WOLFCLU_SUCCESS) {
        /* Write to stdout */
        bioOut = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
        if (bioOut != NULL) {
            wolfSSL_BIO_set_fp(bioOut, stdout, BIO_NOCLOSE);
            ret = wolfSSL_BIO_write(bioOut, output, outputSz);
            if (ret <= 0) {
                wolfCLU_LogError("Failed to write to stdout: %d", ret);
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
        else {
            wolfCLU_LogError("Failed to create stdout BIO");
            ret = MEMORY_E;
        }
    }

    /* Clean up */
    if (input != NULL) {
        XFREE(input, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (output != NULL) {
        XFREE(output, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }
#ifdef WOLFSSL_PEM_TO_DER
    if (der != NULL) {
        wc_FreeDer(&der);
    }
#endif
    if (bioIn != NULL) {
        wolfSSL_BIO_free(bioIn);
    }
    if (bioOut != NULL) {
        wolfSSL_BIO_free(bioOut);
    }

    return WOLFCLU_SUCCESS;
#else
    (void)argc;
    (void)argv;
#ifdef NO_CODING
    WOLFCLU_LOG(WOLFCLU_E0, "No coding support");
#endif
#ifdef WOLFCLU_NO_FILESYSTEM
    wolfCLU_LogError("No filesystem support");
#endif
    return WOLFCLU_FATAL_ERROR;
#endif /* !WOLFCLU_NO_FILESYSTEM */
}
