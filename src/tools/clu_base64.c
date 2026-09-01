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
#include <wolfclu/clu_error_codes.h>
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
    char *bioInFile = NULL;
    char *bioOutFile = NULL;
    byte* input = NULL;
    byte* output = NULL;
    int ret = WOLFCLU_SUCCESS;
    int decode = 0;
    int isPEM = 0;
    /* initial buffer size to read stdin */
    word32 inputSz = 0;
    word32 outputSz = 0;
    int option;
    int longIndex = 1;
#ifdef WOLFSSL_PEM_TO_DER
    DerBuffer* der = NULL;
#endif

    opterr = 0; /* do not display unrecognized options */
    optind = 0; /* start at indent 0 */
    while (ret == WOLFCLU_SUCCESS && (option = wolfCLU_GetOpt(argc, argv, "",
                   base64_options, &longIndex )) != END_OF_ARGS) {
        switch (option) {
            case ARG_FOUND_TWICE:
                wolfCLU_LogError("Found duplicate argument");
                ret = WOLFCLU_FATAL_ERROR;
                break;

            case WOLFCLU_INFILE:
                if (optarg == NULL) {
                    wolfCLU_LogError("-in expected a value");
                    ret = WOLFCLU_FATAL_ERROR;
                }
                bioInFile = optarg;
                break;

            case WOLFCLU_OUTFILE:
                if (optarg == NULL) {
                    wolfCLU_LogError("-out expected a value");
                    ret = WOLFCLU_FATAL_ERROR;
                }
                bioOutFile = optarg;
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

    if (ret == WOLFCLU_SUCCESS) {
        if (bioInFile == NULL) {
           ret = wolfCLU_readInIo(WOLFCLU_IO_STDIN, stdin, (char**)(&input),
                   &inputSz);
        }
        else {
            XFILE fp = XFOPEN(bioInFile, "rb");
            if (fp == NULL) {
                wolfCLU_LogError("Could not open file %s", bioInFile);
                ret = WOLFCLU_FATAL_ERROR;
            }
            else {
                ret = wolfCLU_readInIo(WOLFCLU_IO_FILE, fp,
                       (char**)(&input), &inputSz);
                XFCLOSE(fp);
            }
        }
    }

    /* For decoding, check if input is in PEM format */
    if (ret == WOLFCLU_SUCCESS && decode && inputSz > 11) {
        /* Check if the input starts with a PEM header */
        if (XMEMCMP(input, "-----BEGIN", 10) == 0) {
            isPEM = 1;
        }
    }

    /* Perform encoding/decoding */
    if (ret == WOLFCLU_SUCCESS && inputSz == 0) {
        /* empty input produces empty output, matching 'openssl base64' */
        outputSz = 0;
    }
    else if (ret == WOLFCLU_SUCCESS && decode) {
        if (isPEM) {
#ifdef WOLFSSL_PEM_TO_DER
            /* Try different PEM types */
            ret = wc_PemToDer(input, (long)inputSz, PRIVATEKEY_TYPE,
                                &der, NULL, NULL, NULL);
            if (ret < 0) {
                /* Try other types if PRIVATEKEY_TYPE fails */
                ret = wc_PemToDer(input, (long)inputSz, CERT_TYPE,
                                    &der, NULL, NULL, NULL);
            }

            if (ret < 0) {
                ret = wc_PemToDer(input, (long)inputSz, PKCS7_TYPE,
                                        &der, NULL, NULL, NULL);
            }

            /* If all PEM to DER attempts failed then set error */
            if (ret < 0) {
                wolfCLU_LogError("PEM to DER conversion failed: %d", ret);
                ret = WOLFCLU_FATAL_ERROR;
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
            outputSz = (inputSz / 4) * 3 + (inputSz % 4) * 3 / 4 + 1;

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
    else if (ret == WOLFCLU_SUCCESS && !decode) {
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
            int encRet = Base64_Encode(input, inputSz, output, &outputSz);
            if (encRet < 0) {
                wolfCLU_LogError("Base64 encode failed: %d", encRet);
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        if (bioOutFile == NULL) {
            ret = wolfCLU_writeOutIo(WOLFCLU_IO_STDOUT, stdout, (char*)output,
                    outputSz);
        }
        else {
            XFILE fp = XFOPEN(bioOutFile, "wb");
            if (fp == NULL) {
                wolfCLU_LogError("Could not open file %s", bioOutFile);
                ret = WOLFCLU_FATAL_ERROR;
            }
            else {
                ret = wolfCLU_writeOutIo(WOLFCLU_IO_FILE, fp,
                        (char*)output, outputSz);
                XFCLOSE(fp);
            }
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

    return ret;
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
