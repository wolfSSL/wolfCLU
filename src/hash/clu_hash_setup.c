/* clu_hash_setup.c
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

#include "wolfclu/clu_error_codes.h"
#include <wolfclu/clu_header_main.h>
#include <wolfclu/clu_log.h>
#include <wolfclu/clu_optargs.h>
#include <wolfssl/wolfcrypt/blake2-int.h>
#include <wolfssl/wolfcrypt/sha512.h>

#ifndef WOLFCLU_NO_FILESYSTEM
static void wolfCLU_hashHelp(void)
{
    int i;

    /* hash options */
    const char* algsenc[] = {        /* list of acceptable algorithms */
    "Algorithms: "
#ifndef NO_MD5
        ,"md5"
#endif
#ifndef NO_SHA
        ,"sha"
#endif
#ifndef NO_SHA256
        ,"sha256"
#endif
#ifdef WOLFSSL_SHA384
        ,"sha384"
#endif
#ifdef WOLFSSL_SHA512
        ,"sha512"
#endif
#ifdef HAVE_BLAKE2B
        ,"blake2b"
#endif
#ifndef NO_CODING
    #ifdef WOLFSSL_BASE64_ENCODE
        ,"base64enc"
    #endif
        ,"base64dec"
#endif
        };

    WOLFCLU_LOG(WOLFCLU_L0, "\nAvailable algorithms with current configure settings:");
    for (i = 0; i < (int) sizeof(algsenc)/(int) sizeof(algsenc[0]); i++) {
        WOLFCLU_LOG(WOLFCLU_L0, "%s", algsenc[i]);
    }
            /* encryption/decryption help lists options */
    WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
    WOLFCLU_LOG(WOLFCLU_L0, "\nUSAGE: wolfssl -hash <-algorithm> -in <file to hash>");
    WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
    WOLFCLU_LOG(WOLFCLU_L0, "\nEXAMPLE: \n\nwolfssl -hash sha -in <some file>\n");
}

static const struct option hash_options[] = {
    {"-in",   required_argument, 0, WOLFCLU_INFILE  },
    {"-out",  required_argument, 0, WOLFCLU_OUTFILE },
    {"-h",    no_argument,       0, WOLFCLU_HELP    },
    {"-help", no_argument,       0, WOLFCLU_HELP    },

    /* Algorithms */
    {"-md5",        no_argument,       0, WOLFCLU_MD5      },
    {"-sha",        no_argument,       0, WOLFCLU_SHA      },
    {"-sha256",     no_argument,       0, WOLFCLU_SHA256   },
    {"-sha384",     no_argument,       0, WOLFCLU_SHA384   },
    {"-sha512",     no_argument,       0, WOLFCLU_SHA512   },
    {"-base64enc",  no_argument,       0, WOLFCLU_BASE64ENC},
    {"-base64dec",  no_argument,       0, WOLFCLU_BASE64DEC},
    {"-blake2b",    required_argument, 0, WOLFCLU_BLAKE    },

    {0, 0, 0, 0} /* terminal element */
};
#endif

/*
 * hash argument function
 * return WOLFCLU_SUCCESS on success
 */
int wolfCLU_hashSetup(int argc, char** argv)
{
#ifndef WOLFCLU_NO_FILESYSTEM
    int option;
    int longIndex = 1;
    int ret        =   WOLFCLU_SUCCESS;

    const char* alg =   NULL;   /* algorithm being used */
    int     algCheck=   0;      /* acceptable algorithm check */
    int     size    =   0;      /* message digest size */

    WOLFSSL_BIO *bioIn = NULL;
    WOLFSSL_BIO *bioOut = NULL;
    char* inFile = NULL;
    char* outFile = NULL;


    opterr = 0; /* do not display unrecognized options */
    optind = 0; /* start at index 0 */
    while ((option = wolfCLU_GetOpt(argc, argv, "", hash_options,
                    &longIndex)) != END_OF_ARGS) {
        switch (option) {
            case WOLFCLU_HELP:
                wolfCLU_hashHelp();
                return WOLFCLU_SUCCESS;

            case WOLFCLU_INFILE:
                inFile = optarg;
                break;

            case WOLFCLU_OUTFILE:
                outFile = optarg;
                break;

            case WOLFCLU_MD5:
            #ifndef WC_MD5
                wolfCLU_LogError("MD5 not avalable in your current wolfSSL "
                        "build");
                return WOLFCLU_FATAL_ERROR;
            #else
                if (alg != NULL) {
                    wolfCLU_LogError("alg already set");
                    return WOLFCLU_FATAL_ERROR;
                }
                alg = "md5";
                algCheck = 1;
                size = WC_MD5_DIGEST_SIZE;
            #endif
                break;

            case WOLFCLU_SHA:
            #ifndef WC_SHA
                wolfCLU_LogError("SHA not avalible in your current wolfSSL "
                        "build");
                return WOLFCLU_FATAL_ERROR;
            #else
                if (alg != NULL) {
                    wolfCLU_LogError("alg already set");
                    return WOLFCLU_FATAL_ERROR;
                }
                alg = "sha";
                algCheck = 1;
                size = WC_SHA_DIGEST_SIZE;
            #endif
                break;

            case WOLFCLU_SHA256:
            #ifndef WC_SHA256
                wolfCLU_LogError("SHA-256 not avalible in your current wolfSSL "
                        "build");
                return WOLFCLU_FATAL_ERROR;
            #else
                if (alg != NULL) {
                    wolfCLU_LogError("alg already set");
                    return WOLFCLU_FATAL_ERROR;
                }
                alg = "sha256";
                algCheck = 1;
                size = WC_SHA256_DIGEST_SIZE;
            #endif
                break;

            case WOLFCLU_SHA384:
            #ifndef WC_SHA384
                wolfCLU_LogError("SHA-384 not avalible in your current wolfSSL "
                        "build");
                return WOLFCLU_FATAL_ERROR;
            #else
                if (alg != NULL) {
                    wolfCLU_LogError("alg already set");
                    return WOLFCLU_FATAL_ERROR;
                }

                alg = "sha384";
                algCheck = 1;
                size = WC_SHA384_DIGEST_SIZE;
            #endif
                break;

            case WOLFCLU_SHA512:
            #ifndef WC_SHA512
                wolfCLU_LogError("SHA-512 not avalible in your current wolfSSL "
                        "build");
                return WOLFCLU_FATAL_ERROR;
            #else
                if (alg != NULL) {
                    wolfCLU_LogError("alg already set");
                    return WOLFCLU_FATAL_ERROR;
                }

                alg = "sha512";
                algCheck = 1;
                size = WC_SHA512_DIGEST_SIZE;
            #endif
                break;

            case WOLFCLU_BLAKE:
            #ifndef HAVE_BLAKE2B
                wolfCLU_LogError("BLAKE2 not avalible in your current wolfSSL "
                        "build");
                return WOLFCLU_FATAL_ERROR;
            #else
                if (alg != NULL) {
                    wolfCLU_LogError("alg already set");
                    return WOLFCLU_FATAL_ERROR;
                }

                alg = "blake2b";
                algCheck = 1;
                if (optarg != NULL)
                    size = XATOI(optarg);
                else
                    size = BLAKE2B_BLOCKBYTES;
                if (size < 1 || size > 64) {
                    wolfCLU_LogError("black2b size must be between 1-64");
                    ret = WOLFCLU_FATAL_ERROR;
                }
            #endif
                break;

            case WOLFCLU_BASE64ENC:
            #if defined(NO_CODING) || !defined(WOLFSSL_BASE64_ENCODE)
                wolfCLU_LogError("BASE64 encoding not avalible in your "
                        "current wolfSSL build");
                return WOLFCLU_FATAL_ERROR;
            #else
                if (alg != NULL) {
                    wolfCLU_LogError("alg already set");
                    return WOLFCLU_FATAL_ERROR;
                }

                alg = "base64enc";
                algCheck = 1;
            #endif
                break;

            case WOLFCLU_BASE64DEC:
            #if defined(NO_CODING)
                wolfCLU_LogError("BASE64 encoding not avalible in your "
                        "current wolfSSL build");
                return WOLFCLU_FATAL_ERROR;
            #else
                if (alg != NULL) {
                    wolfCLU_LogError("alg already set");
                    return WOLFCLU_FATAL_ERROR;
                }

                alg = "base64dec";
                algCheck = 1;
            #endif
                break;

            case ARG_FOUND_TWICE:
                wolfCLU_LogError("Found duplicate argument");
                return WOLFCLU_FATAL_ERROR;

            case ':':
            case '?':
                break;

            default:
                wolfCLU_LogError("Unsupported argument");
                ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS && algCheck == 0) {
        wolfCLU_LogError("Invalid algorithm");
        ret = WOLFCLU_FATAL_ERROR;
    }

    if (ret == WOLFCLU_SUCCESS && inFile == NULL) {
        wolfCLU_LogError("Must have input as either a file or standard I/O");
        ret = WOLFCLU_FATAL_ERROR;
    }

    if (ret == WOLFCLU_SUCCESS) {
        bioIn = wolfSSL_BIO_new_file(inFile, "rb");
        if (bioIn == NULL) {
            wolfCLU_LogError("unable to open file %s", inFile);
            ret = USER_INPUT_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS && outFile != NULL) {
        bioOut = wolfSSL_BIO_new_file(outFile, "wb");
        if (bioOut == NULL) {
            wolfCLU_LogError("unable to open output file %s", outFile);
            ret = USER_INPUT_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        /* hashing function */
        ret = wolfCLU_hash(bioIn, bioOut, alg, size);
    }

    wolfSSL_BIO_free(bioIn);
    wolfSSL_BIO_free(bioOut);

    return ret;
#else
    (void)argc;
    (void)argv;
    WOLFCLU_LOG(WOLFCLU_E0, "No filesystem support");
    return WOLFCLU_FATAL_ERROR;
#endif
}
