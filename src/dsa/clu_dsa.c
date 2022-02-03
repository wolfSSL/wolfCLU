/* clu_dsa.c
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

#ifndef NO_DSA
static const struct option dsa_options[] = {
    {"in",        required_argument, 0, WOLFCLU_INFILE    },
    {"out",       required_argument, 0, WOLFCLU_OUTFILE   },
    {"genkey",    no_argument,       0, WOLFCLU_PUBOUT    },
    {"help",      no_argument,       0, WOLFCLU_HELP      },
    {"h",         no_argument,       0, WOLFCLU_HELP      },

    {0, 0, 0, 0} /* terminal element */
};


static void wolfCLU_DsaHelp(void)
{
    WOLFCLU_LOG(WOLFCLU_L0, "./wolfssl dsaparam");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-in file input for key to read");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-out file to output to (default stdout)");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-genkey generate DSA key using param input");
}
#endif /* !NO_DSA */


int wolfCLU_DsaParamSetup(int argc, char** argv)
{
#ifndef NO_DSA
    WC_RNG rng;
    DsaKey dsa;
    int modSz;
    int ret    = WOLFCLU_SUCCESS;
    int option;
    int longIndex = 1;
    char* out = NULL;
    byte genKey   = 0;
    WOLFSSL_BIO *bioIn  = NULL;
    WOLFSSL_BIO *bioOut = NULL;

    /* last parameter is the dsa size */
    if (XSTRNCMP("-h", argv[argc-1], 2) == 0) {
        wolfCLU_DsaHelp();
        return WOLFCLU_SUCCESS;
    }
    else {
        modSz = XATOI(argv[argc-1]);
        if (modSz <= 0) {
            /* hold off on error'ing out in case there is '-in' used */
        }
    }

    optind = 0; /* start at indent 0 */
    while ((option = getopt_long_only(argc, argv, "",
                   dsa_options, &longIndex )) != -1) {
        switch (option) {
            case WOLFCLU_INFILE:
                bioIn = wolfSSL_BIO_new_file(optarg, "rb");
                if (bioIn == NULL) {
                    WOLFCLU_LOG(WOLFCLU_E0, "Unable to open input file %s",
                            optarg);
                    ret = WOLFCLU_FATAL_ERROR;
                }
                break;

            case WOLFCLU_OUTFILE:
                out = optarg;
                break;

            case WOLFCLU_GEN_KEY:
                genKey = 1;
                break;

            case WOLFCLU_HELP:
                wolfCLU_DsaHelp();
                return WOLFCLU_SUCCESS;

            case ':':
            case '?':
                WOLFCLU_LOG(WOLFCLU_E0, "Bad argument");
                ret = USER_INPUT_ERROR;
                break;

            default:
                WOLFCLU_LOG(WOLFCLU_E0, "Bad argument");
                ret = USER_INPUT_ERROR;
        }
    }

    /* try initializing both because both get free'd regardless at the end */
    if (wc_InitRng(&rng) != 0 || wc_InitDsaKey(&dsa) != 0) {
        WOLFCLU_LOG(WOLFCLU_E0, "Unable to initialize rng and dsa");
        ret = WOLFCLU_FATAL_ERROR;
    }

    /* read in parameters */
    if (ret == WOLFCLU_SUCCESS && bioIn != NULL) {
        //wc_DsaParamsDecode(in, &idx, &dsa, inSz);
    }

    if (ret == WOLFCLU_SUCCESS) {
        if (out != NULL) {
            bioOut = wolfSSL_BIO_new_file(out, "wb");
            if (bioOut == NULL) {
                WOLFCLU_LOG(WOLFCLU_E0, "Unable to open output file %s",
                        optarg);
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
        else {
            /* use stdout by default */
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

    /* generate the dsa parameters */
    if (ret == WOLFCLU_SUCCESS && bioIn == NULL) {
        if (wc_MakeDsaParameters(&rng, modSz, &dsa) != 0) {
            WOLFCLU_LOG(WOLFCLU_E0, "Error generating parameters");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* print out the dsa parameters */
    if (ret == WOLFCLU_SUCCESS) {
        byte* outBuf = NULL;
        byte* pem    = NULL;
        word32 outBufSz = 0;
        word32 pemSz    = 0;

        if (wc_DsaKeyToParamsDer_ex(&dsa, NULL, &outBufSz) != 0) {
            ret = WOLFCLU_FATAL_ERROR;
        }

        if (ret == WOLFCLU_SUCCESS) {
            outBuf = (byte*)XMALLOC(outBufSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (outBuf == NULL) {
                ret = WOLFCLU_FATAL_ERROR;
            }
        }

        if (ret == WOLFCLU_SUCCESS &&
                wc_DsaKeyToParamsDer_ex(&dsa, outBuf, &outBufSz) != 0) {
            ret = WOLFCLU_FATAL_ERROR;
        }

        if (ret == WOLFCLU_SUCCESS) {
            pemSz = wc_DerToPem(outBuf, outBufSz, NULL, 0, DSA_PARAM_TYPE);
            if (pemSz > 0) {
                pem = (byte*)XMALLOC(pemSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                if (pem == NULL) {
                    ret = WOLFCLU_FATAL_ERROR;
                }
            }
            else {
                ret = WOLFCLU_FATAL_ERROR;
            }
        }

        if (ret == WOLFCLU_SUCCESS) {
            pemSz = wc_DerToPem(outBuf, outBufSz, pem, pemSz, DSA_PARAM_TYPE);
            if (pemSz <= 0) {
                ret = WOLFCLU_FATAL_ERROR;
            }
        }

        if (ret == WOLFCLU_SUCCESS &&
                wolfSSL_BIO_write(bioOut, pem, pemSz) <= 0) {
            ret = WOLFCLU_FATAL_ERROR;
        }

        if (pem != NULL)
            XFREE(pem, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (outBuf != NULL)
            XFREE(outBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    /* print out the dsa key */
    //wc_MakeDsaKey(&rng, &dsa);
    //wc_DsaKeyToDer(&key, out, outSz);

    wolfSSL_BIO_free(bioIn);
    wolfSSL_BIO_free(bioOut);

    wc_FreeDsaKey(&dsa);
    wc_FreeRng(&rng);

    return ret;
#else
    (void)argc;
    (void)argv;
    WOLFCLU_LOG(WOLFCLU_E0, "DSA support not compiled into wolfSSL");
    return WOLFCLU_FATAL_ERROR;
#endif
}


