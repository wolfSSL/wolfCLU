/* clu_ecparam.c
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
#include <wolfclu/genkey/clu_genkey.h>
#include <wolfclu/x509/clu_cert.h>    /* PER_FORM/DER_FORM */
#include <wolfclu/clu_optargs.h>

static const struct option ecparam_options[] = {
    {"in",        required_argument, 0, WOLFCLU_INFILE    },
    {"out",       required_argument, 0, WOLFCLU_OUTFILE   },
    {"outform",   required_argument, 0, WOLFCLU_OUTFORM   },
    {"genkey",    no_argument,       0, WOLFCLU_GEN_KEY    },
    {"name",      required_argument, 0, WOLFCLU_CURVE_NAME },

    {0, 0, 0, 0} /* terminal element */
};


static void wolfCLU_ecparamHelp(void)
{
    WOLFCLU_LOG(WOLFCLU_L0, "./wolfssl ecparam");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-genkey create new key");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-out output file");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-name curve name i.e. secp384r1");
}


/* return WOLFCLU_SUCCESS on success */
int wolfCLU_ecparam(int argc, char** argv)
{
    char* name = NULL;
    char* out  = NULL;    /* default output file name */
    int   ret        = WOLFCLU_SUCCESS;
    int   longIndex  = 0;
    int   genKey     = 0;
    int   outForm    = PEM_FORM;
    int   i, option;
    WC_RNG rng;

    if (wolfCLU_checkForArg("-h", 2, argc, argv) > 0) {
        wolfCLU_ecparamHelp();
        return WOLFCLU_SUCCESS;
    }

    opterr = 0; /* do not display unrecognized options */
    optind = 0; /* start at indent 0 */
    while ((option = getopt_long_only(argc, argv, "",
                   ecparam_options, &longIndex )) != -1) {

        switch (option) {
            case WOLFCLU_OUTFILE:
                out = optarg;
                break;

            case WOLFCLU_OUTFORM:
                outForm = wolfCLU_checkOutform(optarg);
                if (outForm < 0) {
                    WOLFCLU_LOG(WOLFCLU_L0, "bad outform");
                    return USER_INPUT_ERROR;
                }
                break;

            case WOLFCLU_GEN_KEY:
                genKey = 1;
                break;

            case WOLFCLU_CURVE_NAME:
                if (name != NULL) {
                    XFREE(name, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
                }
                name = (char*)XMALLOC(ECC_MAXNAME, HEAP_HINT,
                        DYNAMIC_TYPE_TMP_BUFFER);
                if (name == NULL) {
                    ret = MEMORY_E;
                    break;
                }
                XSTRNCPY(name, optarg, ECC_MAXNAME);

                /* convert name to upper case */
                for (i = 0; i < (int)XSTRLEN(name); i++)
                    (void)toupper(name[i]);

                #if 0
                /* way to get the key size if needed in the future */
                keySz = wc_ecc_get_curve_size_from_name(name);
                #endif

                break;

            case ':':
            case '?':
                break;

            default:
                /* do nothing. */
                (void)ret;
        }
    }

    if (genKey == 0) {
        WOLFCLU_LOG(WOLFCLU_L0, "only supporting genkey so far");
        if (name != NULL) {
            XFREE(name, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        }
        return WOLFCLU_FAILURE;
    }

    if (ret == WOLFCLU_SUCCESS) {
        if (wc_InitRng(&rng) != 0) {
            ret = WOLFCLU_FAILURE;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = wolfCLU_genKey_ECC(&rng, out, ECPARAM, outForm, name);
        wc_FreeRng(&rng);
    }

    if (name != NULL) {
        XFREE(name, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }
    return ret;
}

