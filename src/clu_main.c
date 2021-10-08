/* clu_main.c
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
#include <wolfclu/x509/clu_cert.h>
#include <wolfclu/clu_optargs.h>
#include <wolfclu/clu_error_codes.h>
#include <wolfclu/x509/clu_request.h>
#include <wolfclu/genkey/clu_genkey.h>
#include <wolfclu/pkey/clu_pkey.h>
#include <wolfclu/sign-verify/clu_sign_verify_setup.h>
/* enumerate optionals beyond ascii range to dis-allow use of alias IE we
 * do not want "-e" to work for encrypt, user must use "encrypt"
 */

static struct option mode_options[] = {
    {"encrypt",   required_argument, 0, WOLFCLU_ENCRYPT   },
    {"decrypt",   required_argument, 0, WOLFCLU_DECRYPT   },
    {"enc",       no_argument,       0, WOLFCLU_CRYPT     },
    {"bench",     no_argument,       0, WOLFCLU_BENCHMARK },
    {"hash",      required_argument, 0, WOLFCLU_HASH      },
    {"md5",       no_argument,       0, WOLFCLU_MD5       },
    {"x509",      no_argument,       0, WOLFCLU_X509      },
    {"req",       no_argument,       0, WOLFCLU_REQUEST   },
    {"genkey",    required_argument, 0, WOLFCLU_GEN_KEY   },
    {"ecparam",   no_argument,       0, WOLFCLU_ECPARAM   },
    {"pkey",      no_argument,       0, WOLFCLU_PKEY      },
    {"rsa",       no_argument,       0, WOLFCLU_RSA       },
    {"ecc",       no_argument,       0, WOLFCLU_ECC       },
    {"ed25519",   no_argument,       0, WOLFCLU_ED25519   },
    {"dgst",      no_argument,       0, WOLFCLU_DGST      },
    {"help",      no_argument,       0, WOLFCLU_HELP      },
    {"h",         no_argument,       0, WOLFCLU_HELP      },
    {"v",         no_argument,       0, 'v'       },
    {"version",   no_argument,       0, 'v'       },

    {0, 0, 0, 0} /* terminal element */
};


/**
 * Takes in the second string passed into the function and compares it to known
 * modes. When a match is found the modes value is returned, otherwise a
 * negative value is returned.
 */
static int getMode(char* arg)
{
    int ret = WOLFCLU_FATAL_ERROR, i = 0;

    if (arg != NULL) {
        int argSz = (int)XSTRLEN(arg);
        struct option current = mode_options[i];
        while (current.name != NULL) {
            if ((int)XSTRLEN(current.name) == argSz &&
                    XSTRNCMP(arg, current.name, argSz) == 0) {
                ret = current.val;
                break;
            }
            current = mode_options[i];
            i = i+1;
        }
    }
    return ret;
}



int main(int argc, char** argv)
{
    int     flag = 0;
    int     ret = WOLFCLU_SUCCESS;
    int     longIndex = 0;

    if (argc == 1) {
        WOLFCLU_LOG(WOLFCLU_L0, "Main Help.");
        wolfCLU_help();
    }

#ifdef HAVE_FIPS
    if (wolfCrypt_GetStatus_fips() == IN_CORE_FIPS_E) {
        WOLFCLU_LOG(WOLFCLU_L0, "Linked to a FIPS version of wolfSSL that has failed the in core"
               "integrity check. ALL FIPS crypto will report ERRORS when used."
               "To resolve please recompile wolfSSL with the correct integrity"
               "hash. If the issue continues, contact fips @ wolfssl.com");
    }
#endif

    /* If the first string does not have a '-' in front of it then try to
     * get the mode to use i.e. x509, req, version ... this is for
     * compatibility with the behavior of the OpenSSL command line utility
     */
    if (argc > 1 && argv[1] != NULL && argv[1][0] != '-') {
        flag = getMode(argv[1]);
    }
    else {
        /* retain old version of modes where '-' is used. i.e -x509, -req */
        flag = getopt_long_only(argc, argv,"", mode_options, &longIndex);
    }

    switch (flag) {
        case 0:
            WOLFCLU_LOG(WOLFCLU_L0, "No mode provided.");
            ret = 0;
            break;

        case WOLFCLU_CRYPT:
            /* generic 'enc' used, default to encrypt unless -d was used */
            ret = wolfCLU_checkForArg("-d", 2, argc, argv);
            if (ret > 0) {
                ret = wolfCLU_setup(argc, argv, 'd');
            }
            else {
                ret = wolfCLU_setup(argc, argv, 'e');
            }
            break;

        case WOLFCLU_ENCRYPT:
            ret = wolfCLU_setup(argc, argv, 'e');
            break;

        case WOLFCLU_DECRYPT:
            ret = wolfCLU_setup(argc, argv, 'd');
            break;

        case WOLFCLU_BENCHMARK:
            ret = wolfCLU_benchSetup(argc, argv);
            break;

        case WOLFCLU_HASH:
            ret = wolfCLU_hashSetup(argc, argv);
            break;

        case WOLFCLU_MD5:
            ret = wolfCLU_md5Setup(argc, argv);
            break;

        case WOLFCLU_X509:
            ret = wolfCLU_certSetup(argc, argv);
            break;

        case WOLFCLU_REQUEST:
            ret = wolfCLU_requestSetup(argc, argv);
            break;

        case WOLFCLU_GEN_KEY:
            ret = wolfCLU_genKeySetup(argc, argv);
            break;

        case WOLFCLU_ECPARAM:
            ret = wolfCLU_ecparam(argc, argv);
            break;

        case WOLFCLU_PKEY:
            ret = wolfCLU_pKeySetup(argc, argv);
            break;

        case WOLFCLU_DGST:
            ret = wolfCLU_dgst_setup(argc, argv);
            break;

        case WOLFCLU_RSA:
        case WOLFCLU_ECC:
        case WOLFCLU_ED25519:
            ret = wolfCLU_sign_verify_setup(argc, argv);
            break;

        case WOLFCLU_HELP:
            /* only print for -help if no mode has been declared */
            WOLFCLU_LOG(WOLFCLU_L0, "Main help menu:");
            wolfCLU_help();
            ret = WOLFCLU_SUCCESS;
            break;

        case WOLFCLU_VERBOSE:
            wolfCLU_verboseHelp();
            ret = WOLFCLU_SUCCESS;
            break;

        case 'v':
            ret = wolfCLU_version();
            break;

        default:
            WOLFCLU_LOG(WOLFCLU_L0, "Unknown mode");
            wolfCLU_help();
            ret = WOLFCLU_FATAL_ERROR;
    }

    if (ret <= 0)
        WOLFCLU_LOG(WOLFCLU_L0, "Error returned: %d.", ret);

    /* main function we want to return 0 on success so that the executable
     * returns the expected 0 on success */
    return (ret == WOLFCLU_SUCCESS)? 0 : ret;
}

