/* clu_sign_verify_setup.c
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
#include <wolfclu/clu_error_codes.h>
#include <wolfclu/clu_optargs.h>
#include <wolfclu/sign-verify/clu_sign.h>
#include <wolfclu/sign-verify/clu_verify.h>
#include <wolfclu/sign-verify/clu_sign_verify_setup.h>
#include <wolfclu/x509/clu_cert.h>

#ifndef WOLFCLU_NO_FILESYSTEM
static void wolfCLU_verifyHelp(int keyType) {
    int i;
    const char* keysother[] = { /* list of acceptable key types */
        "KEYS: "
        #ifndef NO_RSA
        ,"rsa"
        #endif
        #ifdef HAVE_ED25519
        ,"ed25519"
        #endif
        #ifdef HAVE_ECC
        ,"ecc"
        #endif
        #ifdef HAVE_DILITHIUM
        ,"ml-dsa"
        ,"dilithium"
        #endif
        #ifdef WOLFSSL_HAVE_XMSS
        ,"xmss"
        ,"xmssmt"
        #endif
        };

        WOLFCLU_LOG(WOLFCLU_L0, "\nAvailable keys with current configure settings:");
        for(i = 0; i < (int) sizeof(keysother)/(int) sizeof(keysother[0]); i++) {
            WOLFCLU_LOG(WOLFCLU_L0, "%s", keysother[i]);
        }

        WOLFCLU_LOG(WOLFCLU_L0, "\n***************************************************************");
        switch(keyType) {
            #ifndef NO_RSA
            case RSA_SIG_VER:
                WOLFCLU_LOG(WOLFCLU_L0, "RSA Verify with Private Key:"
                        "wolfssl -rsa -verify -inkey <priv_key>"
                        " -sigfile <filename> -out <filename>\n");
                WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
                WOLFCLU_LOG(WOLFCLU_L0, "RSA Verify with Public Key"
                       "wolfssl -rsa -verify -inkey <pub_key>"
                       " -sigfile <filename> -out <filename> -pubin\n");
                WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
                break;
            #endif
            #ifdef HAVE_DILITHIUM
            case DILITHIUM_SIG_VER:
                WOLFCLU_LOG(WOLFCLU_L0, "ML-DSA (Dilithium) Verify Usage:\n"
                       "wolfssl -ml-dsa -verify -inkey <pub_key> -inform <pem|der>\n"
                       "                -in <original_file> -sigfile <signature_file>\n");
                WOLFCLU_LOG(WOLFCLU_L0, "  Verifies with the public key (.pub).\n"
                       "  PEM keys require '-inform pem' (default is der).\n"
                       "  'dilithium' is accepted as an alias for 'ml-dsa'.\n"
                       "  (-pubin is not applicable; verification always uses the public key)\n");
                WOLFCLU_LOG(WOLFCLU_L0, "EXAMPLE:\n"
                       "wolfssl -ml-dsa -verify -inkey ml-dsa-key-A.pub -inform pem\n"
                       "                -in input.txt -sigfile input.sign\n");
                WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
                break;
            #endif
            #ifdef HAVE_ED25519
            case ED25519_SIG_VER:
                WOLFCLU_LOG(WOLFCLU_L0, "ED25519 Verifiy with Private Key"
                       "wolfssl -ed25519 -verify -inkey "
                       "<priv_key> -sigfile <filename> -in <original>"
                       "\n");
                WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
                WOLFCLU_LOG(WOLFCLU_L0, "ED25519 Verifiy with Public Key"
                       "wolfssl -ed25519 -verify -inkey "
                       "<pub_key> -sigfile <filename> -in <original> -pubin"
                       "\n");
                WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
                break;
            #endif
            #ifdef HAVE_ECC
            case ECC_SIG_VER:
                WOLFCLU_LOG(WOLFCLU_L0, "ECC Verify with Public Key"
                       "wolfssl -ecc -verify -inkey <pub_key>"
                       " -sigfile <signature> -in <original> -pubin\n");
                break;
            #endif
            #ifdef WOLFSSL_HAVE_XMSS
            case XMSS_SIG_VER:
                WOLFCLU_LOG(WOLFCLU_L0, "XMSS Verify with Public Key"
                       "wolfssl -xmss -verify -inkey <pub_key>"
                       " -sigfile <signature> -in <original>\n");
                WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
                break;
            case XMSSMT_SIG_VER:
                WOLFCLU_LOG(WOLFCLU_L0, "XMSS^MT Verify with Public Key"
                       "wolfssl -xmssmt -verify -inkey <pub_key>"
                       " -sigfile <signature> -in <original>\n");
                WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
                break;
            #endif
            default:
                WOLFCLU_LOG(WOLFCLU_L0, "No valid key type defined.\n");
        }
}

static void wolfCLU_signHelp(int keyType)
{
    int i;
    const char* keysother[] = { /* list of acceptable key types */
        "KEYS: "
        #ifndef NO_RSA
        ,"rsa"
        #endif
        #ifdef HAVE_ED25519
        ,"ed25519"
        #endif
        #ifdef HAVE_ECC
        ,"ecc"
        #endif
        #ifdef HAVE_DILITHIUM
        ,"ml-dsa"
        ,"dilithium"
        #endif
        #ifdef WOLFSSL_HAVE_XMSS
        ,"xmss"
        ,"xmssmt"
        #endif
        };

        WOLFCLU_LOG(WOLFCLU_L0, "\nAvailable keys with current configure settings:");
        for(i = 0; i < (int) sizeof(keysother)/(int) sizeof(keysother[0]); i++) {
            WOLFCLU_LOG(WOLFCLU_L0, "%s", keysother[i]);
        }

        WOLFCLU_LOG(WOLFCLU_L0, "\n***************************************************************");
        switch(keyType) {
            #ifndef NO_RSA
            case RSA_SIG_VER:
                WOLFCLU_LOG(WOLFCLU_L0, "RSA Sign Usage: \nwolfssl -rsa -sign -inkey <priv_key>"
                       " -in <filename> -out <filename>\n");
                WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
                break;
            #endif
            #ifdef HAVE_DILITHIUM
            case DILITHIUM_SIG_VER:
                WOLFCLU_LOG(WOLFCLU_L0, "ML-DSA (Dilithium) Sign Usage:\n"
                       "wolfssl -ml-dsa -sign -inkey <priv_key> -inform <pem|der>\n"
                       "                -in <file_to_sign> -out <signature_file>\n");
                WOLFCLU_LOG(WOLFCLU_L0, "  -level [2|3|5] is set at key generation, not here.\n"
                       "  PEM keys require '-inform pem' (default is der).\n"
                       "  'dilithium' is accepted as an alias for 'ml-dsa'.\n");
                WOLFCLU_LOG(WOLFCLU_L0, "EXAMPLE:\n"
                       "wolfssl -ml-dsa -sign -inkey ml-dsa-key-A.priv -inform pem\n"
                       "                -in input.txt -out input.sign\n");
                WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
                break;
            #endif
            #ifdef HAVE_ED25519
            case ED25519_SIG_VER:
                WOLFCLU_LOG(WOLFCLU_L0, "ED25519 Sign Usage: \nwolfssl -ed25519 -sign -inkey "
                       "<priv_key> -in <filename> -out <filename>\n");
                WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
                break;
            #endif
            #ifdef HAVE_ECC
            case ECC_SIG_VER:
                WOLFCLU_LOG(WOLFCLU_L0, "ECC Sign Usage: \nwolfssl -ecc -sign -inkey <priv_key>"
                       " -in <filename> -out <filename>\n");
                break;
            #endif
            #ifdef WOLFSSL_HAVE_XMSS
            case XMSS_SIG_VER:
                WOLFCLU_LOG(WOLFCLU_L0, "XMSS Sign Usage: \nwolfssl -xmss -sign -inkey <priv_key>"
                       " -in <filename> -out <filename>\n");
                WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
                break;
            case XMSSMT_SIG_VER:
                WOLFCLU_LOG(WOLFCLU_L0, "XMSS^MT Sign Usage: \nwolfssl -xmssmt -sign -inkey <priv_key>"
                       " -in <filename> -out <filename>\n");
                WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
                break;
            #endif
            default:
                WOLFCLU_LOG(WOLFCLU_L0, "No valid key type defined.\n");
        }
}

static const struct option sign_verify_options[] = {
    {"-sign",    no_argument,       0, WOLFCLU_SIGN    },
    {"-verify",  no_argument,       0, WOLFCLU_VERIFY  },
    {"-pubin",   no_argument,       0, WOLFCLU_PUBIN   },

    {"-inkey",   required_argument, 0, WOLFCLU_INKEY   },
    {"-in",      required_argument, 0, WOLFCLU_INFILE  },
    {"-out",     required_argument, 0, WOLFCLU_OUTFILE },
    {"-sigfile", required_argument, 0, WOLFCLU_SIGFILE },
    {"-inform",  required_argument, 0, WOLFCLU_INFORM  },

    {"-h",       no_argument,       0, WOLFCLU_HELP    },
    {"-help",    no_argument,       0, WOLFCLU_HELP    },

    {0, 0, 0, 0} /* terminal element */
};
#endif

int wolfCLU_sign_verify_setup(int argc, char** argv)
{
#ifndef WOLFCLU_NO_FILESYSTEM
    int    option;
    int    longIndex = 1;
    int    ret  = WOLFCLU_SUCCESS;

    char*  in   = NULL;         /* input file name */
    char*  out  = NULL;         /* output file name */
    char*  priv = NULL;         /* private/public key file name */
    char*  sig  = NULL;         /* signature file name */

    int    algCheck;            /* acceptable algorithm check */
    int    inCheck     = 0;     /* input check */
    int    signCheck   = 0;
    int    verifyCheck = 0;
    int    pubInCheck  = 0;
    int    helpCheck   = 0;
    int    inForm      = DER_FORM; /* the key input format */

    /* The algorithm name is a positional mode selector (rsa, ecc, ...).
     * checkForArg doesn't look for "-" here, as it would have been
     * removed in clu_main.c if present. */
    if (wolfCLU_checkForArg("rsa", 3, argc, argv) > 0) {
        algCheck = RSA_SIG_VER;
    }
    else if (wolfCLU_checkForArg("ed25519", 7, argc, argv) > 0) {
        algCheck = ED25519_SIG_VER;
    }
    else if (wolfCLU_checkForArg("ecc", 3, argc, argv) > 0) {
        algCheck = ECC_SIG_VER;
    }
    else if (wolfCLU_checkForArg("dilithium", 9, argc, argv) > 0) {
        algCheck = DILITHIUM_SIG_VER;
    }
    else if (wolfCLU_checkForArg("ml-dsa", 6, argc, argv) > 0) {
        algCheck = DILITHIUM_SIG_VER;
    }
    else if (wolfCLU_checkForArg("xmss", 4, argc, argv) > 0) {
        algCheck = XMSS_SIG_VER;
    }
    else if (wolfCLU_checkForArg("xmssmt", 6, argc, argv) > 0) {
        algCheck = XMSSMT_SIG_VER;
    }
    else {
        return WOLFCLU_FATAL_ERROR;
    }

    opterr = 0; /* do not display unrecognized options */
    optind = 0; /* start at index 0 */
    while ((option = wolfCLU_GetOpt(argc, argv, "", sign_verify_options,
                    &longIndex)) != END_OF_ARGS) {
        switch (option) {
            case WOLFCLU_HELP:
                helpCheck = 1;
                break;

            case WOLFCLU_SIGN:
                signCheck = 1;
                break;

            case WOLFCLU_VERIFY:
                verifyCheck = 1;
                break;

            case WOLFCLU_PUBIN:
                pubInCheck = 1;
                break;

            case WOLFCLU_INKEY:
                priv = optarg;
                if (access(priv, F_OK) == -1) {
                    wolfCLU_LogError("Inkey file %s did not exist. Please "
                            "check your options.", priv);
                    ret = INPUT_FILE_ERROR;
                }
                break;

            case WOLFCLU_INFILE:
                in = optarg;
                if (access(in, F_OK) == -1) {
                    wolfCLU_LogError("In file did not exist. Please check "
                            "your options.");
                    ret = INPUT_FILE_ERROR;
                }
                else {
                    inCheck = 1;
                }
                break;

            case WOLFCLU_OUTFILE:
                out = optarg;
                break;

            case WOLFCLU_SIGFILE:
                sig = optarg;
                if (access(sig, F_OK) == -1) {
                    wolfCLU_LogError("Signature file did not exist. Please "
                            "check your options.");
                    ret = INPUT_FILE_ERROR;
                }
                break;

            case WOLFCLU_INFORM:
                inForm = wolfCLU_checkInform(optarg);
                if (inForm == USER_INPUT_ERROR) {
                    ret = WOLFCLU_FATAL_ERROR;
                }
                break;

            case ARG_FOUND_TWICE:
                wolfCLU_LogError("Found duplicate argument");
                ret = WOLFCLU_FATAL_ERROR;
                break;

            case ':':
            case '?':
                break;

            default:
                wolfCLU_LogError("Unsupported argument");
                ret = WOLFCLU_FATAL_ERROR;
        }

        if (ret != WOLFCLU_SUCCESS) {
            break;
        }
    }

    /* help checking */
    if (ret == WOLFCLU_SUCCESS && helpCheck) {
        if (signCheck == 1) {
            wolfCLU_signHelp(algCheck);
        }
        else if (verifyCheck == 1) {
            wolfCLU_verifyHelp(algCheck);
        }
        else {
            wolfCLU_signHelp(algCheck);
            wolfCLU_verifyHelp(algCheck);
        }
        return WOLFCLU_SUCCESS;
    }

    /* a key is required when signing or verifying */
    if (ret == WOLFCLU_SUCCESS && priv == NULL) {
        WOLFCLU_LOG(WOLFCLU_L0, "Please specify an -inkey <key> option when "
               "signing or verifying.");
        wolfCLU_signHelp(algCheck);
        wolfCLU_verifyHelp(algCheck);
        ret = USER_INPUT_ERROR;
    }

    /* a signature file is required when verifying */
    if (ret == WOLFCLU_SUCCESS && verifyCheck == 1 && sig == NULL) {
        wolfCLU_LogError("Please specify -sigfile <sig> when verifying.");
        wolfCLU_verifyHelp(algCheck);
        ret = USER_INPUT_ERROR;
    }

    /* check that an output file was provided where one is required */
    if (ret == WOLFCLU_SUCCESS && out == NULL) {
        if (algCheck == RSA_SIG_VER) {
            WOLFCLU_LOG(WOLFCLU_L0, "Please specify an output file when "
                   "signing or verifing with RSA.");
            wolfCLU_signHelp(algCheck);
            wolfCLU_verifyHelp(algCheck);
            ret = WOLFCLU_FATAL_ERROR;
        }
        else if (algCheck == ECC_SIG_VER && verifyCheck == 0) {
            WOLFCLU_LOG(WOLFCLU_L0, "Please specify an output file when "
                   "signing with ECC.");
            wolfCLU_signHelp(algCheck);
            ret = WOLFCLU_FATAL_ERROR;
        }
        else if (algCheck == DILITHIUM_SIG_VER && verifyCheck == 0) {
            WOLFCLU_LOG(WOLFCLU_L0, "Please specify an output file when "
                    "signing with ML-DSA (Dilithium).");
            wolfCLU_signHelp(algCheck);
            ret = WOLFCLU_FATAL_ERROR;
        }
        else if ((algCheck == XMSS_SIG_VER || algCheck == XMSSMT_SIG_VER)
                  && verifyCheck == 0) {
            WOLFCLU_LOG(WOLFCLU_L0, "Please specify an output file when "
                    "signing with XMSS/XMSS^MT.");
            wolfCLU_signHelp(algCheck);
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            /* No out needed for ECC verifying */
            /* ED25519 exceptions will need to be added at a later date */
        }
    }

    /* input is required, except RSA verify which doesn't check the message */
    if (ret == WOLFCLU_SUCCESS && inCheck == 0) {
        if (algCheck == RSA_SIG_VER && verifyCheck == 1) {
            /* ignore no -in. RSA verify doesn't check original message */
        }
        else {
            wolfCLU_LogError("Must have input as either a file or standard I/O");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        if (signCheck == 1) {
            ret = wolfCLU_sign_data(in, out, priv, algCheck, inForm);
        }
        else if (verifyCheck == 1) {
            ret = wolfCLU_verify_signature(sig, in, out, priv, algCheck,
                    pubInCheck, inForm);
        }
    }

    return ret;
#else
    (void)argc;
    (void)argv;
    WOLFCLU_LOG(WOLFCLU_E0, "No filesystem support");
    return WOLFCLU_FATAL_ERROR;
#endif
}
