/* clu_crypto_setup.c
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <wolfclu/clu_header_main.h>
#include <wolfclu/clu_log.h>
#include <wolfclu/clu_optargs.h>

static struct option crypt_options[] = {
    {"sha",       no_argument,       0, WOLFCLU_CERT_SHA   },
    {"sha224",    no_argument,       0, WOLFCLU_CERT_SHA224},
    {"sha256",    no_argument,       0, WOLFCLU_CERT_SHA256},
    {"sha384",    no_argument,       0, WOLFCLU_CERT_SHA384},
    {"sha512",    no_argument,       0, WOLFCLU_CERT_SHA512},

    {"in",        required_argument, 0, WOLFCLU_INFILE    },
    {"out",       required_argument, 0, WOLFCLU_OUTFILE   },
    {"pwd",       required_argument, 0, WOLFCLU_PASSWORD  },
    {"key",       required_argument, 0, WOLFCLU_KEY       },
    {"iv",        required_argument, 0, WOLFCLU_IV        },
    {"inkey",     required_argument, 0, WOLFCLU_INKEY     },
    {"output",    required_argument, 0, WOLFCLU_OUTPUT    },
    {"pbkdf2",    no_argument,       0, WOLFCLU_PBKDF2    },
    {"md",        required_argument, 0, WOLFCLU_MD        },
    {"d",         no_argument,       0, WOLFCLU_DECRYPT   },
    {"p",         no_argument,       0, WOLFCLU_DEBUG     },
    {"k",         required_argument, 0, WOLFCLU_PASSWORD  },

    {0, 0, 0, 0} /* terminal element */
};

int wolfCLU_setup(int argc, char** argv, char action)
{
    char     outNameEnc[256];     /* default outFile for encrypt */
    char     outNameDec[256];     /* default outfile for decrypt */
    char     inName[256];       /* name of the in File if not provided */

    int      alg;               /* algorithm from name */
    char*    mode = NULL;       /* mode from name */
    char*    out  = NULL;       /* default output file name */
    char*    in = inName;       /* default in data */
    byte*    pwdKey = NULL;     /* password for generating pwdKey */
    byte*    key = NULL;        /* user set key NOT PWDBASED */
    byte*    iv = NULL;         /* iv for initial encryption */


    int      keySize    =   0;  /* keysize from name */
    int      ret        =   0;  /* return variable */
    int      block      =   0;  /* block size based on algorithm */
    int      pwdKeyChk  =   0;  /* if a pwdKey has been provided */
    int      ivCheck    =   0;  /* if the user sets the IV explicitly */
    int      keyCheck   =   0;  /* if ivCheck is 1 this should be set also */
    int      inCheck    =   0;  /* if input has been provided */
    int      outCheck   =   0;  /* if output has been provided */
    int      encCheck   =   0;  /* if user is encrypting data */
    int      decCheck   =   0;  /* if user is decrypting data */
    int      inputHex   =   0;  /* if user is encrypting hexidecimal data */
    int      keyType    =   0;  /* tells Decrypt which key it will be using
                                 * 1 = password based key, 2 = user set key
                                 */
    int      verbose   =   0;  /* flag to print out key/iv/salt */
    int      pbkVersion =   1;
    const WOLFSSL_EVP_MD* hashType = wolfSSL_EVP_sha256();

    const WOLFSSL_EVP_CIPHER* cphr = NULL;
    word32   ivSize     =   0;  /* IV if provided should be 2*block since
                                 * reading a hex string passed in */
    word32   numBits    =   0;  /* number of bits in argument from the user */
    int      option;
    int      longIndex = 0;

    if (action == 'e')
        encCheck = 1;
    if (action == 'd')
        decCheck = 1;

    ret = wolfCLU_checkForArg("-h", 2, argc, argv);
    if (ret > 0) {
        if (encCheck == 1) {
            wolfCLU_encryptHelp();
            return 0;
        }
        else {
            wolfCLU_decryptHelp();
            return 0;
        }
    }

    /* gets blocksize, algorithm, mode, and key size from name argument */
    block = wolfCLU_getAlgo(argc, argv, &alg, &mode, &keySize);
    if (block < 0) {
        WOLFCLU_LOG(WOLFCLU_L0, "unable to find algorithm to use");
        return FATAL_ERROR;
    }

    /* initialize memory buffers */
    pwdKey = (byte*)XMALLOC(keySize + block, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (pwdKey == NULL)
        return MEMORY_E;
    XMEMSET(pwdKey, 0, keySize + block);

    iv = (byte*)XMALLOC(block, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (iv == NULL) {
        wolfCLU_freeBins(pwdKey, NULL, NULL, NULL, NULL);
        return MEMORY_E;
    }
    XMEMSET(iv, 0, block);

    key = (byte*)XMALLOC(keySize, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (key == NULL) {
        wolfCLU_freeBins(pwdKey, iv, NULL, NULL, NULL);
        return MEMORY_E;
    }
    XMEMSET(key, 0, keySize);

    opterr = 0; /* do not display unrecognized options */
    optind = 0; /* start at indent 0 */
    while ((option = getopt_long_only(argc, argv, "",
                   crypt_options, &longIndex )) != -1) {

        switch (option) {
        case WOLFCLU_PASSWORD:
            XSTRNCPY((char*)pwdKey, optarg, keySize);
            pwdKeyChk = 1;
            keyType   = 1;
            break;

        case WOLFCLU_PBKDF2:
            pbkVersion = 2;
            break;

        case WOLFCLU_KEY: /* Key if used must be in hex */
            break;

        case WOLFCLU_IV:  /* IV if used must be in hex */
            {
                char* ivString;
                ivString = (char*)XMALLOC(XSTRLEN(optarg), HEAP_HINT,
                        DYNAMIC_TYPE_TMP_BUFFER);
                if (ivString == NULL) {
                    wolfCLU_freeBins(pwdKey, iv, key, NULL, NULL);
                    return MEMORY_E;
                }

                XSTRNCPY(ivString, optarg, XSTRLEN(optarg));
                ret = wolfCLU_hexToBin(ivString, &iv, &ivSize,
                                       NULL, NULL, NULL,
                                       NULL, NULL, NULL,
                                       NULL, NULL, NULL);
                XFREE(ivString, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
                if (ret != 0) {
                    WOLFCLU_LOG(WOLFCLU_L0,
                            "failed during conversion of IV, ret = %d", ret);
                    wolfCLU_freeBins(pwdKey, iv, key, NULL, NULL);
                    return FATAL_ERROR;
                }
                ivCheck = 1;
            }
            break;

        case WOLFCLU_SIGN:
            break;

        case WOLFCLU_VERIFY: /* Verify results, used with -iv and -key */
            /* using hexidecimal format */
            inputHex = 1;
            break;

        case WOLFCLU_INFORM:
        case WOLFCLU_OUTFORM:
        case WOLFCLU_OUTPUT:
        case WOLFCLU_NOOUT:
        case WOLFCLU_TEXT_OUT:
        case WOLFCLU_SILENT:
        case WOLFCLU_PUBIN:
        case WOLFCLU_PUBOUT:
        case WOLFCLU_PUBKEY:


            /* The cases above have their arguments converted to lower case */
            if (optarg) convert_to_lower(optarg, (int)XSTRLEN(optarg));
            /* The cases below won't have their argument's molested */
            FALL_THROUGH;

        case WOLFCLU_INFILE:
            in = optarg;
            inCheck = 1;
            break;

        case WOLFCLU_OUTFILE:
            out = optarg;
            outCheck = 1;
            break;

        case WOLFCLU_INKEY:
            if (optarg == NULL) {
                WOLFCLU_LOG(WOLFCLU_L0, "no key passed in..");
                wolfCLU_freeBins(pwdKey, iv, key, NULL, NULL);
                return FATAL_ERROR;
            }

            /* 2 characters = 1 byte. 1 byte = 8 bits
             */
            numBits = (word32)(XSTRLEN(optarg) * 4);
            /* Key for encryption */
            if ((int)numBits != keySize) {
                WOLFCLU_LOG(WOLFCLU_L0,
                        "Length of key provided was: %d.", numBits);
                WOLFCLU_LOG(WOLFCLU_L0,
                        "Length of key expected was: %d.", keySize);
                WOLFCLU_LOG(WOLFCLU_L0,
                        "Invalid Key. Must match algorithm key size.");
                wolfCLU_freeBins(pwdKey, iv, key, NULL, NULL);
                return FATAL_ERROR;
            }
            else {
                char* keyString;

                keyString = (char*)XMALLOC(XSTRLEN(optarg), HEAP_HINT,
                        DYNAMIC_TYPE_TMP_BUFFER);
                if (keyString == NULL) {
                    wolfCLU_freeBins(pwdKey, iv, key, NULL, NULL);
                    return MEMORY_E;
                }

                XSTRNCPY(keyString, optarg, XSTRLEN(optarg));
                ret = wolfCLU_hexToBin(keyString, &key, &numBits,
                                       NULL, NULL, NULL,
                                       NULL, NULL, NULL,
                                       NULL, NULL, NULL);
                XFREE(keyString, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
                if (ret != 0) {
                    WOLFCLU_LOG(WOLFCLU_L0,
                            "failed during conversion of Key, ret = %d", ret);
                    wolfCLU_freeBins(pwdKey, iv, key, NULL, NULL);
                    return FATAL_ERROR;
                }
                keyCheck = 1;
                keyType = 2;
            }
            break;

        case WOLFCLU_SIGFILE:
            break;

        case WOLFCLU_DECRYPT:
            encCheck = 0;
            decCheck = 1;
            break;

        case WOLFCLU_DEBUG:
            verbose = 1;
            break;

        case WOLFCLU_MD:
            hashType = wolfSSL_EVP_get_digestbyname(optarg);
            if (hashType == NULL) {
                WOLFCLU_LOG(WOLFCLU_L0, "invalid digest name");
                return FATAL_ERROR;
            }
            break;

        case ':':
        case '?':
            break;

        default:
            /* do nothing. */
            (void)ret;
        }
    }

    if (pwdKeyChk == 0 && keyCheck == 0) {
        if (decCheck == 1) {
            WOLFCLU_LOG(WOLFCLU_L0, "\nDECRYPT ERROR:");
            WOLFCLU_LOG(WOLFCLU_L0, "no key set or passphrase");
            WOLFCLU_LOG(WOLFCLU_L0,
                    "Please type \"wolfssl -decrypt -help\" for decryption"
                                                            " usage \n");
            return 0;
        }
        /* if no pwdKey is provided */
        else {
            WOLFCLU_LOG(WOLFCLU_L0,
                    "No -pwd flag set, please enter a password to use for"
                    " encrypting.");
            WOLFCLU_LOG(WOLFCLU_L0,
                    "Write your password down so you don't forget it.");
            ret = wolfCLU_noEcho((char*)pwdKey, keySize);
            pwdKeyChk = 1;
        }
    }

    if (inCheck == 0 && encCheck == 1) {
        ret = 0;
        while (ret == 0) {
            WOLFCLU_LOG(WOLFCLU_L0,
                    "-in flag was not set, please enter a string or"
                   "file name to be encrypted: ");
            ret = (int) scanf("%s", inName);
        }
        in = inName;
        /* if no input is provided */
        WOLFCLU_LOG(WOLFCLU_L0, "Encrypting :\"%s\"", inName);
        inCheck = 1;
    }

    if (encCheck == 1 && decCheck == 1) {
        WOLFCLU_LOG(WOLFCLU_L0,
                "Encrypt and decrypt simultaneously is invalid");
        wolfCLU_freeBins(pwdKey, iv, key, NULL, NULL);
        return FATAL_ERROR;
    }

    if (inCheck == 0 && decCheck == 1) {
        WOLFCLU_LOG(WOLFCLU_L0, "File/string to decrypt needed");
        wolfCLU_freeBins(pwdKey, iv, key, NULL, NULL);
        return FATAL_ERROR;
    }

    if (ivCheck == 1) {
        if (keyCheck == 0) {
            WOLFCLU_LOG(WOLFCLU_L0,
                    "-iv was explicitly set, but no -key was set. User"
                    " needs to provide a non-password based key when setting"
                    " the -iv flag.");
            wolfCLU_freeBins(pwdKey, iv, key, NULL, NULL);
            return FATAL_ERROR;
        }
    }

    if (pwdKeyChk == 1 && keyCheck == 1) {
        XMEMSET(pwdKey, 0, keySize + block);
    }

    /* encryption function call */
    cphr = wolfCLU_CipherTypeFromAlgo(alg);
    if (encCheck == 1) {
        /* if EVP type found then call generic EVP function */
        if (cphr != NULL) {
            ret = wolfCLU_evp_crypto(cphr, mode, pwdKey, key, (keySize+7)/8, in,
                    out, NULL, iv, 0, 1, pbkVersion, hashType, verbose);
        }
        else {
            if (outCheck == 0) {
                ret = 0;
                while (ret == 0) {
                    WOLFCLU_LOG(WOLFCLU_L0,
                            "Please enter a name for the output file: ");
                    ret = (int) scanf("%s", outNameEnc);
                    out = (ret > 0) ? outNameEnc : '\0';
                }
            }
            ret = wolfCLU_encrypt(alg, mode, pwdKey, key, keySize, in, out,
                iv, block, ivCheck, inputHex);
        }
    }
    /* decryption function call */
    else if (decCheck == 1) {
        /* if EVP type found then call generic EVP function */
        if (cphr != NULL) {
            ret = wolfCLU_evp_crypto(cphr, mode, pwdKey, key, (keySize+7)/8, in,
                    out, NULL, iv, 0, 0, pbkVersion, hashType, verbose);
        }
        else {
            if (outCheck == 0) {
                ret = 0;
                while (ret == 0) {
                    WOLFCLU_LOG(WOLFCLU_L0,
                            "Please enter a name for the output file: ");
                    ret = (int) scanf("%s", outNameDec);
                    out = (ret > 0) ? outNameDec : '\0';
                }
            }
            ret = wolfCLU_decrypt(alg, mode, pwdKey, key, keySize, in, out,
                iv, block, keyType);
        }
    }
    else {
        wolfCLU_help();
    }
    /* clear and free data */
    XMEMSET(key, 0, keySize);
    XMEMSET(pwdKey, 0, keySize + block);
    XMEMSET(iv, 0, block);
    wolfCLU_freeBins(pwdKey, iv, key, NULL, NULL);

    if (mode != NULL)
        XFREE(mode, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}
