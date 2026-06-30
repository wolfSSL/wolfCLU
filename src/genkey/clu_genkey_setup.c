/* clu_genkey_setup.c
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
#include <wolfclu/genkey/clu_genkey.h>
#include <wolfclu/x509/clu_cert.h>  /* argument checking */

#ifndef WOLFCLU_NO_FILESYSTEM

static void wolfCLU_genKeyHelp(void)
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

        WOLFCLU_LOG(WOLFCLU_L0, "Available keys with current configure settings:");
        for(i = 0; i < (int) sizeof(keysother)/(int) sizeof(keysother[0]); i++) {
            WOLFCLU_LOG(WOLFCLU_L0, "%s", keysother[i]);
        }
    WOLFCLU_LOG(WOLFCLU_L0, "\n");
    WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
    WOLFCLU_LOG(WOLFCLU_L0, "\ngenkey USAGE:\nwolfssl -genkey <keytype> -size(optional) <bits> "
           "-out <filename> -outform <PEM or DER> -output <PUB/PRIV/KEYPAIR> \n");
    WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
    WOLFCLU_LOG(WOLFCLU_L0, "\nEXAMPLE: \n\nwolfssl -genkey rsa -size 2048 -out mykey -outform der "
           " -output KEYPAIR");
#ifdef HAVE_DILITHIUM
    WOLFCLU_LOG(WOLFCLU_L0, "wolfssl -genkey dilithium -level "
           "[2|3|5] -out mykey -outform der -output KEYPAIR");
    WOLFCLU_LOG(WOLFCLU_L0, "wolfssl -genkey dilithium -level "
           "[2|3|5] -out mykey -outform pem -output KEYPAIR");
    WOLFCLU_LOG(WOLFCLU_L0, "wolfssl -genkey ml-dsa -level "
           "[2|3|5] -out mykey -outform der -output KEYPAIR");
    WOLFCLU_LOG(WOLFCLU_L0, "wolfssl -genkey ml-dsa -level "
           "[2|3|5] -out mykey -outform pem -output KEYPAIR");
#endif
#ifdef WOLFSSL_HAVE_XMSS
    WOLFCLU_LOG(WOLFCLU_L0, "wolfssl -genkey xmss -height [10|16|20] -out mykey -outform raw"
                " -output KEYPAIR");
    WOLFCLU_LOG(WOLFCLU_L0, "wolfssl -genkey xmssmt -height [20|40|60] -layer [2|4|8|3|6|12]"
                "  -out mykey -outform raw -output KEYPAIR");
    WOLFCLU_LOG(WOLFCLU_L0, "XMSS key file name must be something like \"XMSS-SHA2_10_256\""
                "\nXMSS/XMSS^MT parametaers are determined by file name when signing");
#endif
    WOLFCLU_LOG(WOLFCLU_L0,
           "\n\nThe above command would output the files: mykey.priv "
           " and mykey.pub\nChanging the -output option to just PRIV would only"
           "\noutput the mykey.priv and using just PUB would only output"
           "\nmykey.pub\n");
}


static const struct option genkey_options[] = {
    {"-out",      required_argument, 0, WOLFCLU_OUTFILE   },
    {"-outform",  required_argument, 0, WOLFCLU_OUTFORM   },
    {"-output",   required_argument, 0, WOLFCLU_OUTPUT    },
    {"-name",     required_argument, 0, WOLFCLU_CURVE_NAME},
    {"-size",     required_argument, 0, WOLFCLU_SIZE      },
    {"-exponent", required_argument, 0, WOLFCLU_EXPONENT  },
    {"-level",    required_argument, 0, WOLFCLU_LEVEL     },
    {"-height",   required_argument, 0, WOLFCLU_HEIGHT    },
    {"-layer",    required_argument, 0, WOLFCLU_LAYER     },
    {"-h",        no_argument,       0, WOLFCLU_HELP      },
    {"-help",     no_argument,       0, WOLFCLU_HELP      },

    {0, 0, 0, 0} /* terminal element */
};

/* Map a -output value (pub/priv/keypair) to a directive. Returns the directive,
 * defaulting to PRIV_AND_PUB_FILES when output is NULL or unrecognized. */
static int wolfCLU_genKeyDirective(const char* output)
{
    int directiveArg = PRIV_AND_PUB_FILES;

    if (output != NULL) {
        if (XSTRNCASECMP(output, "pub", 3) == 0)
            directiveArg = PUB_ONLY_FILE;
        else if (XSTRNCASECMP(output, "priv", 4) == 0)
            directiveArg = PRIV_ONLY_FILE;
        else if (XSTRNCASECMP(output, "keypair", 7) == 0)
            directiveArg = PRIV_AND_PUB_FILES;
    }
    else {
        WOLFCLU_LOG(WOLFCLU_L0, "No -output <PUB/PRIV/KEYPAIR>");
        WOLFCLU_LOG(WOLFCLU_L0, "DEFAULT: output public and private key pair");
    }

    return directiveArg;
}
#endif

/* return WOLFCLU_SUCCESS on success */
int wolfCLU_genKeySetup(int argc, char** argv)
{
#ifndef WOLFCLU_NO_FILESYSTEM
    char     keyOutFName[MAX_FILENAME_SZ];  /* default outFile for genKey */
    char     defaultFormat[4] = "der";
    WC_RNG   rng;

    char*    keyType  = NULL;       /* keyType */
    char*    outFile  = NULL;       /* -out file name */
    char*    output   = NULL;       /* -output directive (pub/priv/keypair) */
    char*    name     = NULL;       /* -name curve name */
    char*    sizeStr  = NULL;       /* -size argument */
    char*    expStr   = NULL;       /* -exponent argument */
    char*    levelStr = NULL;       /* -level argument */
    char*    heightStr= NULL;       /* -height argument */
    char*    layerStr = NULL;       /* -layer argument */
    char*    format   = defaultFormat;

    int      formatArg;
    int      option;
    int      longIndex = 1;
    int      ret;

    XMEMSET(keyOutFName, 0, MAX_FILENAME_SZ);

    opterr = 0; /* do not display unrecognized options */
    optind = 0; /* start at index 0 */
    while ((option = wolfCLU_GetOpt(argc, argv, "", genkey_options,
                    &longIndex)) != END_OF_ARGS) {
        switch (option) {
            case WOLFCLU_HELP:
                wolfCLU_genKeyHelp();
                return WOLFCLU_SUCCESS;

            case WOLFCLU_OUTFILE:
                outFile = optarg;
                break;

            case WOLFCLU_OUTFORM:
                if (optarg != NULL)
                    format = optarg;
                break;

            case WOLFCLU_OUTPUT:
                output = optarg;
                break;

            case WOLFCLU_CURVE_NAME:
                name = optarg;
                break;

            case WOLFCLU_SIZE:
                sizeStr = optarg;
                break;

            case WOLFCLU_EXPONENT:
                expStr = optarg;
                break;

            case WOLFCLU_LEVEL:
                levelStr = optarg;
                break;

            case WOLFCLU_HEIGHT:
                heightStr = optarg;
                break;

            case WOLFCLU_LAYER:
                layerStr = optarg;
                break;

            case ARG_FOUND_TWICE:
                wolfCLU_LogError("Found duplicate argument");
                return WOLFCLU_FATAL_ERROR;

            case ':':
            case '?':
                break;

            default:
                /* do nothing. */
                break;
        }
    }

    /* key type is the positional argument following the "genkey" command */
    if (argc < 3) {
        wolfCLU_LogError("ERROR: missing key type argument");
        wolfCLU_genKeyHelp();
        return USER_INPUT_ERROR;
    }
    keyType = argv[2];

    /* These options are consumed only by feature-gated key types; cast to
     * void so a build with those types disabled does not warn. */
    (void)output; (void)name; (void)sizeStr; (void)expStr;
    (void)levelStr; (void)heightStr; (void)layerStr;

    /* an output file name is required */
    if (outFile == NULL) {
        wolfCLU_LogError("ERROR: Please specify an output file name");
        wolfCLU_genKeyHelp();
        return USER_INPUT_ERROR;
    }
    if (XSTRLEN(outFile) >= sizeof(keyOutFName)) {
        wolfCLU_LogError("ERROR: -out filename too long (max %d)",
                         (int)sizeof(keyOutFName) - 1);
        return USER_INPUT_ERROR;
    }
    XSTRLCPY(keyOutFName, outFile, sizeof(keyOutFName));

    /* validate the output format */
    formatArg = wolfCLU_checkOutform(format);
    if (formatArg == PEM_FORM || formatArg == DER_FORM ||
            formatArg == RAW_FORM) {
        const char* formatStr = (formatArg == PEM_FORM) ? "PEM" :
                                (formatArg == DER_FORM) ? "DER" :
                                "RAW";

        WOLFCLU_LOG(WOLFCLU_L0, "OUTPUT A %s FILE", formatStr);
    }
    else {
        wolfCLU_LogError("ERROR: \"%s\" is not a valid file format", format);
        return formatArg;
    }

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        wolfCLU_LogError("rng init failed");
        return ret;
    }

    /* type of key to generate */
    if (0) {
        /* force fail w/ check on condition "false" */
    }
    else if (XSTRNCMP(keyType, "ed25519", 7) == 0) {
    #ifdef HAVE_ED25519
        int directiveArg = wolfCLU_genKeyDirective(output);

        ret = wolfCLU_genKey_ED25519(&rng, keyOutFName, directiveArg, formatArg);
    #else
        wolfCLU_LogError("Invalid option, ED25519 not enabled.");
        WOLFCLU_LOG(WOLFCLU_L0, "Please re-configure wolfSSL with --enable-ed25519 and "
               "try again");
        wc_FreeRng(&rng);
        return NOT_COMPILED_IN;
    #endif /* HAVE_ED25519 */
    }
    else if (XSTRNCMP(keyType, "ecc", 3) == 0) {
    #if defined(HAVE_ECC) && defined(WOLFSSL_KEY_GEN)
        /* ECC flags */
        int directiveArg = wolfCLU_genKeyDirective(output);

        WOLFCLU_LOG(WOLFCLU_L0, "generate ECC key");

        /* get the curve name */
        if (name != NULL) {
            int i;

            /* convert name to upper case */
            for (i = 0; i < (int)XSTRLEN(name); i++)
                name[i] = (char)toupper((unsigned char)name[i]);
        }
        else {
            WOLFCLU_LOG(WOLFCLU_L0, "DEFAULT: ECC key curve name used");
        }

        ret = wolfCLU_GenAndOutput_ECC(&rng, keyOutFName, directiveArg,
                                 formatArg, name);
    #else
        wolfCLU_LogError("Invalid option, ECC not enabled.");
        WOLFCLU_LOG(WOLFCLU_L0, "Please re-configure wolfSSL with --enable-ecc and "
               "try again");
        wc_FreeRng(&rng);
        return NOT_COMPILED_IN;
    #endif /* HAVE_ECC */
    }
    else if (XSTRNCMP(keyType, "rsa", 3) == 0) {
    #if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)
        /* RSA flags */
        int directiveArg = wolfCLU_genKeyDirective(output);
        int sizeArg = 0;
        int expArg  = 0;

        WOLFCLU_LOG(WOLFCLU_L0, "generate RSA key");

        /* get the size argument */
        if (sizeStr != NULL) {
            char* cur;
            /* make sure it's an integer */
            if (*sizeStr == '\0') {
                WOLFCLU_LOG(WOLFCLU_L0, "Empty -size argument, using 2048");
                sizeArg = 2048;
            }
            else {
                for (cur = sizeStr; *cur && isdigit(*cur); ++cur);
                if (*cur == '\0') {
                    sizeArg = XATOI(sizeStr);
                }
                else {
                    WOLFCLU_LOG(WOLFCLU_L0, "Invalid -size (%s), using 2048",
                           sizeStr);
                    sizeArg = 2048;
                }
            }
        }
        else {
            WOLFCLU_LOG(WOLFCLU_L0, "No -size <SIZE>");
            WOLFCLU_LOG(WOLFCLU_L0, "DEFAULT: use a 2048 RSA key");
            sizeArg = 2048;
        }

        /* get the exponent argument */
        if (expStr != NULL) {
            char* cur;
            /* make sure it's an integer */
            if (*expStr == '\0') {
                WOLFCLU_LOG(WOLFCLU_L0, "Empty -exponent argument, using 65537");
                expArg = 65537;
            }
            else {
                for (cur = expStr; *cur && isdigit(*cur); ++cur);
                if (*cur == '\0') {
                    expArg = XATOI(expStr);
                }
                else {
                    WOLFCLU_LOG(WOLFCLU_L0, "Invalid -exponent (%s), using 65537",
                           expStr);
                    expArg = 65537;
                }
            }
        }
        else {
            WOLFCLU_LOG(WOLFCLU_L0, "No -exponent <SIZE>");
            WOLFCLU_LOG(WOLFCLU_L0, "DEFAULT: use an exponent of 65537");
            expArg = 65537;
        }

        ret = wolfCLU_genKey_RSA(&rng, keyOutFName, directiveArg,
                                 formatArg, sizeArg, expArg);
    #else
        wolfCLU_LogError("Invalid option, RSA not enabled.");
        WOLFCLU_LOG(WOLFCLU_L0, "Please re-configure wolfSSL with --enable-rsa and "
               "try again");
        wc_FreeRng(&rng);
        return NOT_COMPILED_IN;
    #endif /* NO_RSA */
    }
    else if (XSTRNCMP(keyType, "dilithium", 9) == 0) {
    #if defined(HAVE_DILITHIUM) && defined(WOLFSSL_KEY_GEN)
        int directiveArg = wolfCLU_genKeyDirective(output);
        int keySz = DILITHIUM_LEVEL2_PRV_KEY_SIZE;
        int level = 2;
        int withAlg = DILITHIUM_LEVEL2k;

        WOLFCLU_LOG(WOLFCLU_L0, "Generate Dilithium Key");

        /* get the level argument */
        if (levelStr != NULL) {
            level = XATOI(levelStr);
            switch (level) {
                case 2:
                    keySz = DILITHIUM_LEVEL2_PRV_KEY_SIZE;
                    withAlg = DILITHIUM_LEVEL2k;
                    break;
                case 3:
                    keySz = DILITHIUM_LEVEL3_PRV_KEY_SIZE;
                    withAlg = DILITHIUM_LEVEL3k;
                    break;
                case 5:
                    keySz = DILITHIUM_LEVEL5_PRV_KEY_SIZE;
                    withAlg = DILITHIUM_LEVEL5k;
                    break;
                default:
                    WOLFCLU_LOG(WOLFCLU_L0, "Invalid -level (%s), using level%d",
                                levelStr, level);
                    break;
            }
        }
        else {
            /* no option -level */
            WOLFCLU_LOG(WOLFCLU_L0, "No -level [ 2 | 3 | 5 ]");
            WOLFCLU_LOG(WOLFCLU_L0, "DEFAULT: use Level %d", level);
        }

        WOLFCLU_LOG(WOLFCLU_L0, "using Dilithium%d", level);
        ret = wolfCLU_genKey_Dilithium(&rng, keyOutFName, directiveArg,
            formatArg, keySz, level, withAlg);
    #else
        wolfCLU_LogError("Invalid option, Dithium not enabled.");
        WOLFCLU_LOG(WOLFCLU_L0, "Please re-configure wolfSSL with "
                "--enable-dilithium and try again");
        wc_FreeRng(&rng);
        return NOT_COMPILED_IN;
    #endif  /* HAVE_DILITHIUM */
    }
    else if (XSTRNCMP(keyType, "ml-dsa", 6) == 0) {
    #if defined(HAVE_DILITHIUM) && defined(WOLFSSL_KEY_GEN)
        int directiveArg = wolfCLU_genKeyDirective(output);
        int keySz = ML_DSA_LEVEL2_BOTH_KEY_DER_SIZE;
        int level = WC_ML_DSA_44;
        int withAlg = DILITHIUM_LEVEL2k;

        WOLFCLU_LOG(WOLFCLU_L0, "Generate ML-DSA Key");

        /* get the level argument */
        if (levelStr != NULL) {
            level = XATOI(levelStr);
            switch (level) {
                case WC_ML_DSA_44:
                    keySz    = ML_DSA_LEVEL2_BOTH_KEY_DER_SIZE;
                    withAlg  = ML_DSA_LEVEL2k;
                    break;
                case WC_ML_DSA_65:
                    keySz    = ML_DSA_LEVEL3_BOTH_KEY_DER_SIZE;
                    withAlg  = ML_DSA_LEVEL3k;
                    break;
                case WC_ML_DSA_87:
                    keySz    = ML_DSA_LEVEL5_BOTH_KEY_DER_SIZE;
                    withAlg  = ML_DSA_LEVEL5k;
                    break;
                default:
                    WOLFCLU_LOG(WOLFCLU_L0, "Invalid -level (%s), using level%d",
                                levelStr, level);
                    break;
            }
        }
        else {
            /* no option -level */
            WOLFCLU_LOG(WOLFCLU_L0, "No -level [ 2 | 3 | 5 ]");
            WOLFCLU_LOG(WOLFCLU_L0, "DEFAULT: use Level %d", level);
        }

        ret = wolfCLU_genKey_ML_DSA(&rng, keyOutFName, directiveArg,
                                    formatArg, keySz, level, withAlg);
    #else
        wolfCLU_LogError("Invalid option, ML-DSA not enabled.");
        WOLFCLU_LOG(WOLFCLU_L0, "Please re-configure wolfSSL with "
                "--enable-dilithium and try again");
        wc_FreeRng(&rng);
        return NOT_COMPILED_IN;
    #endif  /* HAVE_DILITHIUM */
    }
    else if (XSTRNCMP(keyType, "xmssmt", 6) == 0) {
    #if defined(WOLFSSL_HAVE_XMSS) && defined(WOLFSSL_KEY_GEN)
        int directiveArg = wolfCLU_genKeyDirective(output);
        char xmssmtParam[XMSSMT_NAME_MAX_LEN + 1];   /* XMSS^MT parameter */
        char xmssmtParamHead[] = "XMSSMT-SHA2_\0";
        const int xmssmtHeadLen = (int)XSTRLEN(xmssmtParamHead);
        int height = 0;
        const int XMSSMT_MIN_HEIGHT = 20;
        const int hdLen = 9;

        WOLFCLU_LOG(WOLFCLU_L0, "Generate XMSS^MT Key");

        /* XMSS/XMSS^MS support only RAW format */
        if (formatArg != RAW_FORM) {
            WOLFCLU_LOG(WOLFCLU_L0, "XMSS/XMSS^MT only supports RAW format");
        }

        /* set XMSS Param head */
        XMEMSET(xmssmtParam, 0, sizeof(xmssmtParam));
        WOLFCLU_LOG(WOLFCLU_L0, "XMSS Param Head: %s\nLength: %d",
                    xmssmtParamHead, xmssmtHeadLen);
        XMEMCPY(xmssmtParam, xmssmtParamHead, xmssmtHeadLen);

        /* get the height argument */
        if (heightStr != NULL) {
            WOLFCLU_LOG(WOLFCLU_L0, "Height: %s", heightStr);

            if (XSTRNCMP(heightStr, "20", 2) == 0
                || XSTRNCMP(heightStr, "40", 2) == 0
                || XSTRNCMP(heightStr, "60", 2) == 0) {
                height = XATOI(heightStr);
            }
            else {
                WOLFCLU_LOG(WOLFCLU_L0, "Invalid -height (%s), using 20", heightStr);
                height = XMSSMT_MIN_HEIGHT;
            }
        }
        else {
            /* no option -height */
            WOLFCLU_LOG(WOLFCLU_L0, "No -height [ 20 | 40 | 60 ]");
            WOLFCLU_LOG(WOLFCLU_L0, "DEFAULT: use height 20");
            height = XMSSMT_MIN_HEIGHT;
        }

        /* get the layer argument */
        if (layerStr != NULL) {
            WOLFCLU_LOG(WOLFCLU_L0, "Layer: %s", layerStr);

            switch (height) {
                case 20:
                    if (XSTRNCMP(layerStr, "2", 1) == 0) {
                        XMEMCPY(xmssmtParam + xmssmtHeadLen, "20/2_256\0", hdLen);
                    }
                    else if (XSTRNCMP(layerStr, "4", 1) == 0) {
                        XMEMCPY(xmssmtParam + xmssmtHeadLen, "20/4_256\0", hdLen);
                    }
                    else {
                        WOLFCLU_LOG(WOLFCLU_L0, "Invalid -layer (%s), using 2", layerStr);
                        XMEMCPY(xmssmtParam + xmssmtHeadLen, "20/2_256\0", hdLen);
                    }
                    break;
                case 40:
                    if (XSTRNCMP(layerStr, "2", 1) == 0) {
                        XMEMCPY(xmssmtParam + xmssmtHeadLen, "40/2_256\0", hdLen);
                    }
                    else if (XSTRNCMP(layerStr, "4", 1) == 0) {
                        XMEMCPY(xmssmtParam + xmssmtHeadLen, "40/4_256\0", hdLen);
                    }
                    else if (XSTRNCMP(layerStr, "8", 1) == 0) {
                        XMEMCPY(xmssmtParam + xmssmtHeadLen, "40/8_256\0", hdLen);
                    }
                    else {
                        WOLFCLU_LOG(WOLFCLU_L0, "Invalid -layer (%s), using 2", layerStr);
                        XMEMCPY(xmssmtParam + xmssmtHeadLen, "40/2_256\0", hdLen);
                    }
                    break;
                case 60:
                    if (XSTRNCMP(layerStr, "3", 1) == 0) {
                        XMEMCPY(xmssmtParam + xmssmtHeadLen, "60/3_256\0", hdLen);
                    }
                    else if (XSTRNCMP(layerStr, "6", 1) == 0) {
                        XMEMCPY(xmssmtParam + xmssmtHeadLen, "60/6_256\0", hdLen);
                    }
                    else if (XSTRNCMP(layerStr, "12", 2) == 0) {
                        XMEMCPY(xmssmtParam + xmssmtHeadLen, "60/12_256\0", hdLen+1);
                    }
                    else {
                        WOLFCLU_LOG(WOLFCLU_L0, "Invalid -layer (%s), using 3", layerStr);
                        XMEMCPY(xmssmtParam + xmssmtHeadLen, "60/3_256\0", hdLen);
                    }
                    break;
                default:
                    WOLFCLU_LOG(WOLFCLU_L0, "Invalid -layer (%s), using 2", layerStr);
                    XMEMCPY(xmssmtParam + xmssmtHeadLen, "20/2_256\0", hdLen);
                    break;
            }
        }
        else {
            /* no option -layer */
            WOLFCLU_LOG(WOLFCLU_L0, "No -layer [ 2 | 4 | 8 ]");
            switch (height) {
                case 20:
                    WOLFCLU_LOG(WOLFCLU_L0, "DEFAULT: use layer 2");
                    XMEMCPY(xmssmtParam + xmssmtHeadLen, "20/2_256\0", hdLen);
                    break;
                case 40:
                    WOLFCLU_LOG(WOLFCLU_L0, "DEFAULT: use layer 2");
                    XMEMCPY(xmssmtParam + xmssmtHeadLen, "40/2_256\0", hdLen);
                    break;
                case 60:
                    WOLFCLU_LOG(WOLFCLU_L0, "DEFAULT: use layer 3");
                    XMEMCPY(xmssmtParam + xmssmtHeadLen, "60/3_256\0", hdLen);
                    break;
                default:
                    WOLFCLU_LOG(WOLFCLU_L0, "DEFAULT: use layer 2");
                    XMEMCPY(xmssmtParam + xmssmtHeadLen, "20/2_256\0", hdLen);
                    break;
            }
        }

        xmssmtParam[XMSSMT_NAME_MAX_LEN] = '\0';

        /* check XMSS Param Length */
        WOLFCLU_LOG(WOLFCLU_L0, "XMSS^MT Param: %s", xmssmtParam);
        if (!(XSTRLEN(xmssmtParam) == XMSSMT_NAME_MIN_LEN
            || XSTRLEN(xmssmtParam) == XMSSMT_NAME_MAX_LEN)) {
            WOLFCLU_LOG(WOLFCLU_L0, "Invalid XMSS parameter length");
            WOLFCLU_LOG(WOLFCLU_L0, "XMSS parameter length: %d", (int)XSTRLEN(xmssmtParam));
            wc_FreeRng(&rng);
            return USER_INPUT_ERROR;
        }

        WOLFCLU_LOG(WOLFCLU_L0, "Generate XMSS^MT Key: %s", xmssmtParam);

        ret = wolfCLU_genKey_XMSS(&rng, keyOutFName, directiveArg, xmssmtParam);
    #else
        wolfCLU_LogError("Invalid option, XMSS not enabled.");
        WOLFCLU_LOG(WOLFCLU_L0, "Please re-configure wolfSSL with"
               "--enable-xmss --enable-experimental andtry again");
        wc_FreeRng(&rng);
        return NOT_COMPILED_IN;
    #endif  /* WOLFSSL_HAVE_XMSS */
    }
    else if (XSTRNCMP(keyType, "xmss", 4) == 0) {
    #if defined(WOLFSSL_HAVE_XMSS) && defined(WOLFSSL_KEY_GEN)
        int directiveArg = wolfCLU_genKeyDirective(output);
        char xmssParam[XMSS_NAME_LEN + 1];   /* XMSS parameter */
        char xmssParamHead[] = "XMSS-SHA2_";
        int xmssHeadLen = (int)XSTRLEN(xmssParamHead);
        const int hLen = 6;

        WOLFCLU_LOG(WOLFCLU_L0, "Generate XMSS Key");

        /* XMSS/XMSS^MS support only RAW format */
        if (formatArg != RAW_FORM) {
            WOLFCLU_LOG(WOLFCLU_L0, "XMSS/XMSS^MT only supports RAW format");
        }

        /* set XMSS Param head */
        XMEMSET(xmssParam, 0, sizeof(xmssParam));
        WOLFCLU_LOG(WOLFCLU_L0, "XMSS Param Head: %s", xmssParamHead);
        XMEMCPY(xmssParam, xmssParamHead, xmssHeadLen);

        /* get the height argument */
        if (heightStr != NULL) {
            WOLFCLU_LOG(WOLFCLU_L0, "Height: %s", heightStr);

            if (XSTRNCMP(heightStr, "10", 2) == 0) {
                XMEMCPY(xmssParam + xmssHeadLen, "10_256", hLen);
            }
            else if (XSTRNCMP(heightStr, "16", 2) == 0) {
                XMEMCPY(xmssParam + xmssHeadLen, "16_256", hLen);
            }
            else if (XSTRNCMP(heightStr, "20", 2) == 0) {
                XMEMCPY(xmssParam + xmssHeadLen, "20_256", hLen);
            }
            else {
                WOLFCLU_LOG(WOLFCLU_L0, "Invalid -height (%s)"
                            "\nDefault: use height 10", heightStr);
                XMEMCPY(xmssParam + xmssHeadLen, "10_256", hLen);
            }
        }
        else {
            /* no option -height */
            WOLFCLU_LOG(WOLFCLU_L0, "No -height [ 10 | 16 | 20 ]");
            WOLFCLU_LOG(WOLFCLU_L0, "DEFAULT: use height 10");
            XMEMCPY(xmssParam + xmssHeadLen, "10_256", hLen);
        }

        xmssParam[XMSS_NAME_LEN] = '\0';

        /* check XMSS Param Length */
        WOLFCLU_LOG(WOLFCLU_L0, "XMSS Param: %s", xmssParam);
        if (XSTRLEN(xmssParam) != XMSS_NAME_LEN) {
            WOLFCLU_LOG(WOLFCLU_L0, "Invalid XMSS parameter length");
            WOLFCLU_LOG(WOLFCLU_L0, "XMSS parameter length: %d", (int)XSTRLEN(xmssParam));
            wc_FreeRng(&rng);
            return WOLFCLU_FATAL_ERROR;
        }

        /* When do sign, file name must be "XMSS-SHA2_<height>_256" */
        if (XSTRNCMP(keyOutFName, xmssParam, XMSS_NAME_LEN) != 0) {
            WOLFCLU_LOG(WOLFCLU_L0, "Warm: When do sign, "
                        "file name must be \"%s\"", xmssParam);
        }

        WOLFCLU_LOG(WOLFCLU_L0, "Generate XMSS Key: %s", xmssParam);

        ret = wolfCLU_genKey_XMSS(&rng, keyOutFName, directiveArg, xmssParam);
    #else
        wolfCLU_LogError("Invalid option, XMSS not enabled.");
        WOLFCLU_LOG(WOLFCLU_L0, "Please re-configure wolfSSL with"
               "--enable-xmss --enable-experimental andtry again");
        wc_FreeRng(&rng);
        return NOT_COMPILED_IN;
    #endif  /* WOLFSSL_HAVE_XMSS */
    }
    else {
        wolfCLU_LogError("\"%s\" is an invalid key type, or not compiled in", keyType);
        wc_FreeRng(&rng);
        return USER_INPUT_ERROR;
    }

    wc_FreeRng(&rng);
    return ret;
#else
    (void)argc;
    (void)argv;
    WOLFCLU_LOG(WOLFCLU_E0, "No filesystem support");
    return WOLFCLU_FATAL_ERROR;
#endif
}

