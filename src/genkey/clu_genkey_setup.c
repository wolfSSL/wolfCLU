/* clu_genkey_setup.c
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
#include <wolfclu/x509/clu_cert.h>  /* argument checking */

/* return WOLFCLU_SUCCESS on success */
int wolfCLU_genKeySetup(int argc, char** argv)
{
#ifndef WOLFCLU_NO_FILESYSTEM
    char     keyOutFName[MAX_FILENAME_SZ];  /* default outFile for genKey */
    char     defaultFormat[4] = "der\0";
    WC_RNG   rng;

    char*    keyType = NULL;       /* keyType */
    char*    format  = defaultFormat;
    char*    name    = NULL;

    int      formatArg;
    int      ret;

    ret = wolfCLU_checkForArg("-h", 2, argc, argv);
    if (ret > 0) {
        wolfCLU_genKeyHelp();
        return WOLFCLU_SUCCESS;
    }

    XMEMSET(keyOutFName, 0, MAX_FILENAME_SZ);

    keyType = argv[2];

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        wolfCLU_LogError("rng init failed");
        return ret;
    }

    ret = wolfCLU_checkForArg("-out", 4, argc, argv);
    if (ret > 0) {
        if (argv[ret+1] != NULL) {
            XSTRLCPY(keyOutFName, argv[ret+1], XSTRLEN(argv[ret+1])+1);
        }
        else {
            wolfCLU_LogError("ERROR: No output file name specified");
            wolfCLU_genKeyHelp();
            wc_FreeRng(&rng);
            return USER_INPUT_ERROR;
        }
    }
    else {
        wolfCLU_LogError("ERROR: Please specify an output file name");
        wolfCLU_genKeyHelp();
        wc_FreeRng(&rng);
        return USER_INPUT_ERROR;
    }

    ret = wolfCLU_checkForArg("-outform", 8, argc, argv);
    if (ret > 0) {
        format = argv[ret+1];
    }
    ret = wolfCLU_checkOutform(format);
    if (ret == PEM_FORM || ret == DER_FORM || ret == RAW_FORM) {
        const char* formatStr = (ret == PEM_FORM) ? "PEM" :
                                (ret == DER_FORM) ? "DER" :
                                "RAW";

        WOLFCLU_LOG(WOLFCLU_L0, "OUTPUT A %s FILE", formatStr);
        formatArg = ret;
    }
    else {
        wolfCLU_LogError("ERROR: \"%s\" is not a valid file format", format);
        wc_FreeRng(&rng);
        return ret;
    }

    /* type of key to generate */
    if (0) {
        /* force fail w/ check on condition "false" */
    }
    else if (XSTRNCMP(keyType, "ed25519", 7) == 0) {

    #ifdef HAVE_ED25519

        ret = wolfCLU_checkForArg("-output", 7, argc, argv);
        if (ret > 0) {
            if (argv[ret+1] != NULL) {
                if (XSTRNCMP(argv[ret+1], "pub", 3) == 0)
                    ret = wolfCLU_genKey_ED25519(&rng, keyOutFName, PUB_ONLY_FILE,
                                                                     formatArg);
                else if (XSTRNCMP(argv[ret+1], "priv", 4) == 0)
                    ret = wolfCLU_genKey_ED25519(&rng, keyOutFName, PRIV_ONLY_FILE,
                                                                     formatArg);
                else if (XSTRNCMP(argv[ret+1], "keypair", 7) == 0)
                    ret = wolfCLU_genKey_ED25519(&rng, keyOutFName,
                                                       PRIV_AND_PUB_FILES, formatArg);
            }
        }
        else {
            WOLFCLU_LOG(WOLFCLU_L0, "No -output <PUB/PRIV/KEYPAIR>");
            WOLFCLU_LOG(WOLFCLU_L0, "DEFAULT: output public and private key pair");
            ret = wolfCLU_genKey_ED25519(&rng, keyOutFName, PRIV_AND_PUB_FILES,
                                                                     formatArg);
        }
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
        int directiveArg = PRIV_AND_PUB_FILES;

        WOLFCLU_LOG(WOLFCLU_L0, "generate ECC key");

        /* get the directive argument */
        ret = wolfCLU_checkForArg("-output", 7, argc, argv);
        if (ret > 0) {
            if (argv[ret+1] != NULL) {
                if (XSTRNCMP(argv[ret+1], "pub", 3) == 0)
                    directiveArg = PUB_ONLY_FILE;
                else if (XSTRNCMP(argv[ret+1], "priv", 4) == 0)
                    directiveArg = PRIV_ONLY_FILE;
                else if (XSTRNCMP(argv[ret+1], "keypair", 7) == 0)
                    directiveArg = PRIV_AND_PUB_FILES;
            }
        }
        else {
            WOLFCLU_LOG(WOLFCLU_L0, "No -output <PUB/PRIV/KEYPAIR>");
            WOLFCLU_LOG(WOLFCLU_L0, "DEFAULT: output public and private key pair");
            directiveArg = PRIV_AND_PUB_FILES;
        }

        /* get the curve name */
        ret = wolfCLU_checkForArg("-name", 5, argc, argv);
        if (ret > 0) {
            if (argv[ret+1] != NULL) {
                int i;

                name = argv[ret+1];

                /* convert name to upper case */
                for (i = 0; i < (int)XSTRLEN(name); i++)
                    (void)toupper(name[i]);
            }
        }

        if (name == NULL) {
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
        int directiveArg = PRIV_AND_PUB_FILES;
        int sizeArg = 0;
        int expArg  = 0;

        WOLFCLU_LOG(WOLFCLU_L0, "generate RSA key");

        /* get the directive argument */
        ret = wolfCLU_checkForArg("-output", 7, argc, argv);
        if (ret > 0) {
            if (argv[ret+1] != NULL) {
                if (XSTRNCMP(argv[ret+1], "pub", 3) == 0)
                    directiveArg = PUB_ONLY_FILE;
                else if (XSTRNCMP(argv[ret+1], "priv", 4) == 0)
                    directiveArg = PRIV_ONLY_FILE;
                else if (XSTRNCMP(argv[ret+1], "keypair", 7) == 0)
                    directiveArg = PRIV_AND_PUB_FILES;
            }
        }
        else {
            WOLFCLU_LOG(WOLFCLU_L0, "No -output <PUB/PRIV/KEYPAIR>");
            WOLFCLU_LOG(WOLFCLU_L0, "DEFAULT: output public and private key pair");
            directiveArg = PRIV_AND_PUB_FILES;
        }

        /* get the size argument */
        ret = wolfCLU_checkForArg("-size", 5, argc, argv);
        if (ret > 0) {
            if (argv[ret+1] != NULL) {
                char* cur;
                /* make sure it's an integer */
                if (*argv[ret+1] == '\0') {
                    WOLFCLU_LOG(WOLFCLU_L0, "Empty -size argument, using 2048");
                    sizeArg = 2048;
                }
                else {
                    for (cur = argv[ret+1]; *cur && isdigit(*cur); ++cur);
                    if (*cur == '\0') {
                        sizeArg = XATOI(argv[ret+1]);
                    }
                    else {
                        WOLFCLU_LOG(WOLFCLU_L0, "Invalid -size (%s), using 2048",
                               argv[ret+1]);
                        sizeArg = 2048;
                    }
                }
            }
        }
        else {
            WOLFCLU_LOG(WOLFCLU_L0, "No -size <SIZE>");
            WOLFCLU_LOG(WOLFCLU_L0, "DEFAULT: use a 2048 RSA key");
            sizeArg = 2048;
        }

        /* get the exponent argument */
        ret = wolfCLU_checkForArg("-exponent", 9, argc, argv);
        if (ret > 0) {
            if (argv[ret+1] != NULL) {
                char* cur;
                /* make sure it's an integer */
                if (*argv[ret+1] == '\0') {
                    WOLFCLU_LOG(WOLFCLU_L0, "Empty -exponent argument, using 65537");
                    expArg = 65537;
                }
                else {
                    for (cur = argv[ret+1]; *cur && isdigit(*cur); ++cur);
                    if (*cur == '\0') {
                        sizeArg = XATOI(argv[ret+1]);
                    }
                    else {
                        WOLFCLU_LOG(WOLFCLU_L0, "Invalid -exponent (%s), using 65537",
                               argv[ret+1]);
                        expArg = 65537;
                    }
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
        int directiveArg = PRIV_AND_PUB_FILES;
        int keySz = DILITHIUM_LEVEL2_PRV_KEY_SIZE;
        int level = 2;
        int withAlg = DILITHIUM_LEVEL2k;

        WOLFCLU_LOG(WOLFCLU_L0, "Generate Dilithium Key");

        /* get the level argument */
        ret = wolfCLU_checkForArg("-level", 6, argc, argv);
        if (ret > 0) {
            level = XATOI(argv[ret+1]);
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
                                argv[ret+1], level);
                    break;
            }
        }
        else {
            /* no option -level */
            WOLFCLU_LOG(WOLFCLU_L0, "No -level [ 2 | 3 | 5 ]");
            WOLFCLU_LOG(WOLFCLU_L0, "DEFAULT: use Level %d", level);
        }

        /* get the directive argument */
        ret = wolfCLU_checkForArg("-output", 7, argc, argv);
        if (ret > 0) {
            if (argv[ret+1] != NULL) {
                if (XSTRNCMP(argv[ret+1], "pub", 3) == 0)
                    directiveArg = PUB_ONLY_FILE;
                else if (XSTRNCMP(argv[ret+1], "priv", 4) == 0)
                    directiveArg = PRIV_ONLY_FILE;
                else if (XSTRNCMP(argv[ret+1], "keypair", 7) == 0)
                    directiveArg = PRIV_AND_PUB_FILES;
            }
        }
        else {
            WOLFCLU_LOG(WOLFCLU_L0, "No -output <PUB/PRIV/KEYPAIR>");
            WOLFCLU_LOG(WOLFCLU_L0, "DEFAULT: output public and private key pair");
        }

        WOLFCLU_LOG(WOLFCLU_L0, "using Dilithium%d", level);
        ret = wolfCLU_genKey_Dilithium(&rng, keyOutFName, directiveArg,
            formatArg, keySz, level, withAlg);
    #else
        wolfCLU_LogError("Invalid option, Dithium not enabled.");
        WOLFCLU_LOG(WOLFCLU_L0, "Please re-configure wolfSSL with "
                "--enable-dilithium, --enable-experimental and try again");
        wc_FreeRng(&rng);
        return NOT_COMPILED_IN;
    #endif  /* HAVE_DILITHIUM */
    }
    else if (XSTRNCMP(keyType, "ml-dsa", 6) == 0) {
    #if defined(HAVE_DILITHIUM) && defined(WOLFSSL_KEY_GEN)
        int directiveArg = PRIV_AND_PUB_FILES;
        int keySz = DILITHIUM_ML_DSA_44_PRV_KEY_SIZE;
        int level = WC_ML_DSA_44;
        int withAlg = DILITHIUM_LEVEL2k;
        const char* levelStr;

        WOLFCLU_LOG(WOLFCLU_L0, "Generate ML-DSA Key");

        /* get the level argument */
        ret = wolfCLU_checkForArg("-level", 6, argc, argv);
        if (ret > 0) {
            level = XATOI(argv[ret+1]);
            switch (level) {
                case WC_ML_DSA_44:
                    keySz = DILITHIUM_ML_DSA_44_PRV_KEY_SIZE;
                    withAlg = ML_DSA_LEVEL2k;
                    break;
                case WC_ML_DSA_65:
                    keySz = DILITHIUM_ML_DSA_65_PRV_KEY_SIZE;
                    withAlg = ML_DSA_LEVEL3k;
                    break;
                case WC_ML_DSA_87:
                    keySz = DILITHIUM_ML_DSA_87_PRV_KEY_SIZE;
                    withAlg = ML_DSA_LEVEL5k;
                    break;
                default:
                    WOLFCLU_LOG(WOLFCLU_L0, "Invalid -level (%s), using level%d",
                                argv[ret+1], level);
                    break;
            }
        }
        else {
            /* no option -level */
            WOLFCLU_LOG(WOLFCLU_L0, "No -level [ 2 | 3 | 5 ]");
            WOLFCLU_LOG(WOLFCLU_L0, "DEFAULT: use Level %d", level);
        }

        /* get the directive argument */
        ret = wolfCLU_checkForArg("-output", 7, argc, argv);
        if (ret > 0) {
            if (argv[ret+1] != NULL) {
                if (XSTRNCMP(argv[ret+1], "pub", 3) == 0)
                    directiveArg = PUB_ONLY_FILE;
                else if (XSTRNCMP(argv[ret+1], "priv", 4) == 0)
                    directiveArg = PRIV_ONLY_FILE;
                else if (XSTRNCMP(argv[ret+1], "keypair", 7) == 0)
                    directiveArg = PRIV_AND_PUB_FILES;
            }
        }
        else {
            WOLFCLU_LOG(WOLFCLU_L0, "No -output <PUB/PRIV/KEYPAIR>");
            WOLFCLU_LOG(WOLFCLU_L0, "DEFAULT: output public and private key pair");
        }

        levelStr = (level == WC_ML_DSA_44) ? "44" :
               (level == WC_ML_DSA_65) ? "65" :
               (level == WC_ML_DSA_87) ? "87" : "Unknown";
        WOLFCLU_LOG(WOLFCLU_L0, "using ML-DSA-%s", levelStr);
        ret = wolfCLU_genKey_ML_DSA(&rng, keyOutFName, directiveArg,
            formatArg, keySz, level, withAlg);
    #else
        wolfCLU_LogError("Invalid option, ML-DSA not enabled.");
        WOLFCLU_LOG(WOLFCLU_L0, "Please re-configure wolfSSL with "
                "--enable-dilithium, --enable-experimental and try again");
        wc_FreeRng(&rng);
        return NOT_COMPILED_IN;
    #endif  /* HAVE_DILITHIUM */
    }
    else if (XSTRNCMP(keyType, "xmssmt", 6) == 0) {
    #if defined(WOLFSSL_HAVE_XMSS) && defined(WOLFSSL_KEY_GEN)
        int directiveArg = PRIV_AND_PUB_FILES;
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

        /* get the directive argument */
        ret = wolfCLU_checkForArg("-output", 7, argc, argv);
        if (ret > 0) {
            if (argv[ret+1] != NULL) {
                if (XSTRNCMP(argv[ret+1], "pub", 3) == 0)
                    directiveArg = PUB_ONLY_FILE;
                else if (XSTRNCMP(argv[ret+1], "priv", 4) == 0)
                    directiveArg = PRIV_ONLY_FILE;
                else if (XSTRNCMP(argv[ret+1], "keypair", 7) == 0)
                    directiveArg = PRIV_AND_PUB_FILES;
            }
        }
        else {
            WOLFCLU_LOG(WOLFCLU_L0, "No -output <PUB/PRIV/KEYPAIR>");
            WOLFCLU_LOG(WOLFCLU_L0, "DEFAULT: output public and private key pair");
        }

        /* set XMSS Param head */
        XMEMSET(xmssmtParam, 0, XSTRLEN(xmssmtParam));
        WOLFCLU_LOG(WOLFCLU_L0, "XMSS Param Head: %s\nLength: %d",
                    xmssmtParamHead, xmssmtHeadLen);
        XMEMCPY(xmssmtParam, xmssmtParamHead, xmssmtHeadLen);

        /* get the height argument */
        ret = wolfCLU_checkForArg("-height", 7, argc, argv);
        if (ret > 0 || argv[ret+1] != NULL) {
            WOLFCLU_LOG(WOLFCLU_L0, "Height: %s", argv[ret+1]);
            
            if (XSTRNCMP(argv[ret+1], "20", 2) == 0
                || XSTRNCMP(argv[ret+1], "40", 2) == 0
                || XSTRNCMP(argv[ret+1], "60", 2) == 0) {
                height = XATOI(argv[ret+1]);
            }
            else {
                WOLFCLU_LOG(WOLFCLU_L0, "Invalid -height (%s), using 20", argv[ret+1]);
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
        ret = wolfCLU_checkForArg("-layer", 6, argc, argv);
        if (ret > 0 || argv[ret+1] != NULL) {
            WOLFCLU_LOG(WOLFCLU_L0, "Layer: %s", argv[ret+1]);
            
            switch (height) {
                case 20:
                    if (XSTRNCMP(argv[ret+1], "2", 1) == 0) {
                        XMEMCPY(xmssmtParam + xmssmtHeadLen, "20/2_256\0", hdLen);
                    }
                    else if (XSTRNCMP(argv[ret+1], "4", 1) == 0) {
                        XMEMCPY(xmssmtParam + xmssmtHeadLen, "20/4_256\0", hdLen);
                    }
                    else {
                        WOLFCLU_LOG(WOLFCLU_L0, "Invalid -layer (%s), using 2", argv[ret+1]);
                        XMEMCPY(xmssmtParam + xmssmtHeadLen, "20/2_256\0", hdLen);
                    }
                    break;
                case 40:
                    if (XSTRNCMP(argv[ret+1], "2", 1) == 0) {
                        XMEMCPY(xmssmtParam + xmssmtHeadLen, "40/2_256\0", hdLen);
                    }
                    else if (XSTRNCMP(argv[ret+1], "4", 1) == 0) {
                        XMEMCPY(xmssmtParam + xmssmtHeadLen, "40/4_256\0", hdLen);
                    }
                    else if (XSTRNCMP(argv[ret+1], "8", 1) == 0) {
                        XMEMCPY(xmssmtParam + xmssmtHeadLen, "40/8_256\0", hdLen);
                    }
                    else {
                        WOLFCLU_LOG(WOLFCLU_L0, "Invalid -layer (%s), using 2", argv[ret+1]);
                        XMEMCPY(xmssmtParam + xmssmtHeadLen, "40/2_25\0", hdLen);
                    }
                    break;
                case 60:
                    if (XSTRNCMP(argv[ret+1], "3", 1) == 0) {
                        XMEMCPY(xmssmtParam + xmssmtHeadLen, "60/3_256\0", hdLen);
                    }
                    else if (XSTRNCMP(argv[ret+1], "6", 1) == 0) {
                        XMEMCPY(xmssmtParam + xmssmtHeadLen, "60/8_256\0", hdLen);
                    }
                    else if (XSTRNCMP(argv[ret+1], "12", 2) == 0) {
                        XMEMCPY(xmssmtParam + xmssmtHeadLen, "60/12_256\0", hdLen+1);
                    }
                    else {
                        WOLFCLU_LOG(WOLFCLU_L0, "Invalid -layer (%s), using 3", argv[ret+1]);
                        XMEMCPY(xmssmtParam + xmssmtHeadLen, "60/3_256\0", hdLen);
                    }
                    break;
                default:
                    WOLFCLU_LOG(WOLFCLU_L0, "Invalid -layer (%s), using 2", argv[ret+1]);
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
        int directiveArg = PRIV_AND_PUB_FILES;
        char xmssParam[XMSS_NAME_LEN + 1];   /* XMSS parameter */
        char xmssParamHead[] = "XMSS-SHA2_";
        int xmssHeadLen = (int)XSTRLEN(xmssParamHead);
        const int hLen = 6;

        WOLFCLU_LOG(WOLFCLU_L0, "Generate XMSS Key");

        /* XMSS/XMSS^MS support only RAW format */
        if (formatArg != RAW_FORM) {
            WOLFCLU_LOG(WOLFCLU_L0, "XMSS/XMSS^MT only supports RAW format");
        }

        /* get the directive argument */
        ret = wolfCLU_checkForArg("-output", 7, argc, argv);
        if (ret > 0) {
            if (argv[ret+1] != NULL) {
                if (XSTRNCMP(argv[ret+1], "pub", 3) == 0)
                    directiveArg = PUB_ONLY_FILE;
                else if (XSTRNCMP(argv[ret+1], "priv", 4) == 0)
                    directiveArg = PRIV_ONLY_FILE;
                else if (XSTRNCMP(argv[ret+1], "keypair", 7) == 0)
                    directiveArg = PRIV_AND_PUB_FILES;
            }
        }
        else {
            WOLFCLU_LOG(WOLFCLU_L0, "No -output <PUB/PRIV/KEYPAIR>");
            WOLFCLU_LOG(WOLFCLU_L0, "DEFAULT: output public and private key pair");
        }

        /* set XMSS Param head */
        XMEMSET(xmssParam, 0, XSTRLEN(xmssParam));
        WOLFCLU_LOG(WOLFCLU_L0, "XMSS Param Head: %s", xmssParamHead);
        XMEMCPY(xmssParam, xmssParamHead, xmssHeadLen);

        /* get the height argument */
        ret = wolfCLU_checkForArg("-height", 7, argc, argv);
        if (ret > 0 || argv[ret+1] != NULL) {
            WOLFCLU_LOG(WOLFCLU_L0, "Height: %s", argv[ret+1]);
            
            if (XSTRNCMP(argv[ret+1], "10", 2) == 0) {
                XMEMCPY(xmssParam + xmssHeadLen, "10_256", hLen);
            }
            else if (XSTRNCMP(argv[ret+1], "16", 2) == 0) {
                XMEMCPY(xmssParam + xmssHeadLen, "16_256", hLen);
            }
            else if (XSTRNCMP(argv[ret+1], "20", 2) == 0) {
                XMEMCPY(xmssParam + xmssHeadLen, "20_256", hLen);
            }
            else {
                WOLFCLU_LOG(WOLFCLU_L0, "Invalid -height (%s)"
                            "\nDefault: use height 10", argv[ret+1]);
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

