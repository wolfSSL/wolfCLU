/* clu_crypto_setup.c
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

#ifndef WOLFCLU_NO_FILESYSTEM

/* Decode a hex key string into the caller-provided keyOut buffer.
 *
 * Wraps wolfCLU_hexToBin so the caller's pre-allocated key buffer is not
 * replaced by hexToBin's internal allocation (which would leak the original
 * and, on hexToBin failure, leave the caller pointing at a freed buffer).
 *
 * Returns WOLFCLU_SUCCESS on success, WOLFCLU_FATAL_ERROR on length mismatch
 * or hex decode failure, MEMORY_E on allocation failure. */
static int wolfCLU_loadHexKeyInto(byte* keyOut, int keyBytes,
                                   const char* hex, word32 hexLen)
{
    byte*  tmp = NULL;
    word32 tmpSz = 0;
    char*  hexCopy;
    int    ret;

    if (hexLen != (word32)keyBytes * 2) {
        WOLFCLU_LOG(WOLFCLU_L0, "Length of key provided was: %u.",
                (unsigned int)(hexLen * 4));
        WOLFCLU_LOG(WOLFCLU_L0, "Length of key expected was: %d.",
                keyBytes * 8);
        WOLFCLU_LOG(WOLFCLU_E0,
                "Invalid Key. Must match algorithm key size.");
        return WOLFCLU_FATAL_ERROR;
    }

    hexCopy = (char*)XMALLOC(hexLen + 1, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (hexCopy == NULL) {
        return MEMORY_E;
    }
    XMEMCPY(hexCopy, hex, hexLen);
    hexCopy[hexLen] = '\0';

    ret = wolfCLU_hexToBin(hexCopy, &tmp, &tmpSz,
                           NULL, NULL, NULL,
                           NULL, NULL, NULL,
                           NULL, NULL, NULL);
    wolfCLU_ForceZero(hexCopy, hexLen);
    XFREE(hexCopy, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

    if (ret != WOLFCLU_SUCCESS) {
        WOLFCLU_LOG(WOLFCLU_E0,
                "failed during conversion of Key, ret = %d", ret);
        /* On failure wolfCLU_hexToBin frees its own internal buffer; do not
         * touch tmp here. Propagate MEMORY_E unchanged so callers (and the
         * documented contract above) can distinguish allocation failure
         * from a generic decode error. */
        return (ret == MEMORY_E) ? MEMORY_E : WOLFCLU_FATAL_ERROR;
    }

    XMEMCPY(keyOut, tmp, keyBytes);
    wolfCLU_ForceZero(tmp, tmpSz);
    /* tmp was allocated by wolfCLU_hexToBin with a NULL heap hint
     * (see src/tools/clu_hex_to_bin.c); free it with the same hint. */
    XFREE(tmp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return WOLFCLU_SUCCESS;
}

/* Prompt for a filename on stdin with validation.
 * Returns WOLFCLU_SUCCESS on success, WOLFCLU_FATAL_ERROR on EOF/read error.
 * buf is filled with the stripped, non-empty filename on success. */
static int wolfCLU_readFilename(char* buf, int bufSz, const char* prompt)
{
    while (1) {
        WOLFCLU_LOG(WOLFCLU_L0, "%s", prompt);
        if (fgets(buf, bufSz, stdin) == NULL) {
            wolfCLU_LogError("failed to read file name");
            return WOLFCLU_FATAL_ERROR;
        }
        /* If no newline, line was too long: flush remainder and re-prompt */
        if (strchr(buf, '\n') == NULL) {
            int ch;
            do {
                ch = getchar();
            } while (ch != '\n' && ch != EOF);
            wolfCLU_LogError("input too long, please try again");
            continue;
        }
        buf[strcspn(buf, "\r\n")] = '\0';
        if (buf[0] == '\0') {
            wolfCLU_LogError("empty input, please enter a file name");
            continue;
        }
        return WOLFCLU_SUCCESS;
    }
}

static const struct option crypt_options[] = {
    {"-sha",       no_argument,       0, WOLFCLU_CERT_SHA   },
    {"-sha224",    no_argument,       0, WOLFCLU_CERT_SHA224},
    {"-sha256",    no_argument,       0, WOLFCLU_CERT_SHA256},
    {"-sha384",    no_argument,       0, WOLFCLU_CERT_SHA384},
    {"-sha512",    no_argument,       0, WOLFCLU_CERT_SHA512},

    {"-in",        required_argument, 0, WOLFCLU_INFILE    },
    {"-out",       required_argument, 0, WOLFCLU_OUTFILE   },
    {"-pwd",       required_argument, 0, WOLFCLU_PASSWORD  },
    {"-key",       required_argument, 0, WOLFCLU_KEY       },
    {"-iv",        required_argument, 0, WOLFCLU_IV        },
    {"-inkey",     required_argument, 0, WOLFCLU_INKEY     },
    {"-output",    required_argument, 0, WOLFCLU_OUTPUT    },
    {"-pbkdf2",    no_argument,       0, WOLFCLU_PBKDF2    },
    {"-md",        required_argument, 0, WOLFCLU_MD        },
    {"-d",         no_argument,       0, WOLFCLU_DECRYPT   },
    {"-p",         no_argument,       0, WOLFCLU_DEBUG     },
    {"-k",         required_argument, 0, WOLFCLU_PASSWORD  },
    {"-base64",    no_argument,       0, WOLFCLU_BASE64    },
    {"-nosalt",    no_argument,       0, WOLFCLU_NOSALT    },
    {"-pass",      required_argument, 0, WOLFCLU_PASSWORD_SOURCE  },
    {0, 0, 0, 0} /* terminal element */
};
#endif

/* returns WOLFCLU_SUCCESS on success */
int wolfCLU_setup(int argc, char** argv, char action)
{
#ifndef WOLFCLU_NO_FILESYSTEM
    int      ret        =   0;  /* return variable */
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


    int      passwordSz =   0;
    int      noSalt     =   0;
    int      isBase64   =   0;
    int      keySize    =   0;  /* keysize from name */
    int      block      =   0;  /* block size based on algorithm */
    int      pwdKeyChk  =   0;  /* if a pwdKey has been provided */
    int      ivCheck    =   0;  /* if the user sets the IV explicitly */
    int      keyCheck   =   0;  /* if ivCheck is 1 this should be set also */
    int      inCheck    =   0;  /* if input has been provided */
    int      outCheck   =   0;  /* if output has been provided */
    int      encCheck   =   0;  /* if user is encrypting data */
    int      decCheck   =   0;  /* if user is decrypting data */
    int      inputHex   =   0;  /* if user is encrypting hexidecimal data */
    int      keyType    = WOLFCLU_KEYTYPE_NONE;
                                /* tells Decrypt which key it will be using;
                                 * one of the WOLFCLU_KEYTYPE_* values from
                                 * clu_optargs.h (NONE / PASSWORD / USER) */
    int      verbose   =   0;  /* flag to print out key/iv/salt */
    int      pbkVersion =   1;
    const WOLFSSL_EVP_MD* hashType = wolfSSL_EVP_sha256();

    const WOLFSSL_EVP_CIPHER* cphr = NULL;
    int      option;
    int      longIndex = 1;

    if (action == 'e')
        encCheck = 1;
    if (action == 'd')
        decCheck = 1;

    ret = wolfCLU_checkForArg("-h", 2, argc, argv);
    if (ret > 0) {
        if (encCheck == 1) {
            wolfCLU_encryptHelp();
            return WOLFCLU_SUCCESS;
        }
        else {
            wolfCLU_decryptHelp();
            return WOLFCLU_SUCCESS;
        }
    }

    /* gets blocksize, algorithm, mode, and key size from name argument */
    block = wolfCLU_getAlgo(argc, argv, &alg, &mode, &keySize);
    if (block < 0) {
        wolfCLU_LogError("unable to find algorithm to use");
        return WOLFCLU_FATAL_ERROR;
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

    /* keySize is in bits, but the legacy non-EVP wolfCLU_encrypt path
     * writes keySize *bytes* into this buffer (it conflates the two units
     * internally), so over-allocate to keySize bytes to keep that path
     * safe. The cleanup below also zeros the full allocation. */
    key = (byte*)XMALLOC(keySize, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (key == NULL) {
        wolfCLU_freeBins(pwdKey, iv, NULL, NULL, NULL);
        return MEMORY_E;
    }
    XMEMSET(key, 0, keySize);

    opterr = 0; /* do not display unrecognized options */
    optind = 0; /* start at indent 0 */
    while ((option = wolfCLU_GetOpt(argc, argv, "",
                   crypt_options, &longIndex )) != -1) {

        switch (option) {
        case WOLFCLU_PASSWORD_SOURCE:
            passwordSz = keySize;
            ret = wolfCLU_GetPassword((char*)pwdKey, &passwordSz, optarg);
            /* On an unsupported source wolfCLU_GetPassword zeroes the buffer
             * and fails. Bail out so we do not encrypt under an empty key. */
            if (ret != WOLFCLU_SUCCESS) {
                wolfCLU_freeBins(pwdKey, iv, key, NULL, NULL);
                if (mode != NULL)
                    XFREE(mode, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
                return ret;
            }
            pwdKeyChk = 1;
            keyType   = WOLFCLU_KEYTYPE_PASSWORD;
            break;

        case WOLFCLU_PASSWORD:
            if (optarg == NULL) {
                return WOLFCLU_FATAL_ERROR;
            }
            else {
                XSTRLCPY((char*)pwdKey, optarg, keySize);
                pwdKeyChk = 1;
                keyType   = WOLFCLU_KEYTYPE_PASSWORD;
            }
            break;

        case WOLFCLU_PBKDF2:
            pbkVersion = 2;
            break;

        case WOLFCLU_BASE64:
            isBase64 = 1;
            break;

        case WOLFCLU_NOSALT:
            noSalt = 1;
            break;

        case WOLFCLU_KEY: /* hex key string from the command line */
            if (optarg == NULL) {
                wolfCLU_LogError("no key passed in..");
                wolfCLU_freeBins(pwdKey, iv, key, NULL, NULL);
                return WOLFCLU_FATAL_ERROR;
            }

            ret = wolfCLU_loadHexKeyInto(key, (keySize + 7) / 8,
                    optarg, (word32)XSTRLEN(optarg));
            if (ret != WOLFCLU_SUCCESS) {
                wolfCLU_freeBins(pwdKey, iv, key, NULL, NULL);
                return ret;
            }
            keyCheck = 1;
            keyType = WOLFCLU_KEYTYPE_USER;
            break;

        case WOLFCLU_IV:  /* IV if used must be in hex */
            {
                char*  ivString;
                byte*  ivTmp = NULL;
                word32 ivTmpSz = 0;
                if (optarg == NULL) {
                    return WOLFCLU_FATAL_ERROR;
                }
                ivString = (char*)XMALLOC(XSTRLEN(optarg) + 1, HEAP_HINT,
                        DYNAMIC_TYPE_TMP_BUFFER);
                if (ivString == NULL) {
                    wolfCLU_freeBins(pwdKey, iv, key, NULL, NULL);
                    return MEMORY_E;
                }
                XSTRLCPY(ivString, optarg, XSTRLEN(optarg) + 1);

                /* Decode into a temporary so the pre-allocated `iv` buffer
                 * (block bytes) isn't replaced by hexToBin's internal
                 * allocation, which would leak the original. */
                ret = wolfCLU_hexToBin(ivString, &ivTmp, &ivTmpSz,
                                   NULL, NULL, NULL,
                                   NULL, NULL, NULL,
                                   NULL, NULL, NULL);
                XFREE(ivString, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
                if (ret != WOLFCLU_SUCCESS) {
                    WOLFCLU_LOG(WOLFCLU_E0,
                        "failed during conversion of IV, ret = %d", ret);
                    wolfCLU_freeBins(pwdKey, iv, key, NULL, NULL);
                    return WOLFCLU_FATAL_ERROR;
                }
                if ((int)ivTmpSz != block) {
                    WOLFCLU_LOG(WOLFCLU_E0,
                        "IV length mismatch: expected %d bytes, got %u",
                        block, (unsigned int)ivTmpSz);
                    wolfCLU_ForceZero(ivTmp, ivTmpSz);
                    XFREE(ivTmp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                    wolfCLU_freeBins(pwdKey, iv, key, NULL, NULL);
                    return WOLFCLU_FATAL_ERROR;
                }
                XMEMCPY(iv, ivTmp, ivTmpSz);
                wolfCLU_ForceZero(ivTmp, ivTmpSz);
                /* hexToBin allocates with NULL heap hint; free with same. */
                XFREE(ivTmp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
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
            if (optarg) wolfCLU_convertToLower(optarg, (int)XSTRLEN(optarg));
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
            {
                WOLFSSL_BIO* keyBio = NULL;
                byte* fileBuf = NULL;
                int   fileLen = 0;
                int   keyBytes = (keySize + 7) / 8;
                int   isHex = 1;
                int   i;

                if (optarg == NULL) {
                    wolfCLU_LogError("no key file passed in..");
                    wolfCLU_freeBins(pwdKey, iv, key, NULL, NULL);
                    return WOLFCLU_FATAL_ERROR;
                }

                /* -inkey is "input file for key" (matches the help text and
                 * openssl convention). The argument must name a real file;
                 * use -key for a hex key on the command line. */
                keyBio = wolfSSL_BIO_new_file(optarg, "rb");
                if (keyBio == NULL) {
                    wolfCLU_LogError("could not open key file '%s'", optarg);
                    wolfCLU_freeBins(pwdKey, iv, key, NULL, NULL);
                    return WOLFCLU_FATAL_ERROR;
                }

                fileLen = wolfSSL_BIO_get_len(keyBio);
                if (fileLen <= 0) {
                    wolfCLU_LogError("key file '%s' is empty or unreadable",
                            optarg);
                    wolfSSL_BIO_free(keyBio);
                    wolfCLU_freeBins(pwdKey, iv, key, NULL, NULL);
                    return WOLFCLU_FATAL_ERROR;
                }

                fileBuf = (byte*)XMALLOC(fileLen, HEAP_HINT,
                        DYNAMIC_TYPE_TMP_BUFFER);
                if (fileBuf == NULL) {
                    wolfSSL_BIO_free(keyBio);
                    wolfCLU_freeBins(pwdKey, iv, key, NULL, NULL);
                    return MEMORY_E;
                }

                if (wolfSSL_BIO_read(keyBio, fileBuf, fileLen) != fileLen) {
                    wolfCLU_LogError("failed to read key file '%s'", optarg);
                    wolfCLU_ForceZero(fileBuf, fileLen);
                    XFREE(fileBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
                    wolfSSL_BIO_free(keyBio);
                    wolfCLU_freeBins(pwdKey, iv, key, NULL, NULL);
                    return WOLFCLU_FATAL_ERROR;
                }
                wolfSSL_BIO_free(keyBio);

                /* Decide hex vs raw by inspecting every byte. Whitespace
                 * (\r \n space tab) is allowed inside hex files as a
                 * separator; any non-hex non-whitespace byte means the
                 * file is raw binary. fileLen is left unmodified so a
                 * raw-binary key whose last byte is 0x09/0x0A/0x0D/0x20
                 * still round-trips correctly. */
                for (i = 0; i < fileLen; i++) {
                    byte c = fileBuf[i];
                    if (c == '\r' || c == '\n' || c == ' ' || c == '\t') {
                        continue;
                    }
                    if (!wolfCLU_isHexDigit(c)) {
                        isHex = 0;
                        break;
                    }
                }

                if (isHex) {
                    char* keyString;
                    int   j = 0;

                    keyString = (char*)XMALLOC(fileLen + 1, HEAP_HINT,
                            DYNAMIC_TYPE_TMP_BUFFER);
                    if (keyString == NULL) {
                        wolfCLU_ForceZero(fileBuf, fileLen);
                        XFREE(fileBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
                        wolfCLU_freeBins(pwdKey, iv, key, NULL, NULL);
                        return MEMORY_E;
                    }
                    /* Copy out hex characters, skipping any embedded
                     * whitespace so block-formatted hex files work. */
                    for (i = 0; i < fileLen; i++) {
                        byte c = fileBuf[i];
                        if (c == '\r' || c == '\n' || c == ' ' || c == '\t') {
                            continue;
                        }
                        keyString[j++] = (char)c;
                    }
                    keyString[j] = '\0';

                    ret = wolfCLU_loadHexKeyInto(key, keyBytes,
                            keyString, (word32)j);
                    wolfCLU_ForceZero(keyString, j);
                    XFREE(keyString, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
                    wolfCLU_ForceZero(fileBuf, fileLen);
                    XFREE(fileBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
                    if (ret != WOLFCLU_SUCCESS) {
                        wolfCLU_freeBins(pwdKey, iv, key, NULL, NULL);
                        return ret;
                    }
                }
                else {
                    /* Raw binary key. Length must match the algorithm. */
                    if (fileLen != keyBytes) {
                        WOLFCLU_LOG(WOLFCLU_L0,
                                "Length of key provided was: %d bits.",
                                fileLen * 8);
                        WOLFCLU_LOG(WOLFCLU_L0,
                                "Length of key expected was: %d bits.",
                                keySize);
                        WOLFCLU_LOG(WOLFCLU_E0,
                                "Invalid Key. Must match algorithm key size.");
                        wolfCLU_ForceZero(fileBuf, fileLen);
                        XFREE(fileBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
                        wolfCLU_freeBins(pwdKey, iv, key, NULL, NULL);
                        return WOLFCLU_FATAL_ERROR;
                    }
                    XMEMCPY(key, fileBuf, fileLen);
                    wolfCLU_ForceZero(fileBuf, fileLen);
                    XFREE(fileBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
                }

                keyCheck = 1;
                keyType = WOLFCLU_KEYTYPE_USER;
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
                wolfCLU_LogError("Invalid digest name");
                return WOLFCLU_FATAL_ERROR;
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
            wolfCLU_LogError("no key or passphrase set");
            WOLFCLU_LOG(WOLFCLU_L0,
                    "Please type \"wolfssl -decrypt -help\" for decryption"
                                                            " usage \n");
            return WOLFCLU_FATAL_ERROR;
        }
        /* if no pwdKey is provided */
        else {
            WOLFCLU_LOG(WOLFCLU_L0,
                    "No -pwd flag set, please enter a password to use for"
                    " encrypting.");
            ret = wolfCLU_GetStdinPassword(pwdKey, (word32*)&keySize);
            pwdKeyChk = 1;
        }
    }

    if (inCheck == 0 && encCheck == 1) {
        ret = wolfCLU_readFilename(inName, sizeof(inName),
                "-in flag was not set, please enter a string or"
                " file name to be encrypted: ");
        if (ret != WOLFCLU_SUCCESS) {
            wolfCLU_freeBins(pwdKey, iv, key, NULL, NULL);
            if (mode != NULL)
                XFREE(mode, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            return WOLFCLU_FATAL_ERROR;
        }
        WOLFCLU_LOG(WOLFCLU_L0, "Encrypting :\"%s\"", inName);
        inCheck = 1;
    }

    if (encCheck == 1 && decCheck == 1) {
        WOLFCLU_LOG(WOLFCLU_E0,
                "Encrypt and decrypt simultaneously is invalid");
        wolfCLU_freeBins(pwdKey, iv, key, NULL, NULL);
        return WOLFCLU_FATAL_ERROR;
    }

    if (inCheck == 0 && decCheck == 1) {
        wolfCLU_LogError("File/string to decrypt needed");
        wolfCLU_freeBins(pwdKey, iv, key, NULL, NULL);
        return WOLFCLU_FATAL_ERROR;
    }

    if (ivCheck == 1) {
        if (keyCheck == 0) {
            WOLFCLU_LOG(WOLFCLU_E0,
                    "-iv was explicitly set, but no -key or -inkey was"
                    " provided. A non-password based key must be supplied"
                    " when setting the -iv flag.");
            wolfCLU_freeBins(pwdKey, iv, key, NULL, NULL);
            return WOLFCLU_FATAL_ERROR;
        }
    }

    /* When the user supplies an explicit -key/-inkey, no salt-based
     * key/iv derivation runs. The cipher therefore needs an explicit -iv:
     * silently using the all-zero buffer would produce ciphertext that no
     * one (including this tool on a later run) can decrypt safely. */
    if (keyCheck == 1 && ivCheck == 0) {
        WOLFCLU_LOG(WOLFCLU_E0,
                "-key/-inkey requires -iv to be set: an IV must be"
                " supplied alongside an explicit key.");
        wolfCLU_freeBins(pwdKey, iv, key, NULL, NULL);
        return WOLFCLU_FATAL_ERROR;
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
                  out, NULL, iv, 0, 1, pbkVersion, hashType, verbose, isBase64,
                  noSalt, keyType);
        }
        else {
            if (outCheck == 0) {
                ret = wolfCLU_readFilename(outNameEnc, sizeof(outNameEnc),
                        "Please enter a name for the output file: ");
                if (ret != WOLFCLU_SUCCESS) {
                    wolfCLU_freeBins(pwdKey, iv, key, NULL, NULL);
                    if (mode != NULL)
                        XFREE(mode, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
                    return WOLFCLU_FATAL_ERROR;
                }
                out = outNameEnc;
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
                    out, NULL, iv, 0, 0, pbkVersion, hashType, verbose,
                    isBase64, noSalt, keyType);
        }
        else {
            if (outCheck == 0) {
                ret = wolfCLU_readFilename(outNameDec, sizeof(outNameDec),
                        "Please enter a name for the output file: ");
                if (ret != WOLFCLU_SUCCESS) {
                    wolfCLU_freeBins(pwdKey, iv, key, NULL, NULL);
                    if (mode != NULL)
                        XFREE(mode, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
                    return WOLFCLU_FATAL_ERROR;
                }
                out = outNameDec;
            }
            ret = wolfCLU_decrypt(alg, mode, pwdKey, key, keySize, in, out,
                iv, block, keyType);
        }
    }
    else {
        wolfCLU_help();
    }
    /* clear and free data — zero the full allocation, not just the
     * keyBytes actually used, so any future code path that writes past
     * the cipher key length doesn't leak material across XFREE. */
    XMEMSET(key, 0, keySize);
    XMEMSET(pwdKey, 0, keySize + block);
    XMEMSET(iv, 0, block);
    wolfCLU_freeBins(pwdKey, iv, key, NULL, NULL);

    if (mode != NULL)
        XFREE(mode, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
#else
    (void)argc;
    (void)argv;
    (void)action;
    WOLFCLU_LOG(WOLFCLU_E0, "No filesystem support");
    return WOLFCLU_FATAL_ERROR;
#endif
}
