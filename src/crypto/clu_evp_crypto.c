/* clu_evp_crypto.c
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
#include <wolfclu/genkey/clu_genkey.h>

#ifndef WOLFCLU_MAX_BUFFER
#define WOLFCLU_MAX_BUFFER 1024
#endif


/* return WOLFCLU_SUCCESS on success */
int wolfCLU_evp_crypto(const WOLFSSL_EVP_CIPHER* cphr, char* mode, byte* pwdKey,
        byte* key, int keySz, char* fileIn, char* fileOut, char* hexIn,
        byte* iv, int hexOut, int enc, int pbkVersion,
        const WOLFSSL_EVP_MD* hashType, int printOut, int isBase64, int noSalt)
{
    WOLFSSL_BIO *out = NULL;
    WOLFSSL_BIO *in  = NULL;
    WOLFSSL_BIO *tmp = NULL;
    WOLFSSL_EVP_CIPHER_CTX* ctx    = NULL;

    WC_RNG     rng;                 /* random number generator declaration */

    byte*   input = NULL;           /* input buffer */
    byte*   output = NULL;          /* output buffer */
    byte    salt[SALT_SIZE] = {0};  /* salt variable */

    int     ret             = WOLFCLU_SUCCESS;
    int     hexRet          = 0;    /* hex -> bin return*/
    int     ivSz            = 0;
    int     outputSz        = 0;
    int     iter            = 10000; /* default value for interop */

    word32  tempInputL      = 0;    /* temporary input Length */
    word32  tempMax         = WOLFCLU_MAX_BUFFER; /* controls encryption amount */

    char    inputString[WOLFCLU_MAX_BUFFER];       /* the input string */
    const char isSalted[] = "Salted__";

    if (cphr == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Start up the random number generator */
    if (wc_InitRng(&rng) != 0) {
        WOLFCLU_LOG(WOLFCLU_E0, "Random Number Generator failed to start.");
        ret = WOLFCLU_FATAL_ERROR;
    }

    /* open the inFile in read mode */
    if (fileIn != NULL) {
        in = wolfSSL_BIO_new_file(fileIn, "rb");
        if (in != NULL && !enc && isBase64) {
            byte *decodedBase64 = NULL;
            word32 decodeSz;

            decodeSz = wolfSSL_BIO_get_len(in);
            decodedBase64 = (byte*)XMALLOC(decodeSz, HEAP_HINT,
                    DYNAMIC_TYPE_TMP_BUFFER);
            if (decodedBase64 == NULL) {
                ret = WOLFCLU_FATAL_ERROR;
            }
            else {
                if (wolfSSL_BIO_read(in, decodedBase64, decodeSz) !=
                        (int)decodeSz) {
                    ret = WOLFCLU_FATAL_ERROR;
                }

                if (ret == WOLFCLU_SUCCESS &&
                        Base64_Decode(decodedBase64, decodeSz,
                            decodedBase64, &decodeSz) != 0) {
                    ret = WOLFCLU_FATAL_ERROR;
                }

                if (ret == WOLFCLU_SUCCESS) {
                    wolfSSL_BIO_free(in);
                    in = wolfSSL_BIO_new_mem_buf(decodedBase64, decodeSz);
                }
            }
        }
    }
    else {
        /* read hex from string instead */
        in = wolfSSL_BIO_new_mem_buf(hexIn, (int)XSTRLEN(hexIn));
    }

    if (in == NULL) {
        WOLFCLU_LOG(WOLFCLU_E0, "unable to open file %s", fileIn);
        return WOLFCLU_FATAL_ERROR;
    }

    if (ret >= 0) {
        ctx = wolfSSL_EVP_CIPHER_CTX_new();
        if (ctx == NULL) {
            WOLFCLU_LOG(WOLFCLU_E0, "Unable to create new ctx");
            ret = MEMORY_E;
        }
    }

    if (ret >= 0) {
        /* stretches pwdKey to fit size based on wolfCLU_getAlgo() */
        ivSz = wolfSSL_EVP_CIPHER_iv_length(cphr);
        if (enc) {
            /* randomly generates salt */
            ret = wc_RNG_GenerateBlock(&rng, salt, SALT_SIZE);
            if (ret != 0) {
                WOLFCLU_LOG(WOLFCLU_E0, "Error creating salt");
                ret = -1;
            }
        }
        else {
            if (!noSalt) {
                char s[sizeof(isSalted)];

                if (wolfSSL_BIO_read(in, s, (int)XSTRLEN(isSalted)) <= 0) {
                    WOLFCLU_LOG(WOLFCLU_E0, "Error reading salted string");
                    ret = WOLFCLU_FATAL_ERROR;
                }
                s[XSTRLEN(isSalted)] = '\0';

                if (ret >= 0 &&
                    XMEMCMP(s, isSalted, (int)XSTRLEN(isSalted)) != 0) {
                    WOLFCLU_LOG(WOLFCLU_E0, "Was expecting salt");
                    ret = WOLFCLU_FATAL_ERROR;
                }

                if (ret >= 0) {
                    ret = wolfSSL_BIO_read(in, salt, SALT_SIZE);
                    if (ret != SALT_SIZE) {
                        WOLFCLU_LOG(WOLFCLU_E0, "error reading salt");
                        ret = WOLFCLU_FATAL_ERROR;
                    }
                }
            }
        }
    }

    /* stretches pwdKey */
    if (ret >= 0) {
        if (pbkVersion == WOLFCLU_PBKDF2) {
        #ifdef HAVE_FIPS
            if (strlen((const char*)pwdKey) < HMAC_FIPS_MIN_KEY) {
                WOLFCLU_LOG(WOLFCLU_E0, "For use with FIPS mode key needs to be"
                        " at least %d characters long", HMAC_FIPS_MIN_KEY);
                ret = WOLFCLU_FATAL_ERROR;
            }
        #endif
            if (ret >= 0) {
                if (noSalt) {
                    ret = wolfSSL_PKCS5_PBKDF2_HMAC((const char*)pwdKey,
                    (int) strlen((const char*)pwdKey), NULL, 0, iter,
                    hashType, keySz + ivSz, pwdKey);
                }
                else {
                    ret = wolfSSL_PKCS5_PBKDF2_HMAC((const char*)pwdKey,
                    (int) strlen((const char*)pwdKey), salt, SALT_SIZE, iter,
                    hashType, keySz + ivSz, pwdKey);
                }
                if (ret != WOLFSSL_SUCCESS) {
                    WOLFCLU_LOG(WOLFCLU_E0, "failed to create key, ret = %d", ret);
                    ret = WOLFCLU_FATAL_ERROR;
                }
            }

            if (ret >= 0) {
                /* move the generated pwdKey to "key" for encrypting */
                XMEMCPY(key, pwdKey, keySz);
                XMEMCPY(iv, pwdKey + keySz, ivSz);
            }
        }
        else {
            WOLFCLU_LOG(WOLFCLU_L0, "WARNING: Using old version of PBKDF!!!!");
            iter = 1; /* default value for interop */
            if (noSalt) {
                ret = wolfSSL_EVP_BytesToKey(cphr, hashType, NULL,
                    pwdKey, (int)strlen((const char*)pwdKey), iter, key, iv);
            }
            else {
                ret = wolfSSL_EVP_BytesToKey(cphr, hashType, salt,
                    pwdKey, (int)strlen((const char*)pwdKey), iter, key, iv);
            }
            if (ret == 0) {
                WOLFCLU_LOG(WOLFCLU_E0, "failed to create key, ret = %d", ret);
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
    }

    /* open the outFile in write mode */
    if (ret >= 0) {
        if (fileOut != NULL) {
            out = wolfSSL_BIO_new_file(fileOut, "wb");
        }
        else {
            /* write to stdout if no file provided  */
            out = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
            wolfSSL_BIO_set_fp(out, stdout, BIO_NOCLOSE);
        }
        if (out == NULL) {
            WOLFCLU_LOG(WOLFCLU_E0, "unable to open output file %s", fileOut);
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* store up output and pass output through a base64 encoding BIO */
    if (ret >= 0 && enc && isBase64) {
        tmp = out;
        out = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
        if (out == NULL) {
            WOLFCLU_LOG(WOLFCLU_E0, "unable to create temporary memory");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* when encrypting a file write out the salt value generated */
    if (ret >= 0 && enc) {
        if (wolfSSL_BIO_write(out, isSalted, (int)XSTRLEN(isSalted)) !=
                (int)XSTRLEN(isSalted)) {
            WOLFCLU_LOG(WOLFCLU_E0, "issue writing out isSalted");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret >= 0 && enc) {
        if (wolfSSL_BIO_write(out, salt, SALT_SIZE) != SALT_SIZE) {
            WOLFCLU_LOG(WOLFCLU_E0, "issue writing out salt");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (printOut) {
        int z;
        if (!noSalt) {
            printf("salt [%d] :", SALT_SIZE);
            for (z = 0; z < SALT_SIZE; z++)
                printf("%02X", salt[z]);
            printf("\n");
        }
        printf("key  [%d] :", keySz);
        for (z = 0; z < keySz; z++)
            printf("%02X", key[z]);
        printf("\n");
        printf("iv   [%d] :", ivSz);
        for (z = 0; z < ivSz; z++)
            printf("%02X", iv[z]);
        printf("\n");
        WOLFCLU_LOG(WOLFCLU_L0, "itterations = %d", iter);
        WOLFCLU_LOG(WOLFCLU_L0, "PBKDF version = %d", pbkVersion);
    }

    if (ret >= 0) {
        wolfSSL_EVP_CIPHER_CTX_init(ctx);
        if (wolfSSL_EVP_CipherInit(ctx, cphr, key, iv, enc) != WOLFSSL_SUCCESS){
            WOLFCLU_LOG(WOLFCLU_E0, "failed to init evp ctx");
            ret = MEMORY_E;
        }
    }

    /* MALLOC 1kB buffers */
    if (ret >= 0) {
        input = (byte*)XMALLOC(WOLFCLU_MAX_BUFFER, HEAP_HINT,
                DYNAMIC_TYPE_TMP_BUFFER);
        if (input == NULL)
            ret = MEMORY_E;
    }

    if (ret >= 0) {
        output = (byte*)XMALLOC(WOLFCLU_MAX_BUFFER, HEAP_HINT,
                DYNAMIC_TYPE_TMP_BUFFER);
        if (output == NULL) {
            ret = MEMORY_E;
        }
    }

    /* loop, encrypt 1kB at a time till length <= 0 */
    while (ret >= 0 && wolfSSL_BIO_get_len(in) > 0) {
        /* Read in 1kB to input[] */
        ret = wolfSSL_BIO_read(in, input, WOLFCLU_MAX_BUFFER);
        if (ret < 0) {
            WOLFCLU_LOG(WOLFCLU_E0, "error reading in data");
            ret = WOLFCLU_FATAL_ERROR;
        }
        if (ret <= 0) {
            break; /* hit end of buffer or error */
        }

        if (ret >= 0 && hexIn) {
            hexRet = wolfCLU_hexToBin(inputString, &input, &tempInputL,
                                                NULL, NULL, NULL,
                                                NULL, NULL, NULL,
                                                NULL, NULL, NULL);
            if (hexRet != 0) {
                WOLFCLU_LOG(WOLFCLU_E0, "failed during conversion of input, "
                        "ret = %d", hexRet);
                ret = WOLFCLU_FATAL_ERROR;
            }
        }

        if (ret >= 0) {
            tempMax = ret;
            outputSz = WOLFCLU_MAX_BUFFER;
            if (wolfSSL_EVP_CipherUpdate(ctx, output, &outputSz, input, tempMax)
                    != WOLFSSL_SUCCESS) {
                WOLFCLU_LOG(WOLFCLU_E0, "Error with cipher update");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }

        if (ret >= 0) {
            ret = wolfSSL_BIO_write(out, output, outputSz);
            if (ret < 0) {
                WOLFCLU_LOG(WOLFCLU_E0, "Error writing out encrypted data");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
    }

    if (ret >= 0) {
        /* flush out last block (could have padding) */
        outputSz = tempMax;
        if (wolfSSL_EVP_CipherFinal(ctx, output, &outputSz)
                != WOLFSSL_SUCCESS) {
            WOLFCLU_LOG(WOLFCLU_E0, "Error decrypting message");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret >= 0) {
        wolfSSL_BIO_write(out, output, outputSz);
    }

    /* write out stored up output in base64 encrypt case */
    if (ret >= 0 && enc && isBase64) {
        WOLFSSL_BUF_MEM *mem = NULL;
        WOLFSSL_BIO *base64Bio = NULL;

        if (wolfSSL_BIO_get_mem_ptr(out, &mem) != WOLFSSL_SUCCESS) {
            WOLFCLU_LOG(WOLFCLU_E0, "Error getting internal memory of input");
            ret = WOLFCLU_FATAL_ERROR;
        }

        if (ret >= 0) {
            base64Bio = wolfSSL_BIO_push(wolfSSL_BIO_new(
                        wolfSSL_BIO_f_base64()), tmp);
            if (base64Bio == NULL) {
                WOLFCLU_LOG(WOLFCLU_E0, "Error setting up base64 encoding");
                ret = WOLFCLU_FATAL_ERROR;
            }
            else {
                wolfSSL_BIO_write(base64Bio, mem->data, (int)mem->length);
                wolfSSL_BIO_free(base64Bio);
            }
        }
    }

    /* closes the opened files and frees the memory */
    wolfSSL_BIO_free(out);
    wolfSSL_BIO_free(in);
    wolfSSL_BIO_free(tmp);

    XMEMSET(key, 0, keySz);
    XMEMSET(iv, 0 , ivSz);

    wc_FreeRng(&rng);
    wolfCLU_freeBins(input, output, NULL, NULL, NULL);
    wolfSSL_EVP_CIPHER_CTX_free(ctx);

    (void)mode;
    (void)hexOut;
    return ret;
}

