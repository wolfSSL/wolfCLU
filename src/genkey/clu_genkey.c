/* clu_genkey.c
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

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/asn_public.h> /* wc_DerToPem */

#if defined(WOLFSSL_KEY_GEN) && !defined(NO_ASN)

#include <wolfclu/clu_header_main.h>
#include <wolfclu/clu_log.h>
#include <wolfclu/genkey/clu_genkey.h>
#include <wolfclu/x509/clu_parse.h>
#include <wolfclu/x509/clu_cert.h>    /* PER_FORM/DER_FORM */

#ifdef HAVE_ED25519
/* return WOLFCLU_SUCCESS on success */
int wolfCLU_genKey_ED25519(WC_RNG* rng, char* fOutNm, int directive, int format)
{
    int ret;                             /* return value */
    int fOutNmSz;                        /* file name without append */
    int fOutNmAppendSz = 6;              /* # of bytes to append to file name */
    int flagOutputPub = 0;              /* set if outputting both priv/pub */
    char privAppend[6] = ".priv\0";      /* last part of the priv file name */
    char pubAppend[6] = ".pub\0\0";      /* last part of the pub file name*/
    byte privKeyBuf[ED25519_KEY_SIZE*2]; /* will hold public & private parts */
    byte pubKeyBuf[ED25519_KEY_SIZE];    /* holds just the public key part */
    word32 privKeySz;                    /* size of private key */
    word32 pubKeySz;                     /* size of public key */
    ed25519_key edKeyOut;                /* the ed25519 key structure */
    char* finalOutFNm;                   /* file name + append */
    XFILE file;                          /* file stream */


    WOLFCLU_LOG(WOLFCLU_L0, "fOutNm = %s", fOutNm);
    fOutNmSz = (int)XSTRLEN(fOutNm);

    /*--------------- INIT ---------------------*/
    ret = wc_ed25519_init(&edKeyOut);
    if (ret != 0)
        return ret;
    /*--------------- MAKE KEY ---------------------*/
    ret = wc_ed25519_make_key(rng, ED25519_KEY_SIZE, &edKeyOut);
    if (ret != 0)
        return ret;
    /*--------------- GET KEY SIZES ---------------------*/
    privKeySz = wc_ed25519_priv_size(&edKeyOut);
    if (privKeySz <= 0)
        return WC_KEY_SIZE_E;

    pubKeySz = wc_ed25519_pub_size(&edKeyOut);
    if (pubKeySz <= 0)
        return WC_KEY_SIZE_E;
    /*--------------- EXPORT KEYS TO BUFFERS ---------------------*/
    ret = wc_ed25519_export_key(&edKeyOut, privKeyBuf, &privKeySz, pubKeyBuf,
                                                                     &pubKeySz);
    if (ret != 0)
        return ret;

    /*--------------- CONVERT TO PEM IF APPLICABLE  ---------------------*/
    if (format == PEM_FORM) {
        WOLFCLU_LOG(WOLFCLU_L0, "Der to Pem for ed25519 key not yet implemented");
        WOLFCLU_LOG(WOLFCLU_L0, "FEATURE COMING SOON!");
        return FEATURE_COMING_SOON;
    }
    /*--------------- OUTPUT KEYS TO FILE(S) ---------------------*/
    finalOutFNm = (char*) XMALLOC( (fOutNmSz + fOutNmAppendSz), HEAP_HINT,
                                               DYNAMIC_TYPE_TMP_BUFFER);
    if (finalOutFNm == NULL)
        return MEMORY_E;

    /* get the first part of the file name setup */
    XMEMSET(finalOutFNm, 0, fOutNmSz + fOutNmAppendSz);
    XMEMCPY(finalOutFNm, fOutNm, fOutNmSz);

    switch(directive) {
        case PRIV_AND_PUB:
            flagOutputPub = 1;
            /* Fall through to PRIV_ONLY */
            FALL_THROUGH;
        case PRIV_ONLY:
            /* add on the final part of the file name ".priv" */
            XMEMCPY(finalOutFNm+fOutNmSz, privAppend, fOutNmAppendSz);
            WOLFCLU_LOG(WOLFCLU_L0, "finalOutFNm = %s", finalOutFNm);

            file = XFOPEN(finalOutFNm, "wb");
            if (!file) {
                XFREE(finalOutFNm, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
                return OUTPUT_FILE_ERROR;
            }

            ret = (int)XFWRITE(privKeyBuf, 1, privKeySz, file);
            if (ret <= 0) {
                XFCLOSE(file);
                XFREE(finalOutFNm, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
                return OUTPUT_FILE_ERROR;
            }
            fclose(file);

            if (flagOutputPub == 0) {
                break;
            } /* else fall through to PUB_ONLY if flagOutputPub == 1*/
            FALL_THROUGH;
        case PUB_ONLY:
            /* add on the final part of the file name ".pub" */
            XMEMCPY(finalOutFNm+fOutNmSz, pubAppend, fOutNmAppendSz);
            WOLFCLU_LOG(WOLFCLU_L0, "finalOutFNm = %s", finalOutFNm);

            file = XFOPEN(finalOutFNm, "wb");
            if (!file) {
                XFREE(finalOutFNm, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
                return OUTPUT_FILE_ERROR;
            }

            ret = (int)XFWRITE(pubKeyBuf, 1, pubKeySz, file);
            if (ret <= 0) {
                XFCLOSE(file);
                XFREE(finalOutFNm, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
                return OUTPUT_FILE_ERROR;
            }
            XFCLOSE(file);
            break;
        default:
            WOLFCLU_LOG(WOLFCLU_L0, "Invalid directive");
            XFREE(finalOutFNm, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            return BAD_FUNC_ARG;
    }

    XFREE(finalOutFNm, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

    if (ret > 0) {
        /* ret > 0 indicates a successful file write, set to zero for return */
        ret = WOLFCLU_SUCCESS;
    }

    return ret;
}
#endif /* HAVE_ED25519 */

#ifdef HAVE_ECC
/* returns WOLFCLU_SUCCESS on successfully writing out public DER key */
static int wolfCLU_ECC_write_pub_der(WOLFSSL_BIO* out, WOLFSSL_EC_KEY* key)
{
    int derSz, ret = WOLFCLU_SUCCESS;
    unsigned char *der = NULL;

    if (out == NULL || key == NULL)
        return BAD_FUNC_ARG;

    derSz = wc_EccPublicKeyDerSize(key->internal, 1);
    if (derSz <= 0) {
        WOLFCLU_LOG(WOLFCLU_L0, "error getting der size");
        ret = derSz;
    }

    if (ret == WOLFCLU_SUCCESS) {
        der = (byte*)XMALLOC(derSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (der == NULL) {
            ret = MEMORY_E;
        }
        else {
            derSz = wc_EccPublicKeyToDer(key->internal, der, derSz, 1);
            if (derSz < 0) {
                ret = derSz;
            }
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = wolfSSL_BIO_write(out, der, derSz);
        if (ret != derSz) {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (der != NULL)
        XFREE(der, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}


/* returns WOLFCLU_SUCCESS on successfully writing out private DER key */
static int wolfCLU_ECC_write_priv_der(WOLFSSL_BIO* out, WOLFSSL_EC_KEY* key)
{
    int derSz = 0, ret;
    unsigned char *der = NULL;

    if (out == NULL || key == NULL)
        return BAD_FUNC_ARG;

    ret = wc_EccKeyDerSize(key->internal, 0);
    if (ret > 0) {
        derSz = ret;
        der   = (byte*)XMALLOC(derSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (der == NULL) {
            ret = MEMORY_E;
        }
        else {
            ret = wc_EccPrivateKeyToDer(key->internal, der, derSz);
        }
    }

    if (ret > 0) {
        WOLFCLU_LOG(WOLFCLU_L0, "writing out %d bytes for private key", derSz);
        ret = wolfSSL_BIO_write(out, der, derSz);
        if (ret != derSz) {
            ret = WOLFCLU_FATAL_ERROR;
        }
        WOLFCLU_LOG(WOLFCLU_L0, "ret of write = %d", ret);
    }

    if (der != NULL)
        XFREE(der, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

    if (ret > 0)
        ret = WOLFCLU_SUCCESS; /* successfully wrote out key */

    return ret;
}
#endif /* HAVE_ECC */

/* return WOLFCLU_SUCCESS on success */
int wolfCLU_genKey_ECC(WC_RNG* rng, char* fName, int directive, int fmt,
                       char* name)
{
#ifdef HAVE_ECC
    int   fNameSz;
    int   fExtSz      = 6;
    char  fExtPriv[6] = ".priv\0";
    char  fExtPub[6]  = ".pub\0\0";
    char* fOutNameBuf = NULL;

    WOLFSSL_BIO *bioOut = NULL;
    WOLFSSL_BIO *bioPub = NULL;
    WOLFSSL_BIO *bioPri = NULL;
    WOLFSSL_EC_KEY   *key;
    int ret = WOLFCLU_SUCCESS;

    byte*  der   = NULL;
    int    derSz = -1;

    if (rng == NULL || fName == NULL)
        return BAD_FUNC_ARG;
    fNameSz = (int)XSTRLEN(fName);

    key = wolfSSL_EC_KEY_new();
    if (key == NULL)
        return MEMORY_E;

    if (name != NULL) {
        WOLFSSL_EC_GROUP *group;

        group = wolfSSL_EC_GROUP_new_by_curve_name(wolfSSL_OBJ_txt2nid(name));
        if (group == NULL) {
            WOLFCLU_LOG(WOLFCLU_L0, "unable to set curve");
            ret = WOLFCLU_FATAL_ERROR;
        }

        if (ret == WOLFCLU_SUCCESS) {
            if (wolfSSL_EC_KEY_set_group(key, group) != WOLFSSL_SUCCESS) {
                WOLFCLU_LOG(WOLFCLU_L0, "unable to set ec group");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        if (wolfSSL_EC_KEY_generate_key(key) != WOLFSSL_SUCCESS) {
            WOLFCLU_LOG(WOLFCLU_L0, "error generating EC key");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        bioOut = wolfSSL_BIO_new_file(fName, "wb");
        if (bioOut == NULL) {
            WOLFCLU_LOG(WOLFCLU_L0, "unable to open output file %s", fName);
            ret = MEMORY_E;
        }
    }

    /* create buffer for alternate file name use */
    if (ret == WOLFCLU_SUCCESS) {
        fOutNameBuf = (char*)XMALLOC(fNameSz + fExtSz + 1, NULL,
                DYNAMIC_TYPE_TMP_BUFFER);
        if (fOutNameBuf == NULL) {
            ret = MEMORY_E;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        switch(directive) {
            case ECPARAM:
                {
                    if (fmt == PEM_FORM) {
                        if (wolfSSL_PEM_write_bio_ECPrivateKey(bioOut, key,
                                NULL, NULL, 0, NULL, NULL) != WOLFSSL_SUCCESS) {
                            ret = WOLFCLU_FATAL_ERROR;
                        }
                    }
                    else {

                        derSz = wolfSSL_i2d_ECPrivateKey(key, &der);

                        if (ret == 0 && derSz > 0) {
                            ret = wolfSSL_BIO_write(bioOut, der, derSz);
                            if (ret != derSz) {
                                WOLFCLU_LOG(WOLFCLU_L0, "issue writing out data");
                                ret = WOLFCLU_FATAL_ERROR;
                            }
                        }

                        if (der != NULL) {
                            /* der was created by wolfSSL library so we assume
                             * that XMALLOC was used and call XFREE here */
                            XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                        }
                    }
                }
                break;
            case PUB_ONLY:
                if (fmt == PEM_FORM) {
                    if (wolfSSL_PEM_write_bio_EC_PUBKEY(bioOut, key)
                            != WOLFSSL_SUCCESS) {
                        ret = WOLFCLU_FATAL_ERROR;
                    }
                }
                else {
                    ret = wolfCLU_ECC_write_pub_der(bioOut, key);
                }
                break;
            case PRIV_AND_PUB:
                /* Fall through to PRIV_ONLY */
            case PRIV_ONLY_FILE: /* adding .priv to file name */
                if (ret == WOLFCLU_SUCCESS) {
                    XMEMCPY(fOutNameBuf, fName, fNameSz);
                    XMEMCPY(fOutNameBuf + fNameSz, fExtPriv, fExtSz);
                    fOutNameBuf[fNameSz + fExtSz] = '\0';
                    WOLFCLU_LOG(WOLFCLU_L0, "Private key file = %s", fOutNameBuf);

                    bioPri = wolfSSL_BIO_new_file(fOutNameBuf, "wb");
                    if (bioPri == NULL) {
                        WOLFCLU_LOG(WOLFCLU_L0, "unable to read outfile %s", fOutNameBuf);
                        ret = MEMORY_E;
                    }
                }

                if (ret == WOLFCLU_SUCCESS) {
                    if (fmt == PEM_FORM) {
                        if (wolfSSL_PEM_write_bio_ECPrivateKey(bioPri, key,
                                NULL, NULL, 0, NULL, NULL) != WOLFSSL_SUCCESS) {
                            ret = WOLFCLU_FATAL_ERROR;
                        }
                    }
                    else {
                        ret = wolfCLU_ECC_write_priv_der(bioPri, key);
                    }
                }

                if (ret < 0) {
                    break;
                }
                if (directive != PRIV_AND_PUB) {
                    break;
                }
                FALL_THROUGH;
            case PUB_ONLY_FILE: /* appending .pub to file name */
                if (ret == WOLFCLU_SUCCESS) {
                    XMEMCPY(fOutNameBuf, fName, fNameSz);
                    XMEMCPY(fOutNameBuf + fNameSz, fExtPub, fExtSz);
                    fOutNameBuf[fNameSz + fExtSz] = '\0';
                    WOLFCLU_LOG(WOLFCLU_L0, "Public key file = %s", fOutNameBuf);

                    bioPub = wolfSSL_BIO_new_file(fOutNameBuf, "wb");
                    if (bioPub == NULL) {
                        WOLFCLU_LOG(WOLFCLU_L0, "unable to read outfile %s", fOutNameBuf);
                        ret = MEMORY_E;
                    }
                }

                if (ret == WOLFCLU_SUCCESS) {
                    if (fmt == PEM_FORM) {
                        if (wolfSSL_PEM_write_bio_EC_PUBKEY(bioPub, key)
                            != WOLFSSL_SUCCESS) {
                            ret = WOLFCLU_FATAL_ERROR;
                        }
                    }
                    else {
                        ret = wolfCLU_ECC_write_pub_der(bioPub, key);
                    }
                }
                break;
            default:
                WOLFCLU_LOG(WOLFCLU_L0, "Invalid directive");
                ret = BAD_FUNC_ARG;
        }
    }

    wolfSSL_EC_KEY_free(key);
    wolfSSL_BIO_free(bioOut);
    wolfSSL_BIO_free(bioPri);
    wolfSSL_BIO_free(bioPub);

    if (fOutNameBuf != NULL) {
        XFREE(fOutNameBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    if (ret > 0) {
        /* ret > 0 indicates a successful file write, set to zero for return */
        ret = WOLFCLU_SUCCESS;
    }

    return ret;
#else
    (void)rng;
    (void)fName;
    (void)directive;
    (void)fmt;

    return NOT_COMPILED_IN;
#endif /* HAVE_ECC */
}


#ifndef NO_RSA
/* helper function to convert a key to PEM format. Creates new 'out' buffer on
 * success.
 * returns size of PEM buffer created on success
 * returns 0 or negative value on failure */
static int wolfCLU_KeyDerToPem(byte* der, int derSz, byte** out, int pemType,
        int heapType)
{
    int pemBufSz;
    byte* pemBuf = NULL;

    if (out == NULL || der == NULL || derSz <= 0) {
        return 0;
    }

    pemBufSz = wc_DerToPemEx(der, derSz, NULL, 0, NULL, pemType);
    if (pemBufSz > 0) {
        pemBuf = (byte*)XMALLOC(pemBufSz, HEAP_HINT, heapType);
        if (pemBuf == NULL) {
            pemBufSz = 0;
        }
        else {
            pemBufSz = wc_DerToPemEx(der, derSz, pemBuf, pemBufSz, NULL,
                    pemType);
        }
    }

    if (pemBufSz <= 0 && pemBuf != NULL) {
        XFREE(pemBuf, HEAP_HINT, heapType);
        pemBuf = NULL;
    }
    *out = pemBuf;
    return pemBufSz;
}
#endif /* !NO_RSA */


/* return WOLFCLU_SUCCESS on success */
int wolfCLU_genKey_RSA(WC_RNG* rng, char* fName, int directive, int fmt, int
                       keySz, long exp)
{
#ifndef NO_RSA
    RsaKey key;
    XFILE  file;
    int    ret = WOLFCLU_SUCCESS;

    int   fNameSz;
    int   fExtSz      = 6;
    char  fExtPriv[6] = ".priv\0";
    char  fExtPub[6]  = ".pub\0\0";
    char* fOutNameBuf = NULL;

    #ifdef NO_AES
    /* use 16 bytes for AES block size */
    size_t maxDerBufSz = 4 * keySz * 16;
    #else
    size_t maxDerBufSz = 4 * keySz * AES_BLOCK_SIZE;
    #endif
    byte*  derBuf      = NULL;
    byte*  pemBuf      = NULL;
    byte*  outBuf      = NULL;
    int    derBufSz    = -1;
    int    pemBufSz    = 0;
    int    outBufSz    = 0;

    if (rng == NULL || fName == NULL)
        return BAD_FUNC_ARG;

    if (wc_InitRsaKey(&key, HEAP_HINT) != 0) {
        return WOLFCLU_FAILURE;
    }

    if (wc_MakeRsaKey(&key, keySz, exp, rng) != 0) {
        ret = WOLFCLU_FAILURE;
    }

    /* set up the file name output buffer */
    if (ret == WOLFCLU_SUCCESS) {
        fNameSz     = (int)XSTRLEN(fName);
        fOutNameBuf = (char*)XMALLOC(fNameSz + fExtSz, HEAP_HINT,
                                 DYNAMIC_TYPE_TMP_BUFFER);
        if (fOutNameBuf == NULL)
            ret = MEMORY_E;
    }

    if (ret == WOLFCLU_SUCCESS) {
        XMEMSET(fOutNameBuf, 0, fNameSz + fExtSz);
        XMEMCPY(fOutNameBuf, fName, fNameSz);

        derBuf = (byte*) XMALLOC(maxDerBufSz, HEAP_HINT,
                DYNAMIC_TYPE_TMP_BUFFER);
        if (derBuf == NULL) {
            ret = MEMORY_E;
        }
    }

    switch(directive) {
        case PRIV_AND_PUB:
            /* Fall through to PRIV_ONLY */
            FALL_THROUGH;
        case PRIV_ONLY_FILE:
            /* default to DER output */
            outBuf   = derBuf;
            outBufSz = derBufSz;

            if (ret == WOLFCLU_SUCCESS) {
                /* add on the final part of the file name ".priv" */
                XMEMCPY(fOutNameBuf + fNameSz, fExtPriv, fExtSz);
                WOLFCLU_LOG(WOLFCLU_L0, "fOutNameBuf = %s", fOutNameBuf);

                derBufSz = wc_RsaKeyToDer(&key, derBuf, (word32)maxDerBufSz);
                if (derBufSz < 0) {
                    ret = derBufSz;
                }
            }

            /* check if should convert to PEM format */
            if (ret == WOLFCLU_SUCCESS && fmt == PEM_FORM) {
                pemBufSz = wolfCLU_KeyDerToPem(derBuf, derBufSz, &pemBuf,
                        PRIVATEKEY_TYPE, DYNAMIC_TYPE_PRIVATE_KEY);
                if (pemBufSz <= 0 || pemBuf == NULL) {
                    ret =  WOLFCLU_FAILURE;
                }
                outBuf   = pemBuf;
                outBufSz = pemBufSz;
            }

            if (ret == WOLFCLU_SUCCESS) {
                file = XFOPEN(fOutNameBuf, "wb");
                if (file == XBADFILE) {
                    ret = OUTPUT_FILE_ERROR;
                }
            }

            if (ret == WOLFCLU_SUCCESS) {
                if ((int)XFWRITE(outBuf, 1, outBufSz, file) <= 0) {
                    ret = OUTPUT_FILE_ERROR;
                }
                XFCLOSE(file);
            }

            if (pemBuf != NULL) {
                XFREE(pemBuf, HEAP_HINT, DYNAMIC_TYPE_PRIVATE_KEY);
            }

            if (directive != PRIV_AND_PUB) {
                break;
            }
            FALL_THROUGH;
        case PUB_ONLY_FILE:
            /* default to DER output */
            outBuf   = derBuf;
            outBufSz = derBufSz;

            /* add on the final part of the file name ".pub" */
            if (ret == WOLFCLU_SUCCESS) {
                XMEMCPY(fOutNameBuf + fNameSz, fExtPub, fExtSz);
                WOLFCLU_LOG(WOLFCLU_L0, "fOutNameBuf = %s", fOutNameBuf);

                derBufSz = wc_RsaKeyToPublicDer(&key, derBuf,
                        (word32)maxDerBufSz);
                if (derBufSz < 0) {
                    ret = derBufSz;
                }
            }

            /* check if should convert to PEM format */
            if (ret == WOLFCLU_SUCCESS && fmt == PEM_FORM) {
                pemBufSz = wolfCLU_KeyDerToPem(derBuf, derBufSz, &pemBuf,
                        PUBLICKEY_TYPE, DYNAMIC_TYPE_PUBLIC_KEY);
                if (pemBufSz <= 0 || pemBuf == NULL) {
                    ret =  WOLFCLU_FAILURE;
                }
                outBuf   = pemBuf;
                outBufSz = pemBufSz;
            }

            if (ret == WOLFCLU_SUCCESS) {
                file = XFOPEN(fOutNameBuf, "wb");
                if (file == XBADFILE) {
                    ret = OUTPUT_FILE_ERROR;
                }
            }

            if (ret == WOLFCLU_SUCCESS) {
                if ((int)XFWRITE(outBuf, 1, outBufSz, file) <= 0) {
                    ret = OUTPUT_FILE_ERROR;
                }
                XFCLOSE(file);
            }

            if (pemBuf != NULL) {
                XFREE(pemBuf, HEAP_HINT, DYNAMIC_TYPE_PUBLIC_KEY);
            }

            break;
        default:
            WOLFCLU_LOG(WOLFCLU_L0, "Invalid directive");
            ret = BAD_FUNC_ARG;
    }

    if (derBuf != NULL) {
        XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (fOutNameBuf != NULL) {
        XFREE(fOutNameBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }
    wc_FreeRsaKey(&key);

    return ret;
#else
    (void)rng;
    (void)fName;
    (void)directive;
    (void)fmt;
    (void)keySz;
    (void)exp;

    return NOT_COMPILED_IN;
#endif
}

#endif /* WOLFSSL_KEY_GEN && !NO_ASN*/


/*
 * makes a cyptographically secure key by stretching a user entered pwdKey
 * return WOLFCLU_SUCCESS on success
 */
int wolfCLU_genKey_PWDBASED(WC_RNG* rng, byte* pwdKey, int size, byte* salt,
                            int pad)
{
    int ret;        /* return variable */

    /* randomly generates salt */

    ret = wc_RNG_GenerateBlock(rng, salt, SALT_SIZE-1);
    if (ret != 0)
        return ret;

    /* set first value of salt to let us know
     * if message has padding or not
     */
    if (pad == 0)
        salt[0] = 0;

    /* stretches pwdKey */
    ret = (int) wc_PBKDF2(pwdKey, pwdKey, (int) strlen((const char*)pwdKey),
                          salt, SALT_SIZE, CLU_4K_TYPE, size, CLU_SHA256);
    if (ret != 0)
        return ret;

    return WOLFCLU_SUCCESS;
}

