/* clu_sign.c
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
#include <wolfclu/sign-verify/clu_sign.h>
#include <wolfclu/x509/clu_cert.h>

#ifndef WOLFCLU_NO_FILESYSTEM

int wolfCLU_KeyPemToDer(unsigned char** pkeyBuf, int pkeySz, int pubIn) {
    int ret = 0;
    byte* der = NULL;
    const unsigned char* keyBuf = *pkeyBuf;

    if (pubIn == 0) {
        ret = wc_KeyPemToDer(keyBuf, pkeySz, NULL, 0, NULL);
        if (ret > 0) {
            wolfCLU_Log(WOLFCLU_L0, "DER size: %d", ret);
            int derSz = ret;
            der = (byte*)XMALLOC(derSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            if (der == NULL) {
                wolfCLU_Log(WOLFCLU_L0, "Failed to allocate memory for DER");
                ret = MEMORY_E;
            }
            else {
                ret = wc_KeyPemToDer(keyBuf, pkeySz, der, derSz, NULL);
                if (ret > 0) {
                    wolfCLU_Log(WOLFCLU_L0, "DER size2: %d", ret);
                    /* replace incoming pkeyBuf with new der buf */
                    XFREE(*pkeyBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
                    *pkeyBuf = der;
                }
                else {
                    wolfCLU_Log(WOLFCLU_L0, "Failed to convert PEM to DER");
                    /* failure, so cleanup */
                    XFREE(der, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
                }
            }
        }
        wolfCLU_Log(WOLFCLU_L0, "DER size3: %d", ret);
    }
    else {
        ret = wc_PubKeyPemToDer(keyBuf, pkeySz, NULL, 0);
        if (ret > 0) {
            int derSz = ret;
            der = (byte*)XMALLOC(derSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            if (der == NULL) {
                ret = MEMORY_E;
            }
            else {
                ret = wc_PubKeyPemToDer(keyBuf, pkeySz, der, derSz);
                if (ret > 0) {
                    /* replace incoming pkeyBuf with new der buf */
                    XFREE(*pkeyBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
                    *pkeyBuf = der;
                }
                else {
                    /* failure, so cleanup */
                    XFREE(der, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
                }
            }
        }
    }

    return ret;
}

int wolfCLU_sign_data(char* in, char* out, char* privKey, int keyType,
                      int inForm, int level)
{
    int ret;
    int fSz;
    XFILE f;
    byte *data = NULL;

    f = XFOPEN(in, "rb");
    if (f == NULL) {
        wolfCLU_LogError("unable to open file %s", in);
        return BAD_FUNC_ARG;
    }
    XFSEEK(f, 0, SEEK_END);
    fSz = (int)XFTELL(f);

    data = (byte*)XMALLOC(fSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (data == NULL) {
        XFCLOSE(f);
        return MEMORY_E;
    }

    if (XFSEEK(f, 0, SEEK_SET) != 0 || (int)XFREAD(data, 1, fSz, f) != fSz) {
        XFCLOSE(f);
        return WOLFCLU_FATAL_ERROR;
    }
    XFCLOSE(f);

    switch(keyType) {

    case RSA_SIG_VER:
        ret = wolfCLU_sign_data_rsa(data, out, fSz, privKey, inForm);
        break;

    case ECC_SIG_VER:
        ret = wolfCLU_sign_data_ecc(data, out, fSz, privKey, inForm);
        break;

    case ED25519_SIG_VER:
        ret = wolfCLU_sign_data_ed25519(data, out, fSz, privKey, inForm);
        break;

    case DILITHIUM_SIG_VER:
        ret = wolfCLU_sign_data_dilithium(data, out, fSz, privKey, level, inForm);
        break;

    default:
        wolfCLU_LogError("No valid sign algorithm selected.");
        ret = WOLFCLU_FATAL_ERROR;
    }

    XFREE(data, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

int wolfCLU_sign_data_rsa(byte* data, char* out, word32 dataSz, char* privKey,
                          int inForm)
{
#ifndef NO_RSA
    int ret;
    int privFileSz;
    word32 index = 0;

    XFILE privKeyFile = NULL;
    byte* keyBuf = NULL;

    RsaKey key;
    WC_RNG rng;

    byte* outBuf = NULL;
    int   outBufSz = 0;

    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(&key, 0, sizeof(key));

    /* initialize the RSA key */
    ret = wc_InitRsaKey(&key, NULL);
    if (ret != 0) {
        wolfCLU_LogError("Failed to initialize RsaKey\nRET: %d", ret);
    }

    /* initialize RNG */
    if (ret == 0) {
        ret = wc_InitRng(&rng);
        if (ret != 0) {
            wolfCLU_LogError("Failed to initialize rng.\nRET: %d", ret);
        }
    }

    /* initialize RNG RSA_BLINDING */
    if (ret == 0) {
#ifdef WC_RSA_BLINDING
        ret = wc_RsaSetRNG(&key, &rng);
        if (ret < 0) {
            wolfCLU_LogError("Failed to initialize rng.\nRET: %d", ret);
        }
#endif
    }

    /* open, read, and store RSA key */
    if (ret == 0) {
        privKeyFile = XFOPEN(privKey, "rb");
        if (privKeyFile == NULL) {
            wolfCLU_LogError("unable to open file %s", privKey);
            ret = BAD_FUNC_ARG;
        }
    }
    if (ret == 0) {
        XFSEEK(privKeyFile, 0, SEEK_END);
        privFileSz = (int)XFTELL(privKeyFile);
        keyBuf = (byte*)XMALLOC(privFileSz+1, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (keyBuf == NULL) {
            ret = MEMORY_E;
        }
    }
    if (ret == 0) {
        XMEMSET(keyBuf, 0, privFileSz+1);
        if (XFSEEK(privKeyFile, 0, SEEK_SET) != 0 ||
            (int)XFREAD(keyBuf, 1, privFileSz, privKeyFile) != privFileSz) {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* convert PEM to DER if necessary */
    if (inForm == PEM_FORM && ret == 0) {
        ret = wolfCLU_KeyPemToDer(&keyBuf, privFileSz, 0);
        if (ret < 0) {
            wolfCLU_LogError("Failed to convert PEM to DER.\nRET: %d", ret);
        }
        else {
            privFileSz = ret;
            ret = 0;
        }
    }

    /* retrieving private key and storing in the RsaKey */
    if (ret == 0) {
        ret = wc_RsaPrivateKeyDecode(keyBuf, &index, &key, privFileSz);
        if (privFileSz < 0) {
            wolfCLU_LogError("Failed to decode private key.\nRET: %d", ret);
            ret = privFileSz;
        }
    }

    /* setting up output buffer based on key size */
    if (ret == 0) {
        outBufSz = wc_RsaEncryptSize(&key);
        if (outBufSz <= 0) {
            wolfCLU_LogError("Invalid output buffer size: %d", outBufSz);
            ret = WOLFCLU_FATAL_ERROR;
        }
    }
    if (ret == 0) {
        outBuf = (byte*)XMALLOC(outBufSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (outBuf == NULL) {
            ret = MEMORY_E;
        }
    }
    if (ret == 0) {
        XMEMSET(outBuf, 0, outBufSz);


        /* signing input with RSA priv key to produce signature */
        ret = wc_RsaSSL_Sign(data, dataSz, outBuf, (word32)outBufSz, &key, &rng);
        if (ret >= 0) {
            XFILE s;
            s = XFOPEN(out, "wb");
            XFWRITE(outBuf, 1, outBufSz, s);
            XFCLOSE(s);
        }
        else {
            wolfCLU_LogError("Failed to sign data with RSA private key.\nRET: %d", ret);
        }
    }

    /* cleanup allocated resources */
    XFCLOSE(privKeyFile);

    if (keyBuf!= NULL) {
        XFREE(keyBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (outBuf!= NULL) {
        XFREE(outBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }

    wc_FreeRsaKey(&key);
    wc_FreeRng(&rng);

    /* expected ret == WOLFCLU_SUCCESS */
    return (ret >= 0) ? WOLFCLU_SUCCESS : ret;
#else
    return NOT_COMPILED_IN;
#endif
}

int wolfCLU_sign_data_ecc(byte* data, char* out, word32 fSz, char* privKey,
                          int inForm)
{
#ifdef HAVE_ECC
    int ret;
    int privFileSz;
    word32 index = 0;
    word32 outLen;

    byte* keyBuf = NULL;
    XFILE privKeyFile = NULL;

    ecc_key key;
    WC_RNG rng;

    byte* outBuf = NULL;
    int   outBufSz = 0;

    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(&key, 0, sizeof(key));

    /* initialize ecc key */
    ret = wc_ecc_init(&key);
    if (ret != 0) {
        wolfCLU_LogError("Failed to initialize ecc key.\nRET: %d", ret);
    }

    /* initialize RNG */
    if (ret == 0) {
        ret = wc_InitRng(&rng);
        if (ret != 0) {
            wolfCLU_LogError("Failed to initialize rng.\nRET: %d", ret);
        }
    }

    /* open, read, and store ecc key */
    if (ret == 0) {
        privKeyFile = XFOPEN(privKey, "rb");
        if (privKeyFile == NULL) {
            wolfCLU_LogError("unable to open file %s", privKey);
            ret = BAD_FUNC_ARG;
        }
    }
    if (ret == 0) {
        XFSEEK(privKeyFile, 0, SEEK_END);
        privFileSz = (int)XFTELL(privKeyFile);
        keyBuf = (byte*)XMALLOC(privFileSz+1, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (keyBuf == NULL) {
            ret = MEMORY_E;
        }
    }
    if (ret == 0) {
        XMEMSET(keyBuf, 0, privFileSz+1);
        if (XFSEEK(privKeyFile, 0, SEEK_SET) != 0 ||
            (int)XFREAD(keyBuf, 1, privFileSz, privKeyFile) != privFileSz) {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* convert PEM to DER if necessary */
    if (inForm == PEM_FORM && ret == 0) {
        ret = wolfCLU_KeyPemToDer(&keyBuf, privFileSz, 0);
        if (ret < 0) {
            wolfCLU_LogError("Failed to convert PEM to DER.\nRET: %d", ret);
        }
        else {
            privFileSz = ret;
            ret = 0;
        }
    }

    /* retrieving private key and storing in the Ecc Key */
    if (ret == 0) {
        ret = wc_EccPrivateKeyDecode(keyBuf, &index, &key, privFileSz);
        if (privFileSz < 0) {
            wolfCLU_LogError("Failed to decode Ecc private key.\nRET: %d", ret);
            ret = privFileSz;
        }
    }

    /* setting up output buffer based on key size */
    if (ret == 0) {
        outBufSz = wc_ecc_sig_size(&key);
        outBuf = (byte*)XMALLOC(outBufSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (outBuf == NULL) {
            ret = MEMORY_E;
        }
    }
    if (ret == 0) {
        XMEMSET(outBuf, 0, outBufSz);

        /* signing input with ecc priv key to produce signature */
        outLen = (word32)outBufSz;
        ret = wc_ecc_sign_hash(data, fSz, outBuf, &outLen, &rng, &key);
        if (ret >= 0) {
            XFILE s;
            s = XFOPEN(out, "wb");
            XFWRITE(outBuf, 1, outLen, s);
            XFCLOSE(s);
        }
        else {
            wolfCLU_LogError("Failed to sign data with Ecc private key.\nRET: %d", ret);
        }
    }

    /* cleanup allocated resources */
    XFCLOSE(privKeyFile);

    if (keyBuf!= NULL) {
        XFREE(keyBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (outBuf!= NULL) {
        XFREE(outBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }

    wc_ecc_free(&key);
    wc_FreeRng(&rng);

    /* expected ret == WOLFCLU_SUCCESS */
    return (ret >= 0) ? WOLFCLU_SUCCESS : ret;
#else
    return NOT_COMPILED_IN;
#endif
}

int wolfCLU_sign_data_ed25519 (byte* data, char* out, word32 fSz, char* privKey,
                               int inForm)
{
#ifdef HAVE_ED25519
    int ret;
    int privFileSz;
    word32 index = 0;
    word32 outLen;

    XFILE privKeyFile = NULL;
    byte* keyBuf = NULL;
    byte* outBuf = NULL;
    int   outBufSz = 0;

    ed25519_key key;
    WC_RNG rng;

    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(&key, 0, sizeof(key));

    /* initialize ED25519 key */
    ret = wc_ed25519_init(&key);
    if (ret != 0) {
        wolfCLU_LogError("Failed to initialize ed25519 key\nRET: %d", ret);
    }

    /* initialize RNG */
    if (ret == 0) {
        ret = wc_InitRng(&rng);
        if (ret != 0) {
            wolfCLU_LogError("Failed to initialize rng.\nRET: %d", ret);
        }
    }

    /* open, read, and store ED25519 key */
    if (ret == 0) {
        privKeyFile = XFOPEN(privKey, "rb");
        if (privKeyFile == NULL) {
            wolfCLU_LogError("unable to open file %s", privKey);
            ret = BAD_FUNC_ARG;
        }
    }
    if (ret == 0) {
        XFSEEK(privKeyFile, 0, SEEK_END);
        privFileSz = (int)XFTELL(privKeyFile);
        keyBuf = (byte*)XMALLOC(privFileSz+1, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (keyBuf == NULL) {
            ret = MEMORY_E;
        }
    }
    if (ret == 0) {
        XMEMSET(keyBuf, 0, privFileSz+1);
        if (XFSEEK(privKeyFile, 0, SEEK_SET) != 0 ||
            (int)XFREAD(keyBuf, 1, privFileSz, privKeyFile) != privFileSz) {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* convert PEM to DER if necessary */
    if (inForm == PEM_FORM && ret == 0) {
        ret = wolfCLU_KeyPemToDer(&keyBuf, privFileSz, 0);
        if (ret < 0) {
            wolfCLU_LogError("Failed to convert PEM to DER.\nRET: %d", ret);
        }
        else {
            privFileSz = ret;
            ret = 0;
        }
    }

    /* retrieve RAW private key and store in the ED25519 Key */
    if (inForm == RAW_FORM && ret == 0) {
        ret = wc_ed25519_import_private_key(keyBuf,
                                        ED25519_KEY_SIZE,
                                        keyBuf + ED25519_KEY_SIZE,
                                        ED25519_KEY_SIZE, &key);
        if (ret != 0 ) {
            wolfCLU_LogError("Failed to import RAW private key.\nRET: %d", ret);
        }
    }
    else {
        /* decode the private key from the DER-encoded input */
        if (ret == 0) {
            ret = wc_Ed25519PrivateKeyDecode(keyBuf, &index, &key, privFileSz);
            if (ret == 0) {
                /* Calculate the public key */
                ret = wc_ed25519_make_public(&key, key.p, ED25519_PUB_KEY_SIZE);
                if (ret == 0) {
                    key.pubKeySet = 1;
                }
            }
            else {
                wolfCLU_LogError("Failed to import private key.\nRET: %d", ret);
            }
        }
    }

    /* setting up output buffer based on key size */
    if (ret == 0) {
        outBufSz = ED25519_SIG_SIZE;
        outBuf = (byte*)XMALLOC(outBufSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (outBuf == NULL) {
            ret = MEMORY_E;
        }
    }
    if (ret == 0) {
        XMEMSET(outBuf, 0, outBufSz);
        outLen = outBufSz;

        /* signing input with ED25519 priv key to produce signature */
        ret = wc_ed25519_sign_msg(data, fSz, outBuf, &outLen, &key);
        if (ret >= 0) {
            XFILE s;
            s = XFOPEN(out, "wb");
            XFWRITE(outBuf, 1, outBufSz, s);
            XFCLOSE(s);
        }
        else {
            wolfCLU_LogError("Failed to sign data with ED25519 private key.\nRET: %d", ret);
        }
    }

    /* cleanup allocated resources */
    XFCLOSE(privKeyFile);

    if (keyBuf!= NULL) {
        XFREE(keyBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (outBuf!= NULL) {
        XFREE(outBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }

    wc_ed25519_free(&key);
    wc_FreeRng(&rng);

    /* expected ret == WOLFCLU_SUCCESS */
    return (ret >= 0) ? WOLFCLU_SUCCESS : ret;
#else
    return NOT_COMPILED_IN;
#endif
}

int wolfCLU_sign_data_dilithium (byte* data, char* out, word32 dataSz, char* privKey,
                                int level, int inForm)
{
#ifdef HAVE_DILITHIUM
    int ret = 0;
    XFILE privKeyFile = NULL;
    byte* privBuf = NULL;
    int privFileSz = 0;
    word32 privBufSz = 0;
    word32 index = 0;
    byte* outBuf = NULL;
    word32 outBufSz = 0;

    WC_RNG rng;
    XMEMSET(&rng, 0, sizeof(rng));

#ifdef WOLFSSL_SMALL_STACK
    dilithium_key* key;
    key = (dilithium_key*)XMALLOC(sizeof(dilithium_key), HEAP_HINT,
            DYNAMIC_TYPE_TMP_BUFFER);
    if (key == NULL) {
        return MEMORY_E;
    }
#else
    dilithium_key key[1];
#endif

    /* init the dilithium key */
    if (wc_dilithium_init(key) != 0) {
        wolfCLU_LogError("Failed to initialize Dilithium Key.\nRET: %d", ret);
    #ifdef WOLFSSL_SMALL_STACK
        wc_dilithium_free(key);
    #endif
        return WOLFCLU_FAILURE;
    }
    XMEMSET(key, 0, sizeof(dilithium_key));

    if (wc_InitRng(&rng) != 0) {
        wolfCLU_LogError("Failed to initialize rng.\nRET: %d", ret);
    #ifdef WOLFSSL_SMALL_STACK
        wc_dilithium_free(key);
    #endif
        return WOLFCLU_FAILURE;
    }

    /* check and set Dilithium level */
    if (level != 2 && level != 3 && level != 5) {
        wolfCLU_LogError("Please specify a level when signing with Dilithium.");
        wc_FreeRng(&rng);
    #ifdef WOLFSSL_SMALL_STACK
        wc_dilithium_free(key);
    #endif
        return BAD_FUNC_ARG;
    }
    else {
        ret = wc_dilithium_set_level(key, level);
        if (ret != 0) {
            wolfCLU_LogError("Failed to set level.\nRET: %d", ret);
            wc_FreeRng(&rng);
        #ifdef WOLFSSL_SMALL_STACK
            wc_dilithium_free(key);
        #endif
            return BAD_FUNC_ARG;
        }
    }

    /* open and read private key */
    privKeyFile = XFOPEN(privKey, "rb");
    if (privKeyFile == NULL) {
        wolfCLU_LogError("Faild to open Private key FILE.");
        wc_FreeRng(&rng);
    #ifdef WOLFSSL_SMALL_STACK
        wc_dilithium_free(key);
    #endif
        return ret;
    }

    XFSEEK(privKeyFile, 0, SEEK_END);
    privFileSz = (int)XFTELL(privKeyFile);
    privBuf = (byte*)XMALLOC(privFileSz+1, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (privBuf == NULL) {
        XFCLOSE(privKeyFile);
        wc_FreeRng(&rng);
    #ifdef WOLFSSL_SMALL_STACK
        wc_dilithium_free(key);
    #endif
        return MEMORY_E;
    }

    XMEMSET(privBuf, 0, privFileSz+1);
    privBufSz = privFileSz;
    XFSEEK(privKeyFile, 0, SEEK_SET);
    if (XFREAD(privBuf, 1, privBufSz, privKeyFile) != privBufSz) {
        wolfCLU_Log(WOLFCLU_L0, "incorecct size: %d", privFileSz);
        XFREE(privBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRng(&rng);
    #ifdef WOLFSSL_SMALL_STACK
        wc_dilithium_free(key);
    #endif
        return ret;
    }
    XFCLOSE(privKeyFile);

    /* convert PEM to DER if necessary */
    if (inForm == PEM_FORM) {
        ret = wolfCLU_KeyPemToDer(&privBuf, privFileSz, 0);
        if (ret < 0) {
            wolfCLU_LogError("Failed to convert PEM to DER.\nRET: %d", ret);
            XFREE(privBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            wc_FreeRng(&rng);
        #ifdef WOLFSSL_SMALL_STACK
            wc_dilithium_free(key);
        #endif
            return ret;
        }
        else {
            privFileSz = ret;
        }
    }

    /* retrieving private key and staoring in the Dilithium key */
    ret = wc_Dilithium_PrivateKeyDecode(privBuf, &index, key, privBufSz);
    if (ret != 0) {
        wolfCLU_LogError("Failed to decode private key.\nRET: %d", ret);
        XFREE(privBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRng(&rng);
    #ifdef WOLFSSL_SMALL_STACK
        wc_dilithium_free(key);
    #endif
        return ret;
    }

    /* malloc signature buffer */
    outBufSz = wc_dilithium_sig_size(key);
    outBuf = (byte*)XMALLOC(outBufSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (outBuf == NULL) {
        XFREE(privBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRng(&rng);
    #ifdef WOLFSSL_SMALL_STACK
        wc_dilithium_free(key);
    #endif
        return MEMORY_E;
    }
    
    /* sign the message usign Dilithium private key */
    ret = wc_dilithium_sign_msg(data, dataSz, outBuf, &outBufSz, key, &rng);
    if (ret != 0) {
        wolfCLU_LogError("Failed to sign data with Dilithium private key.\nRET: %d", ret);
        XFREE(outBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRng(&rng);
    #ifdef WOLFSSL_SMALL_STACK
        wc_dilithium_free(key);
    #endif
        return ret;
    }
    else {
        XFILE outFile;
        outFile = XFOPEN(out, "wb");
        XFWRITE(outBuf, 1, outBufSz, outFile);
        XFCLOSE(outFile);
    }

    XFREE(outBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    wc_FreeRng(&rng);

#ifdef WOLFSSL_SMALL_STACK
    wc_dilithium_free(key);
#endif

    return WOLFCLU_SUCCESS;
#else
    return NOT_COMPILED_IN;
#endif
}

#endif /* !WOLFCLU_NO_FILESYSTEM */
