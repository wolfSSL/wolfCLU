/* clu_verify.c
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
#include <wolfclu/sign-verify/clu_verify.h>
#include <wolfclu/x509/clu_cert.h>
#include <wolfclu/sign-verify/clu_sign.h> /* for RSA_SIG_VER, ECC_SIG_VER,
                                           * and ED25519_SIG_VER */
#ifndef WOLFCLU_NO_FILESYSTEM

/* Upper bound (in bytes) on a signature, hash, or message file the verify path
 * will read into memory. Files larger than this are rejected rather than
 * allocated. */
#define WOLFCLU_MAX_FILE_SIZE 0xFFFFFFF

/* Reads the message/digest file used by every wolfCLU_verify_signature()
 * case except RSA (which verifies the signature directly). On success
 * stores the buffer in *hash and its length in *hSzOut and returns
 * WOLFCLU_SUCCESS; on failure returns the error wolfCLU_ReadMessageFileToBuffer()
 * reported, already logged, for the caller to propagate as-is. */
static int wolfCLU_ReadVerifyHash(char* hashFile, byte** hash, long* hSzOut)
{
    int hSzInt = 0;
    int hRet = wolfCLU_ReadMessageFileToBuffer(hashFile, WOLFCLU_MAX_FILE_SIZE,
            hash, &hSzInt);
    if (hRet == WOLFCLU_SUCCESS) {
        *hSzOut = hSzInt;
    }
    return hRet;
}

#ifdef WOLFSSL_HAVE_XMSS
/* Reads an XMSS/XMSS-MT public key file, shared by
 * wolfCLU_verify_signature_xmss() and wolfCLU_verify_signature_xmssmt():
 * both need the same "read it in, then confirm it is at least large enough
 * to hold the OID" check before they can look at the parameter set. On
 * success stores the buffer in *keyBuf and its length in *keyFileSzOut and
 * returns WOLFCLU_SUCCESS; on failure returns the error, already logged. */
static int wolfCLU_ReadXmssPubKey(char* pubKey, byte** keyBuf,
        long* keyFileSzOut)
{
    int keyFileSzInt = 0;
    int ret = wolfCLU_ReadFileToBuffer(pubKey, WOLFCLU_MAX_FILE_SIZE, keyBuf,
            &keyFileSzInt);

    if (ret == WOLFCLU_SUCCESS) {
        if (keyFileSzInt < (int)XMSS_OID_LEN) {
            ret = WOLFCLU_FATAL_ERROR;
            wolfCLU_LogError("File: %s is too small to hold a valid "
                    "XMSS public key.", pubKey);
        }
        else {
            *keyFileSzOut = keyFileSzInt;
        }
    }
    return ret;
}
#endif /* WOLFSSL_HAVE_XMSS */

int wolfCLU_verify_signature(char* sig, char* hashFile, char* out,
                             char* keyPath, int keyType, int pubIn,
                             int inForm)
{
    long hSz = 0;
    long fSz;
    int dataSz = 0;
    int ret = WOLFCLU_FATAL_ERROR;

    byte* hash = NULL;
    byte* data = NULL;


    if (sig == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = wolfCLU_ReadFileToBuffer(sig, WOLFCLU_MAX_FILE_SIZE, &data, &dataSz);
    if (ret != WOLFCLU_SUCCESS) {
        return ret;
    }
    fSz = (long)dataSz;
    ret = WOLFCLU_FATAL_ERROR;

    switch(keyType) {
        case RSA_SIG_VER:
            ret = wolfCLU_verify_signature_rsa(data, out, (int)fSz,
                    keyPath, pubIn, inForm);
            break;

        case ECC_SIG_VER:
            ret = wolfCLU_ReadVerifyHash(hashFile, &hash, &hSz);
            if (ret != WOLFCLU_SUCCESS) {
                break;
            }
            ret = wolfCLU_verify_signature_ecc(data, (int)fSz, hash, (int)hSz,
                    keyPath, pubIn, inForm);
            break;

        case ED25519_SIG_VER:
        #ifdef HAVE_ED25519
            ret = wolfCLU_ReadVerifyHash(hashFile, &hash, &hSz);
            if (ret != WOLFCLU_SUCCESS) {
                break;
            }
            ret = wolfCLU_verify_signature_ed25519(data, (int)fSz, hash,
                    (int)hSz, keyPath, pubIn, inForm);
        #endif
            break;

#ifdef HAVE_DILITHIUM
        case DILITHIUM_SIG_VER:
            ret = wolfCLU_ReadVerifyHash(hashFile, &hash, &hSz);
            if (ret != WOLFCLU_SUCCESS) {
                break;
            }
            ret = wolfCLU_verify_signature_dilithium(data, (int)fSz, hash,
                    (int)hSz, keyPath, inForm);
            break;
#endif

#ifdef WOLFSSL_HAVE_XMSS
        case XMSS_SIG_VER:
            ret = wolfCLU_ReadVerifyHash(hashFile, &hash, &hSz);
            if (ret != WOLFCLU_SUCCESS) {
                break;
            }
            ret = wolfCLU_verify_signature_xmss(data, (int)fSz, hash, (int)hSz,
                    keyPath);
            break;

        case XMSSMT_SIG_VER:
            ret = wolfCLU_ReadVerifyHash(hashFile, &hash, &hSz);
            if (ret != WOLFCLU_SUCCESS) {
                break;
            }
            ret = wolfCLU_verify_signature_xmssmt(data, (int)fSz, hash,
                    (int)hSz, keyPath);
            break;
#endif
        default:
            wolfCLU_LogError("No valid verify algorithm selected.");
            ret = -1;
    }

    if (data != NULL) {
        XFREE(data , HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (hash != NULL) {
        XFREE(hash, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }

    return ret;
}

int wolfCLU_verify_signature_rsa(byte* sig, char* out, int sigSz, char* keyPath,
                                 int pubIn, int inForm) {

#ifndef NO_RSA
    int ret;
    int keyFileSzInt = 0;
    long keyFileSz = 0;
    word32 index = 0;
    RsaKey key;
    byte* keyBuf = NULL;
    byte* outBuf = NULL;
    int   outBufSz = 0;

    /* initialize RSA key */
    ret = wc_InitRsaKey(&key, NULL);
    if (ret != 0) {
        wolfCLU_LogError("Failed to initialize RsaKey.\nRet: %d", ret);
    }

    /* open, read, and store RSA key */
    if (ret == 0) {
        ret = wolfCLU_ReadFileToBuffer(keyPath, WOLFCLU_MAX_FILE_SIZE,
                &keyBuf, &keyFileSzInt);
        if (ret == WOLFCLU_SUCCESS) {
            keyFileSz = keyFileSzInt;
            ret = 0;
        }
        else {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* convert PEM to DER if necessary */
    if (inForm == PEM_FORM && ret == 0) {
        ret = wolfCLU_KeyPemToDer(&keyBuf, (int)keyFileSz, pubIn);
        if (ret < 0) {
            if (ret == WC_NO_ERR_TRACE(ASN_NO_PEM_HEADER)) {
                WOLFCLU_LOG(WOLFCLU_L0,
                    "No PEM header found, treating as DER.");
                ret = 0;
            }
            else {
                wolfCLU_LogError("Failed to convert PEM to DER.\nRET: %d", ret);
            }
        }
        else {
            keyFileSz = ret;
            ret = 0;
        }
    }

    if (pubIn == 1) {
        /* decode public key from DER-encoded input */
        if (ret == 0) {
            ret = wc_RsaPublicKeyDecode(keyBuf, &index, &key,
                    (word32)keyFileSz);
            if (ret != 0) {
                wolfCLU_LogError("Failed to decode public key from DER.\nRET: %d", ret);
            }
        }
    }
    else {
        /* retrieve private key and store in the RsaKey */
        if (ret == 0) {
            ret = wc_RsaPrivateKeyDecode(keyBuf, &index, &key,
                    (word32)keyFileSz);
            if (ret != 0) {
                wolfCLU_LogError("Failed to decode private key.\nRET: %d", ret);
            }
        }
    }

    /* set up output buffer based on key size */
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

        /* verify the RSA signature */
        ret = wc_RsaSSL_Verify(sig, sigSz, outBuf, (word32)outBufSz, &key);
        if (ret < 0) {
            wolfCLU_LogError("Failed to verify data with pub key.\nRET: %d", ret);
        }

        /* write the output to the specified file */
        if (ret > 0) {
            int writeSz = ret;
            XFILE s = wolfCLU_OpenOutFile(out);
            if (s == NULL) {
                ret = BAD_FUNC_ARG;
            }
            else {
                if ((int)XFWRITE(outBuf, 1, writeSz, s) <= 0) {
                    ret = OUTPUT_FILE_ERROR;
                }
                XFCLOSE(s);
            }
        }
    }

    /* Cleanup allocated resources */
    if (outBuf != NULL) {
        XFREE(outBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (keyBuf != NULL) {
        /* With pubIn == 0 this holds a private key. Wipe using the size
         * of the CURRENT allocation: wolfCLU_KeyPemToDer() swaps keyBuf
         * for a smaller DER buffer and the tracking variable differs
         * between these functions.
         */
        wolfCLU_ForceZero(keyBuf, (unsigned int)keyFileSz);
        XFREE(keyBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }

    wc_FreeRsaKey(&key);

    /* expected ret == WOLFCLU_SUCCESS */
    return (ret >= 0) ? WOLFCLU_SUCCESS : ret;
#else
    return NOT_COMPILED_IN;
#endif
}

int wolfCLU_verify_signature_ecc(byte* sig, int sigSz, byte* hash, int hashSz,
                                 char* keyPath, int pubIn, int inForm)
{

#ifdef HAVE_ECC
    int ret;
    int keyFileSzInt = 0;
    long keyFileSz = 0;
    int stat = 0;
    word32 index = 0;

    ecc_key key;
    byte* keyBuf = NULL;
    byte* outBuf = NULL;
    int outBufSz = 0;

    XMEMSET(&key, 0, sizeof(key));

    /* initialize Ecc key */
    ret = wc_ecc_init(&key);
    if (ret != 0) {
        wolfCLU_LogError("Failed to initialize ecc key.\nRet: %d", ret);
    }

    if (ret == 0) {
        ret = wolfCLU_ReadFileToBuffer(keyPath, WOLFCLU_MAX_FILE_SIZE,
                &keyBuf, &keyFileSzInt);
        if (ret == WOLFCLU_SUCCESS) {
            keyFileSz = keyFileSzInt;
            ret = 0;
        }
        else {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* convert PEM to DER if necessary */
    if (inForm == PEM_FORM && ret == 0) {
        ret = wolfCLU_KeyPemToDer(&keyBuf, (int)keyFileSz, pubIn);
        if (ret < 0) {
            if (ret == WC_NO_ERR_TRACE(ASN_NO_PEM_HEADER)) {
                WOLFCLU_LOG(WOLFCLU_L0,
                    "No PEM header found, treating as DER.");
                ret = 0;
            }
            else {
                wolfCLU_LogError("Failed to convert PEM to DER.\nRET: %d", ret);
            }
        }
        else {
            keyFileSz = ret;
            ret = 0;
        }
    }

    if (pubIn == 1) {
        /* retrieve public key and store in the Ecc key */
        if (ret == 0) {
            ret = wc_EccPublicKeyDecode(keyBuf, &index, &key, (word32)keyFileSz);
            if (ret < 0 ) {
                wolfCLU_LogError("Failed to decode public key.\nRET: %d", ret);
            }
        }
    }
    else {
        /* retrieve private key and store in the Ecc Key */
        if (ret == 0) {
            ret = wc_EccPrivateKeyDecode(keyBuf, &index, &key, (word32)keyFileSz);
            if (ret != 0 ) {
                wolfCLU_LogError("Failed to decode Ecc private key.\nRET: %d", ret);
            }
        }
    }

    /* setting up output buffer based on key size */
    if (ret == 0) {
        outBufSz = wc_ecc_sig_size(&key);
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
        int keySz;
        enum wc_HashType hashType;
        int digestSz;
        byte hashBuf[WC_MAX_DIGEST_SIZE];

        XMEMSET(outBuf, 0, outBufSz);

        /* hash the input data before verifying -- ECDSA operates on a digest,
         * not raw data.  Select a curve-appropriate hash paired with the curve
         * strength; ECDSA will truncate the digest as needed. */
        keySz = wc_ecc_size(&key);
        if (keySz <= 32) {
            hashType = WC_HASH_TYPE_SHA256;
        }
        else if (keySz <= 48) {
            hashType = WC_HASH_TYPE_SHA384;
        }
        else {
            hashType = WC_HASH_TYPE_SHA512;
        }
        digestSz = wc_HashGetDigestSize(hashType);
        if (digestSz > 0 && digestSz <= WC_MAX_DIGEST_SIZE) {
            ret = wc_Hash(hashType, hash, hashSz, hashBuf, digestSz);
        }
        else {
            ret = BAD_FUNC_ARG;
        }

        /* verify the hash with Ecc public key */
        if (ret == 0) {
            ret = wc_ecc_verify_hash(sig, sigSz, hashBuf, digestSz,
                                     &stat, &key);
        }
        if (ret < 0) {
            wolfCLU_LogError("Failed to verify data with pub key.\nRET: %d", ret);
        }
        else if (stat == 1) {
            WOLFCLU_LOG(WOLFCLU_L0, "Valid Signature.");
        }
        else {
            wolfCLU_LogError("Invalid Signature.");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* cleanup allocated resources */
    if (outBuf != NULL) {
        XFREE(outBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (keyBuf != NULL) {
        /* With pubIn == 0 this holds a private key. Wipe using the size
         * of the CURRENT allocation: wolfCLU_KeyPemToDer() swaps keyBuf
         * for a smaller DER buffer and the tracking variable differs
         * between these functions.
         */
        wolfCLU_ForceZero(keyBuf, (unsigned int)keyFileSz);
        XFREE(keyBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }

    wc_ecc_free(&key);

    /* expected ret == WOLFCLU_SUCCESS */
    return (ret >= 0) ? WOLFCLU_SUCCESS : ret;
#else
    return NOT_COMPILED_IN;
#endif
}

int wolfCLU_verify_signature_ed25519(byte* sig, int sigSz,
        byte* hash, int hashSz, char* keyPath, int pubIn, int inForm) {

#ifdef HAVE_ED25519
    int ret;
    int stat = 0;
    word32 index = 0;
    int keyFileSzInt = 0;
    long keyFileSz = 0;

    ed25519_key key;
    byte* keyBuf = NULL;

    XMEMSET(&key, 0, sizeof(key));

    /* initialize ED25519 key */
    ret = wc_ed25519_init(&key);
    if (ret != 0) {
        wolfCLU_LogError("Failed to initialize ED25519 key.\nRet: %d", ret);
    }

    if (ret == 0) {
        ret = wolfCLU_ReadFileToBuffer(keyPath, WOLFCLU_MAX_FILE_SIZE,
                &keyBuf, &keyFileSzInt);
        if (ret == WOLFCLU_SUCCESS) {
            keyFileSz = keyFileSzInt;
            ret = 0;
        }
        else {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* convert PEM to DER if necessary */
    if (inForm == PEM_FORM && ret == 0) {
        ret = wolfCLU_KeyPemToDer(&keyBuf, (int)keyFileSz, pubIn);
        if (ret < 0) {
            if (ret == WC_NO_ERR_TRACE(ASN_NO_PEM_HEADER)) {
                WOLFCLU_LOG(WOLFCLU_L0,
                    "No PEM header found, treating as DER.");
                ret = 0;
            }
            else {
                wolfCLU_LogError("Failed to convert PEM to DER.\nRET: %d", ret);
            }
        }
        else {
            keyFileSz = ret;
            ret = 0;
        }
    }

    if (pubIn == 1 && ret == 0) {
        /* decode public key from RAW-encoded input */
        if (inForm == RAW_FORM) {
            ret = wc_ed25519_import_public(keyBuf, ED25519_KEY_SIZE, &key);
            if (ret != 0) {
                wolfCLU_LogError("Failed to import raw public key.\nRET: %d", ret);
            }
        }
        /* decode public key from DER-encoded input */
        else {
            ret = wc_Ed25519PublicKeyDecode(keyBuf, &index, &key,
                    (word32)keyFileSz);
            if (ret != 0) {
                wolfCLU_LogError("Failed to decode public key from DER.\nRET: %d", ret);
            }
        }
    }
    else if (ret == 0) {
        /* handle private key decoding and public key derivation */
        if (inForm == RAW_FORM) {
            ret = wc_ed25519_import_private_key(keyBuf,
                                                ED25519_KEY_SIZE,
                                                keyBuf + ED25519_KEY_SIZE,
                                                ED25519_KEY_SIZE, &key);
            if (ret < 0) {
                wolfCLU_LogError("Failed to decode private key.\nRET: %d", ret);
            }
        }
        else {
            ret = wc_Ed25519PrivateKeyDecode(keyBuf, &index, &key,
                    (word32)keyFileSz);
            if (ret != 0) {
                wolfCLU_LogError("Failed to import private key.\nRET: %d", ret);
            }
        }

        /* calculate the public key */
        if (ret == 0) {
            ret = wc_ed25519_make_public(&key, key.p, ED25519_PUB_KEY_SIZE);
            if (ret == 0) {
                key.pubKeySet = 1;
            }
        }
    }

    /* verify data with ED25519 public key */
    if (ret == 0) {
        ret = wc_ed25519_verify_msg(sig, sigSz, hash, hashSz, &stat, &key);
        if (ret < 0) {
            wolfCLU_LogError("Failed to verify data with ED25519 public key.\nRET: %d", ret);
        }
        else if (stat == 1) {
            WOLFCLU_LOG(WOLFCLU_L0, "Valid Signature.");
        }
        else {
            wolfCLU_LogError("Invalid Signature.");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* cleanup allocated resources */
    if (keyBuf != NULL) {
        /* With pubIn == 0 this holds a private key. Wipe using the size
         * of the CURRENT allocation: wolfCLU_KeyPemToDer() swaps keyBuf
         * for a smaller DER buffer and the tracking variable differs
         * between these functions.
         */
        wolfCLU_ForceZero(keyBuf, (unsigned int)keyFileSz);
        XFREE(keyBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }

    wc_ed25519_free(&key);

    /* expected ret == WOLFCLU_SUCCESS */
    return (ret >= 0) ? WOLFCLU_SUCCESS : ret;
#else
    return NOT_COMPILED_IN;
#endif  /* HAVE_ED25519 */
}

int wolfCLU_verify_signature_dilithium(byte* sig, int sigSz, byte* msg,
                    word32 msgLen, char* keyPath, int inForm)
{
#ifdef HAVE_DILITHIUM
    int ret = 0;

    byte* keyBuf = NULL;
    long keyFileSz = 0;
    word32 keyBufSz = 0;
    word32 index = 0;
    int res = 0;

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

    /* zero before init for defensive security */
    XMEMSET(key, 0, sizeof(dilithium_key));

    /* init the dilithium key */
    ret = wc_dilithium_init(key);
    if (ret != 0) {
        wolfCLU_LogError("Failed to initialize Dilithium Key.\nRET: %d", ret);
    #ifdef WOLFSSL_SMALL_STACK
        XFREE(key, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    #endif
        return ret;
    }

    /* open and read public key */
    {
        int keyFileSzInt = 0;
        int keyRet = wolfCLU_ReadFileToBuffer(keyPath,
                DILITHIUM_MAX_BOTH_KEY_PEM_SIZE, &keyBuf, &keyFileSzInt);
        if (keyRet != WOLFCLU_SUCCESS) {
            /* wolfCLU_ReadFileToBuffer() already reported the reason. */
            wc_dilithium_free(key);
        #ifdef WOLFSSL_SMALL_STACK
            XFREE(key, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        #endif
            return keyRet;
        }
        keyFileSz = keyFileSzInt;
    }
    keyBufSz = (word32)keyFileSz;

    /* convert PEM to DER if necessary */
    if (inForm == PEM_FORM) {
        ret = wolfCLU_KeyPemToDer(&keyBuf, (int)keyFileSz, 1);
        if (ret < 0) {
            if (ret == WC_NO_ERR_TRACE(ASN_NO_PEM_HEADER)) {
                WOLFCLU_LOG(WOLFCLU_L0,
                    "No PEM header found, treating as DER.");
                ret = 0;
            }
            else {
                wolfCLU_LogError("Failed to convert PEM to DER.\nRET: %d", ret);
                /* The conversion failed, so keyBuf still holds the original
                 * file contents and keyBufSz is still its allocation size.
                 * Wipe it here too, matching the success path below. */
                wolfCLU_ForceZero(keyBuf, keyBufSz);
                XFREE(keyBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
                wc_dilithium_free(key);
            #ifdef WOLFSSL_SMALL_STACK
                XFREE(key, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            #endif
                return ret;
            }
        }
        else {
            keyBufSz = ret;
        }
    }

    /* retrieving public key and storing in the dilithium key */
    ret = wc_Dilithium_PublicKeyDecode(keyBuf, &index, key, keyBufSz);
    /* keyBuf holds whatever file -inkey named, which may be a private key.
     * keyBufSz (not keyFileSz) is the size of the CURRENT allocation:
     * wolfCLU_KeyPemToDer() swaps keyBuf for a smaller DER buffer and this
     * function tracks that size in keyBufSz. */
    wolfCLU_ForceZero(keyBuf, keyBufSz);
    XFREE(keyBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (ret != 0) {
        wolfCLU_LogError("Failed to decode public key.\nRET: %d", ret);
        wc_dilithium_free(key);
    #ifdef WOLFSSL_SMALL_STACK
        XFREE(key, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    #endif
        return ret;
    }

    /* verify the message using the dilithium public key. Note that the
     * context is empty. This is for interoperability. */
    ret = wc_dilithium_verify_ctx_msg(sig, sigSz, NULL, 0, msg, msgLen, &res,
                                      key);
    if (ret != 0) {
        wolfCLU_LogError("Failed to verify data with Dilithium public key.\n"
                        "RET: %d", ret);
        wc_dilithium_free(key);
    #ifdef WOLFSSL_SMALL_STACK
        XFREE(key, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    #endif
        return ret;
    }
    else if(res == 1) {
        WOLFCLU_LOG(WOLFCLU_L0, "Valid Signature.");
    }
    else {
        wolfCLU_LogError("Invalid Signature.");
        ret = WOLFCLU_FATAL_ERROR;
    }
    wc_dilithium_free(key);

#ifdef WOLFSSL_SMALL_STACK
    XFREE(key, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return (ret >= 0) ? WOLFCLU_SUCCESS : ret;
#else
    (void)sig;
    (void)sigSz;
    (void)msg;
    (void)msgLen;
    (void)keyPath;
    (void)inForm;

    return NOT_COMPILED_IN;
#endif  /* HAVE_DILITHIUM */
}

int wolfCLU_verify_signature_xmss(byte* sig, int sigSz,
                                  byte* msg, int msgLen, char* pubKey)
{
#ifdef WOLFSSL_HAVE_XMSS
    int ret        = 0;
    byte* keyBuf   = NULL;               /* public key buffer            */
    long keyFileSz  = 0;                  /* public key buffer size       */
    word32 oid     = 0x0;                /* OID of the XMSS parameter    */
    char* paramStr = NULL;               /* XMSS parameter string        */
    int paramLen   = XMSS_NAME_LEN + 1;  /* XMSS parameter string length */

#ifdef WOLFSSL_SMALL_STACK
    XmssKey *key = (XmssKey*)XMALLOC(sizeof(XmssKey),
                                     HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (key == NULL) {
        wolfCLU_LogError("Failed to malloc key buffer.");
        return MEMORY_E;
    }
#else
    XmssKey key[1];
#endif

    /* init the xmss key */
    ret = wc_XmssKey_Init(key, HEAP_HINT, 0);
    if (ret != 0) {
        wolfCLU_LogError("Failed to initialize XMSS Key.\nRET: %d", ret);
    }

    /* open and read public key */
    if (ret == 0) {
        ret = wolfCLU_ReadXmssPubKey(pubKey, &keyBuf, &keyFileSz);
        if (ret == WOLFCLU_SUCCESS) {
            ret = 0;
        }
    }

    /* get the parameter from OID */
    if (ret == 0) {
        paramStr = XMALLOC(paramLen , HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (paramStr == NULL) {
            ret = MEMORY_E;
            wolfCLU_LogError("Failed to malloc parameter string."
                             "\nRET: %d", ret);
        }
        else {
            XMEMSET(paramStr, 0, paramLen);
        }
    }

    if (ret == 0) {
        for (unsigned int i = 0; i < XMSS_OID_LEN; i++) {
            oid = (oid << 8) | keyBuf[i];
        }

        switch (oid) {
            case WC_XMSS_OID_SHA2_10_256:
                XMEMCPY(paramStr, "XMSS-SHA2_10_256\0", paramLen);
                break;
            case WC_XMSS_OID_SHA2_16_256:
                XMEMCPY(paramStr, "XMSS-SHA2_16_256\0", paramLen);
                break;
            case WC_XMSS_OID_SHA2_20_256:
                XMEMCPY(paramStr, "XMSS-SHA2_20_256\0", paramLen);
                break;
            default:
                wolfCLU_LogError("Invalid XMSS OID.\nRET: %d", ret);
                ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* set the parameter string */
    if (ret == 0) {
        ret = wc_XmssKey_SetParamStr(key, paramStr);
        if (ret != 0) {
            wolfCLU_LogError("Failed to set parameter string."
                             "\nRET: %d", ret);
        }
    }

    /* import the public key */
    if (ret == 0) {
        ret = wc_XmssKey_ImportPubRaw(key, keyBuf, (word32)keyFileSz);
        if (ret != 0) {
            wolfCLU_LogError("Failed to decode public key."
                             "\nRET: %d", ret);
        }
    }

    /* verify message with XMSS/XMSS^MT public key */
    if (ret == 0) {
        ret = wc_XmssKey_Verify(key, sig, sigSz, msg, msgLen);
        if (ret != 0) {
            WOLFCLU_LOG(WOLFCLU_L0, "Invalid Signature.");
        }
        else {
            WOLFCLU_LOG(WOLFCLU_L0, "Valid Signature.");
        }
    }

    /* cleanup allocated resources */
    if (keyBuf != NULL) {
        XFREE(keyBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (paramStr != NULL) {
        XFREE(paramStr, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }

    wc_XmssKey_Free(key);
#ifdef WOLFSSL_SMALL_STACK
    XFREE(key, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return (ret == 0) ? WOLFCLU_SUCCESS : ret;
#else
    (void)sig;
    (void)sigSz;
    (void)msg;
    (void)msgLen;
    (void)pubKey;

    return NOT_COMPILED_IN;
#endif  /* WOLFSSL_HAVE_XMSS */
}

int wolfCLU_verify_signature_xmssmt(byte* sig, int sigSz,
                                    byte* msg, int msgLen, char* pubKey)
{
#ifdef WOLFSSL_HAVE_XMSS
    int ret        = 0;
    byte* keyBuf   = NULL;                     /* public key buffer            */
    long keyFileSz  = 0;                        /* public key buffer size       */
    word32 oid     = 0x0;                      /* OID of the XMSS parameter    */
    char* paramStr = NULL;                     /* XMSS parameter string        */
    int paramLen   = XMSSMT_NAME_MAX_LEN + 1;  /* XMSS parameter string length */

#ifdef WOLFSSL_SMALL_STACK
    XmssKey *key = (XmssKey*)XMALLOC(sizeof(XmssKey),
                                     HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (key == NULL) {
        wolfCLU_LogError("Failed to malloc key buffer.");
        return MEMORY_E;
    }
#else
    XmssKey key[1];
#endif

    /* init the xmss key */
    ret = wc_XmssKey_Init(key, HEAP_HINT, 0);
    if (ret != 0) {
        wolfCLU_LogError("Failed to initialize XMSS Key.\nRET: %d", ret);
    }

    /* open and read public key */
    if (ret == 0) {
        ret = wolfCLU_ReadXmssPubKey(pubKey, &keyBuf, &keyFileSz);
        if (ret == WOLFCLU_SUCCESS) {
            ret = 0;
        }
    }

    /* get the parameter from OID */
    if (ret == 0) {
        paramStr = XMALLOC(paramLen , HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (paramStr == NULL) {
            ret = MEMORY_E;
            wolfCLU_LogError("Failed to malloc parameter string."
                             "\nRET: %d", ret);
        }
        else {
            XMEMSET(paramStr, 0, paramLen);
        }
    }

    if (ret == 0) {
        for (unsigned int i = 0; i < XMSS_OID_LEN; i++) {
            oid = (oid << 8) | keyBuf[i];
        }

        switch (oid) {
            case WC_XMSSMT_OID_SHA2_20_2_256:
                XMEMCPY(paramStr, "XMSSMT-SHA2_20/2_256\0\0", paramLen);
                break;
            case WC_XMSSMT_OID_SHA2_20_4_256:
                XMEMCPY(paramStr, "XMSSMT-SHA2_20/4_256\0\0", paramLen);
                break;
            case WC_XMSSMT_OID_SHA2_40_2_256:
                XMEMCPY(paramStr, "XMSSMT-SHA2_40/2_256\0\0", paramLen);
                break;
            case WC_XMSSMT_OID_SHA2_40_4_256:
                XMEMCPY(paramStr, "XMSSMT-SHA2_40/4_256\0\0", paramLen);
                break;
            case WC_XMSSMT_OID_SHA2_40_8_256:
                XMEMCPY(paramStr, "XMSSMT-SHA2_40/8_256\0\0", paramLen);
                break;
            case WC_XMSSMT_OID_SHA2_60_3_256:
                XMEMCPY(paramStr, "XMSSMT-SHA2_60/3_256\0\0", paramLen);
                break;
            case WC_XMSSMT_OID_SHA2_60_6_256:
                XMEMCPY(paramStr, "XMSSMT-SHA2_60/6_256\0\0", paramLen);
                break;
            case WC_XMSSMT_OID_SHA2_60_12_256:
                XMEMCPY(paramStr, "XMSSMT-SHA2_60/12_256\0", paramLen);
                break;
            default:
                wolfCLU_LogError("Invalid XMSS OID.\nRET: %d", ret);
                ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* set the parameter string */
    if (ret == 0) {
        ret = wc_XmssKey_SetParamStr(key, paramStr);
        if (ret != 0) {
            wolfCLU_LogError("Failed to set parameter string."
                             "\nRET: %d", ret);
        }
    }

    /* import the public key */
    if (ret == 0) {
        ret = wc_XmssKey_ImportPubRaw(key, keyBuf, (word32)keyFileSz);
        if (ret != 0) {
            wolfCLU_LogError("Failed to decode public key."
                             "\nRET: %d", ret);
        }
    }

    /* verify message with XMSS/XMSS^MT public key */
    if (ret == 0) {
        ret = wc_XmssKey_Verify(key, sig, sigSz, msg, msgLen);
        if (ret != 0) {
            WOLFCLU_LOG(WOLFCLU_L0, "Invalid Signature.");
        }
        else {
            WOLFCLU_LOG(WOLFCLU_L0, "Valid Signature.");
        }
    }

    /* cleanup allocated resources */
    if (keyBuf != NULL) {
        XFREE(keyBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (paramStr != NULL) {
        XFREE(paramStr, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }

    wc_XmssKey_Free(key);
#ifdef WOLFSSL_SMALL_STACK
    XFREE(key, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return (ret == 0) ? WOLFCLU_SUCCESS : ret;
#else
    (void)sig;
    (void)sigSz;
    (void)msg;
    (void)msgLen;
    (void)pubKey;

    return NOT_COMPILED_IN;
#endif  /* WOLFSSL_HAVE_XMSS */
}

#endif /* WOLFCLU_NO_FILESYSTEM */
