/* clu_mldsa.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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
#include <wolfclu/x509/clu_parse.h>
#include <wolfclu/x509/clu_cert.h>
#include <wolfclu/x509/clu_mldsa.h>
#include <wolfclu/x509/clu_x509_sign.h>
#include <wolfclu/sign-verify/clu_sign.h>
#include <wolfssl/openssl/x509v3.h>

#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/asn_public.h>

#if defined(WOLFCLU_HAVE_MLDSA)

/* Free heap MlDsaKey at *key. returns WOLFCLU_SUCCESS or BAD_FUNC_ARG. */
int wolfCLU_FreeMLDSAKeyHeap(MlDsaKey** key)
{
    if (key == NULL) {
        return BAD_FUNC_ARG;
    }
    if (*key == NULL) {
        return WOLFCLU_SUCCESS;
    }

    wc_MlDsaKey_Free(*key);
    /* Belt-and-suspenders zero. */
    wolfCLU_ForceZero(*key, (unsigned int)sizeof(MlDsaKey));
    XFREE(*key, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    *key = NULL;
    return WOLFCLU_SUCCESS;
}

/* CLU_KEY_CTX::keyFree adapter; see wolfclu/x509/clu_mldsa.h. */
void wolfCLU_MLDSAKeyCtxFree(void** key)
{
    if (key != NULL) {
        wolfCLU_FreeMLDSAKeyHeap((MlDsaKey**)key);
    }
}

/*ML-DSA parameter sets wolfCLU supports. */
#define WOLFCLU_MLDSA_SIGN_BUF_SZ2  (16 * 1024)
#define WOLFCLU_MLDSA_SIGN_BUF_SZ3  (24 * 1024)
#define WOLFCLU_MLDSA_SIGN_BUF_SZ5  (32 * 1024)
#define WOLFCLU_MLDSA_SIGN_BUF_DFLT WOLFCLU_MLDSA_SIGN_BUF_SZ5

/* Input limits: cap to prevent integer truncation and unbounded heap use */
#define WOLFCLU_MLDSA_PEM_HDR_MARGIN  64  /* header + footer + rounding */
#define WOLFCLU_MLDSA_MAX_PATH_LEN    512
#define WOLFCLU_MLDSA_MAX_CERT_DER_SZ WOLFCLU_MLDSA_SIGN_BUF_SZ5
#define WOLFCLU_MLDSA_MAX_PEM_SZ      (WOLFCLU_MLDSA_MAX_CERT_DER_SZ + \
                                         (WOLFCLU_MLDSA_MAX_CERT_DER_SZ / 2))

typedef struct WOLFCLU_MLDSA_PARAMS {
    int  wcLevel;      /* WC_ML_DSA_44 / 65 / 87 */
    int  wcType;       /* ML_DSA_LEVELx_TYPE */
    int  sigType;      /* CTC_ML_DSA_LEVELx (certificate signature) */
    int  keyOid;       /* canonical ML_DSA_xxk */
    int  legacyOid;    /* DILITHIUM_LEVELxk alias */
    int  signBufSz;    /* cert TBS + signature + PEM headroom */
    int  keyDerSz;      /* ML_DSA_LEVELx_BOTH_KEY_DER_SIZE (keygen) */
    byte level;        /* user-facing 2 / 3 / 5 */
} WOLFCLU_MLDSA_PARAMS;

static const WOLFCLU_MLDSA_PARAMS wolfCLU_mldsaParams[] = {
    { WC_ML_DSA_44, ML_DSA_LEVEL2_TYPE, CTC_ML_DSA_LEVEL2,
      ML_DSA_44k, DILITHIUM_LEVEL2k,
      WOLFCLU_MLDSA_SIGN_BUF_SZ2, ML_DSA_LEVEL2_BOTH_KEY_DER_SIZE, 2 },
    { WC_ML_DSA_65, ML_DSA_LEVEL3_TYPE, CTC_ML_DSA_LEVEL3,
      ML_DSA_65k, DILITHIUM_LEVEL3k,
      WOLFCLU_MLDSA_SIGN_BUF_SZ3, ML_DSA_LEVEL3_BOTH_KEY_DER_SIZE, 3 },
    { WC_ML_DSA_87, ML_DSA_LEVEL5_TYPE, CTC_ML_DSA_LEVEL5,
      ML_DSA_87k, DILITHIUM_LEVEL5k,
      WOLFCLU_MLDSA_SIGN_BUF_SZ5, ML_DSA_LEVEL5_BOTH_KEY_DER_SIZE, 5 },
};

#define WOLFCLU_MLDSA_PARAMS_CNT \
    (sizeof(wolfCLU_mldsaParams) / sizeof(wolfCLU_mldsaParams[0]))

/* Find parameters by user level. Returns pointer or NULL. */
static const WOLFCLU_MLDSA_PARAMS* wolfCLU_MLDSAParamsByLevel(byte level)
{
    size_t i;
    for (i = 0; i < WOLFCLU_MLDSA_PARAMS_CNT; i++) {
        if (wolfCLU_mldsaParams[i].level == level) {
            return &wolfCLU_mldsaParams[i];
        }
    }
    return NULL;
}

/* Find parameters by key OID. Returns pointer or NULL. */
static const WOLFCLU_MLDSA_PARAMS* wolfCLU_MLDSAParamsByOid(int oid)
{
    size_t i;
    for (i = 0; i < WOLFCLU_MLDSA_PARAMS_CNT; i++) {
        if (wolfCLU_mldsaParams[i].keyOid == oid ||
                wolfCLU_mldsaParams[i].legacyOid == oid) {
            return &wolfCLU_mldsaParams[i];
        }
    }
    return NULL;
}

/* Check if keyType OID is ML-DSA. Returns 1 if ML-DSA, else 0. */
int wolfCLU_IsMLDSAKeyType(int keyType)
{
    return (wolfCLU_MLDSAParamsByOid(keyType) != NULL) ? 1 : 0;
}

/* Get signing buffer size for level. Returns size in bytes. */
int wolfCLU_MLDSASignBufSz(byte level)
{
    const WOLFCLU_MLDSA_PARAMS* p = wolfCLU_MLDSAParamsByLevel(level);

    return (p != NULL) ? p->signBufSz : WOLFCLU_MLDSA_SIGN_BUF_DFLT;
}

/* Buffer size for CA-signing a cert/CSR: must hold both the CA's own
 * TBS/signature material at caLevel and the subject's public key material,
 * so use the larger of the two per-level sign buffer sizes. */
static int wolfCLU_MLDSACertSignBufSz(byte caLevel, WOLFSSL_X509* subject)
{
    int bufSz = wolfCLU_MLDSASignBufSz(caLevel);
    const WOLFCLU_MLDSA_PARAMS* subjParams =
            wolfCLU_MLDSAParamsByOid(wolfSSL_X509_get_pubkey_type(subject));

    if (subjParams != NULL && subjParams->signBufSz > bufSz) {
        bufSz = subjParams->signBufSz;
    }
    return bufSz;
}

#if defined(WOLFSSL_CERT_GEN)
/* Set key parameters from public OID. Returns WOLFCLU_SUCCESS or error. */
static int wolfCLU_MLDSAPubOidSetParams(MlDsaKey* key, int pubOid)
{
    const WOLFCLU_MLDSA_PARAMS* p = wolfCLU_MLDSAParamsByOid(pubOid);

    if (p == NULL) {
        return WOLFCLU_FATAL_ERROR;
    }

    return (wc_MlDsaKey_SetParams(key, (byte)p->wcLevel) == 0) ?
            WOLFCLU_SUCCESS : WOLFCLU_FATAL_ERROR;
}
#endif /* WOLFSSL_CERT_GEN */

/* Get signature and key type for level. Returns WOLFCLU_SUCCESS or error. */
int wolfCLU_MLDSALevelToTypes(byte level, int* sigType, int* mldsaType)
{
    const WOLFCLU_MLDSA_PARAMS* p;

    if (sigType == NULL || mldsaType == NULL) {
        return BAD_FUNC_ARG;
    }

    p = wolfCLU_MLDSAParamsByLevel(level);
    if (p == NULL) {
        wolfCLU_LogError("Unexpected ML-DSA level %d (supported: 2, 3, 5)",
                level);
        return BAD_FUNC_ARG;
    }

    *sigType   = p->sigType;
    *mldsaType = p->wcType;
    return WOLFCLU_SUCCESS;
}

/* Map user level to legacy key OID. Returns OID value, or 0. */
int wolfCLU_MLDSALevelToKeyOid(byte level)
{
    const WOLFCLU_MLDSA_PARAMS* p = wolfCLU_MLDSAParamsByLevel(level);

    return (p != NULL) ? p->legacyOid : 0;
}

/* Get key-generation params (wcLevel, DER size, canonical key OID) for a
 * user-facing level. Returns WOLFCLU_SUCCESS or BAD_FUNC_ARG for an
 * unsupported level. */
int wolfCLU_MLDSALevelToKeyGenParams(byte level, int* wcLevel, int* keyDerSz,
        int* keyOid)
{
    const WOLFCLU_MLDSA_PARAMS* p;

    if (wcLevel == NULL || keyDerSz == NULL || keyOid == NULL) {
        return BAD_FUNC_ARG;
    }

    p = wolfCLU_MLDSAParamsByLevel(level);
    if (p == NULL) {
        wolfCLU_LogError("Unexpected ML-DSA level %d (supported: 2, 3, 5)",
                level);
        return BAD_FUNC_ARG;
    }

    *wcLevel  = p->wcLevel;
    *keyDerSz = p->keyDerSz;
    *keyOid   = p->keyOid;
    return WOLFCLU_SUCCESS;
}

#if defined(WOLFSSL_CERT_GEN)
/* Validate DER size against maximum. Returns WOLFCLU_SUCCESS or error. */
static int wolfCLU_MLDSACheckDerSz(int derSz, int maxDerSz)
{
    if (derSz <= 0 || derSz > maxDerSz) {
        return WOLFCLU_FATAL_ERROR;
    }
    return WOLFCLU_SUCCESS;
}
#endif /* WOLFSSL_CERT_GEN */

#ifndef WOLFCLU_NO_FILESYSTEM

/* Check file path length against limit. Returns WOLFCLU_SUCCESS or error. */
static int wolfCLU_MLDSACheckPathLen(const char* path)
{
    size_t len;

    if (path == NULL) {
        return BAD_FUNC_ARG;
    }
    len = XSTRLEN(path);
    if (len == 0 || len > WOLFCLU_MLDSA_MAX_PATH_LEN) {
        return BAD_FUNC_ARG;
    }
    return WOLFCLU_SUCCESS;
}

/* Replace oldSuf at the end of path with newSuf; return allocated path or NULL. */
static char* wolfCLU_MLDSASwapSuffix(const char* path, const char* oldSuf,
        const char* newSuf)
{
    int   len;
    int   oldSufLen;
    int   newSufLen;
    int   stemLen;
    char* out = NULL;

    if (path == NULL || oldSuf == NULL || newSuf == NULL) {
        return NULL;
    }
    if (wolfCLU_MLDSACheckPathLen(path) != WOLFCLU_SUCCESS) {
        return NULL;
    }
    len = (int)XSTRLEN(path);
    oldSufLen = (int)XSTRLEN(oldSuf);
    newSufLen = (int)XSTRLEN(newSuf);
    if (len <= oldSufLen ||
            XSTRNCMP(path + len - oldSufLen, oldSuf, oldSufLen) != 0) {
        return NULL;
    }
    stemLen = len - oldSufLen;
    out = (char*)XMALLOC(stemLen + newSufLen + 1, HEAP_HINT,
            DYNAMIC_TYPE_TMP_BUFFER);
    if (out != NULL) {
        XMEMCPY(out, path, stemLen);
        XMEMCPY(out + stemLen, newSuf, newSufLen);
        out[stemLen + newSufLen] = '\0';
    }
    return out;
}

/* Return a newly allocated "<stem>Pub.pem" path derived from "<stem>.pem". */
static char* wolfCLU_MLDSADupKeyPubPath(const char* keyPath)
{
    return wolfCLU_MLDSASwapSuffix(keyPath, ".pem", "Pub.pem");
}

/* Return a newly allocated "<name>.pub" path derived from "<name>.priv". */
char* wolfCLU_MLDSADupPrivPubPath(const char* privPath)
{
    return wolfCLU_MLDSASwapSuffix(privPath, ".priv", ".pub");
}

/* Read an entire file into a newly allocated buffer, capped at
 * DILITHIUM_MAX_BOTH_KEY_PEM_SIZE. */
/* isSecret selects the symlink-refusing reader, so an ML-DSA private key
 * gets the same treatment as every other private key wolfCLU reads. */
static int wolfCLU_MLDSAReadFile(const char* path, byte** outBuf, int* outSz,
        int isSecret)
{
    if (wolfCLU_MLDSACheckPathLen(path) != WOLFCLU_SUCCESS) {
        return BAD_FUNC_ARG;
    }

    if (isSecret) {
        return wolfCLU_ReadKeyFileToBuffer(path,
                DILITHIUM_MAX_BOTH_KEY_PEM_SIZE, outBuf, outSz);
    }
    return wolfCLU_ReadFileToBuffer(path, DILITHIUM_MAX_BOTH_KEY_PEM_SIZE,
            outBuf, outSz);
}

/*Derive the companion public-key path for an ML-DSA private key. */
static char* wolfCLU_MLDSADeriveCompanionPath(const char* keyPath, int* err)
{
    int   len;
    char* pub = NULL;

    if (err == NULL) {
        return NULL;
    }
    if (wolfCLU_MLDSACheckPathLen(keyPath) != WOLFCLU_SUCCESS) {
        *err = BAD_FUNC_ARG;
        return NULL;
    }
    len = (int)XSTRLEN(keyPath);
    if (len > (int)(sizeof(".pem") - 1) &&
            XSTRNCMP(keyPath + len - (sizeof(".pem") - 1), ".pem",
                    sizeof(".pem") - 1) == 0) {
        pub = wolfCLU_MLDSADupKeyPubPath(keyPath);
        *err = (pub == NULL) ? MEMORY_E : WOLFCLU_SUCCESS;
    }
    else if (len > (int)(sizeof(".priv") - 1) &&
            XSTRNCMP(keyPath + len - (sizeof(".priv") - 1), ".priv",
                    sizeof(".priv") - 1) == 0) {
        pub = wolfCLU_MLDSADupPrivPubPath(keyPath);
        *err = (pub == NULL) ? MEMORY_E : WOLFCLU_SUCCESS;
    }
    else {
        wolfCLU_LogError("Cannot derive ML-DSA public key path from %s",
                keyPath);
        *err = BAD_FUNC_ARG;
    }
    return pub;
}

/* Load companion public key from file. Returns WOLFCLU_SUCCESS or error. */
int wolfCLU_LoadMLDSACompanionPub(const char* keyPath, MlDsaKey* key, int quiet)
{
    int    ret      = WOLFCLU_SUCCESS;
    int    pubBufSz = 0;
    word32 pubIdx   = 0;
    char*  pubPath  = NULL;
    byte*  pubBuf   = NULL;

    if (keyPath == NULL || key == NULL) {
        return BAD_FUNC_ARG;
    }

    pubPath = wolfCLU_MLDSADeriveCompanionPath(keyPath, &ret);
    if (pubPath == NULL) {
        return ret;
    }

    ret = wolfCLU_MLDSAReadFile(pubPath, &pubBuf, &pubBufSz, 0);
    if (ret != WOLFCLU_SUCCESS) {
        if (!quiet)
            wolfCLU_LogError("Unable to open public key file %s", pubPath);
    }

    if (ret == WOLFCLU_SUCCESS) {
        /* Convert PEM to DER. wolfCLU_KeyPemToDer checks for no PEM header. */
        int derSz = wolfCLU_KeyPemToDer(&pubBuf, pubBufSz, 1);

        if (derSz > 0) {
            pubBufSz = derSz;
        }
        else if (derSz == WC_NO_ERR_TRACE(MEMORY_E)) {
            if (!quiet)
                wolfCLU_LogError("Out of memory converting public key PEM to DER");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else if (derSz == WOLFCLU_FATAL_ERROR) {
            /* Already logged by wolfCLU_KeyPemToDer (size limit). */
            ret = WOLFCLU_FATAL_ERROR;
        }
        else if (derSz < 0 && derSz != WC_NO_ERR_TRACE(ASN_NO_PEM_HEADER)) {
            if (!quiet)
                wolfCLU_LogError("Failed to convert public key PEM to DER: %d",
                        derSz);
            ret = WOLFCLU_FATAL_ERROR;
        }
        /* derSz == 0 or ASN_NO_PEM_HEADER: no PEM structure, try raw DER */
    }

    if (ret == WOLFCLU_SUCCESS &&
            wc_Dilithium_PublicKeyDecode(pubBuf, &pubIdx, key,
                (word32)pubBufSz) != 0) {
        if (!quiet)
            wolfCLU_LogError("Failed to decode ML-DSA public key");
        ret = WOLFCLU_FATAL_ERROR;
    }

    XFREE(pubPath, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (pubBuf != NULL) {
        wolfCLU_ForceZero(pubBuf, pubBufSz);
        XFREE(pubBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }
    return ret;
}

/*Load ML-DSA key from file and get level. */
int wolfCLU_LoadMLDSAKey(const char* keyPath, MlDsaKey* key, byte* level,
        int quiet)
{
    int ret = WOLFCLU_SUCCESS;
    int keySz = 0;
    word32 idx = 0;
    byte* keyBuf = NULL;

    if (keyPath == NULL || key == NULL || level == NULL) {
        return BAD_FUNC_ARG;
    }
    if (wolfCLU_MLDSACheckPathLen(keyPath) != WOLFCLU_SUCCESS) {
        return BAD_FUNC_ARG;
    }

    ret = wolfCLU_MLDSAReadFile(keyPath, &keyBuf, &keySz, 1);
    if (ret != WOLFCLU_SUCCESS) {
        if (!quiet)
            wolfCLU_LogError("Unable to read ML-DSA key file %s", keyPath);
        return ret;
    }

    ret = wc_MlDsaKey_Init(key, NULL, INVALID_DEVID);
    if (ret != 0) {
        if (!quiet)
            wolfCLU_LogError("Failed to initialize ML-DSA key: %d", ret);
        wolfCLU_ForceZero(keyBuf, keySz);
        XFREE(keyBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        return WOLFCLU_FAILURE;
    }

    idx = 0;
    if (wc_Dilithium_PrivateKeyDecode(keyBuf, &idx, key, (word32)keySz) != 0) {
        /* origBuf/pemSz for error path; KeyPemToDer frees keyBuf on success
         * and repoints it at the DER buffer. */
        byte* origBuf = keyBuf;
        int   pemSz   = keySz;

        /* DER decode failed; try PEM instead. */
        wc_MlDsaKey_Free(key);

        ret = wolfCLU_KeyPemToDer(&keyBuf, keySz, 0);
        if (ret <= 0) {
            if (!quiet)
                wolfCLU_LogError("Failed to load ML-DSA key (tried DER and PEM)");
            wolfCLU_ForceZero(origBuf, pemSz);
            XFREE(origBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            return WOLFCLU_FAILURE;
        }
        keySz = ret; /* keySz is now the DER size */

        ret = wc_MlDsaKey_Init(key, NULL, INVALID_DEVID);
        if (ret != 0) {
            if (!quiet)
                wolfCLU_LogError("Failed to initialize ML-DSA key: %d", ret);
            wolfCLU_ForceZero(keyBuf, keySz);
            XFREE(keyBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            return WOLFCLU_FAILURE;
        }

        idx = 0;
        if (wc_Dilithium_PrivateKeyDecode(keyBuf, &idx, key,
                (word32)keySz) != 0) {
            if (!quiet)
                wolfCLU_LogError("Failed to decode ML-DSA private key");
            wolfCLU_ForceZero(keyBuf, keySz);
            XFREE(keyBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            wc_MlDsaKey_Free(key);
            return WOLFCLU_FAILURE;
        }
        wolfCLU_ForceZero(keyBuf, keySz);
        XFREE(keyBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        keyBuf = NULL;
    }
    else {
        wolfCLU_ForceZero(keyBuf, keySz);
        XFREE(keyBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        keyBuf = NULL;
    }

    ret = wc_MlDsaKey_GetParams(key, level);
    if (ret != 0) {
        if (!quiet)
            wolfCLU_LogError("Failed to get ML-DSA key level: %d", ret);
        wc_MlDsaKey_Free(key);
        return WOLFCLU_FAILURE;
    }

    if (wolfCLU_MLDSAParamsByLevel(*level) == NULL) {
        if (!quiet)
            wolfCLU_LogError("Unsupported ML-DSA key level %d (supported: 2, 3, 5)",
                    *level);
        wc_MlDsaKey_Free(key);
        return WOLFCLU_FAILURE;
    }

    if (!WOLFCLU_MLDSA_PUB_KEY_IS_SET(key)) {
        ret = wolfCLU_LoadMLDSACompanionPub(keyPath, key, quiet);
        if (ret != WOLFCLU_SUCCESS) {
            wc_MlDsaKey_Free(key);
            return ret;
        }

#ifdef WOLFSSL_DILITHIUM_CHECK_KEY
        /* Companion pub file is loaded separately from the private key;
         * confirm it actually pairs with it before using either. */
        if (wc_dilithium_check_key(key) != 0) {
            if (!quiet)
                wolfCLU_LogError("Public key file does not match "
                        "ML-DSA private key %s", keyPath);
            wc_MlDsaKey_Free(key);
            return WOLFCLU_FAILURE;
        }
#endif
    }
    return WOLFCLU_SUCCESS;
}

/* Return 1 when path holds ML-DSA private key wolfCLU_LoadMLDSAKey accepts. */
int wolfCLU_IsMLDSAKeyFile(const char* path)
{
    MlDsaKey* key = NULL;
    byte      level = 0;
    int       isMLDSA = 0;

    if (path == NULL) {
        return 0;
    }

    key = (MlDsaKey*)XMALLOC(sizeof(MlDsaKey), HEAP_HINT,
            DYNAMIC_TYPE_TMP_BUFFER);
    if (key == NULL) {
        return 0;
    }

    XMEMSET(key, 0, sizeof(*key));
    if (wolfCLU_LoadMLDSAKey(path, key, &level, 1) == WOLFCLU_SUCCESS) {
        isMLDSA = 1;
    }

    wolfCLU_FreeMLDSAKeyHeap(&key);
    return isMLDSA;
}

#endif /* !WOLFCLU_NO_FILESYSTEM */

#if defined(WOLFSSL_CERT_GEN)
/*pubKey must point to a zeroed MlDsaKey sized region. */
static int wolfCLU_X509GetMLDSAPubKey(WOLFSSL_X509* x509, MlDsaKey* pubKey)
{
    byte* der = NULL;
    int derSz = 0;
    word32 idx = 0;
    int pubOid;
    int ret;
    int keyInit = 0;
    WOLFSSL_EVP_PKEY* pkey = NULL;

    if (x509 == NULL || pubKey == NULL) {
        return BAD_FUNC_ARG;
    }
    XMEMSET(pubKey, 0, sizeof(*pubKey));

    pubOid = wolfSSL_X509_get_pubkey_type(x509);
    if (wolfCLU_IsMLDSAKeyType(pubOid) == 0) {
        return WOLFCLU_FATAL_ERROR;
    }

    if (wc_MlDsaKey_Init(pubKey, NULL, INVALID_DEVID) != 0) {
        return WOLFCLU_FATAL_ERROR;
    }
    keyInit = 1;
    ret = WOLFCLU_FATAL_ERROR;

    /* Full SubjectPublicKeyInfo DER (certificates). */
    if (wolfSSL_X509_get_pubkey_buffer(x509, NULL, &derSz) ==
            WOLFSSL_SUCCESS &&
            wolfCLU_MLDSACheckDerSz(derSz, WOLFCLU_MLDSA_MAX_SPKI_DER_SZ) ==
            WOLFCLU_SUCCESS) {
        der = (byte*)XMALLOC(derSz, HEAP_HINT, DYNAMIC_TYPE_PUBLIC_KEY);
        if (der != NULL &&
                wolfSSL_X509_get_pubkey_buffer(x509, der, &derSz) ==
                WOLFSSL_SUCCESS) {
            idx = 0;
            if (wc_MlDsaKey_PublicKeyDecode(pubKey, der, (word32)derSz, &idx)
                    == 0) {
                ret = WOLFCLU_SUCCESS;
            }
        }
        XFREE(der, HEAP_HINT, DYNAMIC_TYPE_PUBLIC_KEY);
        der = NULL;
    }

    /* CSR fallback: needs params set before decode, so re-init first. */
    if (ret != WOLFCLU_SUCCESS) {
        wc_MlDsaKey_Free(pubKey);
        XMEMSET(pubKey, 0, sizeof(*pubKey));
        keyInit = 0;

        if (wc_MlDsaKey_Init(pubKey, NULL, INVALID_DEVID) == 0) {
            keyInit = 1;

            if (wolfCLU_MLDSAPubOidSetParams(pubKey, pubOid)
                    == WOLFCLU_SUCCESS) {
                /* No public API for raw SPKI; use pkey.ptr/pkey_sz. */
                pkey = wolfSSL_X509_get_pubkey(x509);
                if (pkey != NULL && pkey->pkey.ptr != NULL &&
                        pkey->pkey_sz > 0 &&
                        pkey->pkey_sz <= WOLFCLU_MLDSA_MAX_SPKI_DER_SZ) {
                    idx = 0;
                    if (wc_MlDsaKey_PublicKeyDecode(pubKey,
                            (const byte*)pkey->pkey.ptr,
                            (word32)pkey->pkey_sz, &idx) == 0) {
                        ret = WOLFCLU_SUCCESS;
                    }
                }
            }
        }
    }

    if (pkey != NULL) {
        wolfSSL_EVP_PKEY_free(pkey);
    }
    /* on failure, leave pubKey freed and zeroed (see contract above) */
    if (ret != WOLFCLU_SUCCESS && keyInit) {
        wc_MlDsaKey_Free(pubKey);
        XMEMSET(pubKey, 0, sizeof(*pubKey));
    }
    return ret;
}
#endif /* WOLFSSL_CERT_GEN (wolfCLU_X509GetMLDSAPubKey) */

#if defined(WOLFSSL_CERT_GEN)
/* Map ML-DSA public OID to wolfcrypt type. Returns WOLFCLU_SUCCESS or error. */
static int wolfCLU_MLDSAPubOidToWcType(int pubOid, int* wcType)
{
    const WOLFCLU_MLDSA_PARAMS* p;

    if (wcType == NULL) {
        return BAD_FUNC_ARG;
    }

    p = wolfCLU_MLDSAParamsByOid(pubOid);
    if (p == NULL) {
        return WOLFCLU_FATAL_ERROR;
    }

    *wcType = p->wcType;
    return WOLFCLU_SUCCESS;
}
#endif /* WOLFSSL_CERT_GEN */

#if defined(WOLFSSL_CERT_GEN)
#ifndef NO_CHECK_PRIVATE_KEY
/* Verify private key matches CA cert. Returns WOLFCLU_SUCCESS or error. */
int wolfCLU_MLDSACheckPrivateKeyCert(WOLFSSL_X509* caCert,
        MlDsaKey* caKey)
{
    MlDsaKey* pubKey = NULL;
    byte*     keyRaw = NULL;
    byte*     certRaw = NULL;
    word32    keyRawSz = DILITHIUM_MAX_PUB_KEY_SIZE;
    word32    certRawSz = DILITHIUM_MAX_PUB_KEY_SIZE;
    int       ret = WOLFCLU_SUCCESS;
    int       pubKeyInit = 0; /* only free pubKey below if it was init'd */

    if (caCert == NULL || caKey == NULL) {
        return BAD_FUNC_ARG;
    }

    pubKey = (MlDsaKey*)XMALLOC(sizeof(MlDsaKey), HEAP_HINT,
            DYNAMIC_TYPE_TMP_BUFFER);
    keyRaw = (byte*)XMALLOC(DILITHIUM_MAX_PUB_KEY_SIZE, HEAP_HINT,
            DYNAMIC_TYPE_TMP_BUFFER);
    certRaw = (byte*)XMALLOC(DILITHIUM_MAX_PUB_KEY_SIZE, HEAP_HINT,
            DYNAMIC_TYPE_TMP_BUFFER);
    if (pubKey == NULL || keyRaw == NULL || certRaw == NULL) {
        ret = MEMORY_E;
    }

    if (ret == WOLFCLU_SUCCESS) {
        XMEMSET(pubKey, 0, sizeof(*pubKey));
        if (wolfCLU_X509GetMLDSAPubKey(caCert, pubKey) != WOLFCLU_SUCCESS) {
            wolfCLU_LogError("Error getting ML-DSA public key from CA/CSR");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            pubKeyInit = 1;
        }
    }

    if (ret == WOLFCLU_SUCCESS &&
            wc_MlDsaKey_ExportPubRaw(caKey, keyRaw, &keyRawSz) != 0) {
        wolfCLU_LogError("Error exporting ML-DSA public key");
        ret = WOLFCLU_FATAL_ERROR;
    }

    if (ret == WOLFCLU_SUCCESS &&
            wc_MlDsaKey_ExportPubRaw(pubKey, certRaw, &certRawSz) != 0) {
        wolfCLU_LogError("Error exporting ML-DSA public key");
        ret = WOLFCLU_FATAL_ERROR;
    }

    if (ret == WOLFCLU_SUCCESS &&
            ((keyRawSz != certRawSz) ||
             (XMEMCMP(keyRaw, certRaw, keyRawSz) != 0))) {
        wolfCLU_LogError("Private key does not match with CA");
        ret = WOLFCLU_FATAL_ERROR;
    }

    /* single cleanup for every path */
    if (pubKeyInit) {
        wc_MlDsaKey_Free(pubKey);
    }
    if (keyRaw != NULL) {
        wolfCLU_ForceZero(keyRaw, DILITHIUM_MAX_PUB_KEY_SIZE);
    }
    if (certRaw != NULL) {
        wolfCLU_ForceZero(certRaw, DILITHIUM_MAX_PUB_KEY_SIZE);
    }
    if (pubKey != NULL) {
        wolfCLU_ForceZero(pubKey, sizeof(*pubKey));
    }
    XFREE(pubKey, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(keyRaw, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(certRaw, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}
#endif /* NO_CHECK_PRIVATE_KEY */
#endif /* WOLFSSL_CERT_GEN */


#ifndef WOLFCLU_NO_FILESYSTEM

/* Build an ML-DSA self-signed cert (isCSR == 0) or PKCS#10 CSR (isCSR == 1)
 * from key. */
static int wolfCLU_MLDSABuildAndSign(const char* keyPath, MlDsaKey* inKey,
        WOLFSSL_X509* x509, int days, int isCSR, int outForm,
        WOLFSSL_BIO* bioOut, int noOut)
{
    int    ret       = WOLFCLU_SUCCESS;
    byte   level     = 0;
    int    mldsaType = 0;
    int    sigType   = 0;
    int    bufSz     = 0;
    MlDsaKey* key    = NULL;

    if (keyPath == NULL && inKey == NULL) return BAD_FUNC_ARG;
    if (x509 == NULL) return BAD_FUNC_ARG;
    if ((!noOut) && (bioOut == NULL)) return BAD_FUNC_ARG;

    if (inKey != NULL) {
        key = inKey;
        ret = (wc_MlDsaKey_GetParams(key, &level) == 0) ? WOLFCLU_SUCCESS : WOLFCLU_FATAL_ERROR;
    } else {
        key = (MlDsaKey*)XMALLOC(sizeof(MlDsaKey), HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (key == NULL) return MEMORY_E;
        XMEMSET(key, 0, sizeof(*key));
        ret = wolfCLU_LoadMLDSAKey(keyPath, key, &level, 0);
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = wolfCLU_MLDSALevelToTypes(level, &sigType, &mldsaType);
    }

    if (ret == WOLFCLU_SUCCESS) {
        bufSz = wolfCLU_MLDSASignBufSz(level);
        ret = wolfCLU_BuildAndSignNative(key, mldsaType, sigType, bufSz,
                x509, days, isCSR, outForm, bioOut, noOut);
    }

    if (inKey == NULL) {
        wolfCLU_FreeMLDSAKeyHeap(&key);
    }

    return ret;
}

/* Build self-signed ML-DSA cert. Returns WOLFCLU_SUCCESS or error. */
int wolfCLU_MakeMLDSASelfSignedCert(const char* keyPath, MlDsaKey* inKey,
        WOLFSSL_X509* x509, int days, int outForm, WOLFSSL_BIO* bioOut,
        int noOut)
{
    return wolfCLU_MLDSABuildAndSign(keyPath, inKey, x509, days, 0, outForm,
            bioOut, noOut);
}

#ifdef WOLFSSL_CERT_REQ
/* Build ML-DSA PKCS#10 CSR from key. Returns WOLFCLU_SUCCESS or error. */
int wolfCLU_MakeMLDSACSR(const char* keyPath, MlDsaKey* inKey,
        WOLFSSL_X509* x509, int outForm, WOLFSSL_BIO* bioOut, int noOut)
{
    return wolfCLU_MLDSABuildAndSign(keyPath, inKey, x509, 0, 1, outForm,
            bioOut, noOut);
}
#endif /* WOLFSSL_CERT_REQ */

#endif /* !WOLFCLU_NO_FILESYSTEM */

/* Sign x509 with the ML-DSA CA key caKey, writing the encoded cert/CSR to
 * outData/outDataSz. Returns WOLFCLU_SUCCESS or error. */
int wolfCLU_MLDSACertSign(WOLFSSL_X509* x509, MlDsaKey* caKey,
        byte level, WOLFSSL_X509* caCert, int outForm,
        byte** outData, int* outDataSz, int policySanitized)
{
    int ret = WOLFCLU_SUCCESS;
    int bufSz = 0;
    int mldsaType = 0;
    int sigType   = 0;
    int wcKeyType = 0;
    void* subjKey = NULL;
    int initSubjMldsa = 0;
    WOLFSSL_EVP_PKEY* subjPkey = NULL;
    MlDsaKey* subjMldsaKey = NULL;

    if (outData != NULL) *outData = NULL;
    if (outDataSz != NULL) *outDataSz = 0;
    if (x509 == NULL || caKey == NULL || outData == NULL || outDataSz == NULL ||
            wolfCLU_MLDSAParamsByLevel(level) == NULL) {
        return BAD_FUNC_ARG;
    }
    bufSz = wolfCLU_MLDSACertSignBufSz(level, x509);

    subjMldsaKey = (MlDsaKey*)XMALLOC(sizeof(*subjMldsaKey), HEAP_HINT,
            DYNAMIC_TYPE_TMP_BUFFER);
    if (subjMldsaKey == NULL) return MEMORY_E;
    XMEMSET(subjMldsaKey, 0, sizeof(*subjMldsaKey));

    ret = wolfCLU_MLDSALevelToTypes(level, &sigType, &mldsaType);

    if (ret == WOLFCLU_SUCCESS) {
        int subjType = wolfSSL_X509_get_pubkey_type(x509);
        if (subjType == RSAk || subjType == ECDSAk) {
            subjPkey = wolfSSL_X509_get_pubkey(x509);
            if (subjPkey == NULL) {
                wolfCLU_LogError("Error getting subject public key");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        switch (wolfSSL_X509_get_pubkey_type(x509)) {
            case RSAk:
            #ifndef NO_RSA
                if (subjPkey->rsa != NULL) {
                    subjKey = subjPkey->rsa->internal;
                    wcKeyType = RSA_TYPE;
                }
            #else
                wolfCLU_LogError("RSA not compiled in");
                ret = WOLFCLU_FATAL_ERROR;
            #endif
                break;
            case ECDSAk:
            #ifdef HAVE_ECC
                if (subjPkey->ecc != NULL) {
                    subjKey = subjPkey->ecc->internal;
                    wcKeyType = ECC_TYPE;
                }
            #else
                wolfCLU_LogError("ECC not compiled in");
                ret = WOLFCLU_FATAL_ERROR;
            #endif
                break;
            case ML_DSA_44k:
            case ML_DSA_65k:
            case ML_DSA_87k:
            case DILITHIUM_LEVEL2k:
            case DILITHIUM_LEVEL3k:
            case DILITHIUM_LEVEL5k:
                if (wolfCLU_X509GetMLDSAPubKey(x509, subjMldsaKey) != WOLFCLU_SUCCESS) {
                    wolfCLU_LogError("Error decoding ML-DSA subject public key");
                    ret = WOLFCLU_FATAL_ERROR;
                }
                else {
                    initSubjMldsa = 1;
                    if (wolfCLU_MLDSAPubOidToWcType(wolfSSL_X509_get_pubkey_type(x509), &wcKeyType) != WOLFCLU_SUCCESS) {
                        ret = WOLFCLU_FATAL_ERROR;
                    }
                    else {
                        subjKey = subjMldsaKey;
                    }
                }
                break;
            default:
                wolfCLU_LogError("Unsupported subject key type for ML-DSA CA sign");
                ret = WOLFCLU_FATAL_ERROR;
        }
        if (ret == WOLFCLU_SUCCESS && subjKey == NULL) {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = wolfCLU_CertSignNative(x509, caKey, mldsaType, sigType, bufSz,
                caCert, outForm, outData, outDataSz, policySanitized,
                subjKey, wcKeyType);
    }

    if (subjPkey != NULL) {
        wolfSSL_EVP_PKEY_free(subjPkey);
    }
    if (subjMldsaKey != NULL) {
        if (initSubjMldsa) {
            wc_MlDsaKey_Free(subjMldsaKey);
        }
        XFREE(subjMldsaKey, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }

    return ret;
}

#endif /* WOLFCLU_HAVE_MLDSA */
