/* clu_mldsa.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * Temporary ML-DSA shim for wolfCLU CA sign/verify while wolfSSL lacks full
 * EVP/API coverage.  Delete this file once callers can use native EVP paths
 * (PEM key load, X509_sign, store verify, etc.).
 */

#include <wolfclu/clu_header_main.h>
#include <wolfclu/clu_log.h>
#include <wolfclu/clu_error_codes.h>
#include <wolfclu/x509/clu_parse.h>
#include <wolfclu/x509/clu_cert.h>
#include <wolfclu/x509/clu_mldsa.h>
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
    /* Defense-in-depth: zero the struct before handing the block back to the
     * heap allocator regardless of whether wc_MlDsaKey_Free already did so. */
    wolfCLU_ForceZero(*key, (unsigned int)sizeof(MlDsaKey));
    XFREE(*key, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    *key = NULL;
    return WOLFCLU_SUCCESS;
}

/* ML-DSA parameter sets wolfCLU supports. Adding a parameter set is a one-line
 * change here instead of editing several parallel switch statements. */
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
#define WOLFCLU_CERT_DAYS_DEFAULT      365

typedef struct WOLFCLU_MLDSA_PARAMS {
    int  wcLevel;      /* WC_ML_DSA_44 / 65 / 87 */
    int  wcType;       /* ML_DSA_LEVELx_TYPE */
    int  sigType;      /* CTC_ML_DSA_LEVELx (certificate signature) */
    int  keyOid;       /* canonical ML_DSA_xxk */
    int  legacyOid;    /* DILITHIUM_LEVELxk alias */
    int  signBufSz;    /* cert TBS + signature + PEM headroom */
    byte level;        /* user-facing 2 / 3 / 5 */
} WOLFCLU_MLDSA_PARAMS;

static const WOLFCLU_MLDSA_PARAMS wolfCLU_mldsaParams[] = {
    { WC_ML_DSA_44, ML_DSA_LEVEL2_TYPE, CTC_ML_DSA_LEVEL2,
      ML_DSA_44k, DILITHIUM_LEVEL2k,
      WOLFCLU_MLDSA_SIGN_BUF_SZ2, 2 },
    { WC_ML_DSA_65, ML_DSA_LEVEL3_TYPE, CTC_ML_DSA_LEVEL3,
      ML_DSA_65k, DILITHIUM_LEVEL3k,
      WOLFCLU_MLDSA_SIGN_BUF_SZ3, 3 },
    { WC_ML_DSA_87, ML_DSA_LEVEL5_TYPE, CTC_ML_DSA_LEVEL5,
      ML_DSA_87k, DILITHIUM_LEVEL5k,
      WOLFCLU_MLDSA_SIGN_BUF_SZ5, 5 },
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

/* Validate PEM output size. Returns WOLFCLU_SUCCESS or error. */
static int wolfCLU_MLDSACheckPemOutSz(int pemSz, int derSz)
{
    if (pemSz <= 0 || pemSz > WOLFCLU_MLDSA_MAX_PEM_SZ) {
        return WOLFCLU_FATAL_ERROR;
    }
    /* base64 expands DER by ~4/3 (33%); 50% cap (derSz/2) adds 17%
     * headroom for PEM headers, newlines, and rounding. */
    if (derSz > 0 &&
            pemSz > derSz + (derSz / 2) + WOLFCLU_MLDSA_PEM_HDR_MARGIN) {
        return WOLFCLU_FATAL_ERROR;
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
 * DILITHIUM_MAX_BOTH_KEY_PEM_SIZE. On success *outBuf and *outSz are set */
static int wolfCLU_MLDSAReadFile(const char* path, byte** outBuf, int* outSz)
{
    int   sz;
    long  fsz;
    byte* buf = NULL;
    XFILE f;

    if (path == NULL || outBuf == NULL || outSz == NULL) {
        return BAD_FUNC_ARG;
    }
    if (wolfCLU_MLDSACheckPathLen(path) != WOLFCLU_SUCCESS) {
        return BAD_FUNC_ARG;
    }
    *outBuf = NULL;
    *outSz  = 0;

    f = XFOPEN(path, "rb");
    if (f == XBADFILE) {
        return BAD_FUNC_ARG;
    }

    if (XFSEEK(f, 0, SEEK_END) != 0) {
        XFCLOSE(f);
        return WOLFCLU_FATAL_ERROR;
    }
    fsz = XFTELL(f);
    if (XFSEEK(f, 0, SEEK_SET) != 0) {
        XFCLOSE(f);
        return WOLFCLU_FATAL_ERROR;
    }
    if (fsz <= 0) {
        wolfCLU_LogError("%s: key file is empty or unreadable", path);
        XFCLOSE(f);
        return WOLFCLU_FATAL_ERROR;
    }
    if (fsz > DILITHIUM_MAX_BOTH_KEY_PEM_SIZE) {
        wolfCLU_LogError("%s: size %ld exceeds %d-byte key file limit",
                path, fsz, DILITHIUM_MAX_BOTH_KEY_PEM_SIZE);
        XFCLOSE(f);
        return WOLFCLU_FATAL_ERROR;
    }
    /* fsz <= DILITHIUM_MAX_BOTH_KEY_PEM_SIZE << INT_MAX. */
    sz = (int)fsz;

    buf = (byte*)XMALLOC(sz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (buf == NULL) {
        XFCLOSE(f);
        return MEMORY_E;
    }

    if (XFREAD(buf, 1, (size_t)sz, f) != (size_t)sz) {
        XFCLOSE(f);
        XFREE(buf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        return WOLFCLU_FAILURE;
    }
    XFCLOSE(f);

    *outBuf = buf;
    *outSz  = sz;
    return WOLFCLU_SUCCESS;
}

/* Derive the companion public-key path for an ML-DSA private key.
 * Returns a newly allocated path, or NULL. */
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
    if (len > 4 && XSTRNCMP(keyPath + len - 4, ".pem", 4) == 0) {
        pub = wolfCLU_MLDSADupKeyPubPath(keyPath);
        *err = (pub == NULL) ? MEMORY_E : WOLFCLU_SUCCESS;
    }
    else if (len > 5 && XSTRNCMP(keyPath + len - 5, ".priv", 5) == 0) {
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

    ret = wolfCLU_MLDSAReadFile(pubPath, &pubBuf, &pubBufSz);
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

/* Load ML-DSA key from file and get level. Returns WOLFCLU_SUCCESS or error.
 * Pass quiet=1 to suppress all error logging (e.g. when used as a probe). */
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

    ret = wolfCLU_MLDSAReadFile(keyPath, &keyBuf, &keySz);
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
        /* origBuf/pemSz capture the incoming PEM allocation so the error path
         * below can zero/free it.  On success, wolfCLU_KeyPemToDer frees the
         * original buffer internally and updates keyBuf to the new DER buffer,
         * leaving origBuf dangling. */
        byte* origBuf = keyBuf;
        int   pemSz   = keySz;

        /* DER decode failed; try PEM.  Free and zero the key struct so
         * wc_MlDsaKey_Init re-initialises from a clean state.
         * Callers are responsible for releasing the key via
         * wolfCLU_FreeMLDSAKeyHeap on both success and error paths. */
        wc_MlDsaKey_Free(key);
        XMEMSET(key, 0, sizeof(*key));

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
        return WOLFCLU_FAILURE;
    }

    if (wolfCLU_MLDSAParamsByLevel(*level) == NULL) {
        if (!quiet)
            wolfCLU_LogError("Unsupported ML-DSA key level %d (supported: 2, 3, 5)",
                    *level);
        return WOLFCLU_FAILURE;
    }

    if (!WOLFCLU_MLDSA_PUB_KEY_IS_SET(key)) {
        ret = wolfCLU_LoadMLDSACompanionPub(keyPath, key, quiet);
        if (ret != WOLFCLU_SUCCESS) {
            return ret;
        }
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
/* pubKey must point to a zeroed MlDsaKey sized region. Decode the ML-DSA
 * subject public key from a cert or CSR.
 *
 * On success: 'pubKey' is initialized. Caller frees with wc_MlDsaKey_Free on
 * success, but is called here on failure.
 * Caller always XFREEs heap buffer that holds *pubkey. */
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

    /* CSR / raw BIT STRING fallback: ImportPubRaw needs params before decode,
     * so re-initialize the key with the correct parameter set first. */
    if (ret != WOLFCLU_SUCCESS) {
        wc_MlDsaKey_Free(pubKey);
        XMEMSET(pubKey, 0, sizeof(*pubKey));
        keyInit = 0;

        if (wc_MlDsaKey_Init(pubKey, NULL, INVALID_DEVID) == 0) {
            keyInit = 1;

            if (wolfCLU_MLDSAPubOidSetParams(pubKey, pubOid)
                    == WOLFCLU_SUCCESS) {
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
#endif

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
    /* Track whether pubKey was initialized by wolfCLU_X509GetMLDSAPubKey:
     * only then must the single cleanup below call wc_MlDsaKey_Free on it
     * (freeing an uninitialized key would be incorrect). */
    int       pubKeyInit = 0;

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
    XFREE(pubKey, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(keyRaw, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(certRaw, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}
#endif /* NO_CHECK_PRIVATE_KEY */
#endif /* WOLFSSL_CERT_GEN */

#if defined(WOLFSSL_CERT_GEN)
/* Copy X509 name fields to CertName. Returns WOLFCLU_SUCCESS or error. */
static int wolfCLU_CopyX509NameToCert(WOLFSSL_X509_NAME* name, CertName* dst)
{
    int i;

    if (name == NULL || dst == NULL) {
        return BAD_FUNC_ARG;
    }

    for (i = 0; i < wolfSSL_X509_NAME_entry_count(name); i++) {
        WOLFSSL_X509_NAME_ENTRY* e;
        WOLFSSL_ASN1_OBJECT*     obj;
        WOLFSSL_ASN1_STRING*     str;
        const char*              val;
        char*                    field = NULL;
        int                      nid;
        int                      valLen;

        e = wolfSSL_X509_NAME_get_entry(name, i);
        if (e == NULL) {
            continue;
        }
        obj = wolfSSL_X509_NAME_ENTRY_get_object(e);
        str = wolfSSL_X509_NAME_ENTRY_get_data(e);
        if (obj == NULL || str == NULL) {
            continue;
        }

        nid    = wolfSSL_OBJ_obj2nid(obj);
        val    = (const char*)wolfSSL_ASN1_STRING_data(str);
        valLen = wolfSSL_ASN1_STRING_length(str);
        if (val == NULL || valLen <= 0) {
            continue;
        }

        switch (nid) {
            case NID_countryName:
                field = dst->country;
                break;
            case NID_stateOrProvinceName:
                field = dst->state;
                break;
            case NID_localityName:
                field = dst->locality;
                break;
            case NID_organizationName:
                field = dst->org;
                break;
            case NID_organizationalUnitName:
                field = dst->unit;
                break;
            case NID_commonName:
                field = dst->commonName;
                break;
            case NID_emailAddress:
                field = dst->email;
                break;
            default:
                break;
        }

        if (field != NULL) {
            if (valLen > CTC_NAME_SIZE - 1) {
                wolfCLU_LogError("DN field (nid %d) exceeds %d-byte limit",
                        nid, CTC_NAME_SIZE - 1);
                return WOLFCLU_FATAL_ERROR;
            }
            XMEMCPY(field, val, (size_t)valLen);
            field[valLen] = '\0';
        }
    }

    return WOLFCLU_SUCCESS;
}

/* Write signed cert DER to bioOut; returns WOLFCLU_SUCCESS or an error code. */
static int wolfCLU_MLDSAWriteCertBio(WOLFSSL_BIO* bioOut, int outForm,
        const byte* certBuf, int certDerSz, int pemType)
{
    int   ret = WOLFCLU_SUCCESS;
    int   pemOutSz = 0;
    byte* pemBuf = NULL;

    if (bioOut == NULL || certBuf == NULL || certDerSz <= 0) {
        return BAD_FUNC_ARG;
    }

    if (outForm == DER_FORM) {
        if (wolfSSL_BIO_write(bioOut, certBuf, certDerSz) <= 0) {
            ret = WOLFCLU_FATAL_ERROR;
        }
        return ret;
    }

    pemOutSz = wc_DerToPem(certBuf, (word32)certDerSz, NULL, 0, pemType);
    if (pemOutSz <= 0 ||
            wolfCLU_MLDSACheckPemOutSz(pemOutSz, certDerSz) !=
            WOLFCLU_SUCCESS) {
        wolfCLU_LogError("wc_DerToPem size query failed: %d", pemOutSz);
        return (pemOutSz < 0) ? pemOutSz : WOLFCLU_FATAL_ERROR;
    }

    pemBuf = (byte*)XMALLOC(pemOutSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (pemBuf == NULL) {
        return MEMORY_E;
    }

    ret = wc_DerToPem(certBuf, (word32)certDerSz, pemBuf, (word32)pemOutSz,
                      pemType);
    if (ret <= 0) {
        wolfCLU_LogError("wc_DerToPem failed: %d", ret);
        wolfCLU_ForceZero(pemBuf, pemOutSz);
        XFREE(pemBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        return WOLFCLU_FATAL_ERROR;
    }

    if (wolfSSL_BIO_write(bioOut, pemBuf, ret) <= 0) {
        ret = WOLFCLU_FATAL_ERROR;
    }
    else {
        ret = WOLFCLU_SUCCESS;
    }

    wolfCLU_ForceZero(pemBuf, pemOutSz);
    XFREE(pemBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

#ifndef WOLFCLU_NO_FILESYSTEM

/* Build self-signed ML-DSA cert. Returns WOLFCLU_SUCCESS or error. */
int wolfCLU_MakeMLDSASelfSignedCert(const char* keyPath, WOLFSSL_X509* x509,
        int days, int outForm, WOLFSSL_BIO* bioOut, int noOut)
{
    int    ret       = WOLFCLU_SUCCESS;
    byte   level     = 0;
    int    rngInit   = 0;
    int    certDerSz = 0;
    int    mldsaType = 0;
    int    sigType   = 0;
    int    bufSz     = 0;

    WC_RNG             rng;
    WOLFSSL_X509_NAME* name = NULL;
    Cert*              newCert = NULL;
    MlDsaKey*          key = NULL;
    byte*              certBuf = NULL;

    if (keyPath == NULL || x509 == NULL) {
        return BAD_FUNC_ARG;
    }
    if ((!noOut) && (bioOut == NULL)) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(&rng, 0, sizeof(rng));

    newCert = (Cert*)XMALLOC(sizeof(Cert), HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    key     = (MlDsaKey*)XMALLOC(sizeof(MlDsaKey), HEAP_HINT,
                                 DYNAMIC_TYPE_TMP_BUFFER);
    if (newCert == NULL || key == NULL) {
        XFREE(newCert, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(key,     HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }

    XMEMSET(key,     0, sizeof(*key));
    XMEMSET(newCert, 0, sizeof(*newCert));

    ret = wolfCLU_LoadMLDSAKey(keyPath, key, &level, 0);
    if (ret != WOLFCLU_SUCCESS) {
        wolfCLU_LogError("Failed to load ML-DSA key from %s", keyPath);
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = wc_InitRng(&rng);
        if (ret != 0) {
            wolfCLU_LogError("Failed to init RNG: %d", ret);
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            rngInit = 1;
            ret = WOLFCLU_SUCCESS;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = wolfCLU_MLDSALevelToTypes(level, &sigType, &mldsaType);
    }

    if (ret == WOLFCLU_SUCCESS) {
        bufSz = wolfCLU_MLDSASignBufSz(level);
        if (wc_InitCert(newCert) != 0) {
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            newCert->daysValid = (days > 0) ? days : WOLFCLU_CERT_DAYS_DEFAULT;
            newCert->isCA = 1;
            newCert->keyUsage = KU_KEY_CERT_SIGN | KU_CRL_SIGN;
            newCert->sigType = sigType;

            name = wolfSSL_X509_get_subject_name(x509);
            if (name != NULL) {
                ret = wolfCLU_CopyX509NameToCert(name, &newCert->subject);
            }
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        certBuf = (byte*)XMALLOC(bufSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (certBuf == NULL) {
            ret = MEMORY_E;
        }
        else {
            XMEMSET(certBuf, 0, bufSz);
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = wc_MakeCert_ex(newCert, certBuf, (word32)bufSz, mldsaType, key,
                &rng);
        if (ret < 0) {
            wolfCLU_LogError("wc_MakeCert_ex failed: %d", ret);
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            newCert->bodySz = (word32)ret;
            ret = WOLFCLU_SUCCESS;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = wc_SignCert_ex(newCert->bodySz, newCert->sigType, certBuf,
                (word32)bufSz, mldsaType, key, &rng);
        if (ret < 0) {
            wolfCLU_LogError("wc_SignCert_ex failed: %d", ret);
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            certDerSz = ret;
            if (certDerSz <= 0 || certDerSz > bufSz) {
                wolfCLU_LogError("Self-signed certificate has invalid size");
                ret = WOLFCLU_FATAL_ERROR;
            }
            else {
                ret = WOLFCLU_SUCCESS;
            }
        }
    }

    if (ret == WOLFCLU_SUCCESS && !noOut) {
        ret = wolfCLU_MLDSAWriteCertBio(bioOut, outForm, certBuf, certDerSz,
                CERT_TYPE);
    }

    if (certBuf != NULL) {
        wolfCLU_ForceZero(certBuf, bufSz);
        XFREE(certBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (rngInit) {
        wc_FreeRng(&rng);
    }
    XFREE(newCert, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    wolfCLU_FreeMLDSAKeyHeap(&key);

    return ret;
}

#ifdef WOLFSSL_CERT_REQ
/* Build ML-DSA PKCS#10 CSR from key. Returns WOLFCLU_SUCCESS or error. */
int wolfCLU_MakeMLDSACSR(const char* keyPath, WOLFSSL_X509* x509,
        int outForm, WOLFSSL_BIO* bioOut, int noOut)
{
    int    ret       = WOLFCLU_SUCCESS;
    byte   level     = 0;
    int    rngInit   = 0;
    int    reqDerSz  = 0;
    int    mldsaType = 0;
    int    sigType   = 0;
    int    bufSz     = 0;

    WC_RNG             rng;
    WOLFSSL_X509_NAME* name = NULL;
    Cert*              req = NULL;
    MlDsaKey*          key = NULL;
    byte*              reqBuf = NULL;

    if (keyPath == NULL || x509 == NULL) {
        return BAD_FUNC_ARG;
    }
    if ((!noOut) && (bioOut == NULL)) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(&rng, 0, sizeof(rng));

    req = (Cert*)XMALLOC(sizeof(Cert), HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    key = (MlDsaKey*)XMALLOC(sizeof(MlDsaKey), HEAP_HINT,
                             DYNAMIC_TYPE_TMP_BUFFER);
    if (req == NULL || key == NULL) {
        XFREE(req, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(key, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }

    XMEMSET(key, 0, sizeof(*key));
    XMEMSET(req, 0, sizeof(*req));

    ret = wolfCLU_LoadMLDSAKey(keyPath, key, &level, 0);
    if (ret != WOLFCLU_SUCCESS) {
        wolfCLU_LogError("Failed to load ML-DSA key from %s", keyPath);
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = wc_InitRng(&rng);
        if (ret != 0) {
            wolfCLU_LogError("Failed to init RNG: %d", ret);
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            rngInit = 1;
            ret = WOLFCLU_SUCCESS;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = wolfCLU_MLDSALevelToTypes(level, &sigType, &mldsaType);
    }

    if (ret == WOLFCLU_SUCCESS) {
        bufSz = wolfCLU_MLDSASignBufSz(level);
        if (wc_InitCert(req) != 0) {
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            req->sigType = sigType;

            name = wolfSSL_X509_get_subject_name(x509);
            if (name != NULL) {
                ret = wolfCLU_CopyX509NameToCert(name, &req->subject);
            }
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        reqBuf = (byte*)XMALLOC(bufSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (reqBuf == NULL) {
            ret = MEMORY_E;
        }
        else {
            XMEMSET(reqBuf, 0, bufSz);
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = wc_MakeCertReq_ex(req, reqBuf, (word32)bufSz, mldsaType, key);
        if (ret < 0) {
            wolfCLU_LogError("wc_MakeCertReq_ex failed: %d", ret);
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            req->bodySz = (word32)ret;
            ret = WOLFCLU_SUCCESS;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = wc_SignCert_ex(req->bodySz, req->sigType, reqBuf, (word32)bufSz,
                mldsaType, key, &rng);
        if (ret < 0) {
            wolfCLU_LogError("wc_SignCert_ex failed: %d", ret);
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            reqDerSz = ret;
            if (reqDerSz <= 0 || reqDerSz > bufSz) {
                wolfCLU_LogError("Certificate request has invalid size");
                ret = WOLFCLU_FATAL_ERROR;
            }
            else {
                ret = WOLFCLU_SUCCESS;
            }
        }
    }

    if (ret == WOLFCLU_SUCCESS && !noOut) {
        ret = wolfCLU_MLDSAWriteCertBio(bioOut, outForm, reqBuf, reqDerSz,
                CERTREQ_TYPE);
    }

    if (reqBuf != NULL) {
        wolfCLU_ForceZero(reqBuf, bufSz);
        XFREE(reqBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (rngInit) {
        wc_FreeRng(&rng);
    }
    XFREE(req, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    wolfCLU_FreeMLDSAKeyHeap(&key);

    return ret;
}
#endif /* WOLFSSL_CERT_REQ */

#endif /* !WOLFCLU_NO_FILESYSTEM */

/* Convert ASN.1 TIME to Cert date field format. Returns length or BUFFER_E. */
static int wolfCLU_Asn1TimeToCertDate(byte* out, int outSz,
        const WOLFSSL_ASN1_TIME* t)
{
    int sz, i;

    if (out == NULL || t == NULL || t->length <= 0 ||
            t->length > CTC_DATE_SIZE) {
        return BUFFER_E;
    }
    /* Validate DER tag: UTCTime (23) or GeneralizedTime (24) expected. */
    if (t->type != V_ASN1_UTCTIME && t->type != V_ASN1_GENERALIZEDTIME) {
        return BUFFER_E;
    }
    if (outSz <= 0) {
        return BUFFER_E;
    }
    /* t->length <= CTC_DATE_SIZE (32), so t->length + 6 cannot overflow int. */
    if (t->length + 6 > outSz) {
        return BUFFER_E;
    }

    sz = (int)SetLength((word32)t->length, out + 1) + 1;
    if (sz + t->length > outSz) {
        return BUFFER_E;
    }

    out[0] = (byte)t->type;
    for (i = 0; i < t->length; i++) {
        out[sz + i] = t->data[i];
    }
    return t->length + sz;
}

/* Copy subjectAltName from CSR to cert. Returns WOLFCLU_SUCCESS or error. */
static int wolfCLU_CopyX509SanToCert(WOLFSSL_X509* x509, Cert* cert)
{
    int extIdx;

    if (x509 == NULL || cert == NULL) {
        return WOLFCLU_SUCCESS;
    }
    if (cert->altNamesSz > 0) {
        wolfCLU_Log(WOLFCLU_L0, "Warning: wolfCLU_CopyX509SanToCert called "
                "on a Cert that already has altNames; skipping to avoid "
                "double-population");
        return WOLFCLU_SUCCESS;
    }

    extIdx = wolfSSL_X509_get_ext_by_NID(x509, NID_subject_alt_name, -1);
    if (extIdx < 0) {
        return WOLFCLU_SUCCESS;
    }

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL) || defined(WOLFSSL_QT)
    {
        WOLFSSL_X509_EXTENSION* ext;
        WOLFSSL_ASN1_STRING* sanData;

        ext = wolfSSL_X509_get_ext(x509, extIdx);
        if (ext == NULL) {
            wolfCLU_LogError("Failed to get subjectAltName extension");
            return WOLFCLU_FATAL_ERROR;
        }

        sanData = wolfSSL_X509_EXTENSION_get_data(ext);
        if (sanData == NULL || sanData->data == NULL || sanData->length <= 0) {
            return WOLFCLU_SUCCESS;
        }

        if (sanData->length > (int)sizeof(cert->altNames)) {
            wolfCLU_LogError(
                "subjectAltName extension too large for cert buffer");
            return WOLFCLU_FATAL_ERROR;
        }

        XMEMCPY(cert->altNames, sanData->data, (size_t)sanData->length);
        cert->altNamesSz = sanData->length;
    }
#else
    (void)extIdx;
    /* wolfSSL_X509_get_ext requires OPENSSL_EXTRA. */
    wolfCLU_Log(WOLFCLU_L0, "Warning: subjectAltName not copied; build with "
            "OPENSSL_EXTRA to preserve SANs in ML-DSA CA-signed certs");
#endif

    return WOLFCLU_SUCCESS;
}

#ifdef WOLFSSL_CERT_EXT
/* NIDs that wolfCLU_X509FillCert already transfers to the Cert explicitly, so
 * the generic copy below must skip them to avoid duplicating an extension. */
static int wolfCLU_MLDSAExtHandledNid(int nid)
{
    switch (nid) {
        case NID_basic_constraints:
        case NID_key_usage:
        case NID_ext_key_usage:
        case NID_subject_key_identifier:
        case NID_authority_key_identifier:
        case NID_subject_alt_name:
            return 1;
        default:
            return 0;
    }
}

/* Carry CSR extensions that wolfCLU_X509FillCert does not handle explicitly
 * onto the wolfcrypt Cert. */
static int wolfCLU_CopyX509ExtsToCert(WOLFSSL_X509* x509, Cert* cert)
{
    int ret = WOLFCLU_SUCCESS;
    int count = wolfSSL_X509_get_ext_count(x509);
    int i;
    int uncopied = 0;

    for (i = 0; ret == WOLFCLU_SUCCESS && i < count; i++) {
        WOLFSSL_X509_EXTENSION* ext = wolfSSL_X509_get_ext(x509, i);
        WOLFSSL_ASN1_OBJECT* obj;
        int nid;

        if (ext == NULL) {
            continue;
        }
        obj = wolfSSL_X509_EXTENSION_get_object(ext);
        if (obj == NULL) {
            continue;
        }
        nid = wolfSSL_OBJ_obj2nid(obj);
        if (wolfCLU_MLDSAExtHandledNid(nid)) {
            continue; /* already copied explicitly by wolfCLU_X509FillCert */
        }

#if defined(WOLFSSL_ASN_TEMPLATE) && defined(WOLFSSL_CUSTOM_OID) && \
    defined(HAVE_OID_ENCODING)
        {
            char oid[80];
            WOLFSSL_ASN1_STRING* data;
            const unsigned char* val;
            int valSz;
            int crit;

            /* numerical (dotted-decimal) OID, the form wc_SetCustomExtension
             * expects */
            if (wolfSSL_OBJ_obj2txt(oid, (int)sizeof(oid), obj, 1) <= 0) {
                wolfCLU_Log(WOLFCLU_L0,
                        "Warning: could not encode an extension "
                        "OID; not copied to the ML-DSA certificate");
                uncopied = 1;
                continue;
            }
            data = wolfSSL_X509_EXTENSION_get_data(ext);
            if (data == NULL) {
                continue;
            }
            val = wolfSSL_ASN1_STRING_get0_data(data);
            valSz = wolfSSL_ASN1_STRING_length(data);
            if (val == NULL || valSz <= 0) {
                continue;
            }
            crit = wolfSSL_X509_EXTENSION_get_critical(ext);
            /* wc_SetCustomExtension stores the OID pointer directly without copying.
             * Allocate the OID on the heap; the caller must free customCertExt OIDs
             * after wc_MakeCert_ex. */
            {
                char* oidHeap = (char*)XMALLOC(XSTRLEN(oid) + 1, HEAP_HINT,
                        DYNAMIC_TYPE_TMP_BUFFER);
                if (oidHeap == NULL) {
                    ret = MEMORY_E;
                }
                else {
                    XMEMCPY(oidHeap, oid, XSTRLEN(oid) + 1);
                    if (wc_SetCustomExtension(cert, crit, oidHeap, val,
                                (word32)valSz) < 0) {
                        wolfCLU_LogError("Failed to copy extension (OID %s) to the "
                                "ML-DSA certificate", oid);
                        XFREE(oidHeap, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
                        ret = WOLFCLU_FATAL_ERROR;
                    }
                }
            }
        }
#else
        (void)nid;
        uncopied = 1; /* this build cannot copy arbitrary extensions */
#endif
    }

    if (ret == WOLFCLU_SUCCESS && uncopied) {
        wolfCLU_Log(WOLFCLU_L0,
                "Warning: the ML-DSA CA-sign path carries only "
                "basicConstraints, keyUsage, extKeyUsage, "
                "subjectKeyIdentifier, authorityKeyIdentifier and "
                "subjectAltName; other CSR extensions were not copied to the "
                "issued certificate (build wolfSSL with WOLFSSL_CUSTOM_OID + "
                "HAVE_OID_ENCODING to carry arbitrary extensions)");
    }

    return ret;
}
#endif /* WOLFSSL_CERT_EXT */

/* Populate a wolfcrypt Cert from a CSR for ML-DSA CA signing.
 * x509 must remain live until after wc_MakeCert_ex; wc_SetCustomExtension
 * aliases x509 extension bytes without copying. */
static int wolfCLU_X509FillCert(WOLFSSL_X509* x509, Cert* cert, int sigType,
        WOLFSSL_EVP_PKEY* subjPkey, void* subjWcKey, int subjWcKeyType,
        void* caWcKey, int caWcKeyType, WOLFSSL_X509* caCert)
{
    int ret = WOLFCLU_SUCCESS;
    int ku;
    int isCA;
    WOLFSSL_X509_NAME* name;
    const WOLFSSL_ASN1_TIME* nb;
    const WOLFSSL_ASN1_TIME* na;

    if (x509 == NULL || cert == NULL) {
        return BAD_FUNC_ARG;
    }

    ku = wolfSSL_X509_get_keyUsage(x509);

    /* Caller has sanitized x509 against operator policy; trust it. */
    isCA = 0;
#ifdef OPENSSL_EXTRA
    {
        int extIdx = wolfSSL_X509_get_ext_by_NID(x509, NID_basic_constraints,
                -1);
        if (extIdx >= 0) {
            WOLFSSL_X509_EXTENSION* bcExt = wolfSSL_X509_get_ext(x509, extIdx);
            if (bcExt != NULL) {
                WOLFSSL_ASN1_OBJECT* obj =
                        wolfSSL_X509_EXTENSION_get_object(bcExt);
                if (obj != NULL && obj->ca)
                    isCA = 1;
            }
        }
        else {
            isCA = wolfSSL_X509_get_isCA(x509);
        }
    }
#else
    isCA = wolfSSL_X509_get_isCA(x509);
#endif

    if (wc_InitCert(cert) != 0) {
        return WOLFCLU_FATAL_ERROR;
    }
    cert->version = 2; /* X.509 v3; wc_InitCert default */
    cert->sigType = sigType;

    cert->isCA = isCA ? 1 : 0;
    cert->pathLen = 0;
    cert->pathLenSet = isCA ? 1 : 0;

    if (isCA) {
        cert->keyUsage = KU_KEY_CERT_SIGN | KU_CRL_SIGN;
        /* Apply CSR key usage only when it carries both CA bits; if it also
         * carries extra bits the issued cert will be wider than the
         * CA-only default.  If narrowing is desired, mask ku
         * with (KU_KEY_CERT_SIGN | KU_CRL_SIGN) before assigning. */
        if (ku >= 0 && (ku & (KU_KEY_CERT_SIGN | KU_CRL_SIGN)) ==
                            (KU_KEY_CERT_SIGN | KU_CRL_SIGN)) {
            cert->keyUsage = ku;
        }
    }
    else {
        /* ML-DSA is a signature-only primitive; KU_KEY_ENCIPHERMENT does not
         * apply. If the CSR carries no keyUsage, default to signature only. */
        cert->keyUsage = KU_DIGITAL_SIGNATURE;
        if (ku >= 0) {
            int leafKu = ku & ~(KU_KEY_CERT_SIGN | KU_CRL_SIGN);
            if (leafKu > 0)
                cert->keyUsage = (word16)leafKu;
        }
    }

    {
        /* wolfSSL_X509_get_extended_key_usage() returns WOLFSSL_XKU_* bits
         * (x509v3.h). cert->extKeyUsage expects EXTKEYUSE_* bits (asn.h).
         * The two enums have different bit positions for every flag except
         * CODE_SIGN (0x08 in both). Translate explicitly. */
        unsigned int xku = wolfSSL_X509_get_extended_key_usage(x509);
        byte eku = 0;
        if (xku & WOLFSSL_XKU_SSL_SERVER) eku |= EXTKEYUSE_SERVER_AUTH;
        if (xku & WOLFSSL_XKU_SSL_CLIENT) eku |= EXTKEYUSE_CLIENT_AUTH;
        if (xku & WOLFSSL_XKU_SMIME)      eku |= EXTKEYUSE_EMAILPROT;
        if (xku & WOLFSSL_XKU_CODE_SIGN)  eku |= EXTKEYUSE_CODESIGN;
        if (xku & WOLFSSL_XKU_OCSP_SIGN)  eku |= EXTKEYUSE_OCSP_SIGN;
        if (xku & WOLFSSL_XKU_TIMESTAMP)  eku |= EXTKEYUSE_TIMESTAMP;
        if (xku & WOLFSSL_XKU_ANYEKU)     eku |= EXTKEYUSE_ANY;
        cert->extKeyUsage = eku;
    }

    nb = wolfSSL_X509_get_notBefore(x509);
    na = wolfSSL_X509_get_notAfter(x509);
    if (nb != NULL) {
        cert->beforeDateSz = wolfCLU_Asn1TimeToCertDate(cert->beforeDate,
                CTC_DATE_SIZE, nb);
        if (cert->beforeDateSz <= 0) {
            wolfCLU_LogError("Error converting notBefore date");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }
    if (ret == WOLFCLU_SUCCESS && na != NULL) {
        cert->afterDateSz = wolfCLU_Asn1TimeToCertDate(cert->afterDate,
                CTC_DATE_SIZE, na);
        if (cert->afterDateSz <= 0) {
            wolfCLU_LogError("Error converting notAfter date");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        byte serial[EXTERNAL_SERIAL_SIZE];
        int serialSz = EXTERNAL_SERIAL_SIZE;

        if (wolfSSL_X509_get_serial_number(x509, serial, &serialSz) ==
                WOLFSSL_SUCCESS && serialSz > 0) {
            if (serialSz > CTC_SERIAL_SIZE) {
                wolfCLU_LogError("Serial number too large");
                ret = WOLFCLU_FATAL_ERROR;
            }
            else {
                XMEMCPY(cert->serial, serial, (size_t)serialSz);
                cert->serialSz = serialSz;
            }
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        name = wolfSSL_X509_get_subject_name(x509);
        if (name == NULL) {
            wolfCLU_LogError("CSR has no subject name");
            ret = BAD_FUNC_ARG;
        }
        else {
            ret = wolfCLU_CopyX509NameToCert(name, &cert->subject);
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        /* CA-signed: issuer is CA's subject. Self-signed (caCert == NULL):
         * issuer == subject (RFC 5280). CSR issuer field is empty. */
        name = (caCert != NULL)
                ? wolfSSL_X509_get_subject_name(caCert)
                : wolfSSL_X509_get_subject_name(x509);
        cert->selfSigned = (caCert == NULL) ? 1 : 0;
        if (name != NULL) {
            ret = wolfCLU_CopyX509NameToCert(name, &cert->issuer);
        }
        else if (caCert != NULL) {
            wolfCLU_LogError("CA certificate has no subject name");
            ret = BAD_FUNC_ARG;
        }
    }

#ifdef WOLFSSL_CERT_EXT
    if (ret == WOLFCLU_SUCCESS &&
            wolfSSL_X509_get_ext_by_NID(x509, NID_subject_key_identifier,
                -1) >= 0) {
        void* pubKey = subjWcKey;
        int wcKeyType = subjWcKeyType;

        if (pubKey == NULL && subjPkey != NULL) {
            /* wolfSSL internal: WOLFSSL_RSA::internal (RsaKey*) and
             * WOLFSSL_EC_KEY::internal (ecc_key*) are accessed directly
             * because no public API exposes the raw wolfcrypt key pointer.
             * Replace with a public accessor once wolfSSL provides one. */
            switch (wolfSSL_X509_get_pubkey_type(x509)) {
                case RSAk:
                #ifndef NO_RSA
                    if (subjPkey->rsa != NULL) {
                        pubKey = subjPkey->rsa->internal;
                        wcKeyType = RSA_TYPE;
                    }
                #endif
                    break;
                case ECDSAk:
                #ifdef HAVE_ECC
                    if (subjPkey->ecc != NULL) {
                        pubKey = subjPkey->ecc->internal;
                        wcKeyType = ECC_TYPE;
                    }
                #endif
                    break;
                default:
                    break;
            }
        }

        if (pubKey == NULL ||
                wc_SetSubjectKeyIdFromPublicKey_ex(cert, wcKeyType,
                    pubKey) < 0) {
            wolfCLU_LogError("Error setting subject key identifier");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS && caWcKey != NULL &&
            wolfSSL_X509_get_ext_by_NID(x509, NID_authority_key_identifier,
                -1) >= 0) {
        if (wc_SetAuthKeyIdFromPublicKey_ex(cert, caWcKeyType,
                    caWcKey) < 0) {
            wolfCLU_LogError("Error setting authority key identifier");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }
#endif /* WOLFSSL_CERT_EXT */

#if defined(WOLFSSL_ALT_NAMES)
    if (ret == WOLFCLU_SUCCESS) {
        ret = wolfCLU_CopyX509SanToCert(x509, cert);
    }
#endif

#ifdef WOLFSSL_CERT_EXT
    /* Carry any remaining CSR extensions (or warn that they were dropped). */
    if (ret == WOLFCLU_SUCCESS) {
        ret = wolfCLU_CopyX509ExtsToCert(x509, cert);
    }
#endif

    return ret;
}
#endif /* WOLFSSL_CERT_GEN */

/* Sign a certificate (X509/CSR) with an ML-DSA CA key using wc_SignCert_ex.
 * Subject public key may be RSA, ECDSA, or ML-DSA. On success, *outData
 * receives a heap buffer (PEM or DER per outForm) and the caller must XFREE it.
 * Precondition: x509 must have notBefore/notAfter set (e.g. via
 * _wolfCLU_CertSetDate) before this call; wolfCLU_X509FillCert reads those
 * fields from x509 and will return BUFFER_E if they are absent.
 * Lifetime constraint: x509 must NOT be freed between this call and its
 * return. wc_SetCustomExtension (called inside wolfCLU_CopyX509ExtsToCert)
 * stores a pointer alias into x509's extension data; freeing x509 early
 * would leave the Cert struct with a dangling pointer before wc_MakeCert_ex
 * has encoded the cert. */
int wolfCLU_MLDSACertSign(WOLFSSL_X509* x509, MlDsaKey* caKey,
        byte level, WOLFSSL_X509* caCert, int outForm,
        byte** outData, int* outDataSz)
{
#if !defined(WOLFSSL_CERT_GEN)
    (void)x509;
    (void)caKey;
    (void)level;
    (void)caCert;
    (void)outForm;
    (void)outData;
    (void)outDataSz;
    wolfCLU_LogError("WOLFSSL_CERT_GEN required for ML-DSA CA signing");
    return WOLFCLU_FATAL_ERROR;
#else
    int ret = WOLFCLU_SUCCESS;
    WC_RNG rng;
    int initRNG = 0;
    byte* certBuf = NULL;
    byte* outBuf = NULL;
    int bufSz = 0;
    int certSz = 0;
    int outBufSz = 0;
    int pemBufSz = 0;
    int mldsaType = 0;
    int sigType   = 0;
    int wcKeyType = 0;
    void* subjKey = NULL;
    int initSubjMldsa = 0;
    WOLFSSL_EVP_PKEY* subjPkey = NULL;
    MlDsaKey* subjMldsaKey = NULL;
    Cert*     newCert = NULL;

    if (outData != NULL) {
        *outData = NULL;
    }
    if (outDataSz != NULL) {
        *outDataSz = 0;
    }
    if (x509 == NULL || caKey == NULL || outData == NULL || outDataSz == NULL ||
            wolfCLU_MLDSAParamsByLevel(level) == NULL) {
        return BAD_FUNC_ARG;
    }
    bufSz = wolfCLU_MLDSASignBufSz(level);

    subjMldsaKey = (MlDsaKey*)XMALLOC(sizeof(*subjMldsaKey), HEAP_HINT,
            DYNAMIC_TYPE_TMP_BUFFER);
    if (subjMldsaKey == NULL) {
        return MEMORY_E;
    }
    XMEMSET(subjMldsaKey, 0, sizeof(*subjMldsaKey));
    XMEMSET(&rng, 0, sizeof(rng));
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        wolfCLU_LogError("Error initializing RNG");
        ret = WOLFCLU_FATAL_ERROR;
    }
    else {
        initRNG = 1;
        ret = WOLFCLU_SUCCESS;
    }

    if (ret == WOLFCLU_SUCCESS) {
        newCert = (Cert*)XMALLOC(sizeof(Cert), HEAP_HINT,
                DYNAMIC_TYPE_TMP_BUFFER);
        if (newCert == NULL) {
            ret = MEMORY_E;
        }
        else {
            XMEMSET(newCert, 0, sizeof(*newCert));
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        certBuf = (byte*)XMALLOC(bufSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (certBuf == NULL) {
            wolfCLU_LogError("Memory allocation failed");
            ret = MEMORY_E;
        }
        else {
            XMEMSET(certBuf, 0, bufSz);
        }
        /* outBuf for PEM output is allocated later, after the DER to PEM size
         * query, so it is sized exactly to the PEM output rather than bufSz. */
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = wolfCLU_MLDSALevelToTypes(level, &sigType, &mldsaType);
    }

    if (ret == WOLFCLU_SUCCESS) {
        /* Only RSA/ECDSA subjects use the EVP key; ML-DSA subjects are decoded
         * directly below, and EVP may not support ML-DSA on this build. */
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
                wolfCLU_LogError("RSA not compiled in; cannot sign RSA "
                        "subject cert with ML-DSA CA key");
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
                wolfCLU_LogError("ECC not compiled in; cannot sign ECDSA "
                        "subject cert with ML-DSA CA key");
                ret = WOLFCLU_FATAL_ERROR;
            #endif
                break;
            case ML_DSA_44k:
            case ML_DSA_65k:
            case ML_DSA_87k:
            case DILITHIUM_LEVEL2k:
            case DILITHIUM_LEVEL3k:
            case DILITHIUM_LEVEL5k:
                if (wolfCLU_X509GetMLDSAPubKey(x509, subjMldsaKey) !=
                        WOLFCLU_SUCCESS) {
                    wolfCLU_LogError(
                        "Error decoding ML-DSA subject public key");
                    ret = WOLFCLU_FATAL_ERROR;
                }
                else {
                    /* Mark as initialized so the single cleanup at the end of
                     * the function frees it regardless of later failures. */
                    initSubjMldsa = 1;
                    if (wolfCLU_MLDSAPubOidToWcType(
                                wolfSSL_X509_get_pubkey_type(x509),
                                &wcKeyType) != WOLFCLU_SUCCESS) {
                        wolfCLU_LogError(
                                "Error decoding ML-DSA subject public key");
                        ret = WOLFCLU_FATAL_ERROR;
                    }
                    else {
                        subjKey = subjMldsaKey;
                    }
                }
                break;
            default:
                wolfCLU_LogError("Unsupported subject key type for ML-DSA CA "
                        "sign");
                ret = WOLFCLU_FATAL_ERROR;
        }
        if (ret == WOLFCLU_SUCCESS && subjKey == NULL) {
            wolfCLU_LogError("Subject public key decode failed");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = wolfCLU_X509FillCert(x509, newCert, sigType, subjPkey,
                subjKey, wcKeyType, caKey, mldsaType, caCert);
    }

    if (ret == WOLFCLU_SUCCESS && caCert != NULL && caCert == x509) {
        /* ca -selfsign: signer IS the subject; match MakeMLDSASelfSignedCert */
        newCert->selfSigned = 1;
        newCert->isCA = 1;
        newCert->pathLen = 0;
        newCert->pathLenSet = 1;
        newCert->keyUsage = KU_KEY_CERT_SIGN | KU_CRL_SIGN;
    }

    if (ret == WOLFCLU_SUCCESS) {
        /* Do not free x509: wc_SetCustomExtension aliases it. */
        ret = wc_MakeCert_ex(newCert, certBuf, (word32)bufSz, wcKeyType,
                subjKey, &rng);
        if (ret < 0) {
            wolfCLU_LogError("Error building certificate TBS: %d", ret);
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            newCert->bodySz = (word32)ret;
            ret = WOLFCLU_SUCCESS;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = wc_SignCert_ex(newCert->bodySz, sigType, certBuf, (word32)bufSz,
                             mldsaType, caKey, &rng);
        if (ret < 0) {
            wolfCLU_LogError("Error signing certificate with ML-DSA: %d", ret);
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            certSz = ret; /* wc_SignCert_ex returns > 0 on success */
            if (certSz <= 0 || certSz > bufSz) {
                wolfCLU_LogError("Signed certificate has invalid size");
                ret = WOLFCLU_FATAL_ERROR;
            }
            else {
                ret = WOLFCLU_SUCCESS;
            }
        }
    }

    if (ret == WOLFCLU_SUCCESS && outForm == PEM_FORM) {
        pemBufSz = wc_DerToPem(certBuf, (word32)certSz, NULL, 0, CERT_TYPE);
        if (pemBufSz <= 0 ||
                wolfCLU_MLDSACheckPemOutSz(pemBufSz, certSz) !=
                WOLFCLU_SUCCESS) {
            wolfCLU_LogError("Error querying PEM output size");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            outBuf = (byte*)XMALLOC((size_t)pemBufSz, HEAP_HINT,
                    DYNAMIC_TYPE_TMP_BUFFER);
            if (outBuf == NULL) {
                wolfCLU_LogError("Memory allocation failed for PEM output");
                ret = MEMORY_E;
            }
            else {
                ret = wc_DerToPem(certBuf, (word32)certSz, outBuf,
                        (word32)pemBufSz, CERT_TYPE);
                if (ret < 0) {
                    wolfCLU_LogError("Error converting DER to PEM");
                    wolfCLU_ForceZero(outBuf, (unsigned int)pemBufSz);
                    XFREE(outBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
                    outBuf = NULL;
                    ret = WOLFCLU_FATAL_ERROR;
                }
                else {
                    outBufSz = ret;
                    ret = WOLFCLU_SUCCESS;
                }
            }
        }
    }
    if (ret == WOLFCLU_SUCCESS) {
        if (outForm == PEM_FORM) {
            *outData = outBuf;
            *outDataSz = outBufSz;
            outBuf = NULL;
        }
        else {
            /* Zero certBuf tail bytes not part of final DER cert. */
            if (bufSz > certSz) {
                wolfCLU_ForceZero(certBuf + certSz,
                        (unsigned int)(bufSz - certSz));
            }
            *outData = certBuf;
            *outDataSz = certSz;
            certBuf = NULL;
        }
    }

    if (initRNG) {
        wc_FreeRng(&rng);
    }
    if (subjPkey != NULL) {
        wolfSSL_EVP_PKEY_free(subjPkey);
    }
    if (initSubjMldsa) {
        wc_MlDsaKey_Free(subjMldsaKey);
    }

    if (certBuf != NULL) {
        wolfCLU_ForceZero(certBuf, bufSz);
        XFREE(certBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (outBuf != NULL) {
        wolfCLU_ForceZero(outBuf, (unsigned int)pemBufSz);
        XFREE(outBuf,  HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }
    XFREE(subjMldsaKey, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (newCert != NULL) {
#ifdef WOLFSSL_CUSTOM_OID
        int idx;
        for (idx = 0; idx < newCert->customCertExtCount; idx++) {
            if (newCert->customCertExt[idx].oid != NULL) {
                XFREE(newCert->customCertExt[idx].oid, HEAP_HINT,
                      DYNAMIC_TYPE_TMP_BUFFER);
            }
        }
#endif
        XFREE(newCert, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }

    return ret;
#endif /* WOLFSSL_CERT_GEN */
}

#endif /* WOLFCLU_HAVE_MLDSA */
