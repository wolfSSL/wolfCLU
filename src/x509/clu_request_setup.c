/* clu_request_setup.c
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
#include <wolfclu/x509/clu_request.h>
#include <wolfclu/x509/clu_cert.h>
#include <wolfclu/pkey/clu_pkey.h>
#include <wolfclu/certgen/clu_certgen.h>

#ifdef HAVE_DILITHIUM
    #include <wolfssl/wolfcrypt/dilithium.h>
    #include <wolfclu/sign-verify/clu_sign.h>
    #include <wolfclu/genkey/clu_genkey.h>
#endif

/* The pure ML-DSA certificate path uses the raw wolfcrypt cert builder
 * (wc_InitCert/wc_MakeCert_ex/wc_SignCert_ex and Cert.subject), all of which
 * require WOLFSSL_CERT_GEN. Gate the whole feature on it so builds with
 * WOLFSSL_CERT_REQ but without WOLFSSL_CERT_GEN still compile (ML-DSA cert
 * generation is simply not offered). */
#if defined(HAVE_DILITHIUM) && defined(WOLFSSL_CERT_GEN)
    #define WOLFCLU_MLDSA_CERTGEN
#endif

#ifndef WOLFCLU_NO_FILESYSTEM
/* Return 1 if a file exists (is openable for reading), 0 otherwise. */
static int wolfCLU_FileExists(const char* path)
{
    XFILE f = XFOPEN(path, "rb");
    if (f != XBADFILE) {
        XFCLOSE(f);
        return 1;
    }
    return 0;
}
#endif /* !WOLFCLU_NO_FILESYSTEM */

#if defined(WOLFCLU_MLDSA_CERTGEN) && defined(WOLFSSL_CERT_REQ) && \
    !defined(WOLFCLU_NO_FILESYSTEM)

/* Cert buffer: ML-DSA-87 self-signed (issuer DN duplicated from subject) with
 * a full subject DN ~= 8.2 KB; 16 KB leaves comfortable headroom. */
#define WOLFCLU_MLDSA_CERT_BUF_SZ (1024 * 16)
#define WOLFCLU_MLDSA_KEY_PATH_SZ 512
/* TODO: replace with wc_MlDsaKey_IsPubKeySet(k) once that API exists. */
#define WOLFCLU_MLDSA_PUB_KEY_IS_SET(k) ((k)->pubKeySet)

/* Return a newly allocated "<name>.pub" path derived from a "<name>.priv"
 * path. Returns NULL if privPath does not end in ".priv" OR if XMALLOC
 * fails (OOM); callers must treat both NULL cases the same way.
 * Caller frees with XFREE(.., DYNAMIC_TYPE_TMP_BUFFER). */
static char* wolfCLU_MLDSADupPubPath(const char* privPath)
{
    int   len = (int)XSTRLEN(privPath);
    char* pub = NULL;

    if (len > 5 && XSTRNCMP(privPath + len - 5, ".priv", 5) == 0) {
        /* ".priv" (5) -> ".pub" (4) */
        pub = (char*)XMALLOC(len - 5 + 4 + 1, HEAP_HINT,
                             DYNAMIC_TYPE_TMP_BUFFER);
        if (pub != NULL) {
            XMEMCPY(pub, privPath, len - 5);
            XMEMCPY(pub + len - 5, ".pub", 4);
            pub[len - 5 + 4] = '\0';
        }
    }
    return pub;
}

/* Remove an ML-DSA key pair: "<name>.priv" and "<name>.pub".
 * Uses a stack buffer for the .pub path to avoid malloc failure during
 * cleanup. */
static void wolfCLU_RemoveMLDSAKeyPair(const char* privPath)
{
    char pubPath[WOLFCLU_MLDSA_KEY_PATH_SZ];
    int  len = (int)XSTRLEN(privPath);

    remove(privPath);
    if (len > 5 && XSTRNCMP(privPath + len - 5, ".priv", 5) == 0 &&
            len - 5 + 4 < (int)sizeof(pubPath)) {
        XMEMCPY(pubPath, privPath, len - 5);
        XMEMCPY(pubPath + len - 5, ".pub", 4);
        pubPath[len - 5 + 4] = '\0';
        remove(pubPath);
    }
}

/* Load the public key for an ML-DSA private key that did not carry its own
 * public component. wolfCLU writes private-only DER, so the matching public
 * key lives in a companion "<name>.pub" file alongside "<name>.priv".
 * key : decoded private key to add the public portion to.
 * Returns WOLFCLU_SUCCESS on success, negative on failure. */
static int wolfCLU_LoadMLDSACompanionPub(const char* keyPath, MlDsaKey* key)
{
    int    ret        = WOLFCLU_SUCCESS;
    int    pubBufSz   = 0;
    word32 pubIdx     = 0;
    char*  pubPath    = NULL;
    byte*  pubBuf     = NULL;
    XFILE  pubFile    = XBADFILE;

    /* derive "<name>.pub" from "<name>.priv". check the suffix first so the
     * error message distinguishes a bad name from an allocation failure */
    {
        int kLen = (int)XSTRLEN(keyPath);
        if (kLen <= 5 || XSTRNCMP(keyPath + kLen - 5, ".priv", 5) != 0) {
            wolfCLU_LogError("ML-DSA private key file name does not end in "
                             ".priv; cannot locate companion .pub (got: %s)",
                             keyPath);
            ret = BAD_FUNC_ARG;
        }
        else {
            pubPath = wolfCLU_MLDSADupPubPath(keyPath);
            if (pubPath == NULL) {
                ret = MEMORY_E;
            }
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        pubFile = XFOPEN(pubPath, "rb");
        if (pubFile == XBADFILE) {
            wolfCLU_LogError("Unable to open public key file %s", pubPath);
            ret = BAD_FUNC_ARG;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        XFSEEK(pubFile, 0, SEEK_END);
        pubBufSz = (int)XFTELL(pubFile);
        XFSEEK(pubFile, 0, SEEK_SET);
        if (pubBufSz <= 0) {
            wolfCLU_LogError("Invalid public key file size for %s", pubPath);
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        pubBuf = (byte*)XMALLOC(pubBufSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (pubBuf == NULL) {
            ret = MEMORY_E;
        }
    }

    if (ret == WOLFCLU_SUCCESS &&
            (int)XFREAD(pubBuf, 1, pubBufSz, pubFile) != pubBufSz) {
        wolfCLU_LogError("Failed to read public key file %s", pubPath);
        ret = WOLFCLU_FAILURE;
    }

    if (pubFile != XBADFILE) {
        XFCLOSE(pubFile);
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = wolfCLU_KeyPemToDer(&pubBuf, pubBufSz, 1);
        if (ret < 0) {
            wolfCLU_LogError("Failed to convert pub key PEM to DER: %d", ret);
        }
        else {
            pubBufSz = ret;
            ret      = WOLFCLU_SUCCESS;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = wc_Dilithium_PublicKeyDecode(pubBuf, &pubIdx, key,
                                           (word32)pubBufSz);
        if (ret != 0) {
            wolfCLU_LogError("Failed to decode ML-DSA public key: %d", ret);
        }
        else {
            ret = WOLFCLU_SUCCESS;
        }
    }

    XFREE(pubPath, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(pubBuf,  HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}

/* Return 1 if the file at 'path' holds a PKCS#8 PEM ML-DSA private key.
 * Used to route -key inputs to the raw ML-DSA cert path, since
 * wolfSSL_PEM_read_bio_PrivateKey has no ML-DSA case. */
static int wolfCLU_FileIsMLDSAKey(const char* path)
{
    int   isMLDSA = 0;
    int   pemSz   = 0;
    byte* pemBuf  = NULL;
    XFILE f;

    if (path == NULL) {
        return 0;
    }

    f = XFOPEN(path, "rb");
    if (f == XBADFILE) {
        return 0;
    }

    XFSEEK(f, 0, SEEK_END);
    pemSz = (int)XFTELL(f);
    XFSEEK(f, 0, SEEK_SET);
    if (pemSz > 0) {
        pemBuf = (byte*)XMALLOC(pemSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (pemBuf == NULL) {
            wolfCLU_LogError("Memory allocation failed probing key %s", path);
        }
    }

    if (pemBuf != NULL && (int)XFREAD(pemBuf, 1, pemSz, f) == pemSz) {
        if (pemSz < 27 ||
                XMEMCMP(pemBuf, "-----BEGIN PRIVATE KEY-----", 27) != 0) {
            wolfCLU_ForceZero(pemBuf, pemSz);
            XFREE(pemBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            XFCLOSE(f);
            return 0;
        }
        int derSz = wc_KeyPemToDer(pemBuf, pemSz, NULL, 0, NULL);
        if (derSz > 0) {
            byte* derBuf = (byte*)XMALLOC(derSz, HEAP_HINT,
                                          DYNAMIC_TYPE_TMP_BUFFER);
            if (derBuf != NULL) {
                int derAlloc = derSz;
#ifdef WOLFSSL_SMALL_STACK
                MlDsaKey* probeKey = NULL;
#else
                MlDsaKey  probeKeyStack;
                MlDsaKey* probeKey = &probeKeyStack;
#endif
                derSz = wc_KeyPemToDer(pemBuf, pemSz, derBuf, derAlloc, NULL);
#ifdef WOLFSSL_SMALL_STACK
                if (derSz > 0) {
                    probeKey = (MlDsaKey*)XMALLOC(sizeof(MlDsaKey), HEAP_HINT,
                                                  DYNAMIC_TYPE_TMP_BUFFER);
                }
#endif
                if (derSz > 0 && probeKey != NULL) {
                    word32 idx = 0;
                    XMEMSET(probeKey, 0, sizeof(*probeKey));
                    if (wc_MlDsaKey_Init(probeKey, NULL, INVALID_DEVID) == 0) {
                        if (wc_Dilithium_PrivateKeyDecode(derBuf, &idx,
                                probeKey, (word32)derSz) == 0) {
                            isMLDSA = 1;
                        }
                        wc_MlDsaKey_Free(probeKey);
                    }
#ifdef WOLFSSL_SMALL_STACK
                    XFREE(probeKey, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
#endif
                }
                wolfCLU_ForceZero(derBuf, derAlloc);
                XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            }
        }
    }

    if (pemBuf != NULL) {
        /* pemBuf held the plaintext PEM private key */
        wolfCLU_ForceZero(pemBuf, pemSz);
        XFREE(pemBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }
    XFCLOSE(f);

    return isMLDSA;
}

/* Build a self-signed pure ML-DSA X.509 certificate via raw wolfcrypt.
 * keyPath : path to PKCS#8 PEM private key file
 * x509    : already-populated X509 object (subject name, validity set)
 * days    : certificate validity in days (>0); defaults to 365 if zero
 * outForm : PEM_FORM or DER_FORM
 * bioOut  : open BIO to write the finished cert to
 * noOut   : when non-zero, build the cert but do not write it out (-noout)
 * Returns WOLFCLU_SUCCESS on success, negative on failure. */
static int wolfCLU_MakeMLDSACert(const char* keyPath, WOLFSSL_X509* x509,
                                  int days, int outForm, WOLFSSL_BIO* bioOut,
                                  int noOut)
{
    int    ret        = WOLFCLU_SUCCESS;
    word32 idx        = 0;
    byte   level      = 0;
    int    keyInit    = 0;
    int    rngInit    = 0;
    int    certDerSz  = 0;
    int    pemBufSz   = 0;
    int    mldsaType  = 0;
    int    i;
    XFILE  keyFile    = XBADFILE;

    WC_RNG             rng;
    WOLFSSL_X509_NAME* name = NULL;
    /* Cert and MlDsaKey are several KB each; heap-allocate on small-stack */
#ifdef WOLFSSL_SMALL_STACK
    Cert*     newCert = NULL;
    MlDsaKey* key     = NULL;
#else
    Cert      newCertStack;
    MlDsaKey  keyStack;
    Cert*     newCert = &newCertStack;
    MlDsaKey* key     = &keyStack;
#endif

    byte* keyBuf   = NULL;
    int   keyBufSz = 0;
    byte* certBuf  = NULL;
    byte* pemBuf   = NULL;

#ifdef WOLFSSL_SMALL_STACK
    newCert = (Cert*)XMALLOC(sizeof(Cert), HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    key     = (MlDsaKey*)XMALLOC(sizeof(MlDsaKey), HEAP_HINT,
                                 DYNAMIC_TYPE_TMP_BUFFER);
    if (newCert == NULL || key == NULL) {
        XFREE(newCert, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(key,     HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }
#endif

    XMEMSET(&rng,    0, sizeof(rng));
    XMEMSET(key,     0, sizeof(*key));
    XMEMSET(newCert, 0, sizeof(*newCert));

    /* read key file into buffer */
    keyFile = XFOPEN(keyPath, "rb");
    if (keyFile == XBADFILE) {
        wolfCLU_LogError("Unable to open key file %s", keyPath);
        ret = BAD_FUNC_ARG;
    }

    if (ret == WOLFCLU_SUCCESS) {
        XFSEEK(keyFile, 0, SEEK_END);
        keyBufSz = (int)XFTELL(keyFile);
        XFSEEK(keyFile, 0, SEEK_SET);
        if (keyBufSz <= 0) {
            wolfCLU_LogError("Invalid key file size for %s", keyPath);
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        keyBuf = (byte*)XMALLOC(keyBufSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (keyBuf == NULL) {
            ret = MEMORY_E;
        }
    }

    if (ret == WOLFCLU_SUCCESS &&
            (int)XFREAD(keyBuf, 1, keyBufSz, keyFile) != keyBufSz) {
        wolfCLU_LogError("Failed to read key file %s", keyPath);
        ret = WOLFCLU_FAILURE;
    }

    if (keyFile != XBADFILE) {
        XFCLOSE(keyFile);
    }

    /* convert PEM to DER (handles "-----BEGIN PRIVATE KEY-----" PKCS#8) */
    if (ret == WOLFCLU_SUCCESS) {
        ret = wolfCLU_KeyPemToDer(&keyBuf, keyBufSz, 0);
        if (ret < 0) {
            wolfCLU_LogError("Failed to convert key PEM to DER: %d", ret);
        }
        else {
            keyBufSz = ret;
            ret = WOLFCLU_SUCCESS;
        }
    }

    /* init and decode the ML-DSA private key */
    if (ret == WOLFCLU_SUCCESS) {
        ret = wc_MlDsaKey_Init(key, NULL, INVALID_DEVID);
        if (ret != 0) {
            wolfCLU_LogError("Failed to init MlDsaKey: %d", ret);
        }
        else {
            keyInit = 1;
            ret     = WOLFCLU_SUCCESS;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = wc_Dilithium_PrivateKeyDecode(keyBuf, &idx, key,
                                            (word32)keyBufSz);
        if (ret != 0) {
            wolfCLU_LogError("Failed to decode ML-DSA private key: %d",
                             ret);
        }
        else {
            ret = WOLFCLU_SUCCESS;
        }
    }

    /* zero and free key buffer unconditionally */
    if (keyBuf != NULL) {
        wolfCLU_ForceZero(keyBuf, keyBufSz);
        XFREE(keyBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        keyBuf = NULL;
    }

    /* wolfCLU writes private-only DER so pubKeySet is unset after decode */
    if (ret == WOLFCLU_SUCCESS && !WOLFCLU_MLDSA_PUB_KEY_IS_SET(key)) {
        ret = wolfCLU_LoadMLDSACompanionPub(keyPath, key);
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = wc_MlDsaKey_GetParams(key, &level);
        if (ret != 0) {
            wolfCLU_LogError("wc_MlDsaKey_GetParams failed: %d", ret);
        }
        else {
            ret = WOLFCLU_SUCCESS;
        }
    }

    /* init RNG */
    if (ret == WOLFCLU_SUCCESS) {
        ret = wc_InitRng(&rng);
        if (ret != 0) {
            wolfCLU_LogError("Failed to init RNG: %d", ret);
        }
        else {
            rngInit = 1;
            ret     = WOLFCLU_SUCCESS;
        }
    }

    /* populate Cert struct from the already-built x509 subject */
    if (ret == WOLFCLU_SUCCESS) {
        wc_InitCert(newCert);
        newCert->daysValid = (days > 0) ? days : 365;
        newCert->isCA      = 1;

        switch (level) {
            case 2:
                newCert->sigType = CTC_ML_DSA_LEVEL2;
                mldsaType        = ML_DSA_LEVEL2_TYPE;
                break;
            case 3:
                newCert->sigType = CTC_ML_DSA_LEVEL3;
                mldsaType        = ML_DSA_LEVEL3_TYPE;
                break;
            case 5:
                newCert->sigType = CTC_ML_DSA_LEVEL5;
                mldsaType        = ML_DSA_LEVEL5_TYPE;
                break;
            default:
                wolfCLU_LogError("Unexpected ML-DSA level %d", level);
                ret = BAD_FUNC_ARG;
                break;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        name = wolfSSL_X509_get_subject_name(x509);
    }

    if (ret == WOLFCLU_SUCCESS && name != NULL) {
        for (i = 0; i < wolfSSL_X509_NAME_entry_count(name); i++) {
            WOLFSSL_X509_NAME_ENTRY* e;
            WOLFSSL_ASN1_OBJECT*     obj;
            WOLFSSL_ASN1_STRING*     str;
            const char*              val;
            char*                    dst = NULL;
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
                    dst = newCert->subject.country;
                    break;
                case NID_stateOrProvinceName:
                    dst = newCert->subject.state;
                    break;
                case NID_localityName:
                    dst = newCert->subject.locality;
                    break;
                case NID_organizationName:
                    dst = newCert->subject.org;
                    break;
                case NID_organizationalUnitName:
                    dst = newCert->subject.unit;
                    break;
                case NID_commonName:
                    dst = newCert->subject.commonName;
                    break;
                case NID_emailAddress:
                    dst = newCert->subject.email;
                    break;
                default:
                    break;
            }

            if (dst != NULL) {
                /* Cert name fields are fixed CTC_NAME_SIZE buffers; warn
                 * rather than silently truncating an over-long DN value. */
                if (valLen > CTC_NAME_SIZE - 1) {
                    wolfCLU_Log(WOLFCLU_L0, "Warning: subject field (nid %d) "
                            "truncated to %d bytes for the certificate", nid,
                            CTC_NAME_SIZE - 1);
                    valLen = CTC_NAME_SIZE - 1;
                }
                XMEMCPY(dst, val, valLen);
                dst[valLen] = '\0';
            }
        }
    }

    /* allocate cert DER buffer */
    if (ret == WOLFCLU_SUCCESS) {
        certBuf = (byte*)XMALLOC(WOLFCLU_MLDSA_CERT_BUF_SZ, HEAP_HINT,
                                 DYNAMIC_TYPE_TMP_BUFFER);
        if (certBuf == NULL) {
            ret = MEMORY_E;
        }
        else {
            XMEMSET(certBuf, 0, WOLFCLU_MLDSA_CERT_BUF_SZ);
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = wc_MakeCert_ex(newCert, certBuf, WOLFCLU_MLDSA_CERT_BUF_SZ,
                             mldsaType, key, &rng);
        if (ret < 0) {
            wolfCLU_LogError("wc_MakeCert_ex failed: %d", ret);
        }
        else {
            ret = WOLFCLU_SUCCESS;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = wc_SignCert_ex(newCert->bodySz, newCert->sigType,
                             certBuf, WOLFCLU_MLDSA_CERT_BUF_SZ,
                             mldsaType, key, &rng);
        if (ret < 0) {
            wolfCLU_LogError("wc_SignCert_ex failed: %d", ret);
        }
        else {
            certDerSz = ret;
            ret = WOLFCLU_SUCCESS;
        }
    }

    /* write output (skipped entirely for -noout) */
    if (ret == WOLFCLU_SUCCESS && !noOut) {
        if (outForm == DER_FORM) {
            if (wolfSSL_BIO_write(bioOut, certBuf, certDerSz) <= 0) {
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
        else {
            /* DER to PEM conversion */
            pemBufSz = wc_DerToPem(certBuf, (word32)certDerSz,
                                   NULL, 0, CERT_TYPE);
            if (pemBufSz <= 0) {
                wolfCLU_LogError("wc_DerToPem size query failed: %d",
                                 pemBufSz);
                ret = (pemBufSz < 0) ? pemBufSz : WOLFCLU_FATAL_ERROR;
            }
            else {
                pemBuf = (byte*)XMALLOC(pemBufSz, HEAP_HINT,
                                        DYNAMIC_TYPE_TMP_BUFFER);
                if (pemBuf == NULL) {
                    ret = MEMORY_E;
                }
            }

            if (ret == WOLFCLU_SUCCESS) {
                ret = wc_DerToPem(certBuf, (word32)certDerSz,
                                  pemBuf, (word32)pemBufSz, CERT_TYPE);
                if (ret <= 0) {
                    wolfCLU_LogError("wc_DerToPem failed: %d", ret);
                    ret = WOLFCLU_FATAL_ERROR;
                }
                else {
                    if (wolfSSL_BIO_write(bioOut, pemBuf, ret) <= 0) {
                        ret = WOLFCLU_FATAL_ERROR;
                    }
                    else {
                        ret = WOLFCLU_SUCCESS;
                    }
                }
            }
        }
    }

    /* cleanup */
    XFREE(certBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(pemBuf,  HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (keyInit) {
        wc_MlDsaKey_Free(key);
    }
    if (rngInit) {
        wc_FreeRng(&rng);
    }
#ifdef WOLFSSL_SMALL_STACK
    XFREE(newCert, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(key,     HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}
#endif /* WOLFCLU_MLDSA_CERTGEN && WOLFSSL_CERT_REQ && !WOLFCLU_NO_FILESYSTEM */

#if defined(WOLFSSL_CERT_REQ) && !defined(WOLFCLU_NO_FILESYSTEM)
static const struct option req_options[] = {

    {"-sha",       no_argument,       0, WOLFCLU_CERT_SHA   },
    {"-sha224",    no_argument,       0, WOLFCLU_CERT_SHA224},
    {"-sha256",    no_argument,       0, WOLFCLU_CERT_SHA256},
    {"-sha384",    no_argument,       0, WOLFCLU_CERT_SHA384},
    {"-sha512",    no_argument,       0, WOLFCLU_CERT_SHA512},
    {"-rsa",       no_argument,       0, WOLFCLU_RSA       },
    {"-ed25519",   no_argument,       0, WOLFCLU_ED25519   },

    {"-in",        required_argument, 0, WOLFCLU_INFILE    },
    {"-out",       required_argument, 0, WOLFCLU_OUTFILE   },
    {"-key",       required_argument, 0, WOLFCLU_KEY       },
    {"-new",       no_argument,       0, WOLFCLU_NEW       },
    {"-newkey",    required_argument, 0, WOLFCLU_NEWKEY },
    {"-inkey",     required_argument, 0, WOLFCLU_INKEY     },
    {"-keyout",    required_argument, 0, WOLFCLU_OUTKEY     },
    {"-inform",    required_argument, 0, WOLFCLU_INFORM    },
    {"-outform",   required_argument, 0, WOLFCLU_OUTFORM   },
    {"-config",    required_argument, 0, WOLFCLU_CONFIG },
    {"-days",      required_argument, 0, WOLFCLU_DAYS },
    {"-x509",      no_argument,       0, WOLFCLU_X509 },
    {"-subj",      required_argument, 0, WOLFCLU_SUBJECT },
    {"-verify",    no_argument,       0, WOLFCLU_VERIFY },
    {"-text",      no_argument,       0, WOLFCLU_TEXT_OUT },
    {"-passout",   required_argument, 0, WOLFCLU_PASSWORD_OUT },
    {"-noout",     no_argument,       0, WOLFCLU_NOOUT },
    {"-extensions",required_argument, 0, WOLFCLU_EXTENSIONS},
    {"-addext",    required_argument, 0, WOLFCLU_ADDEXT },
    {"-nodes",     no_argument,       0, WOLFCLU_NODES },
    {"-h",         no_argument,       0, WOLFCLU_HELP },
    {"-help",      no_argument,       0, WOLFCLU_HELP },

    {0, 0, 0, 0} /* terminal element */
};


#define MAX_WIDTH 80
#ifdef NO_WOLFSSL_REQ_PRINT
/* print serial number out
 * return WOLFSSL_SUCCESS on success
 */
static int _wolfSSL_X509_print_serial(WOLFSSL_BIO* bio, WOLFSSL_X509* x509,
        int indent)
{
    unsigned char serial[32];
    int  sz = sizeof(serial);
    char scratch[MAX_WIDTH];

    XMEMSET(serial, 0, sz);
    if (wolfSSL_X509_get_serial_number(x509, serial, &sz) == WOLFSSL_SUCCESS) {

        XSNPRINTF(scratch, MAX_WIDTH, "%*s%s", indent, "",
                "Serial Number:");
        if (wolfSSL_BIO_write(bio, scratch, (int)XSTRLEN(scratch)) <= 0) {
            return WOLFSSL_FAILURE;
        }

        if (sz > (int)sizeof(byte)) {
            int i;
            char tmp[100];
            int  tmpSz = 100;
            char val[5];
            int  valSz = 5;

            /* serial is larger than int size so print off hex values */
            XSNPRINTF(scratch, MAX_WIDTH, "\n%*s", indent, "");
            if (wolfSSL_BIO_write(bio, scratch, (int)XSTRLEN(scratch))
                    <= 0) {
                return WOLFSSL_FAILURE;
            }
            tmp[0] = '\0';
            for (i = 0; i < sz - 1 && (3 * i) < tmpSz - valSz; i++) {
                XSNPRINTF(val, sizeof(val) - 1, "%02x:", serial[i]);
                val[3] = '\0'; /* make sure is null terminated */
                XSTRNCAT(tmp, val, valSz);
            }
            XSNPRINTF(val, sizeof(val) - 1, "%02x\n", serial[i]);
            val[3] = '\0'; /* make sure is null terminated */
            XSTRNCAT(tmp, val, valSz);
            if (wolfSSL_BIO_write(bio, tmp, (int)XSTRLEN(tmp)) <= 0) {
                return WOLFSSL_FAILURE;
            }
        }

        /* if serial can fit into byte than print on the same line */
        else if (sz <= (int)sizeof(byte)) {
            XSNPRINTF(scratch, MAX_WIDTH, " %d (0x%x)\n", serial[0],
                    serial[0]);
            if (wolfSSL_BIO_write(bio, scratch, (int)XSTRLEN(scratch))
                    <= 0) {
                return WOLFSSL_FAILURE;
            }
        }

    }
    return WOLFSSL_SUCCESS;
}


/* convert key usage type to human readable print out
 * return WOLFSSL_SUCCESS on success
 */
static int _keyUsagePrint(WOLFSSL_BIO* bio, int keyUsage, int indent)
{
    char scratch[MAX_WIDTH];

    if (keyUsage > 0) {
        if (keyUsage & KEYUSE_KEY_ENCIPHER) {
            XSNPRINTF(scratch, MAX_WIDTH, "%*s%s\n", indent, "",
                    "keyEncipherment");
            wolfSSL_BIO_write(bio, scratch, (int)XSTRLEN(scratch));
        }

        if (keyUsage & KEYUSE_DIGITAL_SIG) {
            XSNPRINTF(scratch, MAX_WIDTH, "%*s%s\n", indent, "",
                    "digitalSignature");
            wolfSSL_BIO_write(bio, scratch, (int)XSTRLEN(scratch));
        }

        if (keyUsage & KEYUSE_CONTENT_COMMIT) {
            XSNPRINTF(scratch, MAX_WIDTH, "%*s%s\n", indent, "",
                    "nonRepudiation");
            wolfSSL_BIO_write(bio, scratch, (int)XSTRLEN(scratch));
        }

        if (keyUsage & KEYUSE_DATA_ENCIPHER) {
            XSNPRINTF(scratch, MAX_WIDTH, "%*s%s\n", indent, "",
                    "dataEncipherment");
            wolfSSL_BIO_write(bio, scratch, (int)XSTRLEN(scratch));
        }

        if (keyUsage & KEYUSE_KEY_AGREE) {
            XSNPRINTF(scratch, MAX_WIDTH, "%*s%s\n", indent, "",
                    "keyAgreement");
            wolfSSL_BIO_write(bio, scratch, (int)XSTRLEN(scratch));
        }

        if (keyUsage & KEYUSE_KEY_CERT_SIGN) {
            XSNPRINTF(scratch, MAX_WIDTH, "%*s%s\n", indent, "", "keyCertSign");
            wolfSSL_BIO_write(bio, scratch, (int)XSTRLEN(scratch));
        }

        if (keyUsage & KEYUSE_CRL_SIGN) {
            XSNPRINTF(scratch, MAX_WIDTH, "%*s%s\n", indent, "", "cRLSign");
            wolfSSL_BIO_write(bio, scratch, (int)XSTRLEN(scratch));
        }

        if (keyUsage & KEYUSE_ENCIPHER_ONLY) {
            XSNPRINTF(scratch, MAX_WIDTH, "%*s%s\n", indent, "",
                    "encipherOnly");
            wolfSSL_BIO_write(bio, scratch, (int)XSTRLEN(scratch));
        }

        if (keyUsage & KEYUSE_DECIPHER_ONLY) {
            XSNPRINTF(scratch, MAX_WIDTH, "%*s%s\n", indent, "",
                    "decipherOnly");
            wolfSSL_BIO_write(bio, scratch, (int)XSTRLEN(scratch));
        }
    }

    return WOLFSSL_SUCCESS;
}


/* iterate through certificate extensions printing them out in human readable
 * form
 * return WOLFSSL_SUCCESS on success
 */
static int _wolfSSL_X509_extensions_print(WOLFSSL_BIO* bio, WOLFSSL_X509* x509,
        int indent)
{
    char scratch[MAX_WIDTH];
    int count, i;

    count = wolfSSL_X509_get_ext_count(x509);
    if (count > 0) {
        XSNPRINTF(scratch, MAX_WIDTH, "%*s%s\n", indent, "",
                "Requested extensions:");
        if (wolfSSL_BIO_write(bio, scratch, (int)XSTRLEN(scratch)) <= 0) {
            return WOLFSSL_FAILURE;
        }

        for (i = 0; i < count; i++) {
            WOLFSSL_X509_EXTENSION* ext = wolfSSL_X509_get_ext(x509, i);
            if (ext != NULL) {
                WOLFSSL_ASN1_OBJECT* obj;
                char buf[MAX_WIDTH];
                char* altName;
                int nid;

                obj = wolfSSL_X509_EXTENSION_get_object(ext);
                wolfSSL_OBJ_obj2txt(buf, MAX_WIDTH, obj, 0);
                XSNPRINTF(scratch, MAX_WIDTH, "%*s", indent + 4, "");
                XSTRLCAT(scratch, buf, MAX_WIDTH);

                int crit = wolfSSL_X509_EXTENSION_get_critical(ext) ? 1 : 0;
                XSTRLCAT(scratch, crit ? ": Critical\n" : ":\n", MAX_WIDTH);
                (void)crit;

                wolfSSL_BIO_write(bio, scratch, (int)XSTRLEN(scratch));
                nid = wolfSSL_OBJ_obj2nid(obj);
                switch (nid) {
                    case NID_subject_alt_name:
                        while ((altName = wolfSSL_X509_get_next_altname(x509))
                                != NULL) {
                            XSNPRINTF(scratch, MAX_WIDTH, "%*s%s\n", indent + 8,
                                    "", altName);
                            wolfSSL_BIO_write(bio, scratch,
                                    (int)XSTRLEN(scratch));
                        }
                        break;
                #if LIBWOLFSSL_VERSION_HEX > 0x05001000
                    case NID_key_usage:
                        _keyUsagePrint(bio, wolfSSL_X509_get_key_usage(x509),
                                indent + 8);
                        break;
                #endif
                    default:
                        /* extension nid not yet supported */
                        XSNPRINTF(scratch, MAX_WIDTH,
                                "%*sNID %d print not yet supported\n",
                                indent + 8, "", nid);
                        wolfSSL_BIO_write(bio, scratch, (int)XSTRLEN(scratch));
                }
            }
        }
    }
    return WOLFSSL_SUCCESS;
}


/* @TODO print out of REQ attributes
 * return WOLFSSL_SUCCESS on success
 */
static int _wolfSSL_X509_REQ_attributes_print(WOLFSSL_BIO* bio,
        WOLFSSL_X509* x509, int indent)
{
    WOLFSSL_X509_ATTRIBUTE* attr;
    char scratch[MAX_WIDTH];
    int i = 0;

    XSNPRINTF(scratch, MAX_WIDTH, "%*s%s", indent, "", "Attributes: \n");
    if (wolfSSL_BIO_write(bio, scratch, (int)XSTRLEN(scratch)) <= 0) {
        return WOLFSSL_FAILURE;
    }

    attr = wolfSSL_X509_REQ_get_attr(x509, i);
    while (attr != NULL) {
        char longName[NAME_SZ/4]; /* NAME_SZ default is 80 */
        int longNameSz = NAME_SZ/4;
        const byte* data;

        wolfSSL_OBJ_obj2txt(longName, longNameSz, attr->object, 0);
        longNameSz = (int)XSTRLEN(longName);
        data = wolfSSL_ASN1_STRING_get0_data(
                attr->value->value.asn1_string);
        if (data == NULL) {
            wolfCLU_LogError("No REQ attribute found when "
                    "expected");
            return WOLFSSL_FAILURE;
        }
        XSNPRINTF(scratch, MAX_WIDTH, "%*s%s%*s:%s\n", indent+4, "",
                longName, (NAME_SZ/4)-longNameSz, "", data);
        if (wolfSSL_BIO_write(bio, scratch, (int)XSTRLEN(scratch))
                <= 0) {
            wolfCLU_LogError("Error writing REQ attribute");
            return WOLFSSL_FAILURE;
        }

        i++;
        attr = wolfSSL_X509_REQ_get_attr(x509, i);
    }

    return WOLFSSL_SUCCESS;
}


/* print out the signature in human readable format for use with
 * wolfSSL_X509_print()
 * return WOLFSSL_SUCCESS on success
 */
static int _wolfSSL_X509_signature_print_ex(WOLFSSL_BIO* bio,
        WOLFSSL_X509* x509, int indent)
{
    char scratch[MAX_WIDTH];
    int sigSz = 0;

    wolfSSL_X509_get_signature(x509, NULL, &sigSz);
    if (sigSz > 0) {
        unsigned char* sig;
        int i;
        char tmp[100];
        int sigNid = wolfSSL_X509_get_signature_nid(x509);
        WOLFSSL_ASN1_OBJECT* obj;

        XSNPRINTF(scratch, MAX_WIDTH, "%*s%s", indent, "",
                "Signature Algorithm: ");
        if (wolfSSL_BIO_write(bio, scratch, (int)XSTRLEN(scratch)) <= 0) {
            return WOLFSSL_FAILURE;
        }
        obj = wolfSSL_OBJ_nid2obj(sigNid);
        wolfSSL_OBJ_obj2txt(scratch, MAX_WIDTH, obj, 0);
        wolfSSL_ASN1_OBJECT_free(obj);
        XSNPRINTF(tmp, sizeof(tmp) - 1,"%s\n", scratch);
        tmp[sizeof(tmp) - 1] = '\0';
        if (wolfSSL_BIO_write(bio, tmp, (int)XSTRLEN(tmp)) <= 0) {
            return WOLFSSL_FAILURE;
        }

        sig = (unsigned char*)XMALLOC(sigSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (sig == NULL) {
            return WOLFSSL_FAILURE;
        }

        if (wolfSSL_X509_get_signature(x509, sig, &sigSz) <= 0) {
            XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return WOLFSSL_FAILURE;
        }
        XSNPRINTF(tmp, sizeof(tmp) - 1,"        ");
        tmp[sizeof(tmp) - 1] = '\0';
        for (i = 0; i < sigSz; i++) {
            char val[5];
            int valSz = 5;

            if (i == 0) {
                XSNPRINTF(val, valSz - 1, "%02x", sig[i]);
            }
            else if (((i % 18) == 0)) {
                tmp[sizeof(tmp) - 1] = '\0';
                if (wolfSSL_BIO_write(bio, tmp, (int)XSTRLEN(tmp))
                        <= 0) {
                    XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                    return WOLFSSL_FAILURE;
                }
                XSNPRINTF(tmp, sizeof(tmp) - 1,
                        ":\n        ");
                XSNPRINTF(val, valSz - 1, "%02x", sig[i]);
            }
            else {
                XSNPRINTF(val, valSz - 1, ":%02x", sig[i]);
            }
            XSTRNCAT(tmp, val, valSz);
        }
        XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);

        /* print out remaining sig values */
        if ((i > 0) && (((i - 1) % 18) != 0)) {
                tmp[sizeof(tmp) - 1] = '\0';
                if (wolfSSL_BIO_write(bio, tmp, (int)XSTRLEN(tmp))
                        <= 0) {
                    return WOLFSSL_FAILURE;
                }
        }
    }
    return WOLFSSL_SUCCESS;
}


/* print out the public key in human readable format for use with
 * wolfSSL_X509_print()
 * return WOLFSSL_SUCCESS on success
 */
static int _wolfSSL_X509_pubkey_print(WOLFSSL_BIO* bio, WOLFSSL_X509* x509,
        int indent)
{
    char scratch[MAX_WIDTH];
    WOLFSSL_EVP_PKEY* pubKey;

    XSNPRINTF(scratch, MAX_WIDTH, "%*sPublic Key:\n", indent, "");
    wolfSSL_BIO_write(bio, scratch, (int)XSTRLEN(scratch));

    pubKey = wolfSSL_X509_get_pubkey(x509);
    wolfSSL_EVP_PKEY_print_public(bio, pubKey, indent + 4, NULL);
    wolfSSL_EVP_PKEY_free(pubKey);
    return WOLFSSL_SUCCESS;
}


/* human readable print out of x509 name formatted for use with
 * wolfSSL_X509_print()
 * return WOLFSSL_SUCCESS on success
 */
static int _X509_name_print(WOLFSSL_BIO* bio, WOLFSSL_X509_NAME* name,
        char* type, int indent)
{
    char scratch[MAX_WIDTH];
    if (name != NULL) {
        XSNPRINTF(scratch, MAX_WIDTH, "%*s%s", indent, "", type);
        wolfSSL_BIO_write(bio, scratch, (int)XSTRLEN(scratch));
        wolfSSL_X509_NAME_print_ex(bio, name, 1, 0);
        wolfSSL_BIO_write(bio, "\n", (int)XSTRLEN("\n"));
    }
    return WOLFSSL_SUCCESS;
}


/* human readable print out of x509 or CSR version
 * return WOLFSSL_SUCCESS on success
 */
static int _wolfSSL_X509_version_print(WOLFSSL_BIO* bio, WOLFSSL_X509* x509,
                                       int indent, byte isCSR)
{
    int version;
    byte version_value;
    char scratch[MAX_WIDTH];

    if ((version = wolfSSL_X509_version(x509)) < 0) {
        return WOLFSSL_FAILURE;
    }

    if (isCSR) {
        version_value = (byte)wolfSSL_X509_REQ_get_version(x509);
    } else {
        version_value = (byte)wolfSSL_X509_get_version(x509);
    }

    XSNPRINTF(scratch, MAX_WIDTH, "%*s%s", indent, "", "Version:");
    if (wolfSSL_BIO_write(bio, scratch, (int)XSTRLEN(scratch)) <= 0) {
        return WOLFSSL_FAILURE;
    }

    XSNPRINTF(scratch, MAX_WIDTH, " %d (0x%x)\n", version, version_value);
    if (wolfSSL_BIO_write(bio, scratch, (int)XSTRLEN(scratch)) <= 0) {
        return WOLFSSL_FAILURE;
    }
    return WOLFSSL_SUCCESS;
}

/* This should work its way into wolfSSL master @TODO
 * For now placing the implementation here so that wolfCLU can be used with
 * the current wolfSSL release.
 * return WOLFSSL_SUCCESS on success
 */
static int wolfSSL_X509_REQ_print(WOLFSSL_BIO* bio, WOLFSSL_X509* x509,
                                  byte isCSR)
{
    char subjType[] = "Subject: ";

    if (bio == NULL || x509 == NULL) {
        return WOLFSSL_FAILURE;
    }

    if (wolfSSL_BIO_write(bio, "Certificate Request:\n",
                  (int)XSTRLEN("Certificate Request:\n")) <= 0) {
            return WOLFSSL_FAILURE;
    }

    if (wolfSSL_BIO_write(bio, "    Data:\n",
                  (int)XSTRLEN("    Data:\n")) <= 0) {
            return WOLFSSL_FAILURE;
    }

    /* print version of cert */
    if (_wolfSSL_X509_version_print(bio, x509, 8, isCSR) != WOLFSSL_SUCCESS) {
        return WOLFSSL_FAILURE;
    }

    if (_wolfSSL_X509_print_serial(bio, x509, 8) != WOLFSSL_SUCCESS) {
        return WOLFSSL_FAILURE;
    }

    /* print subject */
    if (_X509_name_print(bio, wolfSSL_X509_get_subject_name(x509), subjType, 8)
            != WOLFSSL_SUCCESS) {
        return WOLFSSL_FAILURE;
    }

    /* get and print public key */
    if (_wolfSSL_X509_pubkey_print(bio, x509, 8) != WOLFSSL_SUCCESS) {
        return WOLFSSL_FAILURE;
    }

    /* print out extensions */
    if (_wolfSSL_X509_extensions_print(bio, x509, 4) != WOLFSSL_SUCCESS) {
        return WOLFSSL_FAILURE;
    }

    /* print out req attributes */
    if (_wolfSSL_X509_REQ_attributes_print(bio, x509, 4) != WOLFSSL_SUCCESS) {
        return WOLFSSL_FAILURE;
    }

    /* print out signature */
    if (_wolfSSL_X509_signature_print_ex(bio, x509, 4) != WOLFSSL_SUCCESS) {
        return WOLFSSL_FAILURE;
    }

    /* done with print out */
    if (wolfSSL_BIO_write(bio, "\n\0", (int)XSTRLEN("\n\0")) <= 0) {
        return WOLFSSL_FAILURE;
    }

    return WOLFSSL_SUCCESS;
}
#endif /* NO_WOLFSSL_REQ_PRINT */
#endif

/* return WOLFCLU_SUCCESS on success */
int wolfCLU_requestSetup(int argc, char** argv)
{
#ifndef WOLFSSL_CERT_REQ
    wolfCLU_LogError("wolfSSL not compiled with --enable-certreq");
     /* silence unused variable warnings */
    (void) argc;
    (void) argv;
    return NOT_COMPILED_IN;
#elif defined(WOLFCLU_NO_FILESYSTEM)
    WOLFCLU_LOG(WOLFCLU_E0, "No Filesystem Support.");
     /* silence unused variable warnings */
    (void) argc;
    (void) argv;
    return NOT_COMPILED_IN;
#else
    WOLFSSL_BIO *bioOut = NULL;
    WOLFSSL_BIO *keyIn  = NULL;
    WOLFSSL_BIO *reqIn  = NULL;
    WOLFSSL_X509 *x509  = NULL;
    const WOLFSSL_EVP_MD *md  = NULL;
    WOLFSSL_EVP_PKEY *pkey = NULL;

    int     ret = WOLFCLU_SUCCESS;
    char*   in  = NULL;
    char*   out = NULL;
    char*   config = NULL;
    char*   subj = NULL;
    char*   ext = NULL;
    char*   addExt = NULL;
    char*   keyType = NULL;
    char*   keyInfo = NULL;
    char*   keyOut  = NULL;

    int     algCheck =   0;     /* algorithm type */
    int     oid      =   0;
    int     outForm = PEM_FORM; /* default to PEM format */
    int     inForm  = PEM_FORM;
    int     option;
    int     longIndex = 1;
    int     days = 0;
    int     genX509 = 0;
    int     passout = 0;

    char password[MAX_PASSWORD_SIZE];
    int passwordSz = MAX_PASSWORD_SIZE;

    byte doVerify  = 0;
    byte doTextOut = 0;
    byte reSign    = 0; /* flag for if resigning req is needed */
    byte noOut     = 0;
    byte useDes    = 1;
#ifdef WOLFCLU_MLDSA_CERTGEN
    int  isMLDSA    = 0;
    int  mldsaTmpKey = 0; /* 1 if we generated a throwaway ML-DSA key pair */
    /* holds the generated ML-DSA private key path; must outlive the keygen
     * block since 'in' points into it until wolfCLU_MakeMLDSACert runs */
    char mldsaKeyPath[WOLFCLU_MLDSA_KEY_PATH_SZ];
#endif
#ifdef NO_WOLFSSL_REQ_PRINT
    byte isCSR     = 1;
#endif
    /* Multiple -addext is not yet supported. Detect it up front and fail
     * instead of silently dropping the extension and exiting success. */
    {
        int i, addExtCount = 0;
        for (i = 1; i < argc; i++) {
            if (argv[i] != NULL && XSTRCMP(argv[i], "-addext") == 0) {
                addExtCount++;
            }
        }
        if (addExtCount > 1) {
            wolfCLU_LogError("only one -addext arg is currently supported");
            return USER_INPUT_ERROR;
        }
    }

    opterr = 0; /* do not display unrecognized options */
    optind = 0; /* start at indent 0 */
    while ((option = wolfCLU_GetOpt(argc, argv, "", req_options,
                    &longIndex )) != -1) {

        switch (option) {
            case WOLFCLU_EXTENSIONS:
                ext = optarg;
                break;

            case WOLFCLU_ADDEXT:
                addExt = optarg;
                break;

            case WOLFCLU_NODES:
                useDes = 0;
                break;

            case WOLFCLU_OUTKEY:
                keyOut = optarg;
                break;

            case WOLFCLU_NEWKEY:
                if (optarg == NULL) {
                    wolfCLU_LogError("no key string");
                    ret = WOLFCLU_FATAL_ERROR;
                }

                if (ret == WOLFCLU_SUCCESS) {
                    if (XSTRSTR(optarg, ":") == NULL) {
                        wolfCLU_LogError("key string does not have ':'");
                        ret = WOLFCLU_FATAL_ERROR;
                    }
                }

                if (ret == WOLFCLU_SUCCESS) {
                    int idx;

                    idx     = (int)strcspn(optarg, ":");
                    keyType = (char*)XMALLOC(idx + 1, HEAP_HINT,
                            DYNAMIC_TYPE_TMP_BUFFER);
                    if (keyType == NULL) {
                        ret = WOLFCLU_FATAL_ERROR;
                    }
                    else {
                        XMEMCPY(keyType, optarg, idx);
                        keyType[idx] = '\0';
                    }

                    if (ret == WOLFCLU_SUCCESS) {
                        keyInfo = optarg + idx + 1;
                    }
                }
                break;

            case WOLFCLU_INFILE:
                reqIn = wolfSSL_BIO_new_file(optarg, "rb");
                if (reqIn == NULL) {
                    wolfCLU_LogError("Unable to open input file %s",
                            optarg);
                    ret = WOLFCLU_FATAL_ERROR;
                }
                break;

            case WOLFCLU_KEY:
                in = optarg;
                keyIn = wolfSSL_BIO_new_file(optarg, "rb");
                if (keyIn == NULL) {
                    wolfCLU_LogError("Unable to open public key file %s",
                            optarg);
                    ret = WOLFCLU_FATAL_ERROR;
                }
                break;

            case WOLFCLU_OUTFILE:
                out = optarg;
                break;

            case WOLFCLU_INFORM:
                inForm = wolfCLU_checkInform(optarg);
                break;

            case WOLFCLU_OUTFORM:
                outForm = wolfCLU_checkOutform(optarg);
                break;

            case WOLFCLU_SUBJECT:
                subj = optarg;
                break;

            case WOLFCLU_HELP:
                wolfCLU_certgenHelp();
                return WOLFCLU_SUCCESS;

            case WOLFCLU_RSA:
                algCheck = 1;
                break;

            case WOLFCLU_ED25519:
                algCheck = 2;
                break;

            case WOLFCLU_CONFIG:
                config = optarg;
                break;

            case WOLFCLU_DAYS:
                days = XATOI(optarg);
                break;

            case WOLFCLU_CERT_SHA:
                md  = wolfSSL_EVP_sha1();
                oid = SHA_HASH;
                break;

            case WOLFCLU_CERT_SHA224:
                md  = wolfSSL_EVP_sha224();
                oid = SHA_HASH224;
                break;

            case WOLFCLU_CERT_SHA256:
                md  = wolfSSL_EVP_sha256();
                oid = SHA_HASH256;
                break;

            case WOLFCLU_CERT_SHA384:
                md  = wolfSSL_EVP_sha384();
                oid = SHA_HASH384;
                break;

            case WOLFCLU_CERT_SHA512:
                md  = wolfSSL_EVP_sha512();
                oid = SHA_HASH512;
                break;

            case WOLFCLU_X509:
                genX509 = 1;
                break;

            case WOLFCLU_VERIFY:
                doVerify = 1;
                break;

            case WOLFCLU_TEXT_OUT:
                doTextOut = 1;
                break;

            case WOLFCLU_PASSWORD_OUT:
                passout = 1;
                ret = wolfCLU_GetPassword(password, &passwordSz, optarg);
                break;

            case WOLFCLU_NOOUT:
                noOut = 1;
                break;

            case WOLFCLU_NEW:
                break;

            case ':':
            case '?':
                wolfCLU_LogError("Unexpected argument");
                ret = WOLFCLU_FATAL_ERROR;
                wolfCLU_certgenHelp();
                break;

            default:
                wolfCLU_LogError("Unsupported argument");
                ret = WOLFCLU_FATAL_ERROR;
                wolfCLU_certgenHelp();
        }
    }

    /* default to sha256 if not set */
    if (ret == WOLFCLU_SUCCESS && md == NULL) {
        md  = wolfSSL_EVP_sha256();
        oid = SHA_HASH256;
    }

    if (ret == WOLFCLU_SUCCESS) {
        if (reqIn == NULL) {
            x509 = wolfSSL_X509_new();
            if (x509 == NULL) {
                wolfCLU_LogError("Issue creating structure to use");
                ret = MEMORY_E;
            }
        }
        else {
            if (inForm == PEM_FORM) {
                wolfSSL_PEM_read_bio_X509_REQ(reqIn, &x509, NULL, NULL);
            }
            else {
                wolfSSL_d2i_X509_REQ_bio(reqIn, &x509);
            }
            if (x509 == NULL) {
                wolfCLU_LogError("Issue creating structure to use");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
    }

    if (ret == WOLFCLU_SUCCESS && days > 0) {
        WOLFSSL_ASN1_TIME *notBefore, *notAfter;
        time_t t;

        t = time(NULL);
        notBefore = wolfSSL_ASN1_TIME_adj(NULL, t, 0, 0);
        notAfter = wolfSSL_ASN1_TIME_adj(NULL, t, days, 0);
        if (notBefore == NULL || notAfter == NULL) {
            wolfCLU_LogError("Error creating not before/after dates");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            wolfSSL_X509_set_notBefore(x509, notBefore);
            wolfSSL_X509_set_notAfter(x509, notAfter);
        }

        wolfSSL_ASN1_TIME_free(notBefore);
        wolfSSL_ASN1_TIME_free(notAfter);

        reSign = 1; /* re-sign after date change */
    }

    if (ret == WOLFCLU_SUCCESS && keyIn != NULL) {
#ifdef WOLFCLU_MLDSA_CERTGEN
        /* wolfSSL_PEM_read_bio_PrivateKey has no ML-DSA case; route to the
         * raw wolfcrypt path. keyIn is not used there so release it early. */
        if (in != NULL && wolfCLU_FileIsMLDSAKey(in)) {
            isMLDSA = 1;
            wolfSSL_BIO_free(keyIn);
            keyIn = NULL;
        }

        if (!isMLDSA)
#endif /* WOLFCLU_MLDSA_CERTGEN */
        {
            pkey = wolfSSL_PEM_read_bio_PrivateKey(keyIn, NULL, NULL, NULL);
            if (pkey == NULL) {
                wolfCLU_LogError("Error reading key from file");
                ret = USER_INPUT_ERROR;
            }

            if (ret == WOLFCLU_SUCCESS &&
                    wolfSSL_X509_set_pubkey(x509, pkey) != WOLFSSL_SUCCESS) {
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
    }

    /* generate key for -newkey */
    if (ret == WOLFCLU_SUCCESS && keyType != NULL && keyInfo != NULL &&
            pkey == NULL) {
        WOLFSSL_EVP_PKEY_CTX* ctx = NULL;

        if (XSTRNCMP("ec", keyType, 2) == 0) {
            wolfCLU_LogError("No supporting ecc gen with -newkey yet, "
                    "use ecparam command instead");
            ret = WOLFCLU_FATAL_ERROR;
        }

#ifdef WOLFCLU_MLDSA_CERTGEN
        if (ret == WOLFCLU_SUCCESS && !isMLDSA &&
                (XSTRNCMP("ml-dsa", keyType, 6) == 0 ||
                 XSTRNCMP("dilithium", keyType, 9) == 0)) {
            int      mlLevel = 0;
            int      mlKeySz = 0;
            int      mlWithAlg = 0;
            int      levelArg = (int)XATOI(keyInfo);
            WC_RNG   newkeyRng;

            /* -x509 is required; check before keygen to avoid writing files */
            if (!genX509) {
                wolfCLU_LogError("ML-DSA is only supported with -x509 "
                                 "(self-signed certificate) generation");
                ret = USER_INPUT_ERROR;
            }

            if (ret == WOLFCLU_SUCCESS) {
                switch (levelArg) {
                    case 2:
                        mlLevel   = WC_ML_DSA_44;
                        mlKeySz   = ML_DSA_LEVEL2_BOTH_KEY_DER_SIZE;
                        mlWithAlg = ML_DSA_LEVEL2k;
                        break;
                    case 3:
                        mlLevel   = WC_ML_DSA_65;
                        mlKeySz   = ML_DSA_LEVEL3_BOTH_KEY_DER_SIZE;
                        mlWithAlg = ML_DSA_LEVEL3k;
                        break;
                    case 5:
                        mlLevel   = WC_ML_DSA_87;
                        mlKeySz   = ML_DSA_LEVEL5_BOTH_KEY_DER_SIZE;
                        mlWithAlg = ML_DSA_LEVEL5k;
                        break;
                    default:
                        wolfCLU_LogError("Invalid ML-DSA level (use 2, 3, or 5)");
                        ret = USER_INPUT_ERROR;
                        break;
                }
            }

            if (ret == WOLFCLU_SUCCESS) {
                const char* kName = (keyOut != NULL) ?
                                     keyOut : "wolfclu_tmp_mldsa";
                int kNameSz;

                kNameSz = XSNPRINTF(mldsaKeyPath, sizeof(mldsaKeyPath),
                                    "%s.priv", kName);
                if (kNameSz < 0 || kNameSz >= (int)sizeof(mldsaKeyPath)) {
                    wolfCLU_LogError("ML-DSA key output name too long");
                    ret = WOLFCLU_FATAL_ERROR;
                }

                /* When -keyout is specified, partial files (<name>.priv /
                 * <name>.pub) are NOT removed on keygen failure */
                if (ret == WOLFCLU_SUCCESS && keyOut == NULL) {
                    char* tmpPub = wolfCLU_MLDSADupPubPath(mldsaKeyPath);
                    if (wolfCLU_FileExists(mldsaKeyPath) ||
                            (tmpPub != NULL && wolfCLU_FileExists(tmpPub))) {
                        wolfCLU_LogError("Refusing to overwrite existing %s "
                                "(or its .pub); use -keyout to choose a key "
                                "output name", mldsaKeyPath);
                        ret = USER_INPUT_ERROR;
                    }
                    else {
                        in          = mldsaKeyPath;
                        mldsaTmpKey = 1;
                    }
                    XFREE(tmpPub, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
                }

                /* re-check ret: the clobber guard above may have failed */
                if (ret == WOLFCLU_SUCCESS) {
                    XMEMSET(&newkeyRng, 0, sizeof(newkeyRng));
                    if (wc_InitRng(&newkeyRng) != 0) {
                        ret = WOLFCLU_FATAL_ERROR;
                    }
                    else {
                        /* withAlg = ML_DSA_LEVELxk so a kept .pub is a standard
                         * SubjectPublicKeyInfo, matching the genkey command */
                        ret = wolfCLU_genKey_ML_DSA(&newkeyRng, kName,
                                  PRIV_AND_PUB_FILES, PEM_FORM, mlKeySz,
                                  mlLevel, mlWithAlg);
                        wc_FreeRng(&newkeyRng);
                    }
                }

                if (ret == WOLFCLU_SUCCESS) {
                    in = mldsaKeyPath;
                    isMLDSA = 1;

                     /* the DES3/-passout encryption the RSA path applies
                     * is not wired up here. */
                    if (keyOut != NULL && (useDes || passout)) {
                        wolfCLU_Log(WOLFCLU_L0, "Warning: ML-DSA private key "
                                "written unencrypted (-nodes/-passout not "
                                "applied)");
                    }
                }
            }
        }
        else
#endif /* WOLFCLU_MLDSA_CERTGEN */
        if (XSTRNCMP("rsa", keyType, 3) == 0) {
            ctx = wolfSSL_EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
            ret = wolfSSL_EVP_PKEY_CTX_set_rsa_keygen_bits(ctx,
                    (int)XATOI(keyInfo));
        }

        if (ret == WOLFCLU_SUCCESS && ctx == NULL
#ifdef WOLFCLU_MLDSA_CERTGEN
                && !isMLDSA
#endif
                ) {
            wolfCLU_LogError("Unknown/unsupported algo name");
            ret = WOLFCLU_FATAL_ERROR;
        }

        if (ret == WOLFCLU_SUCCESS
#ifdef WOLFCLU_MLDSA_CERTGEN
                && !isMLDSA
#endif
                ) {
            if (wolfSSL_EVP_PKEY_keygen(ctx, &pkey) != WOLFSSL_SUCCESS) {
                wolfCLU_LogError("Error with keygen");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
        wolfSSL_EVP_PKEY_CTX_free(ctx);

        if (ret == WOLFCLU_SUCCESS
#ifdef WOLFCLU_MLDSA_CERTGEN
                && !isMLDSA
#endif
                &&
                wolfSSL_X509_set_pubkey(x509, pkey) != WOLFSSL_SUCCESS) {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS && reqIn == NULL && pkey == NULL
#ifdef WOLFCLU_MLDSA_CERTGEN
            && !isMLDSA
#endif
            ) {
        wolfCLU_LogError("Please specify a -key <key> option when "
               "generating a certificate.");
        wolfCLU_certgenHelp();
        ret = USER_INPUT_ERROR;
    }

    if (ret == WOLFCLU_SUCCESS && config != NULL) {
        ret = wolfCLU_readConfig(x509, config, (char*)"req", ext);
        reSign = 1; /* re-sign after config changes */
    }

    if (ret == WOLFCLU_SUCCESS && subj != NULL) {
        WOLFSSL_X509_NAME *name;
        name = wolfCLU_ParseX509NameString(subj, (int)XSTRLEN(subj));
        if (name != NULL) {
            wolfSSL_X509_REQ_set_subject_name(x509, name);
            wolfSSL_X509_NAME_free(name);
            reSign = 1; /* re-sign after subject change */
        }
        else {
            wolfCLU_LogError("Failed to parse -subj string");
            wolfCLU_certgenHelp();
            ret = USER_INPUT_ERROR;
        }
    }

    /* apply the -addext extension, if present */
    if (ret == WOLFCLU_SUCCESS && addExt != NULL) {
        ret = wolfCLU_parseAddExt(x509, addExt);
        reSign = 1; /* re-sign after extension change */
    }

    /* if no configure is passed in then get input from command line */
    if (ret == WOLFCLU_SUCCESS && subj == NULL && config == NULL &&
            reqIn == NULL) {
        WOLFSSL_X509_NAME *name;

        name = wolfSSL_X509_NAME_new();
        if (name == NULL) {
            ret = MEMORY_E;
        }
        else {
            ret = wolfCLU_CreateX509Name(name);
            if (ret == WOLFCLU_SUCCESS) {
                wolfSSL_X509_REQ_set_subject_name(x509, name);
            }
            wolfSSL_X509_NAME_free(name);
        }
    }

    /* default to CA:TRUE for req -x509 command (self signed certificates) when
     * a basic constraint is not already set */
    if (genX509 && ret == WOLFCLU_SUCCESS &&
            !wolfSSL_X509_ext_isSet_by_NID(x509, NID_basic_constraints)) {
        WOLFSSL_X509_EXTENSION *newExt;
        WOLFSSL_ASN1_OBJECT *obj;

        newExt = wolfSSL_X509_EXTENSION_new();
        obj = wolfCLU_extenstionGetObjectNID(newExt, NID_basic_constraints, 1);

        if (obj == NULL || newExt == NULL) {
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            obj->ca = 1;

            ret = wolfSSL_X509_add_ext(x509, newExt, -1);
            if (ret != WOLFSSL_SUCCESS) {
                WOLFCLU_LOG(WOLFCLU_E0,
                        "error %d adding Basic Constraints extension", ret);
            }
            wolfSSL_X509_EXTENSION_free(newExt);
        }
    }

    /* default to version 1 when generating CSR */
    if (ret == WOLFCLU_SUCCESS) {
        if (wolfSSL_X509_REQ_set_version(x509, WOLFSSL_X509_V1) !=
                WOLFSSL_SUCCESS) {
            wolfCLU_LogError("Error setting CSR version");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* check that we have the key if re-signing */
    if (ret == WOLFCLU_SUCCESS &&
            (reqIn == NULL || reSign) && pkey == NULL
#ifdef WOLFCLU_MLDSA_CERTGEN
            && !isMLDSA
#endif
            ) {
        wolfCLU_LogError("No key loaded to sign with");
        ret = WOLFCLU_FATAL_ERROR;
    }

    if (ret == WOLFCLU_SUCCESS && bioOut == NULL && out != NULL) {
        bioOut = wolfSSL_BIO_new_file(out, "wb");
        if (bioOut == NULL) {
            wolfCLU_LogError("Unable to open output file %s", out);
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS && bioOut == NULL) {
        /* output to stdout if no output is provided */
        bioOut = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
        if (bioOut != NULL) {
            if (wolfSSL_BIO_set_fp(bioOut, stdout, BIO_NOCLOSE)
                    != WOLFSSL_SUCCESS) {
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
    }

#ifdef WOLFCLU_MLDSA_CERTGEN
    /* ML-DSA is only wired up for the self-signed cert path; the EVP_PKEY
     * compat layer used for CSR signing has no ML-DSA support */
    if (ret == WOLFCLU_SUCCESS && isMLDSA && !genX509) {
        wolfCLU_LogError("ML-DSA is only supported with -x509 "
                         "(self-signed certificate) generation");
        ret = USER_INPUT_ERROR;
        if (out != NULL) {
            wolfSSL_BIO_free(bioOut);
            bioOut = NULL;
            remove(out);
        }
    }

    if (ret == WOLFCLU_SUCCESS && genX509 && isMLDSA &&
            (config != NULL || ext != NULL)) {
        wolfCLU_Log(WOLFCLU_L0, "Warning: ML-DSA -x509 ignores "
                "-config/-extensions; only subject DN and CA:TRUE are emitted");
    }

    /* -text/-verify operate via the EVP/req print path which the raw ML-DSA
     * honored below. */
    if (ret == WOLFCLU_SUCCESS && genX509 && isMLDSA &&
            (doTextOut || doVerify)) {
        wolfCLU_Log(WOLFCLU_L0, "Warning: -text/-verify are not supported on "
                "the ML-DSA -x509 path and will be ignored");
    }

    /* ML-DSA cert path: build and sign entirely via raw wolfcrypt,
     * bypassing the EVP_PKEY compat layer which has no ML-DSA support */
    if (ret == WOLFCLU_SUCCESS && genX509 && isMLDSA && in != NULL) {
        ret = wolfCLU_MakeMLDSACert(in, x509, days, outForm, bioOut, noOut);

        wolfSSL_BIO_free(bioOut);
        bioOut = NULL;

        /* don't leave a truncated 0-byte cert file behind on failure */
        if (ret != WOLFCLU_SUCCESS && out != NULL) {
            if (remove(out) != 0) {
                wolfCLU_LogError("Warning: could not remove incomplete "
                                 "output file %s", out);
            }
        }

        /* remove the throwaway key pair (kept only when the
         * user asked for it with -keyout) */
        if (mldsaTmpKey) {
            wolfCLU_RemoveMLDSAKeyPair(in);
        }

        (void)pkey;
        (void)md;
        (void)algCheck;
        (void)oid;
        if (keyType != NULL)
            XFREE(keyType, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        wolfSSL_BIO_free(reqIn);
        wolfSSL_BIO_free(keyIn);
        wolfSSL_X509_free(x509);
        wolfSSL_EVP_PKEY_free(pkey);
        return ret;
    }
#endif /* WOLFCLU_MLDSA_CERTGEN */

    /* sign the req/cert */
    if (ret == WOLFCLU_SUCCESS && (reqIn == NULL || reSign)) {
        if (genX509) {
#ifdef NO_WOLFSSL_REQ_PRINT
            isCSR = 0;
#endif
            /* default to version 3 which supports extensions */
            if (wolfSSL_X509_set_version(x509, WOLFSSL_X509_V3) !=
                    WOLFSSL_SUCCESS) {
                wolfCLU_LogError("Unable to set version 3 for cert");
                ret = WOLFSSL_FAILURE;
            }

            if (ret == WOLFCLU_SUCCESS) {
                ret = wolfSSL_X509_sign(x509, pkey, md);
                if (ret > 0)
                    ret = WOLFSSL_SUCCESS;
            }
        }
        else {
            ret = wolfSSL_X509_REQ_sign(x509, pkey, md);
        }

        if (ret != WOLFSSL_SUCCESS) {
            wolfCLU_LogError("Error %d signing", ret);
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            ret = WOLFCLU_SUCCESS;
        }
    }

    if (ret == WOLFCLU_SUCCESS && doVerify) {

        /* get public key from req if not passed in */
        if (pkey == NULL) {
            pkey = wolfSSL_X509_get_pubkey(x509);
        }

        if (pkey == NULL) {
            wolfCLU_LogError("Error getting the public key to verify");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            if (wolfSSL_X509_REQ_verify(x509, pkey) == 1) {
                WOLFCLU_LOG(WOLFCLU_L0, "verify OK");
            }
            else {
                wolfCLU_LogError("verify failed");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
    }

    if (ret == WOLFCLU_SUCCESS && doTextOut) {
#ifdef NO_WOLFSSL_REQ_PRINT
        wolfSSL_X509_REQ_print(bioOut, x509, isCSR);
#else
        wolfSSL_X509_REQ_print(bioOut, x509);
#endif
    }

    if (ret == WOLFCLU_SUCCESS && !noOut) {
        if (outForm == DER_FORM) {
            if (genX509) {
                ret = wolfSSL_i2d_X509_bio(bioOut, x509);
            }
            else {
                ret = wolfSSL_i2d_X509_REQ_bio(bioOut, x509);
            }
        }
        else {
            if (genX509) {
                ret = wolfSSL_PEM_write_bio_X509(bioOut, x509);
            }
            else {
                ret = wolfSSL_PEM_write_bio_X509_REQ(bioOut, x509);
            }
        }

        if (ret != WOLFSSL_SUCCESS) {
            wolfCLU_LogError("Error %d writing out cert req", ret);
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            /* set WOLFSSL_SUCCESS case to success value */
            ret = WOLFCLU_SUCCESS;
        }
    }

    if (ret == WOLFCLU_SUCCESS && keyType != NULL && keyInfo != NULL) {
        WOLFSSL_BIO* keyOutBio;

        if (keyOut != NULL) {
            keyOutBio = wolfSSL_BIO_new_file(keyOut, "wb");
        }
        else {
            keyOutBio = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
            if (keyOutBio != NULL) {
                if (wolfSSL_BIO_set_fp(keyOutBio, stdout, BIO_NOCLOSE)
                    != WOLFSSL_SUCCESS) {
                    ret = WOLFCLU_FATAL_ERROR;
                }
            }
        }

        if (keyOutBio == NULL) {
            wolfCLU_LogError("Error opening keyout file %s", keyOut);
            ret = WOLFCLU_FATAL_ERROR;
        }

        if (ret == WOLFCLU_SUCCESS) {
            if (useDes) {
                if (!passout) {
                    byte pass[MAX_PASSWORD_SIZE];
                    wolfCLU_GetStdinPassword(pass, (word32*)&passwordSz);

                    if (pass[0] == '\0') {
                        wolfCLU_LogError("Please enter a password");
                        ret = WOLFCLU_FATAL_ERROR;
                    }
                    else {
                        ret = wolfCLU_pKeyPEMtoPriKeyEnc(keyOutBio, pkey, DES3b,
                                pass, passwordSz);
                    }
                }
                else {
                    ret = wolfCLU_pKeyPEMtoPriKeyEnc(keyOutBio, pkey, DES3b,
                            (byte*)password, passwordSz);
                }
            }
            else {
                ret = wolfCLU_pKeyPEMtoPriKey(keyOutBio, pkey);
            }
        }
        wolfSSL_BIO_free(keyOutBio);
    }

    (void)algCheck;
    (void)in;
    (void)oid;

#ifdef WOLFCLU_MLDSA_CERTGEN
    /* error paths that bypass the ML-DSA early-return above */
    if (mldsaTmpKey && in != NULL) {
        wolfCLU_RemoveMLDSAKeyPair(in);
    }
#endif

    if (keyType != NULL) {
        XFREE(keyType, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }

    wolfSSL_BIO_free(reqIn);
    wolfSSL_BIO_free(keyIn);
    wolfSSL_BIO_free(bioOut);
    wolfSSL_X509_free(x509);
    wolfSSL_EVP_PKEY_free(pkey);
    return ret;
#endif
}

