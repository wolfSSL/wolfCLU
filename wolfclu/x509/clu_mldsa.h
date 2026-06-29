/* clu_mldsa.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * ML-DSA helpers for wolfCLU while wolfSSL lacks full EVP/API coverage for
 * ML-DSA certificate operations.  Intended to be deleted once native API
 * support allows swapping callers to EVP (wolfSSL_PEM_read_bio_PrivateKey,
 * wolfSSL_X509_sign, etc.).
 *
 * Parameter sets: user-facing levels 2, 3, and 5 (ML-DSA-44/65/87). The level
 * is taken from the key material (wc_MlDsaKey_GetParams); ca has no -level
 * flag. Sign buffer sizes scale per level in clu_mldsa.c.
 */

#ifndef WOLFCLU_MLDSA_H
#define WOLFCLU_MLDSA_H

#include <wolfclu/clu_header_main.h>

#if defined(WOLFCLU_HAVE_MLDSA)

#include <wolfssl/wolfcrypt/dilithium.h>

#define WOLFCLU_MLDSA_SPKI_DER_MARGIN 32
#define WOLFCLU_MLDSA_MAX_SPKI_DER_SZ (DILITHIUM_MAX_PUB_KEY_DER_SIZE + \
                                        WOLFCLU_MLDSA_SPKI_DER_MARGIN)

int wolfCLU_FreeMLDSAKeyHeap(MlDsaKey** key);
int wolfCLU_MLDSALevelToTypes(byte level, int* sigType, int* mldsaType);
int wolfCLU_MLDSALevelToKeyOid(byte level);
int wolfCLU_IsMLDSAKeyType(int keyType);
int wolfCLU_MLDSASignBufSz(byte level);

#if defined(WOLFSSL_CERT_GEN)
#ifndef NO_CHECK_PRIVATE_KEY
int wolfCLU_MLDSACheckPrivateKeyCert(WOLFSSL_X509* caCert, MlDsaKey* caKey);
#endif /* NO_CHECK_PRIVATE_KEY */
int wolfCLU_MLDSACertSign(WOLFSSL_X509* x509, MlDsaKey* caKey, byte level,
        WOLFSSL_X509* caCert, int outForm, byte** outData, int* outDataSz);
#endif /* WOLFSSL_CERT_GEN */

#ifndef WOLFCLU_NO_FILESYSTEM

char* wolfCLU_MLDSADupPrivPubPath(const char* privPath);
/* Caller must call wolfCLU_FreeMLDSAKeyHeap on error as well as success. */
int wolfCLU_LoadMLDSACompanionPub(const char* keyPath, MlDsaKey* key,
        int quiet);
/* Caller must call wolfCLU_FreeMLDSAKeyHeap on error as well as success. */
int wolfCLU_LoadMLDSAKey(const char* keyPath, MlDsaKey* key, byte* level,
        int quiet);
int wolfCLU_IsMLDSAKeyFile(const char* path);

#if defined(WOLFSSL_CERT_GEN)
int wolfCLU_MakeMLDSASelfSignedCert(const char* keyPath, WOLFSSL_X509* x509,
        int days, int outForm, WOLFSSL_BIO* bioOut, int noOut);
#ifdef WOLFSSL_CERT_REQ
int wolfCLU_MakeMLDSACSR(const char* keyPath, WOLFSSL_X509* x509,
        int outForm, WOLFSSL_BIO* bioOut, int noOut);
#endif /* WOLFSSL_CERT_REQ */
#endif /* WOLFSSL_CERT_GEN */

#endif /* !WOLFCLU_NO_FILESYSTEM */
#endif /* WOLFCLU_HAVE_MLDSA */

#endif /* WOLFCLU_MLDSA_H */
