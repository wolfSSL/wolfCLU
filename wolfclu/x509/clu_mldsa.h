/* clu_mldsa.h
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * ML-DSA implementation for wolfCLU certificate operations.
 *
 * Levels 2, 3, 5 (ML-DSA-44/65/87). Level is taken from key material;
 * CA has no -level flag. Sign buffer sizes scale per level.
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
/* policySanitized must be 1 to confirm CSR extensions (like CA:TRUE) have
 * been neutralized. 0 fails outright to avoid signing attacker-controlled policies. */
int wolfCLU_MLDSACertSign(WOLFSSL_X509* x509, MlDsaKey* caKey, byte level,
        WOLFSSL_X509* caCert, int outForm, byte** outData, int* outDataSz,
        int policySanitized);
#endif /* WOLFSSL_CERT_GEN */

#ifndef WOLFCLU_NO_FILESYSTEM

char* wolfCLU_MLDSADupPrivPubPath(const char* privPath);
/* Caller must wolfCLU_FreeMLDSAKeyHeap on success or error. */
int wolfCLU_LoadMLDSACompanionPub(const char* keyPath, MlDsaKey* key,
        int quiet);
/* Caller must wolfCLU_FreeMLDSAKeyHeap on success or error. */
int wolfCLU_LoadMLDSAKey(const char* keyPath, MlDsaKey* key, byte* level,
        int quiet);
int wolfCLU_IsMLDSAKeyFile(const char* path);

#if defined(WOLFSSL_CERT_GEN)
int wolfCLU_MakeMLDSASelfSignedCert(const char* keyPath, MlDsaKey* inKey,
        WOLFSSL_X509* x509, int days, int outForm, WOLFSSL_BIO* bioOut,
        int noOut);
#ifdef WOLFSSL_CERT_REQ
int wolfCLU_MakeMLDSACSR(const char* keyPath, MlDsaKey* inKey,
        WOLFSSL_X509* x509, int outForm, WOLFSSL_BIO* bioOut, int noOut);
#endif /* WOLFSSL_CERT_REQ */
#endif /* WOLFSSL_CERT_GEN */

#endif /* !WOLFCLU_NO_FILESYSTEM */
#endif /* WOLFCLU_HAVE_MLDSA */

#endif /* WOLFCLU_MLDSA_H */
