/* clu_cert.h
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

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#define PEM_FORM 1
#define DER_FORM 2
#define RAW_FORM 3

/* Unified key context for X.509 operations.
 *
 * wolfSSL's EVP_PKEY cannot represent every key type wolfCLU signs with, so
 * the context carries either an EVP_PKEY or a raw wolfCrypt key together
 * with its type and, for algorithms that have one, its parameter set. The
 * raw slot is deliberately opaque: an algorithm adds support by loading into
 * 'key'/'keyType' and supplying 'keyFree', without this header growing a
 * per-algorithm member. */
typedef struct CLU_KEY_CTX {
    WOLFSSL_EVP_PKEY* evp;      /* set when the key fits the EVP API */
    void*  key;                 /* raw wolfCrypt key, when evp is NULL */
    int    keyType;             /* *k OID enum describing 'key' */
    byte   level;               /* parameter set, where the algorithm has one */
    void (*keyFree)(void** key);/* frees 'key'; set by whoever loaded it */
} CLU_KEY_CTX;

/* Load a private key from 'file' into 'ctx'. Tries the EVP path first.
 * Returns WOLFCLU_SUCCESS, or USER_INPUT_ERROR when no loader accepts it. */
int wolfCLU_LoadKey(const char* file, CLU_KEY_CTX* ctx);

/* Release whatever 'ctx' holds. Safe to call on a zeroed context. */
int wolfCLU_FreeKeyCtx(CLU_KEY_CTX* ctx);

#if defined(WOLFSSL_CERT_EXT)
/* Set (non-critical) basicConstraints CA:TRUE or CA:FALSE on x509. */
int wolfCLU_SetBasicConstraintsCA(WOLFSSL_X509* x509, int ca);
#endif

/* handles incoming arguments for certificate generation */
int wolfCLU_certSetup(int argc, char** argv);

/* print help info */
void wolfCLU_certHelp(void);


#ifdef WOLFSSL_CERT_GEN
int wolfCLU_CopyX509NameToCert(WOLFSSL_X509_NAME* name, CertName* dst);
int wolfCLU_SetCertNameFieldByNid(CertName* dst, int nid, const char* val,
        int valLen);
int wolfCLU_Asn1TimeToCertDate(byte* out, int outSz,
        const WOLFSSL_ASN1_TIME* t);

#if defined(WOLFSSL_ALT_NAMES)
int wolfCLU_CopyX509SanToCert(WOLFSSL_X509* x509, Cert* cert);
#endif /* WOLFSSL_ALT_NAMES */

#ifdef WOLFSSL_CERT_EXT
int wolfCLU_ExtHandledNid(int nid);
int wolfCLU_CopyX509ExtsToCert(WOLFSSL_X509* x509, Cert* cert,
        int* extsDropped);
int wolfCLU_FreeCertCustomExts(Cert* cert);

/* Extracts raw Extensions DER for testing. */
int wolfCLU_UnwrapX509Extensions(const byte** extensions,
        int* extensionsSz);
#endif /* WOLFSSL_CERT_EXT */

#define WOLFCLU_CERT_DAYS_DEFAULT 365

#ifdef WOLFSSL_CERT_EXT
int wolfCLU_BuildAndSignNative(void* key, int keyType, int sigType, int bufSz,
        WOLFSSL_X509* x509, int days, int isCSR, int outForm,
        WOLFSSL_BIO* bioOut, int noOut);

/* Shared build+sign core for wolfCLU_BuildAndSignNative()/CertSignNative().
 * days < 0 leaves cert->daysValid untouched. */
int wolfCLU_MakeAndSignCertDer(WOLFSSL_X509* x509, int isCSR, int sigType,
        int bufSz, void* subjKey, int subjKeyType, void* caKey, int caKeyType,
        WOLFSSL_X509* caCert, int policySanitized, int days,
        byte** outDer, int* outDerSz);
#endif /* WOLFSSL_CERT_EXT */

int wolfCLU_X509FillCert(WOLFSSL_X509* x509, Cert* cert, int sigType,
        void* subjWcKey, int subjWcKeyType,
        void* caWcKey, int caWcKeyType, WOLFSSL_X509* caCert,
        int policySanitized, int* extsDropped);
#endif /* WOLFSSL_CERT_GEN */
