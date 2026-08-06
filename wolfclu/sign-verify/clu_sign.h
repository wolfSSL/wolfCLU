/* clu_sign.h
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

#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#ifdef HAVE_ED25519
    #include <wolfssl/wolfcrypt/ed25519.h>
#endif
#ifndef NO_RSA
    #include <wolfssl/wolfcrypt/rsa.h>
#endif
#ifdef HAVE_ECC
    #include <wolfssl/wolfcrypt/ecc.h>
    #include <wolfssl/wolfcrypt/asn_public.h>
#endif
#ifdef HAVE_DILITHIUM
    #include <wolfssl/wolfcrypt/dilithium.h>
    /* Fallback for older wolfSSL builds predating this constant; 10267 is
     * the largest possible key PEM size
     * (DILITHIUM_LEVEL5_BOTH_KEY_PEM_SIZE). */
    #ifndef DILITHIUM_MAX_BOTH_KEY_PEM_SIZE
        #define DILITHIUM_MAX_BOTH_KEY_PEM_SIZE 10267
    #endif
#endif
#ifdef WOLFSSL_HAVE_XMSS
    #include <wolfssl/wolfcrypt/wc_xmss.h>
#endif

/* Upper bound (256MB) on file size */
#ifndef WOLFCLU_MAX_FILE_SIZE
#define WOLFCLU_MAX_FILE_SIZE 0xFFFFFFF
#endif /* WOLFCLU_MAX_FILE_SIZE */

/* Cap for a classical key file read. The key-type-derived bound can come out
 * very small (e.g. 512 bytes when MAX_ECC_BITS_NEEDED resolves to 256), which
 * would reject a valid PEM carrying surrounding text, such as the output of
 * `openssl pkey -text`. Never cap below WOLFCLU_MIN_KEY_FILE_SIZE. */
#ifndef WOLFCLU_MIN_KEY_FILE_SIZE
#define WOLFCLU_MIN_KEY_FILE_SIZE 4096
#endif
#define WOLFCLU_KEY_FILE_CAP(sz) \
    ((long)((sz) > WOLFCLU_MIN_KEY_FILE_SIZE ? (sz) : WOLFCLU_MIN_KEY_FILE_SIZE))

/* Shared cap for PQ key file reads (Dilithium/ML-DSA, XMSS/XMSSMT). */
#ifndef WOLFCLU_MAX_PQ_KEY_PEM_SIZE
    /* WC_MLDSA_87_* is the newer spelling and is checked first: the
     * DILITHIUM_* arm below always matches under HAVE_DILITHIUM, since it
     * has a fallback definition above. */
    #ifdef WC_MLDSA_87_BOTH_KEY_PEM_SIZE
        #define WOLFCLU_MAX_PQ_KEY_PEM_SIZE WC_MLDSA_87_BOTH_KEY_PEM_SIZE
    #elif defined(DILITHIUM_MAX_BOTH_KEY_PEM_SIZE)
        #define WOLFCLU_MAX_PQ_KEY_PEM_SIZE DILITHIUM_MAX_BOTH_KEY_PEM_SIZE
    #else
        #define WOLFCLU_MAX_PQ_KEY_PEM_SIZE 16384
    #endif
#endif /* WOLFCLU_MAX_PQ_KEY_PEM_SIZE */

enum {
    RSA_SIG_VER,
    ECC_SIG_VER,
    ED25519_SIG_VER,
    DILITHIUM_SIG_VER,
    XMSS_SIG_VER,
    XMSSMT_SIG_VER,
};

int wolfCLU_sign_data(char* in, char* out, char* privKey, int keyType,
        int inForm);


int wolfCLU_sign_data_rsa(byte* data, char* out, word32 dataSz, char* privKey,
        int inForm);
int wolfCLU_sign_data_ecc(byte* data, char* out, word32 fSz, char* privKey,
        int inForm);
int wolfCLU_sign_data_ed25519(byte* data, char* out, word32 fSz,
        char* privKey, int inForm);
int wolfCLU_sign_data_dilithium(byte* data, char* out, word32 dataSz,
        char* privKey, int inForm);
int wolfCLU_sign_data_xmss(byte* data, char* out, int fSz, char* privKey);
int wolfCLU_sign_data_xmssmt(byte* data, char* out, int fSz, char* privKey);

int wolfCLU_KeyPemToDer(unsigned char** pkeyBuf, int pkeySz, int pubIn);

/* Same as wolfCLU_KeyPemToDer, but treats ASN_NO_PEM_HEADER as "already DER"
 * instead of an error, logging either way. Returns 0 on success and updates
 * *pkeySz when a conversion resized the buffer. */
int wolfCLU_KeyPemToDerFallback_ex(unsigned char** pkeyBuf, int* pkeySz,
        int pubIn);
