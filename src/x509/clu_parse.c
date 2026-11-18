/* clu_parse.c
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
#include <wolfclu/clu_error_codes.h>
#include <wolfclu/x509/clu_parse.h>
#include <wolfclu/x509/clu_cert.h>

#ifndef WOLFCLU_NO_FILESYSTEM

#define MAX_CERT_SIZE 16384

enum {
    PEM = 0,
    DER = 1,
    TEXT = 2,
};


/* helper function for shared code when printing out key
 * returns WOLFCLU_SUCCESS on success
 */
int wolfCLU_printDer(WOLFSSL_BIO* bio, unsigned char* der, int derSz,
        int pemType, int heapType)
{
    int ret = WOLFCLU_SUCCESS;
    unsigned char *pem = NULL;
    int pemSz = 0;

    if (bio == NULL) {
        ret = WOLFCLU_FATAL_ERROR;
    }

    /* get pem size alloc buffer and convert to pem format */
    if (ret == WOLFCLU_SUCCESS) {
        pemSz = wc_DerToPemEx(der, derSz, NULL, 0, NULL, pemType);
        if (pemSz > 0) {
            pem = (unsigned char*)XMALLOC(pemSz, NULL, heapType);
            if (pem == NULL) {
                ret = WOLFCLU_FATAL_ERROR;
            }
            else {
                if (wc_DerToPemEx(der, derSz, pem, pemSz, NULL, pemType)
                        <= 0) {
                    ret = WOLFCLU_FATAL_ERROR;
                }
            }
        }
        else {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        if (wolfSSL_BIO_write(bio, pem, pemSz) != pemSz) {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (pem != NULL) {
        wolfCLU_ForceZero(pem, pemSz);
        XFREE(pem, NULL, heapType);
    }

    return ret;
}


/* return WOLFCLU_SUCCESS on success */
int wolfCLU_printDerPubKey(WOLFSSL_BIO* bio, unsigned char* der, int derSz)
{
    return wolfCLU_printDer(bio, der, derSz, PUBLICKEY_TYPE,
            DYNAMIC_TYPE_PUBLIC_KEY);
}


/* return WOLFCLU_SUCCESS on success */
int wolfCLU_printDerPriKey(WOLFSSL_BIO* bio, unsigned char* der, int derSz,
        int keyType)
{
    return wolfCLU_printDer(bio, der, derSz, keyType,
            DYNAMIC_TYPE_PRIVATE_KEY);
}


/* returns WOLFCLU_SUCCESS on success */
int wolfCLU_printX509PubKey(WOLFSSL_X509* x509, WOLFSSL_BIO* out)
{
    int ret = WOLFCLU_SUCCESS;
    unsigned char *der = NULL;
    int derSz = 0;

    if (x509 == NULL || out == NULL) {
        ret = WOLFCLU_FATAL_ERROR;
    }

    /* get the size of the pubkey der buffer and alloc it */
    if (ret == WOLFCLU_SUCCESS) {
        if (wolfSSL_X509_get_pubkey_buffer(x509, NULL, &derSz)
                == WOLFSSL_SUCCESS) {
            der = (unsigned char*)XMALLOC(derSz, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
            if (der == NULL) {
                ret = WOLFCLU_FATAL_ERROR;
            }
            else {
                if (wolfSSL_X509_get_pubkey_buffer(x509, der, &derSz)
                        != WOLFSSL_SUCCESS) {
                    ret = WOLFCLU_FATAL_ERROR;
                }
            }
        }
        else {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS)
        ret = wolfCLU_printDerPubKey(out, der, derSz);

    if (der != NULL)
        XFREE(der, NULL, DYNAMIC_TYPE_PUBLIC_KEY);

    return ret;
}


/* Print the extended key usages held in 'keyUsage'.
 *
 * 'keyUsage' is the bit map returned by wolfSSL_X509_get_extended_key_usage(),
 * so it must be masked with the XKU_* flags rather than with the
 * ExtKeyUsage_Sum OID values, which are not single bit flags.
 *
 * When 'flag' is set every purpose is listed with a YES/NO verdict, otherwise
 * only the purposes present in the certificate are printed.
 */
int wolfCLU_extKeyUsagePrint(WOLFSSL_BIO* bio, unsigned int keyUsage,
        int indent, int flag)
{
#if LIBWOLFSSL_VERSION_HEX > 0x05001000
    unsigned int i;
    char scratch[MAX_TERM_WIDTH];

    static const struct {
        unsigned int bit;
        const char* name;
    } extKeyUsages[] = {
        { XKU_ANYEKU, "Any Extended Key Usage" },
        { XKU_SSL_SERVER, "TLS Web Server Authentication" },
        { XKU_SSL_CLIENT, "TLS Web Client Authentication" },
        { XKU_CODE_SIGN, "Code Signing" },
        { XKU_OCSP_SIGN, "OCSP Signing" },
        { XKU_SMIME, "Email Protect" },
        { XKU_TIMESTAMP, "Time Stamp Signing" },
    };

    if (bio == NULL) {
        return WOLFCLU_FATAL_ERROR;
    }

    if (flag) {
        XSNPRINTF(scratch, MAX_TERM_WIDTH, "%*s%s\n", indent, "",
                "Certificate Purpose:");
        wolfSSL_BIO_write(bio, scratch, (int)XSTRLEN(scratch));
    }

    for (i = 0; i < (sizeof(extKeyUsages) / sizeof(extKeyUsages[0])); i++) {
        unsigned int ava = (extKeyUsages[i].bit & keyUsage);

        if (ava || flag) {
            XSNPRINTF(scratch, MAX_TERM_WIDTH, "%*s%s%s\n", indent, "",
                    extKeyUsages[i].name,
                    (flag == 1)? (ava > 0) ? " : YES" : " : NO" : "");
            wolfSSL_BIO_write(bio, scratch, (int)XSTRLEN(scratch));
        }
    }

    return WOLFCLU_SUCCESS;
#else
    (void)bio;
    (void)keyUsage;
    (void)indent;
    (void)flag;

    wolfCLU_LogError("Extended key function not supported by this"
                     " version of wolfSSL");
    return NOT_COMPILED_IN;
#endif
}

#endif /* WOLFCLU_NO_FILESYSTEM */
