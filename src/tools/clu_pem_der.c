/* clu_pem_der.c
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

/**
 * @brief Load file and convert to DER format
 * @param filename input file path
 * @param der pointer to store DER buffer (caller must XFREE)
 * @param derSz pointer to store DER size
 * @param pemType PEM type (CERT_TYPE, PRIVATEKEY_TYPE, etc.)
 * @return 0 on success, negative on error
 */
static int loadFileToDer(const char* filename, byte** der, word32* derSz, int pemType)
{
    WOLFSSL_BIO* bio = NULL;
    byte* buf = NULL;
    word32 bufSz = 0;
    int isPem = 0;
    int ret;
    DerBuffer* pDer = NULL;

    if (filename == NULL || der == NULL || derSz == NULL)
        return -1;

    bio = wolfSSL_BIO_new_file(filename, "rb");
    if (bio == NULL) {
        wolfCLU_LogError("Unable to open file %s", filename);
        return -1;
    }

    bufSz = wolfSSL_BIO_get_len(bio);
    if (bufSz <= 0) {
        wolfCLU_LogError("Empty or unreadable file %s", filename);
        wolfSSL_BIO_free(bio);
        return -1;
    }

    buf = (byte*)XMALLOC(bufSz + 1, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (buf == NULL) {
        wolfSSL_BIO_free(bio);
        return -1;
    }

    if (wolfSSL_BIO_read(bio, buf, bufSz) != (int)bufSz) {
        wolfCLU_LogError("Failed to read file %s", filename);
        XFREE(buf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        wolfSSL_BIO_free(bio);
        return -1;
    }
    wolfSSL_BIO_free(bio);
    buf[bufSz] = '\0';

    /* Check if PEM format */
    isPem = (XSTRSTR((char*)buf, "-----BEGIN") != NULL) ? 1 : 0;

    if (isPem) {
        ret = wc_PemToDer(buf, bufSz, pemType, &pDer, NULL, NULL, NULL);
        if (ret == 0 && pDer != NULL) {
            *der = (byte*)XMALLOC(pDer->length, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            if (*der != NULL) {
                XMEMCPY(*der, pDer->buffer, pDer->length);
                *derSz = pDer->length;
            }
        }
        wc_FreeDer(&pDer);
        XFREE(buf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        return (*der != NULL) ? 0 : -1;
    }
    else {
        /* Already DER format */
        *der = buf;
        *derSz = bufSz;
        return 0;
    }
}

/**
 * @brief Load certificate file in DER format (handles PEM conversion)
 * @param filename certificate file path
 * @param der pointer to store DER buffer (caller must XFREE)
 * @param derSz pointer to store DER size
 * @return 0 on success, negative on error
 */
int wolfCLU_LoadCertDer(const char* filename, byte** der, word32* derSz)
{
    return loadFileToDer(filename, der, derSz, CERT_TYPE);
}

/**
 * @brief Load private key file in DER format (handles PEM conversion)
 * @param filename key file path
 * @param der pointer to store DER buffer (caller must XFREE)
 * @param derSz pointer to store DER size
 * @return 0 on success, negative on error
 */
int wolfCLU_LoadKeyDer(const char* filename, byte** der, word32* derSz)
{
    return loadFileToDer(filename, der, derSz, PRIVATEKEY_TYPE);
}

/**
 * @brief Load certificate file and return DER size
 * @param filename certificate file path
 * @param outDer pointer to store DER buffer (caller must XFREE)
 * @return DER size on success, negative on error
 */
int wolfCLU_ReadCertDer(const char* filename, byte** outDer)
{
    word32 derSz = 0;
    int ret = wolfCLU_LoadCertDer(filename, outDer, &derSz);
    if (ret != 0) {
        return ret;
    }
    return (int)derSz;
}
