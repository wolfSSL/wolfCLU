/* clu_hex_to_bin.c
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
#include <stdio.h>

#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <wolfclu/clu_header_main.h>

/* Return 1 if c is an ASCII hex digit, 0 otherwise. Provided as a shared
 * predicate for the per-character hex-class checks in wolfCLU; paths that
 * decode whole strings should still use wolfCLU_hexToBin / Base16_Decode
 * rather than open-coding their own scan. */
int wolfCLU_isHexDigit(byte c)
{
    return (c >= '0' && c <= '9') ||
           (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

/* free up to 5 binary buffers using wolfssl abstraction layer */
void wolfCLU_freeBins(byte* b1, byte* b2, byte* b3, byte* b4, byte* b5)
{
    if (b1 != NULL)
        XFREE(b1, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (b2 != NULL)
        XFREE(b2, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (b3 != NULL)
        XFREE(b3, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (b4 != NULL)
        XFREE(b4, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (b5 != NULL)
        XFREE(b5, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
}


/* convert hex string to binary, store size, WOLFCLU_SUCCESS success
 * (free mem on failure) */
int wolfCLU_hexToBin(const char* h1, byte** b1, word32* b1Sz,
                    const char* h2, byte** b2, word32* b2Sz,
                    const char* h3, byte** b3, word32* b3Sz,
                    const char* h4, byte** b4, word32* b4Sz)
{
    int ret = 0;
    const char* hex[4] = {h1,h2,h3,h4};
    byte** bs[4] = {b1,b2,b3,b4};
    word32* bSz[4] = {b1Sz,b2Sz,b3Sz,b4Sz};
    int i = 0;

    for (; i < 4; i++) {
        if (hex[i] && bs[i] && bSz[i]) {
            *bSz[i] = (int)XSTRLEN(hex[i]) / 2;
            *bs[i] = (byte*)XMALLOC(*bSz[i], NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (*bs[i] == NULL) {
                ret = MEMORY_E;
                break;
            }
            ret = Base16_Decode((const byte*)hex[i], (int)XSTRLEN(hex[i]),
                    *bs[i], bSz[i]);
            if (ret != 0) {
                break;
            }
        }
    }

    if (ret != 0) {
        /* free all allocations made before error */
        for (; i >= 0; i--) {
            if (hex[i] && bs[i] && bSz[i]) {
                if (*bs[i] != NULL) {
                    XFREE(*bs[i], NULL, DYNAMIC_TYPE_TMP_BUFFER);
                    *bs[i] = NULL;
                }
                *bSz[i] = 0;
            }
        }
        return ret;
    }

    return WOLFCLU_SUCCESS;
}
