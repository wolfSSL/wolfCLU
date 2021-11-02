/* clu_hash.c
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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

#define MAX_STDINSZ 8192

/*
 * hashing function
 * If bioIn is null then read 8192 max bytes from stdin
 * If bioOut is null then print to stdout
 *
 */
int wolfCLU_hash(WOLFSSL_BIO* bioIn, WOLFSSL_BIO* bioOut, const char* alg,
        int size)
{
#ifdef HAVE_BLAKE2
    Blake2b hash;               /* blake2b declaration */
#endif
    byte*   input;              /* input buffer */
    byte*   output;             /* output buffer */

    int     i  =   0;           /* loop variable */
    int     ret = WOLFCLU_FATAL_ERROR;
    int     inputSz;
    WOLFSSL_BIO* tmp;

    if (bioIn == NULL) {
        inputSz = MAX_STDINSZ;
        tmp = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
        if (tmp != NULL)
            wolfSSL_BIO_set_fp(tmp, stdin, BIO_NOCLOSE);
    }
    else {
        tmp = bioIn;
        inputSz = wolfSSL_BIO_get_len(tmp);
    }

    input = (byte*)XMALLOC(inputSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (input == NULL) {
        if (bioIn == NULL)
            wolfSSL_BIO_free(tmp);
        return MEMORY_E;
    }
    inputSz = wolfSSL_BIO_read(tmp, input, inputSz);
    if (bioIn == NULL)
        wolfSSL_BIO_free(tmp);

    /* if size not provided then use input length to find max possible size */
    if (size == 0) {
    #ifndef NO_CODING
        if (Base64_Encode(input, inputSz, NULL, (word32*)&size) !=
                LENGTH_ONLY_E) {
            wolfCLU_freeBins(input, NULL, NULL, NULL, NULL);
            return BAD_FUNC_ARG;
        }
    #endif
        size = (size < WC_MAX_DIGEST_SIZE) ? WC_MAX_DIGEST_SIZE : size;
    }

    output = XMALLOC(size, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (output == NULL) {
        wolfCLU_freeBins(input, NULL, NULL, NULL, NULL);
        return MEMORY_E;
    }
    XMEMSET(output, 0, size);

    /* hashes using accepted algorithm */
#ifndef NO_MD5
    if (ret == WOLFCLU_FATAL_ERROR && XSTRNCMP(alg, "md5", 3) == 0) {
        ret = wc_Md5Hash(input, inputSz, output);
    }
#endif
#ifndef NO_SHA256
    if (ret == WOLFCLU_FATAL_ERROR && XSTRNCMP(alg, "sha256", 6) == 0) {
        ret = wc_Sha256Hash(input, inputSz, output);
    }
#endif
#ifdef WOLFSSL_SHA384
    if (ret == WOLFCLU_FATAL_ERROR && XSTRNCMP(alg, "sha384", 6) == 0) {
        ret = wc_Sha384Hash(input, inputSz, output);
    }
#endif
#ifdef WOLFSSL_SHA512
    if (ret == WOLFCLU_FATAL_ERROR && XSTRNCMP(alg, "sha512", 6) == 0) {
        ret = wc_Sha512Hash(input, inputSz, output);
    }
#endif
#ifndef NO_SHA
    if (ret == WOLFCLU_FATAL_ERROR && XSTRNCMP(alg, "sha", 3) == 0) {
        ret = wc_ShaHash(input, inputSz, output);
    }
#endif
#ifdef HAVE_BLAKE2
    if (ret == WOLFCLU_FATAL_ERROR && XSTRNCMP(alg, "blake2b", 7) == 0) {
        ret = wc_InitBlake2b(&hash, size);
        if (ret != 0) return ret;
        ret = wc_Blake2bUpdate(&hash, input, inputSz);
        if (ret != 0) return ret;
        ret = wc_Blake2bFinal(&hash, output, size);
        if (ret != 0) return ret;
    }
#endif

#ifndef NO_CODING
#ifdef WOLFSSL_BASE64_ENCODE
    if (ret == WOLFCLU_FATAL_ERROR && XSTRNCMP(alg, "base64enc", 9) == 0) {
        ret = Base64_Encode(input, inputSz, output, (word32*)&size);
    }
#endif /* WOLFSSL_BASE64_ENCODE */
    if (ret == WOLFCLU_FATAL_ERROR && XSTRNCMP(alg, "base64dec", 9) == 0) {
        ret = Base64_Decode(input, inputSz, output, (word32*)&size);
    }
#endif /* !NO_CODING */

    if (ret == 0) {
        if (bioOut != NULL) {
            if (wolfSSL_BIO_write(bioOut, output, size) == size) {
                ret = WOLFCLU_SUCCESS;
            }
            else {
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
        else {
            /* write hashed output to terminal */
            tmp = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
            if (tmp != NULL) {
                wolfSSL_BIO_set_fp(tmp, stdout, BIO_NOCLOSE);

                for (i = 0; i < size; i++)
                    wolfSSL_BIO_printf(tmp, "%02x", output[i]);
                wolfSSL_BIO_printf(tmp, "\n");
                wolfSSL_BIO_free(tmp);
                ret = WOLFCLU_SUCCESS;
            }
            else {
                ret = MEMORY_E;
            }
        }
    }

    /* closes the opened files and frees the memory */
    XMEMSET(input, 0, inputSz);
    XMEMSET(output, 0, size);
    wolfCLU_freeBins(input, output, NULL, NULL, NULL);
    return ret;
}
