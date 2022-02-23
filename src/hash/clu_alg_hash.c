/* clu_alg_hash.c
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
#include <wolfclu/clu_log.h>

#define MAX_BUFSIZE 8192

int wolfCLU_algHashSetup(int argc, char** argv)
{
    WOLFSSL_BIO *bioIn  = NULL;
    WOLFSSL_BIO *bioOut = NULL;
    int     ret         = 0;

const char* algs[]  =   {   /* list of acceptable algorithms */
#ifndef NO_MD5
        "md5",
#endif
#ifndef NO_SHA256
        "sha256",
#endif
#ifdef WOLFSSL_SHA384
        "sha384",
#endif
#ifdef WOLFSSL_SHA512
        "sha512",
#endif
        NULL /* terminal element (also stops the array from being 0-size */
    };
    size_t algsSz = sizeof(algs) / sizeof(algs[0]) - 1; /* -1 to ignore NULL */

    char*   alg;                /* algorithm being used */
    int     size    =   0;      /* message digest size */
    int     i          =   0;   /* loop variable */
    
    for (i = 0; i < (int)algsSz; ++i) {
        /* checks for possible algorithms */
        if (XSTRNCMP(argv[1], algs[i], XSTRLEN(algs[i])) == 0) {
            alg = argv[1];
        }
    }

    /* was a file input provided? if so read from file */
    if (argc >= 3) {
        bioIn = wolfSSL_BIO_new_file(argv[2], "rb");
        if (bioIn == NULL) {
            WOLFCLU_LOG(WOLFCLU_E0, "unable to open file %s", argv[2]);
            return USER_INPUT_ERROR;
        }
    }

    /* sets default size of algorithm */
#ifndef NO_MD5
    if (XSTRNCMP(alg, "md5", 3) == 0)
        size = WC_MD5_DIGEST_SIZE;
#endif

#ifndef NO_SHA256
    if (XSTRNCMP(alg, "sha256", 6) == 0)
        size = WC_SHA256_DIGEST_SIZE;
#endif

#ifdef WOLFSSL_SHA384
    if (XSTRNCMP(alg, "sha384", 6) == 0)
        size = WC_SHA384_DIGEST_SIZE;
#endif

#ifdef WOLFSSL_SHA512
    if (XSTRNCMP(alg, "sha512", 6) == 0)
        size = WC_SHA512_DIGEST_SIZE;
#endif
    
    /* hashing function */
    ret = wolfCLU_hash(bioIn, bioOut, alg, size);
    wolfSSL_BIO_free(bioIn);
    
    return ret;
}

