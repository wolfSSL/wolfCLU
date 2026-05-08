/* clu_hash.c
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

#ifndef WOLFCLU_NO_FILESYSTEM

/*
 * hashing function
 * Stream stdin in MAX_IO_CHUNK_SZ blocks. On fallback to base64 enc/dec:
 * If bioIn is null then read 8192 max bytes from stdin. If bioOut is null then
 * print to stdout
 */
int wolfCLU_hash(WOLFSSL_BIO* bioIn, WOLFSSL_BIO* bioOut, const char* alg,
        int size)
{
#ifdef HAVE_BLAKE2
    Blake2b hash;               /* blake2b declaration */
    byte    chunk[MAX_IO_CHUNK_SZ];
#endif
    byte*   input = NULL;
    byte*   output = NULL;
    int     ret = WOLFCLU_SUCCESS;
    int     outSz;
    int     handled = 0;
    enum wc_HashType hashType = WC_HASH_TYPE_NONE;
    WOLFSSL_BIO* tmp;

    if (bioIn == NULL) {
        tmp = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
        if (tmp == NULL) {
            return MEMORY_E;
        }
        wolfSSL_BIO_set_fp(tmp, stdin, BIO_NOCLOSE);
    }
    else {
        tmp = bioIn;
    }

    /* Output buffer size: digest size for hash algorithms (default is
     * WC_MAX_DIGEST_SIZE), or caller-provided size for base64. */
    outSz = (size == 0) ? WC_MAX_DIGEST_SIZE : size;
    output = (byte*)XMALLOC(outSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (output == NULL) {
        if (bioIn == NULL)
            wolfSSL_BIO_free(tmp);
        return MEMORY_E;
    }
    XMEMSET(output, 0, outSz);

    /* Chunked reads fed to Init/Update/Final. No upfront file-size
     * determination, so files larger than UINT32_MAX are handled correctly. */

#ifndef NO_MD5
    if (XSTRCMP(alg, "md5") == 0)
        hashType = WC_HASH_TYPE_MD5;
#endif
#ifndef NO_SHA
    if (XSTRCMP(alg, "sha") == 0)
        hashType = WC_HASH_TYPE_SHA;
#endif
#ifndef NO_SHA256
    if (XSTRCMP(alg, "sha256") == 0)
        hashType = WC_HASH_TYPE_SHA256;
#endif
#ifdef WOLFSSL_SHA384
    if (XSTRCMP(alg, "sha384") == 0)
        hashType = WC_HASH_TYPE_SHA384;
#endif
#ifdef WOLFSSL_SHA512
    if (XSTRCMP(alg, "sha512") == 0)
        hashType = WC_HASH_TYPE_SHA512;
#endif

    if (hashType != WC_HASH_TYPE_NONE) {
        word32 digestSz = (word32)outSz;
        ret = wolfCLU_streamHashBio(tmp, hashType, output, &digestSz);
        if (ret == WOLFCLU_SUCCESS) {
            outSz = (int)digestSz;
        }
        handled = 1;
    }

#ifdef HAVE_BLAKE2
    if (!handled && ret == WOLFCLU_SUCCESS && XSTRCMP(alg, "blake2b") == 0) {
        int bytesRead;
        if (wc_InitBlake2b(&hash, outSz) != 0) {
            wolfCLU_LogError("Unable to initialize blake2b");
            ret = WOLFCLU_FATAL_ERROR;
        }
        while (ret == WOLFCLU_SUCCESS) {
            bytesRead = wolfSSL_BIO_read(tmp, chunk, sizeof(chunk));
            if (bytesRead < 0) {
                wolfCLU_LogError("Error reading data");
                ret = WOLFCLU_FATAL_ERROR;
                break;
            }
            else if (bytesRead == 0) {
                break;
            }
            if (wc_Blake2bUpdate(&hash, chunk, (word32)bytesRead) != 0) {
                wolfCLU_LogError("Blake2b update failed");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
        if (ret == WOLFCLU_SUCCESS) {
            if (wc_Blake2bFinal(&hash, output, outSz) != 0) {
                wolfCLU_LogError("Blake2b finalization failed");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
        handled = 1;
    }
#endif

#ifndef NO_CODING
    /* Buffered fall-back for base64 enc/dec (not a hash, so streaming
     * Init/Update/Final doesn't apply). size is taken from XFTELL
     * but bounded to INT_MAX */
    if (!handled && ret == WOLFCLU_SUCCESS) {
        long fileLen = MAX_STDINSZ;
        int  inputSz = MAX_STDINSZ;
        XFILE f;

        if (bioIn != NULL) {
            if (wolfSSL_BIO_get_fp(tmp, &f) != WOLFSSL_SUCCESS) {
                wolfCLU_LogError("Unable to get raw file pointer");
                ret = WOLFCLU_FATAL_ERROR;
            }
            if (ret == WOLFCLU_SUCCESS && XFSEEK(f, 0, XSEEK_END) != 0) {
                wolfCLU_LogError("Unable to seek end of file");
                ret = WOLFCLU_FATAL_ERROR;
            }
            if (ret == WOLFCLU_SUCCESS) {
                fileLen = XFTELL(f);
                wolfSSL_BIO_reset(tmp);
                if (fileLen < 0 || fileLen > INT_MAX) {
                    wolfCLU_LogError("Input too large for base64 buffer");
                    ret = WOLFCLU_FATAL_ERROR;
                }
                else {
                    inputSz = (int)fileLen;
                }
            }
        }

        if (ret == WOLFCLU_SUCCESS) {
            input = (byte*)XMALLOC(inputSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            if (input == NULL) {
                ret = MEMORY_E;
            }
        }
        if (ret == WOLFCLU_SUCCESS) {
            inputSz = wolfSSL_BIO_read(tmp, input, inputSz);
            if (inputSz < 0) {
                wolfCLU_LogError("Error reading data");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }

#ifdef WOLFSSL_BASE64_ENCODE
        if (ret == WOLFCLU_SUCCESS && XSTRCMP(alg, "base64enc") == 0) {
            if (size == 0) {
                if (Base64_Encode(input, inputSz, NULL, (word32*)&outSz)
                        != LENGTH_ONLY_E) {
                    ret = BAD_FUNC_ARG;
                }
                else {
                    XFREE(output, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
                    output = (byte*)XMALLOC(outSz, HEAP_HINT,
                                            DYNAMIC_TYPE_TMP_BUFFER);
                    if (output == NULL) {
                        ret = MEMORY_E;
                    }
                    else {
                        XMEMSET(output, 0, outSz);
                    }
                }
            }
            if (ret == WOLFCLU_SUCCESS) {
                if (Base64_Encode(input, inputSz, output, (word32*)&outSz)
                        != 0) {
                    wolfCLU_LogError("Base64 encode failed");
                    ret = WOLFCLU_FATAL_ERROR;
                }
                handled = 1;
            }
        }
#endif /* WOLFSSL_BASE64_ENCODE */
        if (ret == WOLFCLU_SUCCESS && XSTRCMP(alg, "base64dec") == 0) {
            if (size == 0) {
                XFREE(output, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
                outSz = inputSz;
                output = (byte*)XMALLOC(outSz, HEAP_HINT,
                                        DYNAMIC_TYPE_TMP_BUFFER);
                if (output == NULL) {
                    ret = MEMORY_E;
                }
                else {
                    XMEMSET(output, 0, outSz);
                }
            }
            if (ret == WOLFCLU_SUCCESS) {
                if (Base64_Decode(input, inputSz, output, (word32*)&outSz)
                        != 0) {
                    wolfCLU_LogError("Base64 decode failed");
                    ret = WOLFCLU_FATAL_ERROR;
                }
                handled = 1;
            }
        }
    }
#endif /* !NO_CODING */

    if (bioIn == NULL) {
        wolfSSL_BIO_free(tmp);
    }

    if (ret == WOLFCLU_SUCCESS && handled) {
        if (bioOut != NULL) {
            if (wolfSSL_BIO_write(bioOut, output, outSz) != outSz) {
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
        else {
            int i;
            /* write hashed output to terminal */
            tmp = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
            if (tmp == NULL) {
                ret = MEMORY_E;
            }
            else {
                wolfSSL_BIO_set_fp(tmp, stdout, BIO_NOCLOSE);
                for (i = 0; i < outSz; i++) {
                    wolfSSL_BIO_printf(tmp, "%02x", output[i]);
                }
                wolfSSL_BIO_printf(tmp, "\n");
                wolfSSL_BIO_free(tmp);
            }
        }
    }
    else if (!handled && ret == WOLFCLU_SUCCESS) {
        wolfCLU_LogError("Unrecognized algorithm: %s", alg);
        ret = WOLFCLU_FATAL_ERROR;
    }

    if (input != NULL) {
        XFREE(input, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (output != NULL) {
        XMEMSET(output, 0, outSz);
        XFREE(output, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }
    return ret;
}

#endif
