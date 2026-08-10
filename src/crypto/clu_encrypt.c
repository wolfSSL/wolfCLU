/* clu_encrypt.c
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
#include <wolfclu/genkey/clu_genkey.h>

#ifndef WOLFCLU_NO_FILESYSTEM

#define MAX_LEN             1024

/* return WOLFCLU_SUCCESS on success */
int wolfCLU_encrypt(int alg, char* mode, byte* pwdKey, byte* key, int size,
        char* in, char* out, byte* iv, int block, int ivCheck, int inputHex)
{
#ifdef HAVE_CAMELLIA
    Camellia camellia;              /* camellia declaration */
#endif

    XFILE  tempInFile = NULL;       /* if user not provide a file */
    XFILE  inFile = NULL;           /* input file */
    XFILE  outFile = NULL;          /* output file */

    WC_RNG     rng;                 /* random number generator declaration */

    byte*   input = NULL;           /* input buffer */
    byte*   output = NULL;          /* output buffer */
    byte    salt[SALT_SIZE] = {0};  /* salt variable */

    int     ret             = 0;    /* return variable */
    int     inputLength     = 0;    /* length of input */
    int     length          = 0;    /* total length */
    int     padCounter      = 0;    /* number of padded bytes */
    int     i               = 0;    /* loop variable */
    int     hexRet          = 0;    /* hex -> bin return*/

    word32  tempInputL      = 0;    /* temporary input Length */
    word32  tempMax         = MAX_LEN;  /* controls encryption amount */

    char    inputString[MAX_LEN];       /* the input string */
    char*   userInputBuffer = NULL; /* buffer when input is not a file */


    /* wolfCLU_OpenPairedOutFile() below rejects -in == -out before its
     * truncating open, which is what protects the scratch copy the branch
     * below writes to -in when it does not already exist -- see
     * clu_decrypt.c, which relies on the same single check. */

    if (access (in, F_OK) == -1) {
        WOLFCLU_LOG(WOLFCLU_L0, "file did not exist, encrypting string following \"-i\""
                "instead.");

        /* use user entered data to encrypt */
        inputLength = (int) XSTRLEN(in);
        userInputBuffer = (char*) XMALLOC(inputLength, HEAP_HINT,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
        if (userInputBuffer == NULL)
            return MEMORY_E;

        /* writes the entered text to the input buffer */
        XMEMCPY(userInputBuffer, in, inputLength);

        /* open the file to write; use the owner-only, no-follow-symlink
         * secure open rather than wolfCLU_OpenOutFile(), since this scratch
         * copy holds the plaintext the user is about to encrypt. Without
         * this, a dangling symlink at -in would make wolfCLU_OpenOutFile()
         * follow it and write the plaintext to the symlink's target
         * instead of refusing. */
        tempInFile = wolfCLU_OpenKeyFile(in);
        if (tempInFile == NULL) {
            XFREE(userInputBuffer, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            return BAD_FUNC_ARG;
        }
        else {
            XFWRITE(userInputBuffer, 1, inputLength, tempInFile);
            XFCLOSE(tempInFile);
        }

        /* free buffer */
        XFREE(userInputBuffer, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }

    /* open the inFile in read mode */
    inFile = XFOPEN(in, "rb");
    if (inFile == NULL) {
        wolfCLU_LogError("unable to open file %s", in);
        return WOLFCLU_FATAL_ERROR;
    }

    /* find length */
    XFSEEK(inFile, 0, SEEK_END);
    inputLength = (int)XFTELL(inFile);
    XFSEEK(inFile, 0, SEEK_SET);

    length = inputLength;

    /* Start up the random number generator */
    ret = (int) wc_InitRng(&rng);
    if (ret != 0) {
        wolfCLU_LogError("Random Number Generator failed to start.");
        XFCLOSE(inFile);
        return ret;
    }

    /* pads the length until it matches a block,
     * and increases pad number
     */
    while (length % block != 0) {
        length++;
        padCounter++;
    }

    /* if the iv was not explicitly set,
     * generate an iv and use the pwdKey
     */
    if (ivCheck == 0) {
        /* IV not set, generate it */
        ret = wc_RNG_GenerateBlock(&rng, iv, block);

        if (ret != 0) {
            XFCLOSE(inFile);
            wc_FreeRng(&rng);
            return ret;
        }

        /* stretches pwdKey to fit size based on wolfCLU_getAlgo() */
        ret = wolfCLU_genKey_PWDBASED(&rng, pwdKey, size, salt, padCounter);
        if (ret != WOLFCLU_SUCCESS) {
            wolfCLU_LogError("failed to set pwdKey.");
            XFCLOSE(inFile);
            wc_FreeRng(&rng);
            return ret;
        }
        /* move the generated pwdKey to "key" for encrypting */
        for (i = 0; i < size; i++) {
            key[i] = pwdKey[i];
        }
    }

    /* open the outFile in write mode; re-checks -in/-out and proves outFile
     * is not inFile before truncating, so a path swapped in after the
     * check above cannot destroy the plaintext mid-read. */
    outFile = wolfCLU_OpenPairedOutFile(in, out, inFile);
    if (outFile == NULL) {
        XFCLOSE(inFile);
        wc_FreeRng(&rng);
        return WOLFCLU_FATAL_ERROR;
    }
    XFWRITE(salt, 1, SALT_SIZE, outFile);
    XFWRITE(iv, 1, block, outFile);

    /* MALLOC 1kB buffers */
    input = (byte*) XMALLOC(MAX_LEN, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (input == NULL) {
        XFCLOSE(inFile);
        XFCLOSE(outFile);
        wc_FreeRng(&rng);
        return MEMORY_E;
    }
    output = (byte*) XMALLOC(MAX_LEN, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (output == NULL) {
        XFCLOSE(inFile);
        XFCLOSE(outFile);
        wolfCLU_freeBins(input, NULL, NULL, NULL, NULL);
        wc_FreeRng(&rng);
        return MEMORY_E;
    }

    /* loop, encrypt 1kB at a time till length <= 0 */
    while (length > 0) {
        /* Read in 1kB to input[] */
        if (feof(inFile)) {
            ret = 0;
        }
        else {
            if (inputHex == 1)
                ret = (int) fread(inputString, 1, MAX_LEN, inFile);
            else
                ret = (int) fread(input, 1, MAX_LEN, inFile);
        }

        if (ret != MAX_LEN) {
            /* check for end of file */
            if (feof(inFile)) {

                /* hex or ascii */
                if (inputHex == 1) {
                    hexRet = wolfCLU_hexToBin(inputString, &input,
                                                &tempInputL,
                                                NULL, NULL, NULL,
                                                NULL, NULL, NULL,
                                                NULL, NULL, NULL);
                     if (hexRet != WOLFCLU_SUCCESS) {
                        wolfCLU_LogError("failed during conversion of input,"
                            " ret = %d", hexRet);
                        /* wolfCLU_hexToBin() already freed and NULLed its
                         * own allocation, so this is really here to free
                         * 'output' on the way out. */
                        wolfCLU_freeBins(input, output, NULL, NULL, NULL);
                        XFCLOSE(inFile);
                        XFCLOSE(outFile);
                        wc_FreeRng(&rng);
                        return hexRet;
                    }
                }/* end hex or ascii */

                /* pad to end of block */
                for (i = ret ; i < (ret + padCounter); i++) {
                    input[i] = padCounter;
                }
                /* adjust tempMax for less than 1kB encryption */
                tempMax = ret + padCounter;
            }
            else { /* otherwise we got a file read error */
                wolfCLU_freeBins(input, output, NULL, NULL, NULL);
                XFCLOSE(inFile);
                XFCLOSE(outFile);
                wc_FreeRng(&rng);
                return FREAD_ERROR;
            }/* End feof check */
        }/* End fread check */

#ifdef HAVE_CAMELLIA
        if (alg == WOLFCLU_CAMELLIA128CBC || alg == WOLFCLU_CAMELLIA192CBC ||
                alg == WOLFCLU_CAMELLIA256CBC) {
            ret = wc_CamelliaSetKey(&camellia, key, size / 8, iv);
            if (ret != 0) {
                XFCLOSE(inFile);
                XFCLOSE(outFile);
                wolfCLU_LogError("CamelliaSetKey failed.");
                wolfCLU_freeBins(input, output, NULL, NULL, NULL);
                wc_FreeRng(&rng);
                return ret;
            }
            if (XSTRNCMP(mode, "cbc", 3) == 0) {
                wc_CamelliaCbcEncrypt(&camellia, output, input, tempMax);
            }
            else {
                XFCLOSE(inFile);
                XFCLOSE(outFile);
                wolfCLU_LogError("Incompatible mode while using Camellia.");
                wolfCLU_freeBins(input, output, NULL, NULL, NULL);
                wc_FreeRng(&rng);
                return FATAL_ERROR;
            }
        }
#endif /* HAVE_CAMELLIA */

        /* this method added for visual confirmation of nist test vectors,
         * automated tests to come soon
         */

        /* something in the output buffer and using hex */
        if (output != NULL && inputHex == 1) {
            int tempi;

            WOLFCLU_LOG(WOLFCLU_L0, "\nUser specified hex input this is a representation of "
                "what\nis being written to file in hex form.\n\n[ ");
            for (tempi = 0; tempi < block; tempi++ ) {
                WOLFCLU_LOG(WOLFCLU_L0, "%02x", output[tempi]);
            }
            WOLFCLU_LOG(WOLFCLU_L0, " ]\n");
        } /* end visual confirmation */

        /* write this chunk to the already-open outFile */
        ret = (int)XFWRITE(output, 1, tempMax, outFile);

        if (ferror(outFile)) {
            XFCLOSE(outFile);
            XFCLOSE(inFile);
            wolfCLU_LogError("failed to write to file.");
            wolfCLU_freeBins(input, output, NULL, NULL, NULL);
            wc_FreeRng(&rng);
            return FWRITE_ERROR;
        }
        if (ret > MAX_LEN) {
            XFCLOSE(outFile);
            XFCLOSE(inFile);
            wolfCLU_LogError("Wrote too much to file.");
            wolfCLU_freeBins(input, output, NULL, NULL, NULL);
            wc_FreeRng(&rng);
            return FWRITE_ERROR;
        }

        length -= tempMax;
        if (length < 0)
            WOLFCLU_LOG(WOLFCLU_L0, "length went past zero.");
    }

    /* closes the opened files and frees the memory. ret currently holds the
     * byte count from the last XFWRITE() above, not a status code, so the
     * close result is captured separately rather than folded into it. */
    {
        int closeRet = wolfCLU_CloseOutFile(outFile, out);
        if (closeRet != WOLFCLU_SUCCESS) {
            ret = closeRet;
        }
        else {
            ret = WOLFCLU_SUCCESS;
        }
    }
    XFCLOSE(inFile);
    XMEMSET(key, 0, size);
    XMEMSET(iv, 0 , block);

    /* Use the wolfssl free for rng */
    wc_FreeRng(&rng);
    wolfCLU_freeBins(input, output, NULL, NULL, NULL);

    (void)mode;
    (void)alg;
    return (ret == WOLFCLU_SUCCESS) ? WOLFCLU_SUCCESS : WOLFCLU_FATAL_ERROR;
}
#endif
