/* clu_rand.c
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

/* Windows opens stdout in text mode, expanding every 0x0A byte to 0x0D 0x0A.
 * That corrupts raw binary random output (and adds stray bytes to encoded
 * output), so stdout is switched to binary mode below before writing. */
#if defined(_WIN32)
    #include <io.h>
    #include <fcntl.h>
#endif

/* Fallback for RNG configs that leave RNG_MAX_BLOCK_LEN undefined. If a build's
 * real per-call limit is smaller, wc_RNG_GenerateBlock fails cleanly. */
#ifndef RNG_MAX_BLOCK_LEN
    #define RNG_MAX_BLOCK_LEN (0x10000)
#endif

static const struct option rand_options[] = {
    {"-out",    required_argument, 0, WOLFCLU_OUTFILE},
    {"-base64", no_argument,       0, WOLFCLU_BASE64 },
    {"-hex",    no_argument,       0, WOLFCLU_HEX    },

    {0, 0, 0, 0} /* terminal element */
};

static void wolfCLU_RandHelp(void)
{
    WOLFCLU_LOG(WOLFCLU_L0, "wolfssl rand <num bytes>");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-out the file to output data to (default to stdout)");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-base64 output the results in base64 encoding");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-hex output the results in hex encoding");
}

/* Look up token in rand_options[]. On a match, set *dupOpt if already in seen[],
 * then mark it seen. Returns the table index, or -1 if not a known option.
 * Shared by the skipNext and main scan paths so duplicate detection stays in
 * sync. seen[] must have one slot per rand_options[] entry. */
static int wolfCLU_RandMarkOption(const char* token, int* seen,
        const char** dupOpt)
{
    int j;
    for (j = 0; rand_options[j].name != NULL; j++) {
        if (XSTRCMP(token, rand_options[j].name) == 0) {
            if (seen[j]) {
                *dupOpt = token;
            }
            seen[j] = 1;
            return j;
        }
    }
    return -1;
}


int wolfCLU_Rand(int argc, char** argv)
{
#ifndef WC_NO_RNG
    int ret       = WOLFCLU_SUCCESS;
    int useBase64 = 0;
    int useHex    = 0;
    int outIsStdout = 0;
    int size      = 0;
    int option;
    int longIndex = 1;
    WOLFSSL_BIO *bioOut = NULL;
#ifndef WOLFCLU_NO_FILESYSTEM
    /* deferred: opened only after the count validates */
    char *outFile = NULL;
#endif
    byte *buf = NULL;

    /* Match -h/-help exactly so -h-prefixed flags (e.g. -hex) aren't taken as
     * help. */
    if (XSTRCMP("-h", argv[argc-1]) == 0 ||
            XSTRCMP("-help", argv[argc-1]) == 0) {
        wolfCLU_RandHelp();
        return WOLFCLU_SUCCESS;
    }

    opterr = 0; /* do not display unrecognized options */
    optind = 0; /* start at indent 0 */
    while ((option = wolfCLU_GetOpt(argc, argv, "",
                   rand_options, &longIndex )) != -1) {
        switch (option) {
            case WOLFCLU_BASE64:
                useBase64 = 1;
                break;

            case WOLFCLU_HEX:
                useHex = 1;
                break;

            case WOLFCLU_OUTFILE:
#ifdef WOLFCLU_NO_FILESYSTEM
                WOLFCLU_LOG(WOLFCLU_E0, "No filesystem support. Unable to open output file");
                ret = WOLFCLU_FATAL_ERROR;
#else
                /* optarg is NULL when -out is the final token with no filename.
                 * Reject it: the deferred open would otherwise skip and dump
                 * bytes to stdout instead of erroring. */
                if (optarg == NULL) {
                    wolfCLU_LogError("Missing filename argument for -out");
                    ret = WOLFCLU_FATAL_ERROR;
                }
                else {
                    outFile = optarg; /* defer open until the count validates */
                }
#endif
                break;

            case WOLFCLU_HELP:
                wolfCLU_RandHelp();
                return WOLFCLU_SUCCESS;

            case ':':
            case '?':
                break;

            default:
                /* do nothing. */
                (void)ret;
        }
    }


    /* The byte count is the single positional that is neither an option flag
     * nor the value consumed by -out. A manual rescan is needed because
     * wolfCLU_GetOpt's optind indexes the option table, not argv, so it never
     * surfaces leftover positionals. Resolving it here makes `rand -out 32`
     * treat 32 as the path and `rand -hex 16 -out f` keep 16.
     *
     * The walk mirrors GetOpt's binding: for a required_argument option GetOpt
     * sets optarg = argv[index+1], so this scan skips the next token
     * (skipNext). Only the recovered byte count matters, so the one divergence
     * (a value that is itself an option name is treated here only as the bound
     * value) is benign. Any has_arg arity the scan doesn't model is rejected
     * loudly below, turning a silent desync into a test-visible failure. */
    if (ret == WOLFCLU_SUCCESS) {
        int i;
        int countIdx = -1;
        int skipNext = 0;      /* next token is a value bound to the prior opt */
        const char* extra = NULL;  /* second positional token, if any */
        const char* badOpt = NULL; /* first unrecognized -flag, if any */
        const char* dupOpt = NULL; /* first option repeated, if any */
        /* one slot per rand_options[] entry; marks options already seen */
        int seen[sizeof(rand_options) / sizeof(rand_options[0])];

        XMEMSET(seen, 0, sizeof(seen));

        for (i = 2; i < argc; i++) {  /* skip argv[0]=prog and argv[1]="rand" */
            int j;
            int matched = 0;

            if (argv[i] == NULL) {
                break;
            }

            if (skipNext) {
                skipNext = 0;  /* this token was bound to the preceding option */
                /* A token bound as a value may itself be an option name (e.g.
                 * `rand -out -out 16`). The main scan never runs for a swallowed
                 * token, so check and mark it seen here too. This keeps
                 * duplicate detection symmetric whether or not a flag's first
                 * appearance landed in a value slot. */
                wolfCLU_RandMarkOption(argv[i], seen, &dupOpt);
                if (dupOpt != NULL) {
                    break;
                }
                continue;
            }

            /* -h/-help are handled globally, not listed in rand_options[] */
            if (XSTRCMP(argv[i], "-h") == 0 || XSTRCMP(argv[i], "-help") == 0) {
                continue;
            }

            /* Match against the option table. GetOpt rejects any option that
             * appears more than once, so the value is never bound and, for -out,
             * outFile stays NULL and output falls back to stdout. Catch the
             * repeat here so a duplicate -out errors instead of leaking bytes. */
            j = wolfCLU_RandMarkOption(argv[i], seen, &dupOpt);
            if (j >= 0) {
                matched = 1;
                if (dupOpt != NULL) {
                    break;
                }
                if (rand_options[j].has_arg == required_argument) {
                    /* mirror GetOpt: optarg = argv[index+1] */
                    skipNext = 1;
                }
                else if (rand_options[j].has_arg != no_argument) {
                    /* Arity this scan doesn't model; fail loudly instead of
                     * mis-reading the option's value as the count. */
                    wolfCLU_LogError("internal error: option %s has an "
                            "unsupported argument arity", argv[i]);
                    ret = WOLFCLU_FATAL_ERROR;
                }
            }
            /* Redundant today: the j >= 0 block already breaks on a duplicate.
             * Kept as a safety net so a future edit dropping that break can't
             * let a duplicate fall through to positional handling. */
            if (ret != WOLFCLU_SUCCESS || dupOpt != NULL) {
                break;
            }
            if (matched) {
                continue;
            }

            /* A leftover '-' token is an unknown flag, not a count. With
             * opterr = 0 it would otherwise be miscounted as a positional. */
            if (argv[i][0] == '-') {
                badOpt = argv[i];
                break;
            }

            if (countIdx == -1) {
                countIdx = i;
            }
            else {
                /* a second positional is already an error; stop scanning */
                extra = argv[i];
                break;
            }
        }

        if (ret != WOLFCLU_SUCCESS) {
            /* the arity guard above already logged and failed */
        }
        else if (dupOpt != NULL) {
            /* Log locally rather than rely on GetOpt's own duplicate message,
             * keeping this branch self-contained and consistent with its
             * siblings. A duplicated message is acceptable; a silent non-zero
             * exit is not. Note GetOpt's wolfCLU_checkForArg already printed
             * its own "argument found twice" line during the option pass, so
             * two differently-worded lines appear for one duplicate; that
             * double output is expected, not a bug. */
            wolfCLU_LogError("Option %s specified more than once", dupOpt);
            ret = WOLFCLU_FATAL_ERROR;
        }
        else if (badOpt != NULL) {
            wolfCLU_LogError("Unrecognized option %s", badOpt);
            ret = WOLFCLU_FATAL_ERROR;
        }
        else if (countIdx == -1) {
            wolfCLU_LogError("Missing <num bytes> argument");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else if (extra != NULL) {
            wolfCLU_LogError(
                    "Expected a single <num bytes> argument, got extra "
                    "token %s", extra);
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            size = XATOI(argv[countIdx]);
            if (size <= 0) {
                /* Reached for "0", a non-numeric token (XATOI yields 0), or an
                 * all-digit token that overflows to a non-positive value. A
                 * bare "-5" never lands here: the rescan rejects '-'-prefixed
                 * tokens as unrecognized options first. */
                wolfCLU_LogError(
                        "Expected a positive <num bytes> count, got %s",
                        argv[countIdx]);
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
    }

    if (ret == WOLFCLU_SUCCESS && useBase64 && useHex) {
        wolfCLU_LogError("-base64 and -hex are mutually exclusive");
        ret = WOLFCLU_FATAL_ERROR;
    }

    /* Reject sizes that overflow the hex length (size * 2) before the RNG
     * allocation, so an over-large request doesn't first burn a huge malloc
     * and RNG fill. Raw output is uncapped. */
    if (ret == WOLFCLU_SUCCESS && useHex && size > INT_MAX / 2) {
        wolfCLU_LogError("requested size too large for -hex output");
        ret = WOLFCLU_FATAL_ERROR;
    }

    /* Same concern for base64: its ~4/3 expansion (<2x) is carried back into
     * the signed int `size`, so INT_MAX/2 is a safe cap. */
    if (ret == WOLFCLU_SUCCESS && useBase64 && size > INT_MAX / 2) {
        wolfCLU_LogError("requested size too large for -base64 output");
        ret = WOLFCLU_FATAL_ERROR;
    }

#ifndef WOLFCLU_NO_FILESYSTEM
    /* Open output ("wb") only after the count validates, so a bad/missing
     * count never truncates an existing file. */
    if (ret == WOLFCLU_SUCCESS && outFile != NULL) {
        bioOut = wolfSSL_BIO_new_file(outFile, "wb");
        if (bioOut == NULL) {
            wolfCLU_LogError("Unable to open output file %s", outFile);
            ret = WOLFCLU_FATAL_ERROR;
        }
    }
#endif

    if (ret == WOLFCLU_SUCCESS) {
        buf = (byte*)XMALLOC(size, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (buf == NULL) {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        WC_RNG rng;
        if (wc_InitRng(&rng) != 0) {
            wolfCLU_LogError("Unable to initialize RNG");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            /* wc_RNG_GenerateBlock rejects requests larger than the DRBG
             * per-call max (RNG_MAX_BLOCK_LEN), so fill in chunks. */
            int generated = 0;
            while (ret == WOLFCLU_SUCCESS && generated < size) {
                word32 chunk = (word32)(size - generated);
                if (chunk > RNG_MAX_BLOCK_LEN) {
                    chunk = RNG_MAX_BLOCK_LEN;
                }
                if (wc_RNG_GenerateBlock(&rng, buf + generated, chunk) != 0) {
                    wolfCLU_LogError("Unable to generate RNG block");
                    ret = WOLFCLU_FATAL_ERROR;
                }
                else {
                    generated += (int)chunk;
                }
            }
            wc_FreeRng(&rng);
        }
    }

    /* setup output bio to stdout if not set */
    if (ret == WOLFCLU_SUCCESS && bioOut == NULL) {
        outIsStdout = 1;
#if defined(_WIN32)
        /* Put stdout in binary mode so raw bytes pass through untranslated;
         * otherwise a random 0x0A becomes 0x0D 0x0A and `rand N` emits N+1
         * bytes. */
        (void)_setmode(_fileno(stdout), _O_BINARY);
#endif
        bioOut = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
        if (bioOut == NULL) {
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            if (wolfSSL_BIO_set_fp(bioOut, stdout, BIO_NOCLOSE)
                    != WOLFSSL_SUCCESS) {
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
    }

    /* check and convert to hex (size * 2 was already bounded above) */
    if (ret == WOLFCLU_SUCCESS && useHex) {
        static const char hexChars[] = "0123456789abcdef";
        word32 hexSz = (word32)size * 2;
        byte*  hex = (byte*)XMALLOC(hexSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        int    i;

        if (hex == NULL) {
            wolfCLU_LogError("Error malloc'ing for hex");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            for (i = 0; i < size; i++) {
                hex[2 * i]     = hexChars[(buf[i] >> 4) & 0x0F];
                hex[2 * i + 1] = hexChars[buf[i] & 0x0F];
            }
            wolfCLU_ForceZero(buf, size);
            XFREE(buf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            buf  = hex;
            size = (int)hexSz;
        }
    }

    /* check and convert to base64 */
    if (ret == WOLFCLU_SUCCESS && useBase64) {
        byte *base64 = NULL;
        word32 base64Sz;

        if (Base64_Encode(buf, size, NULL, &base64Sz) != LENGTH_ONLY_E) {
            wolfCLU_LogError("Error getting size for base64");
            ret = WOLFCLU_FATAL_ERROR;
        }

        if (ret == WOLFCLU_SUCCESS) {
            base64 = (byte*)XMALLOC(base64Sz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            if (base64 == NULL) {
                wolfCLU_LogError("Error malloc'ing for base64");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }

        if (ret == WOLFCLU_SUCCESS) {
            if (Base64_Encode(buf, size, base64, &base64Sz) != 0) {
                wolfCLU_LogError("Error base64 encoding");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }

        if (ret == WOLFCLU_SUCCESS) {
            wolfCLU_ForceZero(buf, size);
            XFREE(buf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            buf  = base64;
            size = base64Sz;
        }
        else {
            XFREE(base64, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        }
    }

    /* write out the results */
    if (ret == WOLFCLU_SUCCESS) {
        if (wolfSSL_BIO_write(bioOut, buf, size) != size) {
            wolfCLU_LogError("Error writing out RNG data");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else if (useHex && outIsStdout) {
            /* Trailing newline so the next shell prompt isn't on the same
             * line as the output. */
            (void)wolfSSL_BIO_write(bioOut, "\n", 1);
        }
    }

    if (buf != NULL) {
        wolfCLU_ForceZero(buf, size);
        XFREE(buf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }
    wolfSSL_BIO_free(bioOut);

    return ret;
#else
    wolfCLU_LogError("Recompile wolfSSL with RNG support");
    return WOLFCLU_FATAL_ERROR;
#endif
}
