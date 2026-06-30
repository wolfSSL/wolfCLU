/* clu_bench_setup.c
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

#include "wolfclu/clu_error_codes.h"
#include <wolfclu/clu_header_main.h>
#include <wolfclu/clu_log.h>
#include <wolfclu/clu_optargs.h>

/* Index into the option array passed to wolfCLU_benchmark(). These values are
 * also used as the GetOpt val for each algorithm, so the enumeration MUST stay
 * in sync with the ifdef-guarded test ordering in
 * src/benchmark/clu_benchmark.c. */
enum {
#ifndef NO_AES
    WOLFCLU_BENCH_AESCBC,
#endif
#ifdef WOLFSSL_AES_COUNTER
    WOLFCLU_BENCH_AESCTR,
#endif
#ifndef NO_DES3
    WOLFCLU_BENCH_3DES,
#endif
#ifdef HAVE_CAMELLIA
    WOLFCLU_BENCH_CAMELLIA,
#endif
#ifndef NO_MD5
    WOLFCLU_BENCH_MD5,
#endif
#ifndef NO_SHA
    WOLFCLU_BENCH_SHA,
#endif
#ifndef NO_SHA256
    WOLFCLU_BENCH_SHA256,
#endif
#ifdef WOLFSSL_SHA384
    WOLFCLU_BENCH_SHA384,
#endif
#ifdef WOLFSSL_SHA512
    WOLFCLU_BENCH_SHA512,
#endif
#ifdef HAVE_BLAKE2B
    WOLFCLU_BENCH_BLAKE2B,
#endif
    WOLFCLU_BENCH_COUNT /* number of available tests, also terminal index */
};

static const struct option bench_options[] = {
    {"-time", required_argument, 0, WOLFCLU_TIME},
    {"-all",  no_argument,       0, WOLFCLU_ALL },
    {"-h",    no_argument,       0, WOLFCLU_HELP},
    {"-help", no_argument,       0, WOLFCLU_HELP},

    /* Algorithms */
#ifndef NO_AES
    {"aes-cbc",  no_argument, 0, WOLFCLU_BENCH_AESCBC   },
#endif
#ifdef WOLFSSL_AES_COUNTER
    {"aes-ctr",  no_argument, 0, WOLFCLU_BENCH_AESCTR   },
#endif
#ifndef NO_DES3
    {"3des",     no_argument, 0, WOLFCLU_BENCH_3DES     },
#endif
#ifdef HAVE_CAMELLIA
    {"camellia", no_argument, 0, WOLFCLU_BENCH_CAMELLIA },
#endif
#ifndef NO_MD5
    {"md5",      no_argument, 0, WOLFCLU_BENCH_MD5      },
#endif
#ifndef NO_SHA
    {"sha",      no_argument, 0, WOLFCLU_BENCH_SHA      },
#endif
#ifndef NO_SHA256
    {"sha256",   no_argument, 0, WOLFCLU_BENCH_SHA256   },
#endif
#ifdef WOLFSSL_SHA384
    {"sha384",   no_argument, 0, WOLFCLU_BENCH_SHA384   },
#endif
#ifdef WOLFSSL_SHA512
    {"sha512",   no_argument, 0, WOLFCLU_BENCH_SHA512   },
#endif
#ifdef HAVE_BLAKE2B
    {"blake2b",  no_argument, 0, WOLFCLU_BENCH_BLAKE2B  },
#endif

    {0, 0, 0, 0} /* terminal element */
};

/*
 * benchmark argument function
 * return WOLFCLU_SUCCESS on success
 */
int wolfCLU_benchSetup(int argc, char** argv)
{
    int option;
    int longIndex   =   1;
    int ret         =   WOLFCLU_SUCCESS;

    int time        =   3;      /* timer variable */
    int optionCheck =   0;      /* acceptable option check */

    /* acceptable options, one flag per benchmark test */
    int benchOption[WOLFCLU_BENCH_COUNT] = {0};

    opterr = 0; /* do not display unrecognized options */
    optind = 0; /* start at index 0 */
    while ((option = wolfCLU_GetOpt(argc, argv, "", bench_options,
                    &longIndex)) != END_OF_ARGS) {
        switch (option) {
            case WOLFCLU_HELP:
                wolfCLU_benchHelp();
                return WOLFCLU_SUCCESS;

            case WOLFCLU_TIME:
                /* time for each test in seconds */
                if (optarg != NULL) {
                    time = XATOI(optarg);
                    if (time < 1 || time > 10) {
                        WOLFCLU_LOG(WOLFCLU_L0, "Invalid time, must be between "
                                "1-10. Using default of three seconds.");
                        time = 3;
                    }
                }
                else {
                    ret = WOLFCLU_FATAL_ERROR;
                }
                break;

            case WOLFCLU_ALL:
                /* perform all available tests */
                {
                    int i;
                    for (i = 0; i < WOLFCLU_BENCH_COUNT; i++) {
                        benchOption[i] = 1;
                    }
                    optionCheck = 1;
                }
                break;

            case ARG_FOUND_TWICE:
                wolfCLU_LogError("Found duplicate argument");
                return WOLFCLU_FATAL_ERROR;

            case ':':
            case '?':
                break;

            default:
                /* the remaining option values are benchmark test indices */
                if (option >= 0 && option < WOLFCLU_BENCH_COUNT) {
                    benchOption[option] = 1;
                    optionCheck = 1;
                }
                else {
                    wolfCLU_LogError("Unsupported argument");
                    ret = WOLFCLU_FATAL_ERROR;
                }
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        if (optionCheck != 1) {
            wolfCLU_help();
        }
        else {
            /* benchmarking function */
            WOLFCLU_LOG(WOLFCLU_L0, "\nTesting for %d second(s)", time);
            ret = wolfCLU_benchmark(time, benchOption);
        }
    }

    return ret;
}
