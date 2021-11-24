/* clu_client_setup.c
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
#include <wolfclu/clu_optargs.h>
#include <wolfclu/sign-verify/clu_verify.h>
#include <wolfclu/x509/clu_parse.h>
#include <wolfclu/x509/clu_cert.h>
#include <wolfclu/client.h>

static const struct option client_options[] = {
    {"connect",   required_argument, 0, WOLFCLU_CONNECT   },
    {"help",      no_argument,       0, WOLFCLU_HELP      },
    {"h",         no_argument,       0, WOLFCLU_HELP      },

    {0, 0, 0, 0} /* terminal element */
};


static void wolfCLU_ClientHelp(void)
{
    WOLFCLU_LOG(WOLFCLU_L0, "./wolfssl s_client\n"
            "-connect <ip>:<port>");
}

static const char hostFlag[] = "-h";
static const char portFlag[] = "-p";
static const char noVerifyFlag[] = "-d";
static const char noClientCert[] = "-x";

int myoptind = 0;
char* myoptarg = NULL;

#define MAX_CLIENT_ARGS 10

int wolfCLU_Client(int argc, char** argv)
{
    func_args args;
    int ret     = WOLFCLU_SUCCESS;
    int longIndex = 1;
    int option;
    char* host = NULL;
    int   idx  = 0;

    int    clientArgc = 0;
    const char* clientArgv[MAX_CLIENT_ARGS];

    /* burn one argv for executable name spot */
    clientArgv[clientArgc++] = "wolfclu";

    opterr = 0; /* do not display unrecognized options */
    optind = 0; /* start at indent 0 */
    while ((option = getopt_long_only(argc, argv, "", client_options,
                    &longIndex )) != -1) {
        switch (option) {
            case WOLFCLU_CONNECT:
                if (XSTRSTR(optarg, ":") == NULL) {
                    WOLFCLU_LOG(WOLFCLU_L0, "connect string does not have ':'");
                    ret = WOLFCLU_FATAL_ERROR;
                }

                if (ret == WOLFCLU_SUCCESS) {
                    idx = (int)strcspn(optarg, ":");
                    host = (char*)XMALLOC(idx + 1, HEAP_HINT,
                            DYNAMIC_TYPE_TMP_BUFFER);
                    if (host == NULL) {
                        ret = WOLFCLU_FATAL_ERROR;
                    }
                    else {
                        XMEMCPY(host, optarg, idx);
                        host[idx] = '\0';
                        clientArgv[clientArgc++] = hostFlag;
                        clientArgv[clientArgc++] = host;
                    }
                }

                if (ret == WOLFCLU_SUCCESS) {
                    clientArgv[clientArgc++] = portFlag;
                    clientArgv[clientArgc++] = optarg + idx + 1;
                }
                break;

            case WOLFCLU_HELP:
                wolfCLU_ClientHelp();
                return WOLFCLU_SUCCESS;

            case ':':
            case '?':
                break;

            default:
                /* do nothing. */
                (void)ret;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        /* @TODO later check for -CAfile flag and default to verify */
        clientArgv[clientArgc++] = noVerifyFlag;

        clientArgv[clientArgc++] = noClientCert;

        args.argv = (char**)clientArgv;
        args.argc = clientArgc;

        client_test(&args);

        WOLFCLU_LOG(WOLFCLU_L0, "\nWARNING!!! peer was not verified, -CAfile "
                "is upcoming");
    }

    if (host != NULL) {
        XFREE(host, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }

    return ret;
}


