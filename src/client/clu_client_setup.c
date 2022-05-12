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
    {"connect",             required_argument, 0, WOLFCLU_CONNECT            },
    {"starttls",            required_argument, 0, WOLFCLU_STARTTLS           },
    {"CAfile",              required_argument, 0, WOLFCLU_CAFILE             },
    {"verify_return_error", no_argument,       0, WOLFCLU_VERIFY_RETURN_ERROR},
    {"help",                no_argument,       0, WOLFCLU_HELP               },
    {"h",                   no_argument,       0, WOLFCLU_HELP               },

    {0, 0, 0, 0} /* terminal element */
};


static void wolfCLU_ClientHelp(void)
{
    WOLFCLU_LOG(WOLFCLU_L0, "./wolfssl s_client\n"
            "\t-connect <ip>:<port>");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-starttls <proto, i.e. smtp>");
}

static const char hostFlag[]       = "-h";
static const char portFlag[]       = "-p";
static const char noVerifyFlag[]   = "-d";
static const char caFileFlag[]     = "-A";
static const char noClientCert[]   = "-x";
static const char startTLSFlag[]   = "-M";
static const char disableCRLFlag[] = "-C";

int myoptind = 0;
char* myoptarg = NULL;

#define MAX_CLIENT_ARGS 15

/* return WOLFCLU_SUCCESS on success */
static int _addClientArg(const char** args, const char* in, int* idx)
{
    int ret = WOLFCLU_SUCCESS;

    if (*idx >= MAX_CLIENT_ARGS) {
        WOLFCLU_LOG(WOLFCLU_E0, "Too many client args for array");
        ret = WOLFCLU_FATAL_ERROR;
    }
    else {
        args[*idx] = in;
        *idx = *idx + 1;
    }
    return ret;
}

int wolfCLU_Client(int argc, char** argv)
{
    func_args args;
    int ret     = WOLFCLU_SUCCESS;
    int longIndex = 1;
    int option;
    char* host = NULL;
    int   idx  = 0;
    /* Don't verify peer by default (same as OpenSSL). */
    int   verify = 0;

    int    clientArgc = 0;
    const char* clientArgv[MAX_CLIENT_ARGS];

    /* burn one argv for executable name spot */
    ret = _addClientArg(clientArgv, "wolfclu", &clientArgc);

    opterr = 0; /* do not display unrecognized options */
    optind = 0; /* start at indent 0 */
    while ((option = getopt_long_only(argc, argv, "", client_options,
                    &longIndex )) != -1) {
        switch (option) {
            case WOLFCLU_CONNECT:
                if (XSTRSTR(optarg, ":") == NULL) {
                    WOLFCLU_LOG(WOLFCLU_E0, "connect string does not have ':'");
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
                        ret = _addClientArg(clientArgv, hostFlag, &clientArgc);
                        if (ret == WOLFCLU_SUCCESS) {
                            ret = _addClientArg(clientArgv, host, &clientArgc);
                        }
                    }
                }

                if (ret == WOLFCLU_SUCCESS) {
                    ret = _addClientArg(clientArgv, portFlag, &clientArgc);
                    if (ret == WOLFCLU_SUCCESS) {
                        ret = _addClientArg(clientArgv, optarg + idx + 1,
                                &clientArgc);
                    }
                }
                break;

            case WOLFCLU_STARTTLS:
                if (ret == WOLFCLU_SUCCESS) {
                    ret = _addClientArg(clientArgv, startTLSFlag, &clientArgc);
                    if (ret == WOLFCLU_SUCCESS) {
                        ret = _addClientArg(clientArgv, optarg, &clientArgc);
                    }
                }
                break;

            case WOLFCLU_CAFILE:
                if (ret == WOLFCLU_SUCCESS) {
                    ret = _addClientArg(clientArgv, caFileFlag, &clientArgc);
                    if (ret == WOLFCLU_SUCCESS) {
                        ret = _addClientArg(clientArgv, optarg, &clientArgc);
                    }
                }
                break;

            case WOLFCLU_VERIFY_RETURN_ERROR:
                if (ret == WOLFCLU_SUCCESS) {
                    verify = 1;
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

    if (ret == WOLFCLU_SUCCESS && !verify) {
        ret = _addClientArg(clientArgv, noVerifyFlag, &clientArgc);

        WOLFCLU_LOG(WOLFCLU_L0, "\nWarning: -verify_return_error not specified."
            " Defaulting to NOT verifying peer.");
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = _addClientArg(clientArgv, noClientCert, &clientArgc);
    }

    /* add TLS downgrade support i.e -v d to arguments */
    if (ret == WOLFCLU_SUCCESS) {
        ret = _addClientArg(clientArgv, "-v", &clientArgc);
    }
    if (ret == WOLFCLU_SUCCESS) {
        ret = _addClientArg(clientArgv, "d", &clientArgc);
    }

    /* No CRL support, yet. Disable CRL check. */
    if (ret == WOLFCLU_SUCCESS) {
        ret = _addClientArg(clientArgv, disableCRLFlag, &clientArgc);
    }

    if (ret == WOLFCLU_SUCCESS) {
        args.argv = (char**)clientArgv;
        args.argc = clientArgc;

        client_test(&args);

        if (args.return_code != 0) {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (host != NULL) {
        XFREE(host, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }

    return ret;
}


