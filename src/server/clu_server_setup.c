/* clu_server_setup.c
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
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
#include <wolfclu/server.h>

#ifndef WOLFCLU_NO_FILESYSTEM

static const struct option server_options[] = {
    {"-port",           required_argument, 0, WOLFCLU_PORT                  },
    {"-key" ,           required_argument, 0, WOLFCLU_KEYFILE               },
    {"-cert",           required_argument, 0, WOLFCLU_CERTFILE              },
    {"-noVerify",       no_argument,       0, WOLFCLU_VERIFY                },
    {"-CAfile",         required_argument, 0, WOLFCLU_CA                    },
    {"-version",        required_argument, 0, WOLFCLU_VERSION               },
    {"-naccept",        required_argument, 0, WOLFCLU_ACCEPT                },
    {"-www",            no_argument,       0, WOLFCLU_WWW                   },
    {"-readyFile",      required_argument, 0, WOLFCLU_READY_FILE            },
    {"-help",           no_argument,       0, WOLFCLU_HELP                  },
    {"-h",              no_argument,       0, WOLFCLU_HELP                  },
    {0,0,0,0}
};

static const char portFlag[]        = "-p";
static const char keyFileFlag[]     = "-k";
static const char certFileFlag[]    = "-c";
static const char verifyFlag[]      = "-d";
static const char clientCertFlag[]  = "-A";
static const char versionFlag[]     = "-v";
static const char acceptFlag[]      = "-C";
static const char wwwFlag[]         = "-g";
static const char readyFileFlag[]   = "-R";

static void wolfCLU_ServerHelp(void) 
{
    WOLFCLU_LOG(WOLFCLU_L0, "./wolfssl s_server");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-help");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-port <+int>");
    WOLFCLU_LOG(WOLFCLU_L0, "\t\tPort to listen on.");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-key <private key file name>");
    WOLFCLU_LOG(WOLFCLU_L0, "\t\tonly PEM can be used.");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-cert <cert file name>");
    WOLFCLU_LOG(WOLFCLU_L0, "\t\tonly PEM can be used.");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-noVerify");
    WOLFCLU_LOG(WOLFCLU_L0, "\t\tDisable client cert check.");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-CAfile <CA cert file name>");
    WOLFCLU_LOG(WOLFCLU_L0, "\t\tonly PEM can be used.");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-version <int>");
    WOLFCLU_LOG(WOLFCLU_L0, "\t\tSSL version [0-4], SSLv3(0) - TLS1.3(4))");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-naccept <+int>");
    WOLFCLU_LOG(WOLFCLU_L0, "\t\tNumber of times to accept.(default 1)");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-www");
    WOLFCLU_LOG(WOLFCLU_L0, "\t\tThe response is in HTML format.");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-readyFile <readyFile name>");
}

#define MAX_SERVER_ARGS 15

/* return WOLFSSL_SUCCESS on success */
static int _addServerArg(const char** args, const char* in, int* idx)
{
    int ret = WOLFCLU_SUCCESS;

    if (*idx >= MAX_SERVER_ARGS) {
        wolfCLU_LogError("Too many server args for array");
        ret = WOLFCLU_FATAL_ERROR;
    }
    else {
        args[*idx] = in;
        *idx = *idx + 1;
    }
    return ret;
}

#endif /* !WOLFCLU_NO_FILESYSTEM */

int wolfCLU_Server(int argc, char** argv)
{
    func_args args;
    int ret = WOLFCLU_SUCCESS;
    int longIndex = 1;
    int option;
    
    int serverArgc = 0;
    const char* serverArgv[MAX_SERVER_ARGS];

    tcp_ready ready;
    InitTcpReady(&ready);

    ret = _addServerArg(serverArgv, "wolfclu", &serverArgc);

    opterr = 0;
    optind = 0;

    while ((option = wolfCLU_GetOpt(argc, argv, "", server_options, &longIndex))
                    != -1) {
        switch (option) {
            case WOLFCLU_PORT:
                if (ret == WOLFCLU_SUCCESS) {
                    ret = _addServerArg(serverArgv, portFlag, &serverArgc);
                    if (ret == WOLFCLU_SUCCESS) {
                        ret = _addServerArg(serverArgv, optarg, &serverArgc);
                    }
                }
                break;
            case WOLFCLU_KEYFILE:
                if (ret == WOLFCLU_SUCCESS) {
                    ret = _addServerArg(serverArgv, keyFileFlag, &serverArgc);
                    if (ret == WOLFCLU_SUCCESS) {
                        ret = _addServerArg(serverArgv, optarg, &serverArgc);
                    }
                }
                break;
            case WOLFCLU_CERTFILE:
                if (ret == WOLFCLU_SUCCESS) {
                    ret = _addServerArg(serverArgv, certFileFlag, &serverArgc);
                    if (ret == WOLFCLU_SUCCESS) {
                        ret = _addServerArg(serverArgv, optarg, &serverArgc);
                    }
                }
                break;
            case WOLFCLU_VERIFY:
                if (ret == WOLFCLU_SUCCESS) {
                    ret = _addServerArg(serverArgv, verifyFlag, &serverArgc);
                }
                break;
            case WOLFCLU_CA:
                if (ret == WOLFCLU_SUCCESS) {
                    ret = _addServerArg(serverArgv, clientCertFlag, &serverArgc);
                    if (ret == WOLFCLU_SUCCESS) {
                        ret = _addServerArg(serverArgv, optarg, &serverArgc);
                    }
                }
                break;
            case WOLFCLU_VERSION:
                if (ret == WOLFCLU_SUCCESS) {
                    ret = _addServerArg(serverArgv, versionFlag, &serverArgc);
                    if (ret == WOLFCLU_SUCCESS) {
                        ret = _addServerArg(serverArgv, optarg, &serverArgc);
                    }
                }
                break;
            case WOLFCLU_ACCEPT:
                if (ret == WOLFCLU_SUCCESS) {
                    ret = _addServerArg(serverArgv, acceptFlag, &serverArgc);
                    if (ret == WOLFCLU_SUCCESS) {
                        ret = _addServerArg(serverArgv, optarg, &serverArgc);
                    }
                }
                break;
            case WOLFCLU_WWW:
                if (ret == WOLFCLU_SUCCESS) {
                    ret = _addServerArg(serverArgv, wwwFlag, &serverArgc);
                }
                break;
            case WOLFCLU_READY_FILE:
                if (ret == WOLFCLU_SUCCESS) {
                    ret = _addServerArg(serverArgv, readyFileFlag, &serverArgc);
                    if (ret == WOLFCLU_SUCCESS) {
                        ret = _addServerArg(serverArgv, optarg, &serverArgc);
                    }
                }
                args.signal = &ready;
                break;
            case WOLFCLU_HELP:
                wolfCLU_ServerHelp();
                goto exit;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        args.argv = (char**)serverArgv;
        args.argc = serverArgc;
        server_test(&args);
    }

exit:
    FreeTcpReady(&ready);

    return ret;
}
