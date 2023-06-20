#include <wolfclu/clu_header_main.h>
#include <wolfclu/clu_log.h>
#include <wolfclu/clu_optargs.h>
#include <wolfclu/sign-verify/clu_verify.h>
#include <wolfclu/x509/clu_parse.h>
#include <wolfclu/x509/clu_cert.h>
#include <wolfclu/server.h>

#ifndef WOLFCLU_NO_FILESYSTEM

int wolfCLU_Server(int argc, char** argv){
    func_args args;
    args.argc = argc;
    args.argv = argv;
    printf("this is clu_server_setup.c\n");
    return 0;
}

#endif