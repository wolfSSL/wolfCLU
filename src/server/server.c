#ifndef WOLFCLU_NO_FILESYSTEM
#ifdef HAVE_CONFIG_H
        #include <config.h>
#endif

#ifndef WOLFSSL_USER_SETTINGS
        #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>

#define HAVE_GETADDRINFO 1
#define HAVE_ERRNO_H 1

#include <wolfssl/test.h>
#include <wolfssl/error-ssl.h>
#include <wolfclu/clu_log.h>
#include <wolfclu/server.h>

typedef struct sockaddr_in SOCKADDR_IN4_T;
typedef struct sockaddr_in6 SOCKADDR_IN6_T;

THREAD_RETURN WOLFSSL_THREAD server_test(void* args){
    int     argc = ((func_args*)args)->argc;
    // char**  argv = ((func_args*)args)->argv;
    printf("%d\n",argc);
    printf("this is server_test\n");
    return 0;
}

// #define NO_MAIN_DRIVER
#ifndef NO_MAIN_DRIVER
int main(int argc, char** argv){
    func_args args;
    args.argc = argc;
    args.argv = argv;

    printf("this is server.c\n");
    return 0;
}
#endif /* !NO_MAIN_DRIVER */
#endif /* !WOLFCLU_NO_FILESYSTEM */