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
    // SOCKET_T sockfd = WOLFSSL_SOCKET_INVALID;

    wolfSSL_method_func method = NULL;
    WOLFSSL_CTX*    ctx = NULL;
    WOLFSSL*    ssl     = NULL;

    int     argc = ((func_args*)args)->argc;
    char**  argv = ((func_args*)args)->argv;

    word16 port = wolfSSLPort;

    // const char* ourCert = NULL;
    // const char* ourKey = NULL;

    int ch;
    
    static const struct mygetopt_long_config long_options[] = {
        {"help", 0, 257},
        {0, 0, 0}
    };

    // int     version = SERVER_INVALID_VERSION;
    while((ch = mygetopt_long(argc, argv, "?:"
            "ab:c:defgh:i;jk:l:mnop:q:rstu;v:wxyz"
            "A:B:CDE:F:GH:IJKL:M:NO:PQRS:TUVW:XYZ:"
            "01:23:4567:89"
            "@#", long_options, 0)) != -1){
        switch(ch){
            case 'p':
                port = (word16)atoi(myoptarg);
                break;
            default:
                ;
        }
    }

    method = wolfTLSv1_3_server_method_ex;
    
    myoptind = 0;

    if(method != NULL){
        ctx = wolfSSL_CTX_new(method(NULL));
        if(ctx == NULL)
            err_sys("unable to get ctx");
    }
    if(wolfSSL_CTX_use_PrivateKey_file(ctx, "server-key.pem", WOLFSSL_FILETYPE_PEM)
                                    != WOLFSSL_SUCCESS){
        wolfSSL_CTX_free(ctx); ctx = NULL;
        err_sys("can't load server private key file");
    }
    if(wolfSSL_CTX_use_certificate_file(ctx, "server-cert.pem", WOLFSSL_FILETYPE_PEM)
                                    != WOLFSSL_SUCCESS){
        wolfSSL_CTX_free(ctx); ctx = NULL;
        err_sys("can't load server certificate file");
    }

    ssl = wolfSSL_new(ctx);
    if(ssl == NULL){
        wolfSSL_CTX_free(ctx); ctx = NULL;
        err_sys("unable to get SSL object");
    }

    if(1==0){
        printf("%d\n",argc);
        printf("%d\n",port);
    }

    return 0;
}

// #define NO_MAIN_DRIVER
#ifndef NO_MAIN_DRIVER
int main(int argc, char** argv){
    func_args args;
    args.argc = argc;
    args.argv = argv;

    wolfSSL_Init();
    printf("this is server.c\n");
    return 0;
}
#endif /* !NO_MAIN_DRIVER */
#endif /* !WOLFCLU_NO_FILESYSTEM */