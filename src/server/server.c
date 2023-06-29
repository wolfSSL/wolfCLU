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

#define SV_MSG_SZ 32


THREAD_RETURN WOLFSSL_THREAD server_test(void* args)
{
    SOCKET_T sockfd = WOLFSSL_SOCKET_INVALID;
    SOCKET_T clientfd = WOLFSSL_SOCKET_INVALID;
    SOCKADDR_IN_T clientAddr;
    socklen_t clientLen;

    wolfSSL_method_func method = NULL;
    WOLFSSL_CTX*    ctx = NULL;
    WOLFSSL*    ssl     = NULL;

    int     argc = ((func_args*)args)->argc;
    char**  argv = ((func_args*)args)->argv;

    word16 port = wolfSSLPort;
    const char* ourKey = NULL;
    const char* ourCert = NULL;
    int useAnyAddr = 0;
    int dtlsUDP = 0;
    int    dtlsSCTP = 0;
    int    doListen = 1;
    
    int ret;

    char msg[SV_MSG_SZ];
    int msgSz = 0;
    int finish = 0;

    int ch;
    
    static const struct mygetopt_long_config long_options[] = {
        {"help", 0, 257},
        {0, 0, 0}
    };

    

    // int     version = SERVER_INVALID_VERSION;
    while ((ch = mygetopt_long(argc, argv, "?:"
            "ab:c:defgh:i;jk:l:mnop:q:rstu;v:wxyz"
            "A:B:CDE:F:GH:IJKL:M:NO:PQRS:TUVW:XYZ:"
            "01:23:4567:89"
            "@#", long_options, 0)) != -1) {
        switch(ch){
            case 'p': /* port */
                port = (word16)atoi(myoptarg);
                break;
            case 'k': /* key file */
                ourKey = myoptarg;
                break;
            case 'c': /* cert file */
                ourCert = myoptarg;
                break;
            default:
                ;
        }
    }

    method = wolfTLSv1_3_server_method_ex;
    
    myoptind = 0;

    if (method != NULL) {
        ctx = wolfSSL_CTX_new(method(NULL));
        if(ctx == NULL)
            err_sys("unable to get ctx");
    }
    if (wolfSSL_CTX_use_PrivateKey_file(ctx, ourKey, 
                    WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        wolfSSL_CTX_free(ctx); ctx = NULL;
        err_sys("can't load server private key file");
    }
    if (wolfSSL_CTX_use_certificate_file(ctx, ourCert, 
                    WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        wolfSSL_CTX_free(ctx); ctx = NULL;
        err_sys("can't load server certificate file");
    }

    while (!finish) {
        ssl = wolfSSL_new(ctx);
        if (ssl == NULL) {
            wolfSSL_CTX_free(ctx); ctx = NULL;
            err_sys("unable to get SSL object");
            break;
        }
        tcp_accept(&sockfd, &clientfd, args, port, useAnyAddr, dtlsUDP, dtlsSCTP, 0, 
            doListen, &clientAddr, &clientLen);
        
        if ((ret = SSL_set_fd(ssl, clientfd)) != WOLFSSL_SUCCESS) {
            err_sys("error in setting fd");
            finish = 1;
            goto sslclose;
        }
        if ((ret = SSL_accept(ssl)) != WOLFSSL_SUCCESS) {
            err_sys("error in SSL accept");
            finish = 1;
            goto sslclose;
        }
        
        memset(msg, 0, SV_MSG_SZ);
        if ((msgSz = wolfSSL_read(ssl, msg, sizeof(msg)-1))==0) {
            err_sys("error in SSL read");
            finish = 1;
            goto sslclose;
        }
        printf("Message : %s\n",msg);
        if (wolfSSL_write(ssl, msg, msgSz) != msgSz) {
            err_sys("error in SSL_write");
            finish = 1;
            goto sslclose;
        }
        if (strcmp(msg,"finish") == 0) {
            finish = 1;
        }
sslclose:
        wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
        close(clientfd);
    }

    close(sockfd);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();

    return 0;
}

// #define NO_MAIN_DRIVER
#ifndef NO_MAIN_DRIVER
int main(int argc, char** argv)
{
    func_args args;
    args.argc = argc;
    args.argv = argv;

    wolfSSL_Init();
    printf("this is server.c\n");
    return 0;
}
#endif /* !NO_MAIN_DRIVER */
#endif /* !WOLFCLU_NO_FILESYSTEM */