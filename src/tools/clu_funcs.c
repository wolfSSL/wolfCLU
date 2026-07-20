/* clu_funcs.c
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
#include <wolfclu/clu_error_codes.h>
#include <wolfclu/clu_log.h>
#include <wolfclu/clu_optargs.h>
#include <wolfclu/version.h>
#include <wolfclu/x509/clu_cert.h>        /* for PEM_FORM and DER_FORM */
#include <wolfclu/sign-verify/clu_sign.h> /* for RSA_SIG_VER, ECC_SIG_VER,
                                             ED25519_SIG_VER */
#include <wolfclu/x509/clu_parse.h>
#include <wolfssl/openssl/compat_types.h>
#include <wolfssl/openssl/hmac.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/memory.h>

#define SALT_SIZE       8
#define DES3_BLOCK_SIZE 24

#define MAX_ENTRY_NAME 64

static const struct option crypt_algo_options[] = {
    /* AES */
    {"-aes-128-ctr", no_argument, 0, WOLFCLU_AES128CTR},
    {"-aes-192-ctr", no_argument, 0, WOLFCLU_AES192CTR},
    {"-aes-256-ctr", no_argument, 0, WOLFCLU_AES256CTR},
    {"-aes-128-cbc", no_argument, 0, WOLFCLU_AES128CBC},
    {"-aes-192-cbc", no_argument, 0, WOLFCLU_AES192CBC},
    {"-aes-256-cbc", no_argument, 0, WOLFCLU_AES256CBC},

    /* camellia */
    {"-camellia-128-cbc", no_argument, 0, WOLFCLU_CAMELLIA128CBC},
    {"-camellia-192-cbc", no_argument, 0, WOLFCLU_CAMELLIA192CBC},
    {"-camellia-256-cbc", no_argument, 0, WOLFCLU_CAMELLIA256CBC},

    /* 3des */
    {"-des-cbc", no_argument, 0, WOLFCLU_DESCBC},
    {"-d",       no_argument, 0, WOLFCLU_DECRYPT},

    {0, 0, 0, 0} /* terminal element */
};

/*
 * generic help function
 */
 void wolfCLU_help(void)
 {
#if defined(HAVE_FIPS)
    static const char* isFips = ": using FIPS mode";
#else
    static const char* isFips = "";
#endif

    WOLFCLU_LOG(WOLFCLU_L0, "Linked with wolfSSL version %s%s",
        LIBWOLFSSL_VERSION_STRING, isFips);
    WOLFCLU_LOG(WOLFCLU_L0, " ");
    WOLFCLU_LOG(WOLFCLU_L0, "-help           Help, print out this help menu");
    WOLFCLU_LOG(WOLFCLU_L0, " ");
    WOLFCLU_LOG(WOLFCLU_L0, "Only set one of the following.\n");
    WOLFCLU_LOG(WOLFCLU_L0, "ca             Used for signing certificates");
    WOLFCLU_LOG(WOLFCLU_L0, "crl            Used for parsing CRL files");
    WOLFCLU_LOG(WOLFCLU_L0, "bench          Benchmark one of the algorithms");
    WOLFCLU_LOG(WOLFCLU_L0, "decrypt        Decrypt an encrypted file");
    WOLFCLU_LOG(WOLFCLU_L0, "dgst           Used for verifying a signature");
    WOLFCLU_LOG(WOLFCLU_L0, "dhparam        Used for creating dh params and keys");
    WOLFCLU_LOG(WOLFCLU_L0, "dsaparam       Used for creating dsa params and keys");
    WOLFCLU_LOG(WOLFCLU_L0, "ecc            Ecc signing and signature verification");
    WOLFCLU_LOG(WOLFCLU_L0, "ecparam        Generate an ECC key and parameters");
    WOLFCLU_LOG(WOLFCLU_L0, "ed25519        Ed25519 signing and signature verification");
#ifdef HAVE_DILITHIUM
    WOLFCLU_LOG(WOLFCLU_L0, "ml-dsa         ML-DSA signing and signature verification");
    WOLFCLU_LOG(WOLFCLU_L0, "dilithium      Alias for ml-dsa");
#endif
    WOLFCLU_LOG(WOLFCLU_L0, "enc / encrypt  Encrypt a file or some user input");
    WOLFCLU_LOG(WOLFCLU_L0, "hash           Hash a file or input");
    WOLFCLU_LOG(WOLFCLU_L0, "md5            Creates an MD5 hash");
#if defined(HAVE_OCSP) && defined(HAVE_OCSP_RESPONDER)
    WOLFCLU_LOG(WOLFCLU_L0, "ocsp           OCSP utility (client and responder)");
#endif
    WOLFCLU_LOG(WOLFCLU_L0, "pkey           Used for key operations");
    WOLFCLU_LOG(WOLFCLU_L0, "req            Request for certificate generation");
    WOLFCLU_LOG(WOLFCLU_L0, "-rsa           Legacy RSA signing and signature verification");
    WOLFCLU_LOG(WOLFCLU_L0, "rsa            RSA key operations");
    WOLFCLU_LOG(WOLFCLU_L0, "x509           X509 certificate processing");
    WOLFCLU_LOG(WOLFCLU_L0, "verify         X509 certificate verify");
    WOLFCLU_LOG(WOLFCLU_L0, "pkcs7          Used for parsing PKCS7 files");
    WOLFCLU_LOG(WOLFCLU_L0, "pkcs8          Used for parsing PKCS8 files");
    WOLFCLU_LOG(WOLFCLU_L0, "pkcs12         Used for parsing PKCS12 files");
    WOLFCLU_LOG(WOLFCLU_L0, "s_server       Basic TLS server for testing"
                                           " connection");
    WOLFCLU_LOG(WOLFCLU_L0, "s_client       Basic TLS client for testing"
                                           " connection");
    WOLFCLU_LOG(WOLFCLU_L0, "sha256         Creates a SHA256 hash");
    WOLFCLU_LOG(WOLFCLU_L0, "sha384         Creates a SHA384 hash");
    WOLFCLU_LOG(WOLFCLU_L0, "sha512         Creates a SHA512 hash");
    WOLFCLU_LOG(WOLFCLU_L0, "base64         Base64 encode/decode data");
    WOLFCLU_LOG(WOLFCLU_L0, "rand           Generates random data");
    WOLFCLU_LOG(WOLFCLU_L0, "version        Print wolfCLU/wolfSSL versions");
    WOLFCLU_LOG(WOLFCLU_L0, " ");
    /*optional flags*/
    WOLFCLU_LOG(WOLFCLU_L0, "Optional Flags.\n");
    WOLFCLU_LOG(WOLFCLU_L0, "-in             input file to manage");
    WOLFCLU_LOG(WOLFCLU_L0, "-out            file to output as a result of option");
    WOLFCLU_LOG(WOLFCLU_L0, "-pwd            user custom password");
    WOLFCLU_LOG(WOLFCLU_L0, "-iv             user custom IV (hex input only)");
    WOLFCLU_LOG(WOLFCLU_L0, "-key            user custom key(hex input only)");
    WOLFCLU_LOG(WOLFCLU_L0, "-verify         when using -iv and -key this will print result of"
           "                encryption for user verification."
           "                This flag takes no arguments.");
    WOLFCLU_LOG(WOLFCLU_L0, "-time           used by Benchmark, set time in seconds to run.");
    WOLFCLU_LOG(WOLFCLU_L0, "-verbose        display a more verbose help menu");
    WOLFCLU_LOG(WOLFCLU_L0, "-inform         input format of the certificate file [PEM/DER]");
    WOLFCLU_LOG(WOLFCLU_L0, "-outform        format to output [PEM/DER]");
    WOLFCLU_LOG(WOLFCLU_L0, "-output         used with -genkey option to specify which keys to"
           "                output [PUB/PRIV/KEYPAIR]");

    WOLFCLU_LOG(WOLFCLU_L0, "\nFor encryption: wolfssl -encrypt -help");
    WOLFCLU_LOG(WOLFCLU_L0, "For decryption:   wolfssl -decrypt -help");
    WOLFCLU_LOG(WOLFCLU_L0, "For hashing:      wolfssl -hash -help");
    WOLFCLU_LOG(WOLFCLU_L0, "For benchmarking: wolfssl -bench -help");
    WOLFCLU_LOG(WOLFCLU_L0, "For x509:         wolfssl -x509 -help");
    WOLFCLU_LOG(WOLFCLU_L0, "For key creation: wolfssl -genkey -help");
    WOLFCLU_LOG(WOLFCLU_L0, "For certificate creation: wolfssl -req -help");
    WOLFCLU_LOG(WOLFCLU_L0, "For RSA sign/ver: wolfssl -rsa -help");
    WOLFCLU_LOG(WOLFCLU_L0, "For ECC sign/ver: wolfssl -ecc -help");
    WOLFCLU_LOG(WOLFCLU_L0, "For ED25519 sign/ver: wolfssl -ed25519 -help");
    WOLFCLU_LOG(WOLFCLU_L0, "For XMSS sign/ver: wolfssl -xmss -help");
    WOLFCLU_LOG(WOLFCLU_L0, "For XMSS^MT sign/ver: wolfssl -xmssmt -help");
#ifdef HAVE_DILITHIUM
    WOLFCLU_LOG(WOLFCLU_L0, "For ML-DSA sign/ver: wolfssl -ml-dsa -help (or -dilithium -help)");
#endif
 }

/*
 * verbose help function
 */
void wolfCLU_verboseHelp(void)
{
    int i;

    /* hash options */
    const char* algsenc[] = {        /* list of acceptable algorithms */
    "Algorithms:"
#ifndef NO_MD5
        ,"md5"
#endif
#ifndef NO_SHA
        ,"sha"
#endif
#ifndef NO_SHA256
        ,"sha256"
#endif
#ifdef WOLFSSL_SHA384
        ,"sha384"
#endif
#ifdef WOLFSSL_SHA512
        ,"sha512"
#endif
#ifdef HAVE_BLAKE2B
        ,"blake2b"
#endif
#ifndef NO_CODING
    #ifdef WOLFSSL_BASE64_ENCODE
        ,"base64enc"
    #endif
        ,"base64dec"
#endif
    };

    /* benchmark options */
    const char* algsother[] = {      /* list of acceptable algorithms */
        "ALGS: "
#ifndef NO_AES
        , "aes-cbc"
#endif
#ifdef WOLFSSL_AES_COUNTER
        , "aes-ctr"
#endif
#ifndef NO_DES3
        , "3des"
#endif
#ifdef HAVE_CAMELLIA
        , "camellia"
#endif
#ifndef NO_MD5
        , "md5"
#endif
#ifndef NO_SHA
        , "sha"
#endif
#ifndef NO_SHA256
        , "sha256"
#endif
#ifdef WOLFSSL_SHA384
        , "sha384"
#endif
#ifdef WOLFSSL_SHA512
        , "sha512"
#endif
#ifdef HAVE_BLAKE2B
        , "blake2b"
#endif
    };
    WOLFCLU_LOG(WOLFCLU_L0, "\nwolfssl Command Line Utility version %3.1f\n", VERSION);

    wolfCLU_help();

    WOLFCLU_LOG(WOLFCLU_L0, "Available En/De crypt Algorithms with current configure "
        "settings.\n");
#ifndef NO_AES
    WOLFCLU_LOG(WOLFCLU_L0, "aes-cbc-128\t\taes-cbc-192\t\taes-cbc-256");
#endif
#if defined(WOLFSSL_AES_COUNTER) && \
    LIBWOLFSSL_VERSION_HEX >= 0x05009000
    WOLFCLU_LOG(WOLFCLU_L0, "aes-ctr-128\t\taes-ctr-192\t\taes-ctr-256");
#endif
#ifndef NO_DES3
    WOLFCLU_LOG(WOLFCLU_L0, "3des-cbc-56\t\t3des-cbc-112\t\t3des-cbc-168");
#endif
#ifdef HAVE_CAMELLIA
    WOLFCLU_LOG(WOLFCLU_L0, "camellia-cbc-128\tcamellia-cbc-192\t"
            "camellia-cbc-256");
#endif
    WOLFCLU_LOG(WOLFCLU_L0, " ");
    WOLFCLU_LOG(WOLFCLU_L0, "Available hashing algorithms with current configure settings:\n");

    for (i = 0; i < (int) sizeof(algsenc)/(int) sizeof(algsenc[0]); i++) {
            WOLFCLU_LOG(WOLFCLU_L0, "%s", algsenc[i]);
    }
    WOLFCLU_LOG(WOLFCLU_L0, "Available benchmark tests with current configure settings:");
    WOLFCLU_LOG(WOLFCLU_L0, "(-a to test all)\n");

    for(i = 0; i < (int) sizeof(algsother)/(int) sizeof(algsother[0]); i++) {
        WOLFCLU_LOG(WOLFCLU_L0, "%s", algsother[i]);
    }
}

/* return block size on success
 * alg and mode are null terminated strings that need free'd by the caller
 */
static int wolfCLU_parseAlgo(char* name, int* alg, char** mode, int* size)
{
    int     ret         = 0;        /* return variable */
    int     nameCheck   = 0;        /* check for acceptable name */
    int     modeCheck   = 0;        /* check for acceptable mode */
    int     i;
    char*   sz          = 0;        /* key size provided */
    char*   end         = 0;
    char*   tmpAlg      = NULL;
    char*   tmpMode     = NULL;

    const char* acceptAlgs[]  = {   /* list of acceptable algorithms */
        "Algorithms: "
#ifndef NO_AES
        , "aes"
#endif
#ifndef NO_DES3
        , "3des"
#endif
#ifdef HAVE_CAMELLIA
        , "camellia"
#endif
    };

    const char* acceptMode[] = {"cbc"
#ifdef WOLFSSL_AES_COUNTER
        , "ctr"
#endif
    };

    if (name == NULL || alg == NULL || mode == NULL || size == NULL) {
        wolfCLU_LogError("null input to get algo function");
        return WOLFCLU_FATAL_ERROR;
    }

    /* gets name after first '-' and before the second */
    tmpAlg = strtok_r(name, "-", &end);
    if (tmpAlg == NULL) {
        return WOLFCLU_FATAL_ERROR;
    }


    for (i = 0; i < (int)(sizeof(acceptAlgs)/sizeof(acceptAlgs[0])); i++) {
        if (XSTRNCMP(tmpAlg, acceptAlgs[i], XSTRLEN(tmpAlg)) == 0 )
            nameCheck = 1;
    }

    /* gets mode and size after the algorithm name, supports both
     * "alg-size-mode" (aes-256-cbc) and "alg-mode-size" (aes-cbc-256) */
    if (nameCheck != 0) {
        sz = strtok_r(NULL, "-", &end);
        if (sz == NULL) {
            return WOLFCLU_FATAL_ERROR;
        }
        tmpMode = strtok_r(NULL, "-", &end);
        if (tmpMode == NULL) {
            return WOLFCLU_FATAL_ERROR;
        }

        /* if second token isn't numeric, it's the mode (alg-mode-size) */
        if (sz[0] < '0' || sz[0] > '9') {
            char* tmp = sz;
            sz = tmpMode;
            tmpMode = tmp;
        }
        *size = XATOI(sz);
    }
    else {
        tmpMode = strtok_r(NULL, "-", &end);
        if (tmpMode == NULL) {
            return WOLFCLU_FATAL_ERROR;
        }
    }

    for (i = 0; i < (int) (sizeof(acceptMode)/sizeof(acceptMode[0])); i++) {
        if (XSTRNCMP(tmpMode, acceptMode[i], XSTRLEN(tmpMode)) == 0)
            modeCheck = 1;
    }

    /* if name or mode doesn't match acceptable options */
    if (nameCheck == 0 || modeCheck == 0) {
        wolfCLU_LogError("Invalid entry, issue with algo name and mode");
        return WOLFCLU_FATAL_ERROR;
    }

    /* checks key sizes for acceptability */
    if (XSTRNCMP(tmpAlg, "aes", 3) == 0) {
    #ifdef NO_AES
        wolfCLU_LogError("AES not compiled in.");
        return NOT_COMPILED_IN;
    #else
        ret = AES_BLOCK_SIZE;
        if (*size != 128 && *size != 192 && *size != 256) {
            wolfCLU_LogError("Invalid AES pwdKey size. Should be: %d", ret);
            ret = WOLFCLU_FATAL_ERROR;
        }

        if (XSTRNCMP(tmpMode, "cbc", 3) == 0) {
            switch (*size) {
                case 128:
                    *alg = WOLFCLU_AES128CBC;
                    break;
                case 192:
                    *alg = WOLFCLU_AES192CBC;
                    break;
                case 256:
                    *alg = WOLFCLU_AES256CBC;
                    break;
            }
        }

        if (XSTRNCMP(tmpMode, "ctr", 3) == 0) {
            switch (*size) {
                case 128:
                    *alg = WOLFCLU_AES128CTR;
                    break;
                case 192:
                    *alg = WOLFCLU_AES192CTR;
                    break;
                case 256:
                    *alg = WOLFCLU_AES256CTR;
                    break;
            }
        }
    #endif
    }

    else if (XSTRNCMP(tmpAlg, "3des", 4) == 0) {
    #ifdef NO_DES3
        wolfCLU_LogError("3DES not compiled in.");
        return NOT_COMPILED_IN;
    #else
        ret = DES3_BLOCK_SIZE;
        if (*size != 56 && *size != 112 && *size != 168) {
            wolfCLU_LogError("Invalid 3DES pwdKey size");
            ret = WOLFCLU_FATAL_ERROR;
        }
        *alg = WOLFCLU_DESCBC;
    #endif
    }

    else if (XSTRNCMP(tmpAlg, "camellia", 8) == 0) {
    #ifndef HAVE_CAMELLIA
        wolfCLU_LogError("CAMELIA not compiled in.");
        return NOT_COMPILED_IN;
    #else
        ret = CAMELLIA_BLOCK_SIZE;
        if (*size != 128 && *size != 192 && *size != 256) {
            wolfCLU_LogError("Invalid Camellia pwdKey size");
            ret = WOLFCLU_FATAL_ERROR;
        }

        if (XSTRNCMP(tmpMode, "cbc", 3) == 0) {
            switch (*size) {
                case 128:
                    *alg = WOLFCLU_CAMELLIA128CBC;
                    break;
                case 192:
                    *alg = WOLFCLU_CAMELLIA192CBC;
                    break;
                case 256:
                    *alg = WOLFCLU_CAMELLIA256CBC;
                    break;
            }
        }
    #endif
    }

    else {
        wolfCLU_LogError("Invalid algorithm: %s", tmpAlg);
        ret = WOLFCLU_FATAL_ERROR;
    }

    if (ret >= 0) {
        int s;

        /* free any existing mode buffers */
        if (*mode != NULL)
            XFREE(*mode, NULL, DYNAMIC_TYPE_TMP_BUFFER);

        if (ret >= 0) {
            s = (int)XSTRLEN(tmpMode) + 1;
            *mode = (char*)XMALLOC(s, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (*mode == NULL) {
                ret = MEMORY_E;
            }
        }

        if (ret >= 0) {
            XSTRNCPY(*mode, tmpMode, s);
        }
    }

    /* free up stuff in case of error */
    if (ret < 0) {
        if (*mode != NULL)
            XFREE(*mode, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        *mode = NULL;
    }

    return ret;
}

static const char WOLFCLU_AES128CTR_NAME[] = "-aes-128-ctr";
static const char WOLFCLU_AES192CTR_NAME[] = "-aes-192-ctr";
static const char WOLFCLU_AES256CTR_NAME[] = "-aes-256-ctr";
static const char WOLFCLU_AES128CBC_NAME[] = "-aes-128-cbc";
static const char WOLFCLU_AES192CBC_NAME[] = "-aes-192-cbc";
static const char WOLFCLU_AES256CBC_NAME[] = "-aes-256-cbc";
static const char WOLFCLU_CAMELLIA128CBC_NAME[] = "-camellia-128-cbc";
static const char WOLFCLU_CAMELLIA192CBC_NAME[] = "-camellia-192-cbc";
static const char WOLFCLU_CAMELLIA256CBC_NAME[] = "-camellia-256-cbc";
static const char WOLFCLU_DESCBC_NAME[] = "-des-cbc";

static const char* algoName[] = {
    WOLFCLU_AES128CTR_NAME,
    WOLFCLU_AES192CTR_NAME,
    WOLFCLU_AES256CTR_NAME,
    WOLFCLU_AES128CBC_NAME,
    WOLFCLU_AES192CBC_NAME,
    WOLFCLU_AES256CBC_NAME,
    WOLFCLU_CAMELLIA128CBC_NAME,
    WOLFCLU_CAMELLIA192CBC_NAME,
    WOLFCLU_CAMELLIA256CBC_NAME,
    WOLFCLU_DESCBC_NAME,
};

/* support older name schemes MAX_AES_IDX is the maximum index for old AES algo
 * names */
#define MAX_AES_IDX 6
static const char* oldAlgoName[] = {
    "-aes-ctr-128",
    "-aes-ctr-192",
    "-aes-ctr-256",
    "-aes-cbc-128",
    "-aes-cbc-192",
    "-aes-cbc-256",
};


/* convert an old algo name into one optargs can handle */
static void wolfCLU_oldAlgo(int argc, char** argv)
{
    int i, j;

    for (i = 0; i < argc; i++) {
        for (j = 0; j < MAX_AES_IDX; j++) {
            if (XSTRCMP(argv[i], oldAlgoName[j]) == 0) {
                argv[i] = (char*)algoName[j];
            }
        }
    }
}


/* get the WOLFSSL_EVP_CIPHER type from an algo enum value */
const WOLFSSL_EVP_CIPHER* wolfCLU_CipherTypeFromAlgo(int alg)
{
    switch (alg) {
        case WOLFCLU_AES128CTR:
            return wolfSSL_EVP_aes_128_ctr();
        case WOLFCLU_AES192CTR:
            return wolfSSL_EVP_aes_192_ctr();
        case WOLFCLU_AES256CTR:
            return wolfSSL_EVP_aes_256_ctr();
        case WOLFCLU_AES128CBC:
            return wolfSSL_EVP_aes_128_cbc();
        case WOLFCLU_AES192CBC:
            return wolfSSL_EVP_aes_192_cbc();
        case WOLFCLU_AES256CBC:
            return wolfSSL_EVP_aes_256_cbc();
#ifndef NO_DES3
        case WOLFCLU_DESCBC:
            return wolfSSL_EVP_des_cbc();
#endif
        default:
            return NULL;
    }
}


/*
 * finds algorithm for encryption/decryption
 * mode is a null terminated strings that need free'd by the caller
 */
int wolfCLU_getAlgo(int argc, char** argv, int* alg, char** mode, int* size)
{
    int ret = 0;
    int longIndex = 2;
    int option;
    char name[80];

    wolfCLU_oldAlgo(argc, argv);
    XMEMSET(name, 0, sizeof(name));
    if (XSTRLEN(argv[2]) >= sizeof(name)) {
        wolfCLU_LogError("ERROR: algorithm name too long (max %d)",
                         (int)sizeof(name) - 1);
        return USER_INPUT_ERROR;
    }
    XSTRLCPY(name, argv[2], sizeof(name));
    ret = wolfCLU_parseAlgo(name, alg, mode, size);

    /* next check for -cipher option passed through args */
    if (ret < 0) {
        optind = 0;
        opterr = 0; /* do not print out unknown options */
        while ((option = wolfCLU_GetOpt(argc, argv, "",
                       crypt_algo_options, &longIndex )) != END_OF_ARGS) {
            switch (option) {
                case ARG_FOUND_TWICE:
                    wolfCLU_LogError("Found duplicate argument");
                    return WOLFCLU_FATAL_ERROR;

                /* AES */
                case WOLFCLU_AES128CTR:
                    XSTRNCPY(name, WOLFCLU_AES128CTR_NAME,
                            sizeof(name));
                    break;

                case WOLFCLU_AES192CTR:
                    XSTRNCPY(name, WOLFCLU_AES192CTR_NAME,
                            sizeof(name));
                    break;

                case WOLFCLU_AES256CTR:
                    XSTRNCPY(name, WOLFCLU_AES256CTR_NAME,
                            sizeof(name));
                    break;

                case WOLFCLU_AES128CBC:
                    XSTRNCPY(name, WOLFCLU_AES128CBC_NAME,
                            sizeof(name));
                    break;

                case WOLFCLU_AES192CBC:
                    XSTRNCPY(name, WOLFCLU_AES192CBC_NAME,
                            sizeof(name));
                    break;

                case WOLFCLU_AES256CBC:
                    XSTRNCPY(name, WOLFCLU_AES256CBC_NAME,
                            sizeof(name));
                    break;

                /* camellia */
                case WOLFCLU_CAMELLIA128CBC:
                    XSTRNCPY(name, WOLFCLU_CAMELLIA128CBC_NAME,
                            sizeof(name));
                    break;

                case WOLFCLU_CAMELLIA192CBC:
                    XSTRNCPY(name, WOLFCLU_CAMELLIA192CBC_NAME,
                            sizeof(name));
                    break;

                case WOLFCLU_CAMELLIA256CBC:
                    XSTRNCPY(name, WOLFCLU_CAMELLIA256CBC_NAME,
                            sizeof(name));
                    break;

                /* 3des */
                case WOLFCLU_DESCBC:
                    XSTRNCPY(name, WOLFCLU_DESCBC_NAME,
                            sizeof(name));
                    break;

                case '?':
                case ':':
                    break;
                default:
                    /* do nothing. */
                    (void)ret;
            };

            if (XSTRLEN(name) > 0) {
                ret = wolfCLU_parseAlgo(name, alg, mode, size);
                XMEMSET(name, 0, sizeof(name));
            }
        }
    }

    return ret;
}

/*
 * gets current time during program execution
 */
double wolfCLU_getTime(void)
{
#ifdef HAL_RTC_MODULE_ENABLED /* get time on HAL HW */
    extern RTC_HandleTypeDef hrtc;

    RTC_TimeTypeDef time;
    RTC_DateTypeDef date;
    uint32_t subsec = 0;

    /*get time and date here due to STM32 HW bug */
    HAL_RTC_GetTime(&hrtc, &time, FORMAT_BIN);
    HAL_RTC_GetDate(&hrtc, &date, FORMAT_BIN);
    (void) date;

    return ((double) time.Hours * 24) + ((double) time.Minutes * 60)
                    + (double) time.Seconds + ((double) subsec / 1000);

#elif !defined(USE_WINDOWS_API) && !defined(MICROCHIP_PIC32) /* get time on WIN */
    struct timeval tv;

    gettimeofday(&tv, 0);

    return (double)tv.tv_sec + (double)tv.tv_usec / 1000000;

#else /* get time on unix */
    struct _timeb mytime1;

    _ftime64_s(&mytime1);
    return mytime1.time + mytime1.millitm / 1000;
#endif
}

/*
 * prints out stats for benchmarking
 */
void wolfCLU_stats(double start, int blockSize, int64_t blocks)
{
    double bytes;
    double time_total = wolfCLU_getTime() - start;

#if (BYTE_UNIT==KILOBYTE)
    char unit[]="KB";
#else
    char unit[]="MB";
#endif
    WOLFCLU_LOG(WOLFCLU_L0, "took %6.3f seconds, blocks = %llu", time_total,
            (unsigned long long)blocks);

    bytes = ((blocks * blockSize) / MEGABYTE) / time_total;
    WOLFCLU_LOG(WOLFCLU_L0, "Average %s/s = %8.1f", unit, bytes);
    if (blockSize != MEGABYTE) {
        WOLFCLU_LOG(WOLFCLU_L0, "Block size of this algorithm is: %d.\n", blockSize);
    }
    else {
        WOLFCLU_LOG(WOLFCLU_L0, "Benchmarked using 1 %s at a time\n", unit);
    }
}


/* returns WOLFCLU_SUCCESS on success */
int wolfCLU_version(void)
{
#ifdef HAVE_FIPS
    const char *isFIPS = " FIPS";
#else
    const char *isFIPS = "";
#endif

    WOLFCLU_LOG(WOLFCLU_L0, "You are using version %s of the wolfssl Command Line Utility."
        , CLUWOLFSSL_VERSION_STRING);
    WOLFCLU_LOG(WOLFCLU_L0, "Linked to wolfSSL version %s%s",
        LIBWOLFSSL_VERSION_STRING, isFIPS);
#ifdef HAVE_FIPS
    WOLFCLU_LOG(WOLFCLU_L0, "In FIPS builds there are algorithm restrictions "
        "such as use of DES");
#endif
    return WOLFCLU_SUCCESS;
}

/* parse digits-only string into [minVal, maxVal] without overflow; rejects
 * sign, whitespace, empty and trailing text. only non-negative digit strings
 * are accepted, so the parsed value is always >= 0 and a negative minVal can
 * never reject a valid input. returns WOLFCLU_SUCCESS (sets *out) or
 * WOLFCLU_FATAL_ERROR. */
int wolfCLU_parseDecimalBounded(const char* str, long minVal, long maxVal,
                                long* out)
{
    const char* p;
    long val = 0;
    int over = 0;

    if (str == NULL || out == NULL) {
        return WOLFCLU_FATAL_ERROR;
    }

    /* check the bound before multiplying so val never overflows; once over,
     * stop accumulating but keep scanning to reject non-digits */
    for (p = str; *p != '\0'; p++) {
        int digit;
        if (*p < '0' || *p > '9') {
            return WOLFCLU_FATAL_ERROR;
        }
        digit = *p - '0';
        if (!over) {
            if (maxVal < digit || val > (maxVal - digit) / 10) {
                over = 1;
            }
            else {
                val = (val * 10) + digit;
            }
        }
    }

    if (over || p == str || val < minVal || val > maxVal) {
        return WOLFCLU_FATAL_ERROR;
    }

    *out = val;
    return WOLFCLU_SUCCESS;
}

/* return 0 for not found and index found at otherwise */
int wolfCLU_checkForArg(const char* searchTerm, int length, int argc,
        char** argv)
{
    int i;
    int ret = 0;
    int argFound = 0;
    if (searchTerm == NULL) {
        return 0;
    }

    for (i = 0; i < argc; i++) {
        if (argv[i] == NULL) {
            break; /* stop checking if no more args*/
        }

        if (XSTRNCMP(searchTerm, "-help", length) == 0 &&
                   XSTRNCMP(argv[i], "-help", XSTRLEN(argv[i])) == 0 &&
                   (int)XSTRLEN(argv[i]) > 0) {
           return 1;

        }
        else if ((int)XSTRLEN(argv[i]) == length &&
                   XMEMCMP(argv[i], searchTerm, length) == 0) {
            ret = i;
            if (argFound == 1) {
                wolfCLU_LogError("ERROR: argument found twice: \"%s\"", searchTerm);
                return USER_INPUT_ERROR;
            }
            argFound = 1;
        }
    }

    return ret;
}

int wolfCLU_checkOutform(char* outform)
{
    if (outform == NULL) {
        WOLFCLU_LOG(WOLFCLU_L0, "Usage: -outform [PEM/DER/RAW]");
        WOLFCLU_LOG(WOLFCLU_L0, "missing outform required argument");
        return USER_INPUT_ERROR;
    }

    wolfCLU_convertToLower(outform, (int)XSTRLEN(outform));
    if (XSTRNCMP(outform, "pem", 3) == 0) {
        return PEM_FORM;
    }
    else if (XSTRNCMP(outform, "der", 3) == 0) {
        return DER_FORM;
    }
    else if (XSTRNCMP(outform, "raw", 3) == 0) {
        return RAW_FORM;
    }
    else {
        WOLFCLU_LOG(WOLFCLU_L0, "Usage: -outform [PEM/DER/RAW]");
        WOLFCLU_LOG(WOLFCLU_L0, "\"%s\" is not a valid output format", outform);
    }
    return USER_INPUT_ERROR;
}

int wolfCLU_checkInform(char* inform)
{
    if (inform == NULL) {
        WOLFCLU_LOG(WOLFCLU_L0, "Usage: -inform [PEM/DER/RAW]");
        WOLFCLU_LOG(WOLFCLU_L0, "missing inform required argument");
        return USER_INPUT_ERROR;
    }

    wolfCLU_convertToLower(inform, (int)XSTRLEN(inform));
    if (XSTRNCMP(inform, "pem", 3) == 0) {
        return PEM_FORM;
    }
    else if (XSTRNCMP(inform, "der", 3) == 0) {
        return DER_FORM;
    }
    else if (XSTRNCMP(inform, "raw", 3) == 0) {
        return RAW_FORM;
    }
    else {
        WOLFCLU_LOG(WOLFCLU_L0, "Usage: -inform [PEM/DER/RAW]");
        WOLFCLU_LOG(WOLFCLU_L0, "\"%s\" is not a valid input format", inform);
    }
    return USER_INPUT_ERROR;
}


void wolfCLU_AddNameEntry(WOLFSSL_X509_NAME* name, int type, int nid, char* str)
{
    int i, sz;
    WOLFSSL_X509_NAME_ENTRY *entry;

    if (str != NULL) {
        /* strip off newline/carriage-return characters at the end of str */
        i = (int)XSTRLEN((const char*)str) - 1;
        while (i >= 0) {
            if (str[i] == '\n' || str[i] == '\r') {
                str[i] = '\0';
                i--;
            }
            else {
                break;
            }
        }

        /* treats a '.' string as 'do not add' */
        sz = (int)XSTRLEN((const char*)str);
        if (sz > 0 && XSTRCMP(str, ".") != 0) {
            entry = wolfSSL_X509_NAME_ENTRY_create_by_NID(NULL, nid,
                type, (const unsigned char*)str, sz);
            wolfSSL_X509_NAME_add_entry(name, entry, -1, 0);
            wolfSSL_X509_NAME_ENTRY_free(entry);
        }
    }
}


/* Input 'n' is a null-terminated string in the form of '/CN=name/C=company'
 * returns a newly created WOLFSSL_X509_NAME on success */
WOLFSSL_X509_NAME* wolfCLU_ParseX509NameString(const char* n, int nSz)
{
    int encoding = CTC_UTF8;
    int tagSz = 0;
    int nid;
    char* word, *end;
    char* deli = (char*)"/";
    char* entry = NULL;
    WOLFSSL_X509_NAME* ret = NULL;
    char  tag[5];

    if (n == NULL || nSz <= 0) {
        wolfCLU_LogError("unexpected null argument or size with parsing "
                "name");
        return NULL;
    }

    ret = wolfSSL_X509_NAME_new();
    if (ret == NULL) {
        wolfCLU_LogError("error allocating name structure");
        return NULL;
    }
    for (word = strtok_r((char*)n, deli, &end); word != NULL;
            word = strtok_r(NULL, deli, &end)) {
        tagSz = (int)strcspn(word, "=");
        if (tagSz <= 0 || word[tagSz] != '=') {
            wolfCLU_LogError("error finding '=' char in name");
            wolfSSL_X509_NAME_free(ret);
            ret = NULL;
            break;
        }

        if (tagSz + 1 > (int)sizeof(tag)) { /* +1 for null terminator */
            wolfCLU_LogError("found a tag that was too large!");
            wolfSSL_X509_NAME_free(ret);
            ret = NULL;
            break;
        }
        else if (tagSz + 1 > nSz) {
            wolfCLU_LogError("error, entry would be past buffer end");
            wolfSSL_X509_NAME_free(ret);
            ret = NULL;
            break;
        }
        else {
            XMEMCPY(tag, word, tagSz);
            tag[tagSz] = '\0'; /* append terminating character */
        }

        if (ret != NULL) {
            entry = &word[tagSz+1];
            nid = wolfSSL_OBJ_sn2nid(tag);
            if (nid == 0) { /* try using old tag value */
                char oldTag[8];
                tagSz = (int)XSTRLEN(tag);
                if (tagSz + 3 <= (int)sizeof(oldTag)) {
                    XSNPRINTF(oldTag, sizeof(oldTag)-1, "/%s=", tag);
                    nid = wolfSSL_OBJ_sn2nid(oldTag);
                }
            }
            if (nid == NID_countryName) {
                encoding = CTC_PRINTABLE;
            }
            wolfCLU_AddNameEntry(ret, encoding, nid, entry);
        }
    }

    return ret;
}

int wolfCLU_getline(char **lineptr, size_t *len, FILE *fp)
{
    char  line[MAX_ENTRY_NAME];
    char *tmp;

    *len = sizeof(line);
    *lineptr = NULL;

    if ((*lineptr = (char*)XMALLOC(*len, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER))
            == NULL) {
        *len = 0;
        return WOLFCLU_FATAL_ERROR;
    }
    (*lineptr)[0] = '\0';

    while (fgets(line, sizeof(line), fp) != NULL) {
        size_t len_used  = XSTRLEN(*lineptr);
        size_t line_used = XSTRLEN(line);

        if (*len - len_used <= line_used) {
            if (*len > (size_t)(INT_MAX / 2)) {
                XFREE(*lineptr, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
                *lineptr = NULL;
                *len = 0;
                return WOLFCLU_FATAL_ERROR;
            }
            *len *= 2;
            tmp = XREALLOC(*lineptr, *len, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            if (tmp == NULL) {
                XFREE(*lineptr, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
                *lineptr = NULL;
                *len = 0;
                return WOLFCLU_FATAL_ERROR;
            }
            *lineptr = tmp;
        }

        XMEMCPY(*lineptr + len_used, line, line_used);
        len_used += line_used;
        (*lineptr)[len_used] = '\0';

        if (len_used > 0 && (*lineptr)[len_used - 1] == '\n') {
            (*lineptr)[len_used - 1] = '\0';
            return (int)(len_used - 1);
        }
    }

    /* EOF without newline: return accumulated length (0 if nothing was read) */
    return (int)XSTRLEN(*lineptr);
}

/* returns WOLFCLU_SUCCESS on success */
int wolfCLU_CreateX509Name(WOLFSSL_X509_NAME* name)
{
    char   *in = NULL;
    size_t  inSz;
    int     ret;
    FILE *fout = stdout;
    FILE *fin = stdin; /* defaulting to stdin but using a fd variable to make it
                        * easy for expanding to other inputs */

    fprintf(fout, "Enter without data will result in the field being "
            "skipped.\nExamples of inputs are provided as [*]\n");
    fprintf(fout, "Country [US] : ");
    ret = wolfCLU_getline(&in, &inSz, fin);
    if (ret == WOLFCLU_FATAL_ERROR) {
        return WOLFCLU_FATAL_ERROR;
    }
    if (ret > 0) {
        wolfCLU_AddNameEntry(name, CTC_PRINTABLE, NID_countryName, in);
    }
    XFREE(in, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

    fprintf(fout, "State or Province [Montana] : ");
    ret = wolfCLU_getline(&in, &inSz, fin);
    if (ret == WOLFCLU_FATAL_ERROR) {
        return WOLFCLU_FATAL_ERROR;
    }
    if (ret > 0) {
        wolfCLU_AddNameEntry(name, CTC_UTF8, NID_stateOrProvinceName, in);
    }
    XFREE(in, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

    fprintf(fout, "Locality [Bozeman] : ");
    ret = wolfCLU_getline(&in, &inSz, fin);
    if (ret == WOLFCLU_FATAL_ERROR) {
        return WOLFCLU_FATAL_ERROR;
    }
    if (ret > 0) {
        wolfCLU_AddNameEntry(name, CTC_UTF8, NID_localityName, in);
    }
    XFREE(in, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

    fprintf(fout, "Organization Name [wolfSSL] : ");
    ret = wolfCLU_getline(&in, &inSz, fin);
    if (ret == WOLFCLU_FATAL_ERROR) {
        return WOLFCLU_FATAL_ERROR;
    }
    if (ret > 0) {
        wolfCLU_AddNameEntry(name, CTC_UTF8, NID_organizationName, in);
    }
    XFREE(in, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

    fprintf(fout, "Organization Unit [engineering] : ");
    ret = wolfCLU_getline(&in, &inSz, fin);
    if (ret == WOLFCLU_FATAL_ERROR) {
        return WOLFCLU_FATAL_ERROR;
    }
    if (ret > 0) {
        wolfCLU_AddNameEntry(name, CTC_UTF8, NID_organizationalUnitName, in);
    }
    XFREE(in, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

    fprintf(fout, "Common Name : ");
    ret = wolfCLU_getline(&in, &inSz, fin);
    if (ret == WOLFCLU_FATAL_ERROR) {
        return WOLFCLU_FATAL_ERROR;
    }
    if (ret > 0) {
        wolfCLU_AddNameEntry(name, CTC_UTF8, NID_commonName, in);
    }
    XFREE(in, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

    fprintf(fout, "Email Address : ");
    ret = wolfCLU_getline(&in, &inSz, fin);
    if (ret == WOLFCLU_FATAL_ERROR) {
        return WOLFCLU_FATAL_ERROR;
    }
    if (ret > 0) {
        wolfCLU_AddNameEntry(name, CTC_UTF8, NID_emailAddress, in);
    }
    XFREE(in, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

    return WOLFCLU_SUCCESS;
}


void wolfCLU_convertToLower(char* s, int sSz)
{
    int i;
    for (i = 0; i < sSz; i++) {
        s[i] = tolower(s[i]);
    }
}


/* DER definite-length encoder. */
word32 wolfCLU_DerSetLength(word32 length, byte* output)
{
    word32 i;
    word32 sz = 1;

    if (length < 0x80) {
        if (output != NULL)
            output[0] = (byte)length;
    }
    else {
        word32 len = length;

        while (len != 0) {
            sz++;
            len >>= 8;
        }
        if (output != NULL) {
            output[0] = (byte)(0x80 | (sz - 1));
            for (i = 1; i < sz; i++) {
                output[sz - i] = (byte)(length & 0xFF);
                length >>= 8;
            }
        }
    }

    return sz;
}

void wolfCLU_ForceZero(void* mem, unsigned int len)
{
#ifndef WOLFSSL_NO_FORCE_ZERO
    wc_ForceZero(mem, len);
#else
    /* wc_ForceZero unavailable in this build; use a volatile loop instead. */
    volatile byte* z = (volatile byte*)mem;
    while (len--) *z++ = 0;
#endif
}

int wolfCLU_ReadFileToBuffer(const char* path, long maxSz, byte** outBuf,
        int* outSz)
{
    int   sz;
    long  fsz;
    byte* buf = NULL;
    XFILE f;

    if (path == NULL || outBuf == NULL || outSz == NULL || maxSz <= 0) {
        return BAD_FUNC_ARG;
    }
    *outBuf = NULL;
    *outSz  = 0;

    f = XFOPEN(path, "rb");
    if (f == XBADFILE) {
        wolfCLU_LogError("unable to open file %s", path);
        return BAD_FUNC_ARG;
    }

    if (XFSEEK(f, 0, XSEEK_END) != 0) {
        XFCLOSE(f);
        return WOLFCLU_FATAL_ERROR;
    }
    fsz = XFTELL(f);
    if (XFSEEK(f, 0, XSEEK_SET) != 0) {
        XFCLOSE(f);
        return WOLFCLU_FATAL_ERROR;
    }
    if (fsz <= 0) {
        wolfCLU_LogError("%s: file is empty or unreadable", path);
        XFCLOSE(f);
        return WOLFCLU_FATAL_ERROR;
    }
    if (fsz > maxSz || fsz > (long)INT_MAX) {
        wolfCLU_LogError("%s: size %ld exceeds %ld-byte file limit",
                path, fsz, maxSz);
        XFCLOSE(f);
        return WOLFCLU_FATAL_ERROR;
    }
    sz = (int)fsz;

    /* +1/NUL-terminate: matches other PEM-buffer readers in this codebase. */
    buf = (byte*)XMALLOC((size_t)sz + 1, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (buf == NULL) {
        XFCLOSE(f);
        return MEMORY_E;
    }

    /* short/long read here catches a file that changed size after XFTELL. */
    if (XFREAD(buf, 1, (size_t)sz, f) != (size_t)sz) {
        XFCLOSE(f);
        wolfCLU_ForceZero(buf, sz);
        XFREE(buf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        return WOLFCLU_FATAL_ERROR;
    }
    buf[sz] = '\0';
    XFCLOSE(f);

    *outBuf = buf;
    *outSz  = sz;
    return WOLFCLU_SUCCESS;
}

/* Atomically replaces path with fresh, owner-only regular file. */
#ifdef _WIN32
#include <windows.h>
#include <sddl.h>
#include <io.h>
#include <fcntl.h>
#pragma comment(lib, "advapi32.lib")

FILE* wolfCLU_CreateSecureFile(const char* path, DWORD access,
        const char* mode, int ownerOnly)
{
    SECURITY_ATTRIBUTES sa;
    SECURITY_ATTRIBUTES* pSA = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    HANDLE hFile;
    int fd;
    FILE* f = NULL;
    const char* sddl = "D:P(A;;FA;;;OW)";
    int crtFlags = _O_CREAT | _O_TRUNC |
            ((access & GENERIC_READ) ?
                    ((access & GENERIC_WRITE) ? _O_RDWR : _O_RDONLY) :
                    _O_WRONLY);

    (void)_unlink(path);

    if (ownerOnly) {
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(sddl,
                SDDL_REVISION_1, &pSD, NULL)) {
            return NULL;
        }
        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa.bInheritHandle = FALSE;
        sa.lpSecurityDescriptor = pSD;
        pSA = &sa;
    }

    hFile = CreateFileA(path, access, 0, pSA, CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD attrs = GetFileAttributesA(path);
        if (attrs != INVALID_FILE_ATTRIBUTES &&
                (attrs & FILE_ATTRIBUTE_REPARSE_POINT)) {
            /* path was replaced with a symlink/junction between the
             * _unlink() above and this CreateFileA(); refuse to write
             * through it. */
            CloseHandle(hFile);
            hFile = INVALID_HANDLE_VALUE;
            (void)_unlink(path);
        }
    }
    if (hFile != INVALID_HANDLE_VALUE) {
        fd = _open_osfhandle((intptr_t)hFile, crtFlags);
        if (fd != -1) {
            f = _fdopen(fd, mode);
        }
        if (f == NULL) {
            if (fd != -1) _close(fd);
            else CloseHandle(hFile);
            (void)_unlink(path);
        }
    }
    if (pSD != NULL) {
        LocalFree(pSD);
    }
    return f;
}

FILE* wolfCLU_OpenKeyFile(const char* path)
{
    FILE* f = wolfCLU_CreateSecureFile(path, GENERIC_WRITE, "wb", 1);
    if (f == NULL) {
        wolfCLU_LogError("Unable to open output file %s", path);
    }
    return f;
}

FILE* wolfCLU_OpenOutFile(const char* path)
{
    FILE* f = wolfCLU_CreateSecureFile(path, GENERIC_WRITE, "wb", 0);
    if (f == NULL) {
        wolfCLU_LogError("Unable to open output file %s", path);
    }
    return f;
}
#else
#include <fcntl.h>
#include <sys/stat.h>
#ifndef O_NOFOLLOW
    #define O_NOFOLLOW 0
#endif
FILE* wolfCLU_CreateSecureFile(const char* path, int access,
        const char* mode, int ownerOnly)
{
    int         fd;
    FILE*       f;
    struct stat st;
    mode_t      createMode = ownerOnly ? 0600 : 0666;

    /* Non-regular targets (character devices like /dev/null or
     * /dev/stdout, FIFOs, etc.) can't be usefully hardened with
     * unlink()+O_EXCL: unlink() on them commonly fails (they live in
     * directories the caller can't modify) or, when it succeeds, would
     * destroy and replace the special file with a plain regular file
     * instead of writing through it. Fall back to a plain fopen() for
     * these so redirecting output to them keeps working as it did before
     * the O_EXCL hardening was added.
     *
     * Symlinks are deliberately excluded from this fallback: lstat()
     * reports S_IFLNK for a symlink regardless of what it points to, and
     * following it here with a plain fopen() would let an attacker who
     * pre-creates a symlink at path redirect key material to an
     * arbitrary target -- exactly what the O_EXCL|O_NOFOLLOW path below
     * exists to prevent. Symlinks fall through to that path, which
     * unlinks the symlink and creates a fresh regular file in its place. */
    if (lstat(path, &st) == 0 && !S_ISREG(st.st_mode) && !S_ISLNK(st.st_mode)) {
        /* Open with O_NOFOLLOW instead of fopen() so a symlink swapped in
         * between the lstat() above and this open() is rejected rather
         * than followed. */
        fd = open(path, access | O_NOFOLLOW);
        if (fd < 0)
            return NULL;
        f = fdopen(fd, mode);
        if (f == NULL)
            close(fd);
        return f;
    }

    /* Ignore the result (including ENOENT if the file doesn't exist yet);
     * this just ensures the O_EXCL open below gets a fresh inode. */
    (void)unlink(path);
    fd = open(path, O_CREAT | O_EXCL | access | O_NOFOLLOW, createMode);
    if (fd < 0)
        return NULL;
    f = fdopen(fd, mode);
    if (f == NULL) {
        close(fd);
        (void)unlink(path); /* remove the stray empty file we just created */
    }
    return f;
}

FILE* wolfCLU_OpenKeyFile(const char* path)
{
    FILE* f = wolfCLU_CreateSecureFile(path, O_WRONLY, "wb", 1);
    if (f == NULL) {
        wolfCLU_LogError("Unable to open output file %s", path);
    }
    return f;
}

FILE* wolfCLU_OpenOutFile(const char* path)
{
    FILE* f = wolfCLU_CreateSecureFile(path, O_WRONLY, "wb", 0);
    if (f == NULL) {
        wolfCLU_LogError("Unable to open output file %s", path);
    }
    return f;
}
#endif /* _WIN32 */

void wolfCLU_RemoveFile(const char* path)
{
#ifdef _WIN32
    (void)_unlink(path);
#else
    (void)unlink(path);
#endif
}

static WOLFSSL_BIO* wolfCLU_WrapSecureFileBio(FILE* f, const char* path)
{
    WOLFSSL_BIO* bioOut = (f != NULL) ?
            wolfSSL_BIO_new_fp(f, BIO_CLOSE) : NULL;

    if (bioOut == NULL && f != NULL) {
        /* wolfCLU_OpenKeyFile()/wolfCLU_OpenOutFile() already logged when
         * f itself was NULL; only log here for the BIO-wrap failure. */
        XFCLOSE(f);
        wolfCLU_RemoveFile(path);
        wolfCLU_LogError("Unable to open output file %s", path);
    }
    return bioOut;
}

WOLFSSL_BIO* wolfCLU_OpenKeyFileBio(const char* path)
{
    return wolfCLU_WrapSecureFileBio(wolfCLU_OpenKeyFile(path), path);
}

WOLFSSL_BIO* wolfCLU_OpenOutFileBio(const char* path)
{
    return wolfCLU_WrapSecureFileBio(wolfCLU_OpenOutFile(path), path);
}

WOLFSSL_BIO* wolfCLU_OpenOutOrKeyFileBio(const char* path, int isSecret)
{
    return isSecret ? wolfCLU_OpenKeyFileBio(path) :
            wolfCLU_OpenOutFileBio(path);
}

#ifndef WOLFCLU_NO_TERM_SUPPORT

int wolfCLU_GetPassword(char* password, int* passwordSz, char* arg)
{
    int ret = WOLFCLU_SUCCESS;

    if (password == NULL || passwordSz == NULL || *passwordSz <= 0) {
        return WOLFCLU_FATAL_ERROR;
    }

    XMEMSET(password, 0, *passwordSz);
    if (XSTRNCMP(arg, "stdin", 5) == 0) {
        if (XFGETS(password, *passwordSz, stdin) == NULL) {
            wolfCLU_LogError("error getting password");
            ret = WOLFCLU_FATAL_ERROR;
        }
        if (ret == WOLFCLU_SUCCESS) {
            size_t idx = 0;
            *passwordSz = (int)XSTRLEN(password);

            /* span the string up to the first return line and chop
             * it off */
            if (XSTRSTR(password, "\r\n")) {
                idx = strcspn(password, "\r\n");
                if ((int)idx > *passwordSz) {
                    ret = WOLFCLU_FATAL_ERROR;
                }
                else {
                    password[idx] = '\0';
                }
            }

            if (XSTRSTR(password, "\n")) {
                idx = strcspn(password, "\n");
                if ((int)idx > *passwordSz) {
                    ret = WOLFCLU_FATAL_ERROR;
                }
                else {
                    password[idx] = '\0';
                }
            }

            *passwordSz = (int)XSTRLEN(password);
        }
    }
    else if (XSTRNCMP(arg, "pass:", 5) == 0) {
        XSTRNCPY(password, arg + 5, *passwordSz - 1);
        password[*passwordSz - 1] = '\0';
        if (ret == WOLFCLU_SUCCESS) {
            *passwordSz = (int)XSTRLEN(password);
        }
    }
    else {
        wolfCLU_LogError("not supported password in type %s",
                arg);
        ret = WOLFCLU_FATAL_ERROR;
    }
    return ret;
}

#if !defined(USE_WINDOWS_API) && !defined(MICROCHIP_PIC32)
static int HideEcho(struct termios* originalTerm)
{
    struct termios newTerm;
    if (tcgetattr(STDIN_FILENO, originalTerm) != 0) {
        return WOLFCLU_FATAL_ERROR;
    }

    XMEMCPY(&newTerm, originalTerm, sizeof(struct termios));
    newTerm.c_lflag &= ~ECHO;
    newTerm.c_lflag |= (ICANON | ECHONL);

    if (tcsetattr(STDIN_FILENO, TCSANOW, &newTerm) != 0) {
        return WOLFCLU_FATAL_ERROR;
    }
    return WOLFCLU_SUCCESS;
}


static int ShowEcho(struct termios* originalTerm)
{
    if (tcsetattr(STDIN_FILENO, TCSANOW, originalTerm) != 0) {
        return WOLFCLU_FATAL_ERROR;
    }
    return WOLFCLU_SUCCESS;
}

#else

static int HideEcho(DWORD* originalTerm)
{
    HANDLE stdinHandle = GetStdHandle(STD_INPUT_HANDLE);
    if (GetConsoleMode(stdinHandle, originalTerm) == 0) {
        return WOLFCLU_FATAL_ERROR;
    }
    DWORD newTerm = *originalTerm;
    newTerm &= ~ENABLE_ECHO_INPUT;
    if (SetConsoleMode(stdinHandle, newTerm) == 0) {
        return WOLFCLU_FATAL_ERROR;
    }
    return WOLFCLU_SUCCESS;
}


static int ShowEcho(DWORD* originalTerm)
{
    HANDLE stdinHandle = GetStdHandle(STD_INPUT_HANDLE);
    if (SetConsoleMode(stdinHandle, *originalTerm) == 0) {
        return WOLFCLU_FATAL_ERROR;
    }
    return WOLFCLU_SUCCESS;
}
#endif


/* return WOLFCLU_SUCCESS on success */
int wolfCLU_GetStdinPassword(byte* password, word32* passwordSz)
{
    int ret;
#if !defined(USE_WINDOWS_API) && !defined(MICROCHIP_PIC32)
    struct termios originalTerm;
#else
    DWORD originalTerm;
#endif

    if (password == NULL || passwordSz == NULL) {
        return WOLFCLU_FATAL_ERROR;
    }

    ret = HideEcho(&originalTerm);
    if (ret == WOLFCLU_SUCCESS) {
        printf("Input Password: ");
        if (fgets((char*)password, *passwordSz, stdin) == NULL) {
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            char* c = strpbrk((char*)password, "\r\n");
            if (c != NULL)
                *c = '\0';
        }
        *passwordSz = (word32)XSTRLEN((const char*)password);
        ShowEcho(&originalTerm);
    }
    return ret;
}
#endif

/* Not handling options char yet*/
int wolfCLU_GetOpt(int argc, char** argv, const char *options,
       const struct option *long_options, int *opt_index)
{
    int i     = optind; /* variable to keep track of starting option position */
    int index = 0;      /* index at which option was found */
    optarg = NULL;      /* Clear out the last argument */

    while (1) {
        /* set end to 1 if last option is reached */
        if (long_options[i].name == 0 ) {
            return END_OF_ARGS;
        }
        else {

            /* check if option is present in argv */
            index = wolfCLU_checkForArg(long_options[i].name,
                    (int)XSTRLEN(long_options[i].name), argc, argv);
            optind++;

            if (index == USER_INPUT_ERROR) {
                return ARG_FOUND_TWICE;
            }

            /* if index matches *opt_index at first position or if index is found */
            if (index == *opt_index+1 || (*opt_index !=0 && index > 0)) {
                if (long_options[i].has_arg == 1) {
                    /* required_argument binds the value as the token directly
                     * following the option. The positional rescan in
                     * clu_rand.c (wolfCLU_Rand) re-derives this same binding by
                     * hand; any change here to how/when optarg is bound (e.g.
                     * adding --opt=value handling, optional_argument support, or
                     * argv permutation) must be reflected there too. */
                    if (index + 1 < argc) {
                        optarg = argv[index+1];
                    }
                    else {
                        optarg = NULL;
                    }
                }
                return long_options[i].val;
            }
        }

        i++;
    }

    (void) *options;

    return WOLFCLU_FATAL_ERROR;

}


/* Stream bioIn in chunks to update(). */
static int wolfCLU_bioReadUpdate(WOLFSSL_BIO* bioIn,
        int (*update)(void* updateCtx, const byte* data, word32 sz),
        void* updateCtx)
{
    byte chunk[MAX_IO_CHUNK_SZ];
    int bytesRead;
    int ret = WOLFCLU_SUCCESS;

    while (ret == WOLFCLU_SUCCESS) {
        bytesRead = wolfSSL_BIO_read(bioIn, chunk, sizeof(chunk));
        if (bytesRead < 0) {
            wolfCLU_LogError("Error reading data");
            ret = WOLFCLU_FATAL_ERROR;
            break;
        }
        else if (bytesRead == 0) {
            break;
        }
        if (update(updateCtx, chunk, (word32)bytesRead) != 0) {
            wolfCLU_LogError("Hash update failed");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    wolfCLU_ForceZero(chunk, sizeof(chunk));
    return ret;
}

struct wolfCLU_hashUpdateCtx {
    wc_HashAlg* hashAlg;
    enum wc_HashType hashType;
};

static int wolfCLU_hashUpdateCb(void* updateCtx, const byte* data, word32 sz)
{
    struct wolfCLU_hashUpdateCtx* ctx =
            (struct wolfCLU_hashUpdateCtx*)updateCtx;
    return wc_HashUpdate(ctx->hashAlg, ctx->hashType, data, sz);
}

static int wolfCLU_hmacUpdateCb(void* updateCtx, const byte* data, word32 sz)
{
    return (wolfSSL_HMAC_Update((WOLFSSL_HMAC_CTX*)updateCtx, data, sz)
            == WOLFSSL_SUCCESS) ? 0 : WOLFCLU_FATAL_ERROR;
}

/* Stream-hash data read from bioIn using hashType and write the digest to
 * outDigest. On entry *outDigestSz is the capacity of outDigest; on success
 * it is updated to the actual digest length. */
int wolfCLU_streamHashBio(WOLFSSL_BIO* bioIn, enum wc_HashType hashType,
        byte* outDigest, word32* outDigestSz)
{
    wc_HashAlg hashAlg;
    struct wolfCLU_hashUpdateCtx updateCtx;
    int hashInit = 0;
    int dsz;
    int ret;

    if (bioIn == NULL || outDigest == NULL || outDigestSz == NULL) {
        return BAD_FUNC_ARG;
    }

    dsz = wc_HashGetDigestSize(hashType);
    if (dsz <= 0 || (word32)dsz > *outDigestSz) {
        wolfCLU_LogError("Bad digest size for selected hash");
        return WOLFCLU_FATAL_ERROR;
    }

    if (wc_HashInit(&hashAlg, hashType) != 0) {
        wolfCLU_LogError("Unable to initialize hash");
        return WOLFCLU_FATAL_ERROR;
    }
    hashInit = 1;

    updateCtx.hashAlg = &hashAlg;
    updateCtx.hashType = hashType;
    ret = wolfCLU_bioReadUpdate(bioIn, wolfCLU_hashUpdateCb, &updateCtx);

    if (ret == WOLFCLU_SUCCESS) {
        if (wc_HashFinal(&hashAlg, hashType, outDigest) != 0) {
            wolfCLU_LogError("Hash finalization failed");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            *outDigestSz = (word32)dsz;
        }
    }

    if (hashInit) {
        wc_HashFree(&hashAlg, hashType);
    }

    return ret;
}

int wolfCLU_hmacHash(WOLFSSL_HMAC_CTX *ctx, void* key, word32 len,
        enum wc_HashType alg, WOLFSSL_BIO* in, byte* out, word32* outSz)
{
    int ret = WOLFCLU_SUCCESS;
    byte chunk[MAX_IO_CHUNK_SZ];
    word32 hmacLen = 0;
    const WOLFSSL_EVP_MD* md = NULL;

     if (ctx == NULL || key == NULL || in == NULL ||
             out == NULL || outSz == NULL) {
         return BAD_FUNC_ARG;
     }

    /* wc_HashType values are not contiguous, so map each one explicitly.
     * Cast to int so unrelated hash types don't trip -Wswitch-enum. */
    switch ((int)alg) {
        case WC_HASH_TYPE_MD5:
        #ifndef NO_MD5
            md = wolfSSL_EVP_md5();
        #else
            wolfCLU_LogError("MD5 not compiled in");
            ret = WOLFCLU_FATAL_ERROR;
        #endif
            break;
        case WC_HASH_TYPE_SHA:
            md = wolfSSL_EVP_sha1();
            break;
        case WC_HASH_TYPE_SHA224:
            md = wolfSSL_EVP_sha224();
            break;
        case WC_HASH_TYPE_SHA256:
            md = wolfSSL_EVP_sha256();
            break;
        case WC_HASH_TYPE_SHA384:
            md = wolfSSL_EVP_sha384();
            break;
        case WC_HASH_TYPE_SHA512:
            md = wolfSSL_EVP_sha512();
            break;
        default:
            wolfCLU_LogError("Invalid hash type");
            ret = WOLFCLU_FATAL_ERROR;
    }

    if (ret == WOLFCLU_SUCCESS) {
        if (wolfSSL_HMAC_Init(ctx, key, len, md)
                != WOLFSSL_SUCCESS) {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = wolfCLU_bioReadUpdate(in, wolfCLU_hmacUpdateCb, ctx);
    }

    if (ret == WOLFCLU_SUCCESS) {
        if (wolfSSL_HMAC_Final(ctx, chunk, &hmacLen) != WOLFSSL_SUCCESS) {
            wolfCLU_LogError("Unable to get hmac hash of data.");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        if (hmacLen <= *outSz) {
            XMEMCPY(out, chunk, hmacLen);
            *outSz = hmacLen;
        }
        else {
            wolfCLU_LogError("Out buffer too small to hold HMAC dgst");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    wolfCLU_ForceZero(chunk, sizeof(chunk));
    return ret;
}
