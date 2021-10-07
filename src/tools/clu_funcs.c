/* clu_funcs.c
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
#include <wolfclu/version.h>
#include <wolfclu/x509/clu_cert.h>        /* for PEM_FORM and DER_FORM */
#include <wolfclu/sign-verify/clu_sign.h> /* for RSA_SIG_VER, ECC_SIG_VER,
                                             ED25519_SIG_VER */

#define SALT_SIZE       8
#define DES3_BLOCK_SIZE 24

static int loop = 0;

static struct option crypt_algo_options[] = {
    /* AES */
    {"aes-128-ctr", no_argument, 0, WOLFCLU_AES128CTR},
    {"aes-192-ctr", no_argument, 0, WOLFCLU_AES192CTR},
    {"aes-256-ctr", no_argument, 0, WOLFCLU_AES256CTR},
    {"aes-128-cbc", no_argument, 0, WOLFCLU_AES128CBC},
    {"aes-192-cbc", no_argument, 0, WOLFCLU_AES192CBC},
    {"aes-256-cbc", no_argument, 0, WOLFCLU_AES256CBC},

    /* camellia */
    {"camellia-128-cbc", no_argument, 0, WOLFCLU_CAMELLIA128CBC},
    {"camellia-192-cbc", no_argument, 0, WOLFCLU_CAMELLIA192CBC},
    {"camellia-256-cbc", no_argument, 0, WOLFCLU_CAMELLIA256CBC},

    /* 3des */
    {"des-cbc", no_argument, 0, WOLFCLU_DESCBC},
    {"d",       no_argument, 0, WOLFCLU_DECRYPT},

    {0, 0, 0, 0} /* terminal element */
};

/*
 * generic help function
 */
 void wolfCLU_help()
 {  WOLFCLU_LOG(WOLFCLU_L0, "");
    WOLFCLU_LOG(WOLFCLU_L0, "-help           Help, print out this help menu");
    WOLFCLU_LOG(WOLFCLU_L0, "");
    WOLFCLU_LOG(WOLFCLU_L0, "Only set one of the following.\n");
    WOLFCLU_LOG(WOLFCLU_L0, "bench          Benchmark one of the algorithms");
    WOLFCLU_LOG(WOLFCLU_L0, "decrypt        Decrypt an encrypted file");
    WOLFCLU_LOG(WOLFCLU_L0, "dgst           Used for verifying a signature");
    WOLFCLU_LOG(WOLFCLU_L0, "ecc            Ecc signing and signature verification");
    WOLFCLU_LOG(WOLFCLU_L0, "ecparam        Generate an ECC key and parameters");
    WOLFCLU_LOG(WOLFCLU_L0, "ed25519        Ed25519 signing and signature verification");
    WOLFCLU_LOG(WOLFCLU_L0, "encrypt        Encrypt a file or some user input");
    WOLFCLU_LOG(WOLFCLU_L0, "hash           Hash a file or input");
    WOLFCLU_LOG(WOLFCLU_L0, "md5            Creates and MD5 hash");
    WOLFCLU_LOG(WOLFCLU_L0, "pkey           Used for key operations");
    WOLFCLU_LOG(WOLFCLU_L0, "req            Request for certificate generation");
    WOLFCLU_LOG(WOLFCLU_L0, "rsa            Rsa signing and signature verification");
    WOLFCLU_LOG(WOLFCLU_L0, "x509           X509 certificate processing");
    WOLFCLU_LOG(WOLFCLU_L0, "");
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
 }

/*
 * verbose help function
 */
void wolfCLU_verboseHelp()
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
#ifdef HAVE_BLAKE2
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
#ifdef HAVE_BLAKE2
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
#ifdef WOLFSSL_AES_COUNTER
    WOLFCLU_LOG(WOLFCLU_L0, "aes-ctr-128\t\taes-ctr-192\t\taes-ctr-256");
#endif
#ifndef NO_DES3
    WOLFCLU_LOG(WOLFCLU_L0, "3des-cbc-56\t\t3des-cbc-112\t\t3des-cbc-168");
#endif
#ifdef HAVE_CAMELLIA
    WOLFCLU_LOG(WOLFCLU_L0, "camellia-cbc-128\tcamellia-cbc-192\t"
            "camellia-cbc-256");
#endif
    WOLFCLU_LOG(WOLFCLU_L0, "");
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

/*
 * Encrypt Usage
 */
void wolfCLU_encryptHelp()
{
    WOLFCLU_LOG(WOLFCLU_L0, "\nAvailable En/De crypt Algorithms with current configure "
            "settings.\n");
#ifndef NO_AES
    WOLFCLU_LOG(WOLFCLU_L0, "aes-cbc-128\t\taes-cbc-192\t\taes-cbc-256");
#endif
#ifdef WOLFSSL_AES_COUNTER
    WOLFCLU_LOG(WOLFCLU_L0, "aes-ctr-128\t\taes-ctr-192\t\taes-ctr-256");
#endif
#ifndef NO_DES3
    WOLFCLU_LOG(WOLFCLU_L0, "3des-cbc-56\t\t3des-cbc-112\t\t3des-cbc-168");
#endif
#ifdef HAVE_CAMELLIA
    WOLFCLU_LOG(WOLFCLU_L0, "camellia-cbc-128\tcamellia-cbc-192\t"
            "camellia-cbc-256\n");
#endif
    WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
    WOLFCLU_LOG(WOLFCLU_L0, "\nENCRYPT USAGE: wolfssl -encrypt <-algorithm> -in <filename> "
           "-pwd <password> -out <output file name>\n");
    WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
    WOLFCLU_LOG(WOLFCLU_L0, "\nEXAMPLE: \n\nwolfssl -encrypt aes-cbc-128 -pwd Thi$i$myPa$$w0rd"
           " -in somefile.txt -out encryptedfile.txt\n");
}

/*
 * Decrypt Usage
 */
void wolfCLU_decryptHelp()
{
    WOLFCLU_LOG(WOLFCLU_L0, "\nAvailable En/De crypt Algorithms with current configure "
            "settings.\n");
#ifndef NO_AES
    WOLFCLU_LOG(WOLFCLU_L0, "aes-cbc-128\t\taes-cbc-192\t\taes-cbc-256");
#endif
#ifdef WOLFSSL_AES_COUNTER
    WOLFCLU_LOG(WOLFCLU_L0, "aes-ctr-128\t\taes-ctr-192\t\taes-ctr-256");
#endif
#ifndef NO_DES3
    WOLFCLU_LOG(WOLFCLU_L0, "3des-cbc-56\t\t3des-cbc-112\t\t3des-cbc-168");
#endif
#ifdef HAVE_CAMELLIA
    WOLFCLU_LOG(WOLFCLU_L0, "camellia-cbc-128\tcamellia-cbc-192\t"
            "camellia-cbc-256\n");
#endif
    WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
    WOLFCLU_LOG(WOLFCLU_L0, "\nDECRYPT USAGE: wolfssl -decrypt <algorithm> -in <encrypted file> "
           "-pwd <password> -out <output file name>\n");
    WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
    WOLFCLU_LOG(WOLFCLU_L0, "\nEXAMPLE: \n\nwolfssl -decrypt aes-cbc-128 -pwd Thi$i$myPa$$w0rd"
           " -in encryptedfile.txt -out decryptedfile.txt\n");
}

/*
 * Hash Usage
 */
void wolfCLU_hashHelp()
{
    int i;

    /* hash options */
    const char* algsenc[] = {        /* list of acceptable algorithms */
    "Algorithms: "
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
#ifdef HAVE_BLAKE2
        ,"blake2b"
#endif
#ifndef NO_CODING
    #ifdef WOLFSSL_BASE64_ENCODE
        ,"base64enc"
    #endif
        ,"base64dec"
#endif
        };

    WOLFCLU_LOG(WOLFCLU_L0, "\nAvailable algorithms with current configure settings:");
    for (i = 0; i < (int) sizeof(algsenc)/(int) sizeof(algsenc[0]); i++) {
        WOLFCLU_LOG(WOLFCLU_L0, "%s", algsenc[i]);
    }
            /* encryption/decryption help lists options */
    WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
    WOLFCLU_LOG(WOLFCLU_L0, "\nUSAGE: wolfssl -hash <-algorithm> -in <file to hash>");
    WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
    WOLFCLU_LOG(WOLFCLU_L0, "\nEXAMPLE: \n\nwolfssl -hash sha -in <some file>\n");
}

/*
 * Benchmark Usage
 */
void wolfCLU_benchHelp()
{
    int i;

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
#ifdef HAVE_BLAKE2
        , "blake2b"
#endif
    };

    WOLFCLU_LOG(WOLFCLU_L0, "\nAvailable tests: (-a to test all)");
    WOLFCLU_LOG(WOLFCLU_L0, "Available tests with current configure settings:");
    for(i = 0; i < (int) sizeof(algsother)/(int) sizeof(algsother[0]); i++) {
        WOLFCLU_LOG(WOLFCLU_L0, "%s", algsother[i]);
    }
    WOLFCLU_LOG(WOLFCLU_L0, "");
            /* encryption/decryption help lists options */
    WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
    WOLFCLU_LOG(WOLFCLU_L0, "USAGE: wolfssl -bench [alg] -time [time in seconds [1-10]]"
           "       or\n       wolfssl -bench -time 10 -all (to test all)");
    WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
    WOLFCLU_LOG(WOLFCLU_L0, "\nEXAMPLE: \n\nwolfssl -bench aes-cbc -time 10"
           " -in encryptedfile.txt -out decryptedfile.txt\n");
}

void wolfCLU_certHelp()
{
    WOLFCLU_LOG(WOLFCLU_L0, "\n");
    WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
    WOLFCLU_LOG(WOLFCLU_L0, "\nX509 USAGE: wolfssl -x509 -inform <PEM or DER> -in <filename> "
           "-outform <PEM or DER> -out <output file name> \n");
    WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
    WOLFCLU_LOG(WOLFCLU_L0, "\nEXAMPLE: \n\nwolfssl -x509 -inform pem -in testing-certs/"
           "ca-cert.pem -outform der -out testing-certs/ca-cert-converted.der"
           "\n");
}

void wolfCLU_genKeyHelp()
{
    int i;

    const char* keysother[] = { /* list of acceptable key types */
        "KEYS: "
    #ifndef NO_RSA
        ,"rsa"
    #endif
    #ifdef HAVE_ED25519
        ,"ed25519"
    #endif
    #ifdef HAVE_ECC
        ,"ecc"
    #endif
        };

        WOLFCLU_LOG(WOLFCLU_L0, "Available keys with current configure settings:");
        for(i = 0; i < (int) sizeof(keysother)/(int) sizeof(keysother[0]); i++) {
            WOLFCLU_LOG(WOLFCLU_L0, "%s", keysother[i]);
        }
    WOLFCLU_LOG(WOLFCLU_L0, "\n");
    WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
    WOLFCLU_LOG(WOLFCLU_L0, "\ngenkey USAGE:\nwolfssl -genkey <keytype> -size(optional) <bits> "
           "-out <filename> -outform <PEM or DER> -output <PUB/PRIV/KEYPAIR> \n");
    WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
    WOLFCLU_LOG(WOLFCLU_L0, "\nEXAMPLE: \n\nwolfssl -genkey rsa -size 2048 -out mykey -outform der "
           " -output KEYPAIR"
           "\n\nThe above command would output the files: mykey.priv "
           " and mykey.pub\nChanging the -output option to just PRIV would only"
           "\noutput the mykey.priv and using just PUB would only output"
           "\nmykey.pub\n");
}

void wolfCLU_signHelp(int keyType)
{
    int i;
    const char* keysother[] = { /* list of acceptable key types */
        "KEYS: "
        #ifndef NO_RSA
        ,"rsa"
        #endif
        #ifdef HAVE_ED25519
        ,"ed25519"
        #endif
        #ifdef HAVE_ECC
        ,"ecc"
        #endif
        };

        WOLFCLU_LOG(WOLFCLU_L0, "\nAvailable keys with current configure settings:");
        for(i = 0; i < (int) sizeof(keysother)/(int) sizeof(keysother[0]); i++) {
            WOLFCLU_LOG(WOLFCLU_L0, "%s", keysother[i]);
        }
        
        WOLFCLU_LOG(WOLFCLU_L0, "\n***************************************************************");
        switch(keyType) {
            #ifndef NO_RSA
            case RSA_SIG_VER:
                WOLFCLU_LOG(WOLFCLU_L0, "RSA Sign Usage: \nwolfssl -rsa -sign -inkey <priv_key>"
                       " -in <filename> -out <filename>\n");
                WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
                break;
            #endif
            #ifdef HAVE_ED25519
            case ED25519_SIG_VER:
                WOLFCLU_LOG(WOLFCLU_L0, "ED25519 Sign Usage: \nwolfssl -ed25519 -sign -inkey "
                       "<priv_key> -in <filename> -out <filename>\n");
                WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
                break;
            #endif
            #ifdef HAVE_ECC
            case ECC_SIG_VER:
                WOLFCLU_LOG(WOLFCLU_L0, "ECC Sign Usage: \nwolfssl -ecc -sign -inkey <priv_key>"
                       " -in <filename> -out <filename>\n");
                break;
            #endif
            default:
                WOLFCLU_LOG(WOLFCLU_L0, "No valid key type defined.\n");
        }
}

void wolfCLU_verifyHelp(int keyType) {
    int i;
    const char* keysother[] = { /* list of acceptable key types */
        "KEYS: "
        #ifndef NO_RSA
        ,"rsa"
        #endif
        #ifdef HAVE_ED25519
        ,"ed25519"
        #endif
        #ifdef HAVE_ECC
        ,"ecc"
        #endif
        };

        WOLFCLU_LOG(WOLFCLU_L0, "\nAvailable keys with current configure settings:");
        for(i = 0; i < (int) sizeof(keysother)/(int) sizeof(keysother[0]); i++) {
            WOLFCLU_LOG(WOLFCLU_L0, "%s", keysother[i]);
        }
        
        WOLFCLU_LOG(WOLFCLU_L0, "\n***************************************************************");
        switch(keyType) {
            #ifndef NO_RSA
            case RSA_SIG_VER:
                WOLFCLU_LOG(WOLFCLU_L0, "RSA Verify with Private Key:"
                        "wolfssl -rsa -verify -inkey <priv_key>"
                        " -sigfile <filename> -out <filename>\n");
                WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
                WOLFCLU_LOG(WOLFCLU_L0, "RSA Verify with Public Key"
                       "wolfssl -rsa -verify -inkey <pub_key>"
                       " -sigfile <filename> -out <filename> -pubin\n");
                WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
                break;
            #endif
            #ifdef HAVE_ED25519
            case ED25519_SIG_VER:
                WOLFCLU_LOG(WOLFCLU_L0, "ED25519 Verifiy with Private Key"
                       "wolfssl -ed25519 -verify -inkey "
                       "<priv_key> -sigfile <filename> -in <original>"
                       "\n");
                WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
                WOLFCLU_LOG(WOLFCLU_L0, "ED25519 Verifiy with Public Key"
                       "wolfssl -ed25519 -verify -inkey "
                       "<pub_key> -sigfile <filename> -in <original> -pubin"
                       "\n");
                WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
                break;
            #endif
            #ifdef HAVE_ECC
            case ECC_SIG_VER:
                WOLFCLU_LOG(WOLFCLU_L0, "ECC Verify with Public Key"
                       "wolfssl -ecc -verify -inkey <pub_key>"
                       " -sigfile <signature> -in <original>\n");
                break;
            #endif
            default:
                WOLFCLU_LOG(WOLFCLU_L0, "No valid key type defined.\n");
        }
}

void wolfCLU_certgenHelp() {
    WOLFCLU_LOG(WOLFCLU_L0, "\n");
    WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
    WOLFCLU_LOG(WOLFCLU_L0, "\ncertgen USAGE:\nwolfssl -req -ecc/-rsa/-ed25519 -in <filename> -out"
           " <filename> -sha/sha224/sha256/sha384/sha512\n");
    WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
    WOLFCLU_LOG(WOLFCLU_L0, "\nEXAMPLE: \n\nwolfssl -req ecc -in mykey -out cert.pem -sha256 "
           "\n\nThe above command would output the file: cert.pem");
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
        WOLFCLU_LOG(WOLFCLU_L0, "null input to get algo function");
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

    /* gets mode after second "-" and before the third */
    if (nameCheck != 0) {
        /* gets size after third "-" */
        sz = strtok_r(NULL, "-", &end);
        if (sz == NULL) {
            return WOLFCLU_FATAL_ERROR;
        }
        *size = XATOI(sz);
    }

    tmpMode = strtok_r(NULL, "-", &end);
    if (tmpMode == NULL) {
        return WOLFCLU_FATAL_ERROR;
    }

    for (i = 0; i < (int) (sizeof(acceptMode)/sizeof(acceptMode[0])); i++) {
        if (XSTRNCMP(tmpMode, acceptMode[i], XSTRLEN(tmpMode)) == 0)
            modeCheck = 1;
    }

    /* if name or mode doesn't match acceptable options */
    if (nameCheck == 0 || modeCheck == 0) {
        WOLFCLU_LOG(WOLFCLU_L0, "Invalid entry, issue with algo name and mode");
        return WOLFCLU_FATAL_ERROR;
    }

    /* checks key sizes for acceptability */
    if (XSTRNCMP(tmpAlg, "aes", 3) == 0) {
    #ifdef NO_AES
        WOLFCLU_LOG(WOLFCLU_L0, "AES not compiled in.");
        return NOT_COMPILED_IN;
    #else
        ret = AES_BLOCK_SIZE;
        if (*size != 128 && *size != 192 && *size != 256) {
            WOLFCLU_LOG(WOLFCLU_L0, "Invalid AES pwdKey size. Should be: %d", ret);
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
        WOLFCLU_LOG(WOLFCLU_L0, "3DES not compiled in.");
        return NOT_COMPILED_IN;
    #else
        ret = DES3_BLOCK_SIZE;
        if (*size != 56 && *size != 112 && *size != 168) {
            WOLFCLU_LOG(WOLFCLU_L0, "Invalid 3DES pwdKey size");
            ret = WOLFCLU_FATAL_ERROR;
        }
        *alg = WOLFCLU_DESCBC;
    #endif
    }

    else if (XSTRNCMP(tmpAlg, "camellia", 8) == 0) {
    #ifndef HAVE_CAMELLIA
        WOLFCLU_LOG(WOLFCLU_L0, "CAMELIA not compiled in.");
        return NOT_COMPILED_IN;
    #else
        ret = CAMELLIA_BLOCK_SIZE;
        if (*size != 128 && *size != 192 && *size != 256) {
            WOLFCLU_LOG(WOLFCLU_L0, "Invalid Camellia pwdKey size");
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
        WOLFCLU_LOG(WOLFCLU_L0, "Invalid algorithm: %s", tmpAlg);
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

#define WOLFCLU_AES128CTR_NAME "aes-128-ctr"
#define WOLFCLU_AES192CTR_NAME "aes-192-ctr"
#define WOLFCLU_AES256CTR_NAME "aes-256-ctr"
#define WOLFCLU_AES128CBC_NAME "aes-128-cbc"
#define WOLFCLU_AES192CBC_NAME "aes-192-cbc"
#define WOLFCLU_AES256CBC_NAME "aes-256-cbc"
#define WOLFCLU_CAMELLIA128CBC_NAME "camellia-128-cbc"
#define WOLFCLU_CAMELLIA192CBC_NAME "camellia-192-cbc"
#define WOLFCLU_CAMELLIA256CBC_NAME "camellia-256-cbc"
#define WOLFCLU_DESCBC_NAME "des-cbc"

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

/* support older name schemes MAX_AES_IDX is the maximum index for old AES alogo
 * names */
#define MAX_AES_IDX 6
static const char* oldAlgoName[] = {
    "aes-ctr-128",
    "aes-ctr-192",
    "aes-ctr-256",
    "aes-cbc-128",
    "aes-cbc-192",
    "aes-cbc-256",
};


/* convert an old algo name into one optargs can handle */
static void wolfCLU_oldAlgo(int argc, char** argv, int maxIdx)
{
    int end;
    int i, j;

    end = (argc < maxIdx)? argc : maxIdx;
    for (i = 0; i < end; i++) {
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

        case WOLFCLU_DESCBC:
            return wolfSSL_EVP_des_cbc();

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
    char *argvCopy[argc];
    int i;

    /* make a copy of args because getopt_long_only reorders them */
    for (i = 0; i < argc; i++) argvCopy[i] = argv[i];

    /* first just try the 3rd argument for backwords compatibility */
    if (argc < 3 || argvCopy[2] == NULL) {
        return WOLFCLU_FATAL_ERROR;
    }

    wolfCLU_oldAlgo(argc, argvCopy, 3);
    XMEMSET(name, 0, sizeof(name));
    XSTRNCPY(name, argvCopy[2], XSTRLEN(argv[2]));
    ret = wolfCLU_parseAlgo(name, alg, mode, size);

    /* next check for -cipher option passed through args */
    if (ret < 0) {
        opterr = 0; /* do not print out unknown options */
        XMEMSET(name, 0, sizeof(name));
        while ((option = getopt_long_only(argc, argvCopy, "",
                       crypt_algo_options, &longIndex )) != -1) {
            switch (option) {
                /* AES */
                case WOLFCLU_AES128CTR:
                    XSTRNCPY(name, WOLFCLU_AES128CTR_NAME,
                            XSTRLEN(WOLFCLU_AES128CTR_NAME));
                    break;

                case WOLFCLU_AES192CTR:
                    XSTRNCPY(name, WOLFCLU_AES192CTR_NAME,
                            XSTRLEN(WOLFCLU_AES192CTR_NAME));
                    break;

                case WOLFCLU_AES256CTR:
                    XSTRNCPY(name, WOLFCLU_AES256CTR_NAME,
                            XSTRLEN(WOLFCLU_AES256CTR_NAME));
                    break;

                case WOLFCLU_AES128CBC:
                    XSTRNCPY(name, WOLFCLU_AES128CBC_NAME,
                            XSTRLEN(WOLFCLU_AES128CBC_NAME));
                    break;

                case WOLFCLU_AES192CBC:
                    XSTRNCPY(name, WOLFCLU_AES192CBC_NAME,
                            XSTRLEN(WOLFCLU_AES192CBC_NAME));
                    break;

                case WOLFCLU_AES256CBC:
                    XSTRNCPY(name, WOLFCLU_AES256CBC_NAME,
                            XSTRLEN(WOLFCLU_AES256CBC_NAME));
                    break;

                /* camellia */
                case WOLFCLU_CAMELLIA128CBC:
                    XSTRNCPY(name, WOLFCLU_CAMELLIA128CBC_NAME,
                            XSTRLEN(WOLFCLU_CAMELLIA128CBC_NAME));
                    break;

                case WOLFCLU_CAMELLIA192CBC:
                    XSTRNCPY(name, WOLFCLU_CAMELLIA192CBC_NAME,
                            XSTRLEN(WOLFCLU_CAMELLIA192CBC_NAME));
                    break;

                case WOLFCLU_CAMELLIA256CBC:
                    XSTRNCPY(name, WOLFCLU_CAMELLIA256CBC_NAME,
                            XSTRLEN(WOLFCLU_CAMELLIA256CBC_NAME));
                    break;

                /* 3des */
                case WOLFCLU_DESCBC:
                    XSTRNCPY(name, WOLFCLU_DESCBC_NAME,
                            XSTRLEN(WOLFCLU_DESCBC_NAME));
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
 * secure data entry by turning off key echoing in the terminal
 * return WOLFCLU_SUCCESS on success
 */
int wolfCLU_noEcho(char* pwdKey, int size)
{
    struct termios oflags, nflags;
    char* success;
    int ret;

    /* disabling echo */
    tcgetattr(fileno(stdin), &oflags);
    nflags = oflags;
    nflags.c_lflag &= ~ECHO;
    nflags.c_lflag |= ECHONL;

    if (tcsetattr(fileno(stdin), TCSANOW, &nflags) != 0) {
        WOLFCLU_LOG(WOLFCLU_L0, "Error");
        return WOLFCLU_FATAL_ERROR;
    }

    WOLFCLU_LOG(WOLFCLU_L0, "pwdKey: ");
    success = fgets(pwdKey, size, stdin);
    if (success == NULL) {
        /* User wants manual input to be encrypted
         * Do Nothing
         */
    }

    pwdKey[strlen(pwdKey) - 1] = 0;

    /* restore terminal */
    ret = tcsetattr(fileno(stdin), TCSANOW, &oflags);
    if (ret != 0) {
        WOLFCLU_LOG(WOLFCLU_L0, "Error");
        return WOLFCLU_FATAL_ERROR;
    }
    return WOLFCLU_SUCCESS;
}

/*
 * adds character to end of string
 */
void wolfCLU_append(char* s, char c)
{
    int len = (int) strlen(s); /* length of string*/

    s[len] = c;
    s[len+1] = '\0';
}

/*
 * resets benchmarking loop
 */
void wolfCLU_stop(int signo)
{
    (void) signo; /* type cast to void for unused variable */
    loop = 0;
}

/*
 * gets current time durring program execution
 */
double wolfCLU_getTime(void)
{
    struct timeval tv;

    gettimeofday(&tv, 0);

    return (double)tv.tv_sec + (double)tv.tv_usec / 1000000;
}

/*
 * prints out stats for benchmarking
 */
void wolfCLU_stats(double start, int blockSize, int64_t blocks)
{
    double mbs;
    double time_total = wolfCLU_getTime() - start;

    WOLFCLU_LOG(WOLFCLU_L0, "took %6.3f seconds, blocks = %llu", time_total,
            (unsigned long long)blocks);

    mbs = ((blocks * blockSize) / MEGABYTE) / time_total;
    WOLFCLU_LOG(WOLFCLU_L0, "Average MB/s = %8.1f", mbs);
    if (blockSize != MEGABYTE) {
        WOLFCLU_LOG(WOLFCLU_L0, "Block size of this algorithm is: %d.\n", blockSize);
    }
    else {
        WOLFCLU_LOG(WOLFCLU_L0, "Benchmarked using 1 Megabyte at a time\n");
    }
}


/* returns WOLFCLU_SUCCESS on success */
int wolfCLU_version()
{
    WOLFCLU_LOG(WOLFCLU_L0, "You are using version %s of the wolfssl Command Line Utility."
        , CLUWOLFSSL_VERSION_STRING);
    WOLFCLU_LOG(WOLFCLU_L0, "Linked to wolfSSL version %s", LIBWOLFSSL_VERSION_STRING);
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
        else if (XSTRNCMP(searchTerm, "-help", length) == 0 &&
                   XSTRNCMP(argv[i], "-help", XSTRLEN(argv[i])) == 0 &&
                   (int)XSTRLEN(argv[i]) > 0) {
           return 1;

        }
        else if (XMEMCMP(argv[i], searchTerm, length) == 0 &&
                   (int)XSTRLEN(argv[i]) == length) {

            ret = i;
            if (argFound == 1) {
                WOLFCLU_LOG(WOLFCLU_L0, "ERROR: argument found twice: \"%s\"", searchTerm);
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
        WOLFCLU_LOG(WOLFCLU_L0, "Usage: -outform [PEM/DER]");
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
    else {
        WOLFCLU_LOG(WOLFCLU_L0, "Usage: -outform [PEM/DER]");
        WOLFCLU_LOG(WOLFCLU_L0, "\"%s\" is not a valid output format", outform);
    }
    return USER_INPUT_ERROR;
}

int wolfCLU_checkInform(char* inform)
{
    if (inform == NULL) {
        WOLFCLU_LOG(WOLFCLU_L0, "Usage: -inform [PEM/DER]");
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
    else {
        WOLFCLU_LOG(WOLFCLU_L0, "Usage: -inform [PEM/DER]");
        WOLFCLU_LOG(WOLFCLU_L0, "\"%s\" is not a valid input format", inform);
    }
    return USER_INPUT_ERROR;
}


static void wolfCLU_AddNameEntry(WOLFSSL_X509_NAME* name, int type, int nid,
        char* str)
{
    int i, sz;
    WOLFSSL_X509_NAME_ENTRY *entry;

    if (str != NULL) {
        /* strip off newline character if found at the end of str */
        i = (int)XSTRLEN((const char*)str);
        while (i >= 0) {
            if (str[i] == '\n') {
                str[i] = '\0';
                break;
            }
            i--;
        }

        /* treats an empty string as 'do not add' */
        sz = (int)XSTRLEN((const char*)str);
        if (sz > 0) {
            entry = wolfSSL_X509_NAME_ENTRY_create_by_NID(NULL, nid,
                type, (const unsigned char*)str, sz);
            wolfSSL_X509_NAME_add_entry(name, entry, -1, 0);
        }
    }
}


/* returns WOLFCLU_SUCCESS on success */
int wolfCLU_CreateX509Name(WOLFSSL_X509_NAME* name)
{
    char   *in = NULL;
    size_t  inSz;
    ssize_t ret;
    FILE *fin = stdin; /* defaulting to stdin but using a fd variable to make it
                        * easy for expanding to other inputs */

    WOLFCLU_LOG(WOLFCLU_L0, "Enter without data will result in the field being "
            "skipped.\nExamples of inputs are provided as [*]");
    WOLFCLU_LOG(WOLFCLU_L0, "Country [US] : ");
    ret = getline(&in, &inSz, fin);
    if (ret > 0) {
        wolfCLU_AddNameEntry(name, CTC_PRINTABLE, NID_countryName, in);
        free(in); in = NULL;
    }

    WOLFCLU_LOG(WOLFCLU_L0, "State or Province [Montana] : ");
    ret = getline(&in, &inSz, fin);
    if (ret > 0) {
        wolfCLU_AddNameEntry(name, CTC_UTF8, NID_stateOrProvinceName, in);
        free(in); in = NULL;
    }

    WOLFCLU_LOG(WOLFCLU_L0, "Locality [Bozeman] : ");
    ret = getline(&in, &inSz, fin);
    if (ret > 0) {
        wolfCLU_AddNameEntry(name, CTC_UTF8, NID_localityName, in);
        free(in); in = NULL;
    }

    WOLFCLU_LOG(WOLFCLU_L0, "Organization Name [wolfSSL] : ");
    ret = getline(&in, &inSz, fin);
    if (ret > 0) {
        wolfCLU_AddNameEntry(name, CTC_UTF8, NID_organizationName, in);
        free(in); in = NULL;
    }

    WOLFCLU_LOG(WOLFCLU_L0, "Organization Unit [engineering] : ");
    ret = getline(&in, &inSz, fin);
    if (ret > 0) {
        wolfCLU_AddNameEntry(name, CTC_UTF8, NID_organizationalUnitName, in);
        free(in); in = NULL;
    }

    WOLFCLU_LOG(WOLFCLU_L0, "Common Name : ");
    ret = getline(&in, &inSz, fin);
    if (ret > 0) {
        wolfCLU_AddNameEntry(name, CTC_UTF8, NID_commonName, in);
        free(in); in = NULL;
    }

    WOLFCLU_LOG(WOLFCLU_L0, "Email Address : ");
    ret = getline(&in, &inSz, fin);
    if (ret > 0) {
        wolfCLU_AddNameEntry(name, CTC_UTF8, NID_emailAddress, in);
        free(in); in = NULL;
    }

    return WOLFCLU_SUCCESS;
}


void wolfCLU_convertToLower(char* s, int sSz)
{
    int i;
    for (i = 0; i < sSz; i++) {
        s[i] = tolower(s[i]);
    }
}


