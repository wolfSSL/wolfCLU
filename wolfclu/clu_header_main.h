/* clu_header_main.h
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

#ifndef _WOLFSSL_CLU_HEADER_
#define _WOLFSSL_CLU_HEADER_

#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>
#include <stdio.h>

#ifdef _WIN32 /* running on windows */
#include <winsock2.h>
#include <windows.h>
#include <corecrt_io.h>
#include <sys/timeb.h>

#else
#include <unistd.h>
#include <sys/time.h>
#ifndef FREERTOS
#include <termios.h>
#endif
#endif

/* wolfssl includes */
#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#include <wolfssl/error-ssl.h>
#include <wolfssl/ssl.h>
#include <wolfssl/version.h>
#include <wolfssl/openssl/bio.h>
#include <wolfssl/openssl/pem.h>
#include <wolfssl/openssl/x509v3.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/dsa.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/pwdbased.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/des3.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/signature.h>
#include <wolfssl/wolfcrypt/pkcs12.h>
#ifndef WOLFCLU_NO_FILESYSTEM
#include <wolfssl/test.h>
#endif

#ifdef HAVE_FIPS
    #include <wolfssl/wolfcrypt/fips_test.h>
#endif

#ifndef NO_MD5
    #include <wolfssl/wolfcrypt/md5.h>
#endif

#ifndef NO_SHA
    #include <wolfssl/wolfcrypt/sha.h>
#endif

#ifndef NO_SHA256
    #include <wolfssl/wolfcrypt/sha256.h>
#endif

#ifdef WOLFSSL_SHA512
    #include <wolfssl/wolfcrypt/sha512.h>
#endif

#ifdef HAVE_BLAKE2
    #include <wolfssl/wolfcrypt/blake2.h>
#endif

#ifdef HAVE_CAMELLIA
    #include <wolfssl/wolfcrypt/camellia.h>
#endif

#include <wolfssl/wolfcrypt/coding.h>

#define BLOCK_SIZE 16384
#define MEGABYTE (1024*1024)
#define KILOBYTE 1024
#ifdef FREERTOS
	#define BYTE_UNIT KILOBYTE
#else
	#define BYTE_UNIT MEGABYTE
#endif
#define MAX_TERM_WIDTH 80
#define MAX_THREADS 64
#define MAX_STDINSZ 8192
#ifndef MAX_FILENAME_SZ
    #define MAX_FILENAME_SZ 256
#endif
#define CLU_4K_TYPE 4096
#if LIBWOLFSSL_VERSION_HEX >= 50413568 /* int val of hex 0x0301400 = 50413568 */
    #define CLU_SHA256 WC_SHA256
#else
    #define CLU_SHA256 SHA256
#endif

#include <wolfssl/wolfcrypt/types.h>

#ifdef WOLFSSL_STATIC_MEMORY
    #include <wolfssl/wolfcrypt/memory.h>
    static WOLFSSL_HEAP_HINT* HEAP_HINT;
#else
    #define HEAP_HINT NULL
#endif

#include <wolfclu/clu_error_codes.h>

#ifdef WOLFCLU_NO_FILESYSTEM
    #define WOLFCLU_NO_TERM_SUPPORT
#endif

 /* @VERSION
  * Update every time library change,
  * functionality shift,
  * or code update
  */
#define VERSION 0.3

/**
 * @brief structs and variables to parse commands
 */
struct option
{
    const char *name;
    int has_arg;
    int *flag;
    int val;
};

#define required_argument 1
#define no_argument       0

/* define macros, functions, and data types for windows */
#ifdef _WIN32

#define int64_t long long
#define access _access
#define F_OK 00
#define strtok_r strtok_s

extern char* optarg;
extern int   optind ;
extern int   opterr ;
#endif

/* encryption argument function
 *
 * @param argc holds all command line input
 * @param argv each holds one value from the command line input
 * @param action forwarded from wolfCLU_main (-e, -d, -h, or -b)
 */
int wolfCLU_setup(int argc, char** argv, char action);


/* Handle ecparam mode
 *
 * @param argc holds all command line input
 * @param argv each holds one value from the command line input
 * @return returns WOLFLCU_SUCCESS on success
 */
int wolfCLU_ecparam(int argc, char** argv);

/* hash argument function
 *
 * @param argc holds all command line input
 * @param argv each holds one value from the command line input
 */
int wolfCLU_hashSetup(int argc, char** argv);

/* benchmark argument function
 *
 * @param argc holds all command line input
 * @param argv each holds one value from the command line input
 */
int wolfCLU_benchSetup(int argc, char** argv);

/*
 * generic help function
 */
void wolfCLU_help(void);

/*
 * verbose help function
 */
void wolfCLU_verboseHelp(void);

/*
 * encrypt help function
 */
void wolfCLU_encryptHelp(void);

/*
 * decrypt help function
 */
void wolfCLU_decryptHelp(void);

/*
 * hash help function
 */
void wolfCLU_hashHelp(void);

/*
 * benchmark help function
 */
void wolfCLU_benchHelp(void);

/*
 * genkey help function
 */
void wolfCLU_genKeyHelp(void);

/*
 * sign help function
 */
void wolfCLU_signHelp(int);

/*
 * verify help function
 */
void wolfCLU_verifyHelp(int);

/*
 * certgen help function
 */
void wolfCLU_certgenHelp(void);


/* find algorithm for encryption/decryption
 *
 * @param name the whole line sent from user. Example: "aes-cbc-128"
 * @param alg the algorithm specified by the user (aes, 3des, or camellia)
 * @param mode the mode as set by the user (cbc or ctr)
 * @param size set based on the algorithm specified
 */
int wolfCLU_getAlgo(int argc, char** argv, int* alg, char** mode, int* size);


/* find algorithm EVP cipher from alog enum
 *
 * @param alg the algorithm specified by the user (aes, 3des, or camellia)
 */
const WOLFSSL_EVP_CIPHER* wolfCLU_CipherTypeFromAlgo(int alg);

/* adds characters to end of string
 *
 * @param s the char array we'll be appending to
 * @param c the char that will be appended to s
 */
void wolfCLU_append(char* s, char c);

/* interrupt function
 *
 * @param signo gets type cast to void, interrupts the loop.
 */
void wolfCLU_stop(int signo);

/* finds current time during runtime */
double wolfCLU_getTime(void);

/* A function to convert from Hex to Binary
 *
 * @param h1 a char array containing hex values to be converted, can be NULL
 * @param h2 a char array containing hex values to be converted, can be NULL
 * @param h3 a char array containing hex values to be converted, can be NULL
 * @param h4 a char array containing hex values to be converted, can be NULL
 * @param b1 a buffer to store the result of h1 conversion, can be NULL
 * @param b2 a buffer to store the result of h2 conversion, can be NULL
 * @param b3 a buffer to store the result of h3 conversion, can be NULL
 * @param b4 a buffer to store the result of h4 conversion, can be NULL
 * @param b1Sz a word32 that will be set after conversion of b1, can be NULL
 * @param b2Sz a word32 that will be set after conversion of b2, can be NULL
 * @param b3Sz a word32 that will be set after conversion of b3, can be NULL
 * @param b4Sz a word32 that will be set after conversion of b4, can be NULL
 */
int wolfCLU_hexToBin(const char* h1, byte** b1, word32* b1Sz,
                    const char* h2, byte** b2, word32* b2Sz,
                    const char* h3, byte** b3, word32* b3Sz,
                    const char* h4, byte** b4, word32* b4Sz);

/* A function to free MALLOCED buffers
 *
 * @param b1 a buffer to be freed, can be set to NULL
 * @param b2 a buffer to be freed, can be set to NULL
 * @param b3 a buffer to be freed, can be set to NULL
 * @param b4 a buffer to be freed, can be set to NULL
 * @param b5 a buffer to be freed, can be set to NULL
 */
void wolfCLU_freeBins(byte* b1, byte* b2, byte* b3, byte* b4, byte* b5);

/* function to display stats results from benchmark
 *
 * @param start the time when the benchmark was started
 * @param blockSize the block size of the algorithm being benchmarked
 */
void wolfCLU_stats(double start, int blockSize, int64_t blocks);

/* encryption function
 *
 * @param alg this will be the algorithm to use as specified by the user
 *        options include: aes, 3des, or camellia
 * @param mode this is the mode to be used for the encryption
 *        cbc is used with all of the above with an optional ctr for aes
 * @param pwdKey this is the user provided password to be used as the key
 * @param key if entered must be in hex, can be used to verify encryption with
 *            nist test vectors.
 * @param size this is set by wolfCLU_GetAlgo and is used to stretch the
 *        password
 * @param in the filename or user input from command line
 * @param out the filename to output following en/de cryption
 * @param iv if entered must be in hex otherwise generated at run time
 * @param block size of block as determined by the algorithm being used
 * @param ivCheck a flag if user inputs a specific IV
 * @param inputHex a flag to specify encrypting hex data, instead of byte data
 */
int wolfCLU_encrypt(int alg, char* mode, byte* pwdKey, byte* key, int size,
                                char* in, char* out, byte* iv, int block,
                                int ivCheck, int inputHex);

/* decryption function
 *
 * @param alg this will be the algorithm to use as specified by the user
 *        options include: aes, 3des, or camellia
 * @param mode this is the mode to be used for the encryption
 *        cbc is used with all of the above with an optional ctr for aes
 * @param pwdKey this is the user provided password to be used as the key
 * @param key if entered must be in hex, can be used to verify encryption with
 *            nist test vectors.
 * @param size this is set by wolfCLU_GetAlgo and is used to stretch the
 *        password
 * @param in the filename or user input from command line
 * @param out the filename to output following en/de cryption
 * @param iv if entered must be in hex otherwise generated at run time
 * @param block size of block as determined by the algorithm being used
 * @param keyType let's decrypt know if it's using a password based key or a
 *        hexidecimal, user specified key.
 */
int wolfCLU_decrypt(int alg, char* mode, byte* pwdKey, byte* key, int size,
                    char* in, char* out, byte* iv, int block, int keyType);


/* encrypt and decrypt function
 *
 * @param alg this will be the algorithm to use as specified by the user
 *        options include: aes, 3des, or camellia
 * @param mode this is the mode to be used for the encryption
 *        cbc is used with all of the above with an optional ctr for aes
 * @param pwdKey this is the user provided password to be used as the key
 * @param key if entered must be in hex, can be used to verify encryption with
 *            nist test vectors.
 * @param keySz this is the size of the key in bytes
 * @param in the filename input
 * @param out the filename to output, if null then stdout
 * @param iv if entered must be in hex otherwise generated at run time
 * @param hexOut to output in hex
 * @param enc if set to 1 then do encryption 0 for decryption
 * @param pbkVersion WOLFCLU_PBKDF2 or WOLFCLU_PBKDF1
 * @param hashType the hash type to use with key/iv generation
 * @param printOut set to 1 for debug print outs
 */
int wolfCLU_evp_crypto(const WOLFSSL_EVP_CIPHER* cphr, char* mode, byte* pwdKey,
        byte* key, int keySz, char* fileIn, char* fileOut, char* hexIn,
        byte* iv, int hexOut, int enc, int pbkVersion,
        const WOLFSSL_EVP_MD* hashType, int printOut, int isBase64,
        int noSalt);

/* benchmarking function
 *
 * @param timer a timer to be started and stopped for benchmarking purposes
 * @param option a flag to allow benchmark execution
 */
int wolfCLU_benchmark(int timer, int* option);

/* hashing function
 *
 * @param in
 * @param len
 * @param out
 * @param alg
 * @param size
 */
int wolfCLU_hash(WOLFSSL_BIO* bioIn, WOLFSSL_BIO* bioOut, const char* alg,
        int size);


/**
 * @brief Used to create a hash from a specified algorithm
 *
 * @param argc total number of args
 * @param argv array of arg strings
 * @return WOLFCLU_SUCCESS on success
 */
int wolfCLU_algHashSetup(int argc, char** argv, int algorithm);

/*
 * get the current Version
 */
int wolfCLU_version(void);

/**
 * @brief Used to check for specified command
 */
int wolfCLU_GetOpt(int argc, char** argv, const char *options, const struct option *long_options, int *opt_index);

/**
 * @brief wolfCLU getline() implementation
 */
size_t wolfCLU_getline(char **line, size_t *len, FILE *fp);

/*
 * generic function to check for a specific input argument. Return the
 * argv[i] where argument was found. Useful for getting following value after
 * arg.
 * EXAMPLE:
 * --------------------
 * int ret;
 * char myString[BIG_ENOUGH_FOR_INPUT];
 * ret = wolfCLU_checkForArg("-somearg");
 * if (ret > 0)
 *     XSTRNCPY(myString, argv[ret+1], XSTRLEN(argv[ret+1]));
 * else {
 *      <ERROR LOGIC>
 * }
 * --------------------
 *
 *
 */
int wolfCLU_checkForArg(const char* searchTerm, int length, int argc, char** argv);

/*
 * Verify valid output format
 */
int wolfCLU_checkOutform(char* outform);

/*
 * Verify valid input format
 */
int wolfCLU_checkInform(char* inform);


/**
 *  @ingroup X509
 *  @brief This function is used internally to parse a name string
 *
 *  @param n a null-terminated string in the form of /C=company/CN=common name
 *  @return newly create WOLFSSL_X509_NAME structure on success
 */
WOLFSSL_X509_NAME* wolfCLU_ParseX509NameString(const char* n, int nSz);


/**
 *  @ingroup X509
 *  @brief This function is used internally to get user input and fill out a
 *  WOLFSSL_X509_NAME structure.
 *
 *  @param x509 the name structure to be filled in
 *  @return WOLFCLU_SUCCESS On successfully setting the name
 */
int wolfCLU_CreateX509Name(WOLFSSL_X509_NAME* x509);


/**
 * @ingroup X509
 * @brief This function reads a configure file and creates the resulting
 *  WOLFSSL_X509 structure
 *
 * @param config file name of the config to read
 * @param sect   section in the config file to search for when reading
 * @param ext    optional section to read extensions from
 * @return a newly created WOLFSSL_X509 structure on success
 * @return null on fail
*/
int wolfCLU_readConfig(WOLFSSL_X509* x509, char* config, char* sect, char* ext);


/**
 * @brief used to read the 'extensions' section from a config file and put the
 *  extensions found into 'x509'
 */
int wolfCLU_setExtensions(WOLFSSL_X509* x509, WOLFSSL_CONF* conf, char* sect);

/**
 * @brief used to get an object for a given NID and set it to the given
 *  extension
 */
WOLFSSL_ASN1_OBJECT* wolfCLU_extenstionGetObjectNID(WOLFSSL_X509_EXTENSION *ext, int nid, int crit);

/**
 * @brief function to processes 'ca' command
 */
int wolfCLU_CASetup(int argc, char** argv);


/**
 * @brief converts a string to a wolfCrypt hash type
 */
enum wc_HashType wolfCLU_StringToHashType(char* in);


/**
 * @brief gets the wolfCrypt (i.e RSAk) type from a WOLFSSL_EVP_PKEY
 */
int wolfCLU_GetTypeFromPKEY(WOLFSSL_EVP_PKEY* key);


/**
 * @brief Converts a string to be all lower case
 */
void wolfCLU_convertToLower(char* s, int sSz);

/**
 * @brief handles PKCS7 command
 */
int wolfCLU_PKCS7(int argc, char** argv);

/**
 * @brief handles PKCS8 command
 */
int wolfCLU_PKCS8(int argc, char** argv);

/**
 * @brief handles PKCS12 command
 */
int wolfCLU_PKCS12(int argc, char** argv);

/**
 * @brief function to write 0 at each index of 'mem' passed in
 */
void wolfCLU_ForceZero(void* mem, unsigned int len);

/**
 * @brief example client
 */
int wolfCLU_Client(int argc, char** argv);

/**
 * @brief example server
 */
int wolfCLU_Server(int argc, char** argv);

/**
 * @brief function to get password from input
 */
int wolfCLU_GetPassword(char* password, int* passwordSz, char* arg);
#define MAX_PASSWORD_SIZE 256


/**
 * @brief function to generate random data
 */
int wolfCLU_Rand(int argc, char** argv);


/**
 * @brief function to generate dsa params and keys
 */
int wolfCLU_DsaParamSetup(int argc, char** argv);


/**
 * @brief function to encode/decode data in base64 format
 */
int wolfCLU_Base64Setup(int argc, char** argv);

/**
 * @brief function to generate dh params and keys
 */
int wolfCLU_DhParamSetup(int argc, char** argv);


/**
 * @brief function to handle OCSP commands (client and responder)
 */
int wolfCLU_OcspSetup(int argc, char** argv);

/**
 * @brief Get a simple HTTP GET request string
 * @return pointer to static HTTP GET request string
 */
const char* wolfCLU_GetDefaultHttpGet(void);

/**
 * @brief Get the length of the default HTTP GET request (without null terminator)
 * @return length of HTTP GET request
 */
int wolfCLU_GetDefaultHttpGetLength(void);

/**
 * @brief Get a simple HTTP 200 OK response string with HTML content
 * @return pointer to static HTTP response string
 */
const char* wolfCLU_GetDefaultHttpResponse(void);

/**
 * @brief Get the length of the default HTTP response (without null terminator)
 * @return length of HTTP response
 */
int wolfCLU_GetDefaultHttpResponseLength(void);

/**
 * @brief Build a custom HTTP GET request
 * @param path the path to request (e.g., "/index.html")
 * @param host optional host header value (can be NULL)
 * @param buffer buffer to write the request to
 * @param bufferSz size of the buffer
 * @return number of bytes written to buffer, or negative on error
 */
int wolfCLU_BuildHttpGet(const char* path, const char* host, char* buffer,
                         int bufferSz);

/**
 * @brief Build a simple HTTP response
 * @param statusCode HTTP status code (e.g., 200, 404)
 * @param statusText HTTP status text (e.g., "OK", "Not Found")
 * @param contentType MIME type (e.g., "text/html")
 * @param body response body content
 * @param buffer buffer to write the response to
 * @param bufferSz size of the buffer
 * @return number of bytes written to buffer, or negative on error
 */
int wolfCLU_BuildHttpResponse(int statusCode, const char* statusText,
                              const char* contentType, const char* body,
                              char* buffer, int bufferSz);

/* Platform-specific socket type */
#ifdef _WIN32
    #ifndef SOCKET_T
        #define SOCKET_T SOCKET
    #endif
#else
    #ifndef SOCKET_T
        #define SOCKET_T int
    #endif
    #ifndef INVALID_SOCKET
        #define INVALID_SOCKET (-1)
    #endif
#endif

/**
 * @brief Create and bind a server socket using tcp_listen
 * @param port pointer to port number (will be updated with actual port)
 * @return socket descriptor on success, INVALID_SOCKET on error
 */
SOCKET_T wolfCLU_HttpServerListen(word16* port);

/**
 * @brief Accept a client connection
 * @param serverfd server socket descriptor
 * @return client socket descriptor on success, INVALID_SOCKET on error
 */
SOCKET_T wolfCLU_ServerAccept(SOCKET_T serverfd);

/**
 * @brief Receive a complete HTTP request
 * @param clientfd client socket descriptor
 * @param buffer buffer to store request
 * @param bufferSz size of buffer
 * @return number of bytes received, or negative on error
 */
int wolfCLU_HttpServerRecv(SOCKET_T clientfd, byte* buffer, int bufferSz);

/**
 * @brief Send an HTTP response with OCSP content
 * @param clientfd client socket descriptor
 * @param body response body (OCSP response)
 * @param bodySz size of response body
 * @return 0 on success, negative on error
 */
int wolfCLU_HttpServerSendOcspResponse(SOCKET_T clientfd, const byte* body,
                                        int bodySz);

/**
 * @brief Send an HTTP error response
 * @param clientfd client socket descriptor
 * @param statusCode HTTP status code
 * @param statusMsg HTTP status message
 * @return 0 on success, negative on error
 */
int wolfCLU_HttpServerSendError(SOCKET_T clientfd, int statusCode,
                                 const char* statusMsg);

/**
 * @brief Close a socket
 * @param sockfd socket descriptor to close
 */
void wolfCLU_ServerClose(SOCKET_T sockfd);

/**
 * @brief Send all bytes on a socket, looping on partial writes and EINTR
 * @param sockfd socket descriptor
 * @param buf data to send
 * @param len number of bytes to send
 * @return number of bytes sent on success, negative on error
 */
int wolfCLU_SendAll(SOCKET_T sockfd, const char* buf, int len);

/**
 * @brief Parse HTTP POST request to extract OCSP request body
 * @param httpReq HTTP request buffer
 * @param httpReqSz size of HTTP request
 * @param body pointer to store body location (output)
 * @param bodySz pointer to store body size (output)
 * @return 0 on success, negative on error
 */
int wolfCLU_HttpServerParseRequest(const byte* httpReq, int httpReqSz,
                                    const byte** body, int* bodySz);

/* SCGI protocol functions */
/**
 * @brief Read and parse an SCGI request from socket
 * @param sockfd socket descriptor
 * @param buffer buffer to store the complete request
 * @param bufferSz size of buffer
 * @param req output structure to store parsed request (defined in clu_scgi.h)
 * @return 0 on success, negative on error
 */
struct ScgiRequest {
    const byte* body;
    int bodyLen;
    int contentLength;
    const char* requestMethod;
    const char* requestUri;
};
typedef struct ScgiRequest ScgiRequest;
int wolfCLU_ScgiReadRequest(SOCKET_T sockfd, byte* buffer, int bufferSz,
                             ScgiRequest* req);

/**
 * @brief Send SCGI response with status and body
 * @param sockfd socket descriptor
 * @param statusCode HTTP status code
 * @param statusText HTTP status text
 * @param contentType MIME type
 * @param body response body
 * @param bodyLen size of response body
 * @return 0 on success, negative on error
 */
int wolfCLU_ScgiSendResponse(SOCKET_T sockfd, int statusCode,
                              const char* statusText, const char* contentType,
                              const byte* body, int bodyLen);

/**
 * @brief Send SCGI error response
 * @param sockfd socket descriptor
 * @param statusCode HTTP status code
 * @param statusText HTTP status text (also used as body)
 * @return 0 on success, negative on error
 */
int wolfCLU_ScgiSendError(SOCKET_T sockfd, int statusCode,
                           const char* statusText);

/**
 * @brief Load certificate file in DER format (handles PEM conversion)
 * @param filename certificate file path
 * @param der pointer to store DER buffer (caller must XFREE)
 * @param derSz pointer to store DER size
 * @return 0 on success, negative on error
 */
int wolfCLU_LoadCertDer(const char* filename, byte** der, word32* derSz);

/**
 * @brief Load private key file in DER format (handles PEM conversion)
 * @param filename key file path
 * @param der pointer to store DER buffer (caller must XFREE)
 * @param derSz pointer to store DER size
 * @return 0 on success, negative on error
 */
int wolfCLU_LoadKeyDer(const char* filename, byte** der, word32* derSz);

/**
 * @brief Load certificate file and return DER size
 * @param filename certificate file path
 * @param outDer pointer to store DER buffer (caller must XFREE)
 * @return DER size on success, negative on error
 */
int wolfCLU_ReadCertDer(const char* filename, byte** outDer);


/**
 * @brief function to prompt user for password from stdin
 */
int wolfCLU_GetStdinPassword(byte* password, word32* passwordSz);

#ifdef __cplusplus
}
#endif

#endif /* _WOLFSSL_CLU_HEADER_ */
