/* clu_pkcs8.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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
#include <wolfclu/pkey/clu_pkey.h>
#include <wolfclu/x509/clu_cert.h>
#include <wolfclu/x509/clu_parse.h>

#if !defined(NO_PKCS8) && !defined(WOLFCLU_NO_FILESYSTEM)

static const struct option pkcs8_options[] = {
    {"-in",           required_argument, 0, WOLFCLU_INFILE    },
    {"-out",          required_argument, 0, WOLFCLU_OUTFILE   },
    {"-inform",       required_argument, 0, WOLFCLU_INFORM    },
    {"-outform",      required_argument, 0, WOLFCLU_OUTFORM   },
    {"-passin",       required_argument, 0, WOLFCLU_PASSWORD  },
    {"-traditional",  no_argument,       0, WOLFCLU_RSALEGACY },
    {"-topk8",        no_argument,       0, WOLFCLU_TOPKCS8   },
    {"-nocrypt",      no_argument,       0, WOLFCLU_NOCRYPT   },
    {"-help",         no_argument,       0, WOLFCLU_HELP      },
    {"-h",            no_argument,       0, WOLFCLU_HELP      },

    {0, 0, 0, 0} /* terminal element */
};


static void wolfCLU_pKeyHelp(void)
{
    WOLFCLU_LOG(WOLFCLU_L0, "./wolfssl pkcs8");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-in file input for pkcs8");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-out file to write results to (default stdout)");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-inform pem/der");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-outform pem/der");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-passin password for encrypted keys");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-traditional use pkcs#1 format");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-topk8 use pkcs#8 format");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-nocrypt output unencrypted private key");
}

static int password_cb(char *buf, int size, int rwflag, void *u) {
    const char *pass = (const char *)u;
    int len = (int)XSTRLEN(pass);
    (void)rwflag;

    if (len > size)
        len = size;

    XMEMCPY(buf, pass, len);
    return len;
}
#endif

int wolfCLU_PKCS8(int argc, char** argv)
{
#if !defined(NO_PKCS8) && !defined(WOLFCLU_NO_FILESYSTEM)
    int ret    = WOLFCLU_SUCCESS;
    int option;
    int longIndex = 1;
    int inForm  = PEM_FORM;
    int outForm = PEM_FORM;
    int traditional = 0;
    int toPkcs8 = 0;
    int noCrypt = 0;
    WOLFSSL_EVP_PKEY *pkey = NULL;
    WOLFSSL_BIO *bioIn  = NULL;
    WOLFSSL_BIO *bioOut = NULL;
    char password[MAX_PASSWORD_SIZE];
    int passwordSz = MAX_PASSWORD_SIZE;
    byte* pass = NULL;

    opterr = 0; /* do not display unrecognized options */
    optind = 0; /* start at indent 0 */
    while ((option = wolfCLU_GetOpt(argc, argv, "",
                   pkcs8_options, &longIndex )) != -1) {
        switch (option) {
            case WOLFCLU_INFILE:
                bioIn = wolfSSL_BIO_new_file(optarg, "rb");
                if (bioIn == NULL) {
                    wolfCLU_LogError("Unable to open pkcs8 file %s",
                            optarg);
                    ret = WOLFCLU_FATAL_ERROR;
                }
                break;

            case WOLFCLU_OUTFILE:
                bioOut = wolfSSL_BIO_new_file(optarg, "wb");
                if (bioOut == NULL) {
                    wolfCLU_LogError("Unable to open output file %s",
                            optarg);
                    ret = WOLFCLU_FATAL_ERROR;
                }
                break;

            case WOLFCLU_INFORM:
                inForm = wolfCLU_checkInform(optarg);
                break;

            case WOLFCLU_OUTFORM:
                outForm = wolfCLU_checkOutform(optarg);
                break;

            case WOLFCLU_RSALEGACY:
                traditional = 1;
                break;

            case WOLFCLU_TOPKCS8:
                toPkcs8 = 1;
                break;

            case WOLFCLU_NOCRYPT:
                noCrypt = 1;
                break;

            case WOLFCLU_PASSWORD:
                ret = wolfCLU_GetPassword(password, &passwordSz, optarg);
                pass = (byte*)password;
                break;

            case WOLFCLU_HELP:
                wolfCLU_pKeyHelp();
                return WOLFCLU_SUCCESS;

            case ':':
            case '?':
                wolfCLU_LogError("Bad argument found");
                wolfCLU_pKeyHelp();
                ret = WOLFCLU_FATAL_ERROR;
                break;

            default:
                /* do nothing. */
                (void)ret;
        }
    }

    /* currently only supporting PKCS8 parsing, input is expected */
    if (ret == WOLFCLU_SUCCESS && bioIn == NULL) {
        byte keyBuffer[MAX_STDINSZ];
        word32 keyLen = 0;

        XMEMSET(keyBuffer, 0, MAX_STDINSZ);
        keyLen = (int)XFREAD(keyBuffer, 1, sizeof(keyBuffer) - 1, stdin);
        if (keyLen <= 0) {
            WOLFCLU_LOG(WOLFCLU_E0, "Error reading private key from stdin");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            /* Null-terminate the key buffer */
            keyBuffer[keyLen] = '\0';

            bioIn = wolfSSL_BIO_new_mem_buf(keyBuffer, keyLen);

            if (bioIn == NULL) {
                wolfCLU_LogError("Unable to open pkcs8 file %s",
                        optarg);
                ret = MEMORY_E;
            }
            else if (pass == NULL) {
            /* Reopen terminal since we might get password data
             * from stdin later */
            #ifdef USE_WINDOWS_API
                if (freopen("CON", "r", stdin) == NULL) {
            #else
                if (freopen("/dev/tty", "r", stdin) == NULL) {
            #endif
                    ret = WOLFCLU_FATAL_ERROR;
                }
            }
        }
    }

    if (ret == WOLFCLU_SUCCESS && pass == NULL) {
        if (inForm == PEM_FORM) {
            pkey = wolfSSL_PEM_read_bio_PrivateKey(bioIn, NULL, NULL, NULL);
        }
        else {
            pkey = wolfSSL_d2i_PrivateKey_bio(bioIn, NULL);
        }
    }

    if (ret == WOLFCLU_SUCCESS && pass == NULL && pkey == NULL) {
        wolfCLU_GetStdinPassword((byte*)password, (word32*)&passwordSz);
        pass = (byte*)password;
    }

    /* read the input bio to a temporary buffer and convert to PKCS8 */
    if (ret == WOLFCLU_SUCCESS && pkey == NULL) {
        wolfSSL_BIO_reset(bioIn);
        if (inForm == PEM_FORM) {
            pkey = wolfSSL_PEM_read_bio_PrivateKey(bioIn, NULL, NULL, pass);
        }
        else {
            pkey = wolfSSL_d2i_PKCS8PrivateKey_bio(bioIn, NULL, password_cb,
                                                    pass);
        }
    }

    if (ret == WOLFCLU_SUCCESS && pkey == NULL) {
        WOLFCLU_LOG(WOLFCLU_E0, "Error decrypting PKCS8 key");
        ret = WOLFCLU_FATAL_ERROR;
    }

    /* setup output bio to stdout if not already set */
    if (ret == WOLFCLU_SUCCESS && bioOut == NULL) {
        bioOut = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
        if (bioOut == NULL) {
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            if (wolfSSL_BIO_set_fp(bioOut, stdout, BIO_NOCLOSE)
                    != WOLFSSL_SUCCESS) {
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
    }

    if (ret == WOLFCLU_SUCCESS && toPkcs8 == 1 && noCrypt == 0) {
        WOLFCLU_LOG(WOLFCLU_E0, "Encrypting PKCS8 keys not yet supported");
        ret = WOLFCLU_FATAL_ERROR;
    }

    if (ret == WOLFCLU_SUCCESS && pkey != NULL) {
        if (outForm == DER_FORM) {
            unsigned char *der = NULL;
            int derSz = 0;

            if ((derSz = wolfCLU_pKeytoPriKey(pkey, &der)) <= 0) {
                WOLFCLU_LOG(WOLFCLU_E0,
                        "Error converting private key to der");
                ret = WOLFCLU_FATAL_ERROR;
            }

            if (ret == WOLFCLU_SUCCESS) {
                wolfSSL_BIO_write(bioOut, der, derSz);

            }

            if (der != NULL) {
                XFREE(der, HEAP_HINT, DYNAMIC_TYPE_OPENSSL);
            }
        }

        if (outForm == PEM_FORM && traditional == 1) {
            ret = wolfCLU_pKeyPEMtoPriKey(bioOut, pkey);
            if (ret != WOLFCLU_SUCCESS) {
                WOLFCLU_LOG(WOLFCLU_E0,
                        "Error writing from private key to pem");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
        else if (outForm == PEM_FORM) {
            if (wolfSSL_PEM_write_bio_PKCS8PrivateKey(bioOut, pkey, NULL, NULL,
                        0, NULL, NULL) == 0) {
                WOLFCLU_LOG(WOLFCLU_E0,
                        "Error writing from private key to pem");
                ret = WOLFCLU_FATAL_ERROR;
	    }
        }
    }

    wolfSSL_BIO_free(bioIn);
    wolfSSL_BIO_free(bioOut);
    wolfSSL_EVP_PKEY_free(pkey);

    return ret;
#else
    (void)argc;
    (void)argv;
#ifdef NO_PKCS8
    wolfCLU_LogError("Recompile wolfSSL with PKCS8 support");
#endif
#ifdef WOLFCLU_NO_FILESYSTEM
    wolfCLU_LogError("No filesystem support");
#endif
    return WOLFCLU_FATAL_ERROR;
#endif
}

