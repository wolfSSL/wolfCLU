/* clu_cert_setup.c
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

#include <stdio.h>

#include <wolfclu/clu_header_main.h>
#include <wolfclu/clu_log.h>
#include <wolfclu/clu_error_codes.h>
#include <wolfclu/x509/clu_cert.h>
#include <wolfclu/x509/clu_parse.h>

#define PEM_BEGIN_CERT "-----BEGIN CERTIFICATE-----"
#define BEGIN_CERT_REQ "-----BEGIN CERTIFICATE REQUEST-----"

/* return WOLFCLU_SUCCESS on success */
int wolfCLU_certSetup(int argc, char** argv)
{
#ifndef WOLFCLU_NO_FILESYSTEM
    int idx;
    int ret = WOLFCLU_SUCCESS;
    int textFlag    = 0;   /* does user desire human readable cert info */
    int textPubkey  = 0;   /* does user desire human readable pubkey info */
    int nooutFlag   = 0;   /* are we outputting a file */
    int reqFlag     = 0;   /* set to read csr file */
    int silentFlag  = 0;   /* set to disable echo to command line */
    int modulus     = 0;   /* set to view modulus of cert */

    char* inFile  = NULL;   /* pointer to the inFile name */
    char* outFile = NULL;   /* pointer to the outFile name */
    char* extFile = NULL;   /* pointer to the config File name */
    char* ext     = NULL;   /* pointer to the extensions section's name in config File */
    int   inForm  = PEM_FORM; /* the input format */
    int   outForm = PEM_FORM; /* the output format */

    /* flags for printing out specific parts of the x509 */
    byte printSubject = 0;
    byte printIssuer  = 0;
    byte printSerial  = 0;
    byte printDates   = 0;
    byte printEmail   = 0;
    byte printFinger  = 0;
    byte printPurpose = 0;
    byte printSubjHash = 0;

    WOLFSSL_BIO* in  = NULL;
    WOLFSSL_BIO* keyIn = NULL;
    WOLFSSL_BIO* inMem = NULL;
    WOLFSSL_BIO* out = NULL;
    WOLFSSL_X509* x509 = NULL;
    WOLFSSL_EVP_PKEY* privkey = NULL;
    const WOLFSSL_EVP_MD* md = NULL;

    byte* inBufRaw = NULL;
    byte* inBuf = NULL;
    int inBufSz = 0;
    byte* inBufCertBegin = NULL;
    byte* tmpOutBuf = NULL;
    word32 tmpInBufSz = 0;
    word32 tmpOutBufSz = 0;
    const byte* derBufPtr = NULL;
    DerBuffer* derObj = NULL;

/*---------------------------------------------------------------------------*/
/* help */
/*---------------------------------------------------------------------------*/
    if (wolfCLU_checkForArg("-h", 2, argc, argv) > 0) {
        wolfCLU_certHelp();
        return WOLFCLU_SUCCESS;
    }

/*---------------------------------------------------------------------------*/
/* text */
/*---------------------------------------------------------------------------*/
    if (wolfCLU_checkForArg("-text", 5, argc, argv) > 0) {
        /* set flag for converting to human readable.
         */
        textFlag = 1;
    } /* Optional flag do not return error */
/*---------------------------------------------------------------------------*/
/* pubkey */
/*--------------------------------------------------------------------------*/
    if (wolfCLU_checkForArg("-pubkey", 7, argc, argv) > 0) {
        /* set flag for converting to human readable.
         */
        textPubkey = 1;
    } /* Optional flag do not return error */
/*---------------------------------------------------------------------------*/
/* signkey */
/*--------------------------------------------------------------------------*/
    if (ret == WOLFCLU_SUCCESS) {
        idx = wolfCLU_checkForArg("-signkey", 8, argc, argv);
        if (idx > 0) {
            /* If no error, then write keyFile */
            keyIn = wolfSSL_BIO_new_file(argv[idx+1], "rb");
            if (keyIn == NULL) {
                    wolfCLU_LogError("Unable to open private key file %s",
                            optarg);
                    ret = WOLFCLU_FATAL_ERROR;
                }
        }
        if (idx < 0) {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }
/*---------------------------------------------------------------------------*/
/* extFile */
/*--------------------------------------------------------------------------*/
    if (ret == WOLFCLU_SUCCESS) {
        idx = wolfCLU_checkForArg("-extfile", 8, argc, argv);
        if (idx > 0) {
            /* If no error, then write extFile */
            extFile = argv[idx+1];
        }
        if (idx < 0) {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }
/*---------------------------------------------------------------------------*/
/* extensions */
/*---------------------------------------------------------------------------*/
    if (ret == WOLFCLU_SUCCESS) {
        idx = wolfCLU_checkForArg("-extensions", 11, argc, argv);
        if (idx > 0) {
            /*If no error, then write extFile extension's section */
            ext = argv[idx+1];
        }
        if (idx < 0) {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }
/*---------------------------------------------------------------------------*/
/* inForm pem/der/??OTHER?? */
/*---------------------------------------------------------------------------*/
    if (ret == WOLFCLU_SUCCESS) {
        idx = wolfCLU_checkForArg("-inform", 7, argc, argv);
        if (idx > 0) {
            inForm = wolfCLU_checkInform(argv[idx+1]);
            if (inForm == USER_INPUT_ERROR) {
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
        if (idx < 0) {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

/*---------------------------------------------------------------------------*/
/* outForm pem/der/??OTHER?? */
/*---------------------------------------------------------------------------*/
    if (ret == WOLFCLU_SUCCESS) {
        idx = wolfCLU_checkForArg("-outform", 8, argc, argv);
        if (idx > 0) {
            outForm = wolfCLU_checkOutform(argv[idx+1]);
            if (outForm == USER_INPUT_ERROR) {
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
        if (idx < 0) {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }



/*---------------------------------------------------------------------------*/
/* in file */
/*---------------------------------------------------------------------------*/
    if (ret == WOLFCLU_SUCCESS) {
        idx = wolfCLU_checkForArg("-in", 3, argc, argv);
        if (idx > 0) {
            if (idx == USER_INPUT_ERROR) {
                ret = WOLFCLU_FATAL_ERROR;
            }
            else {
                /* set flag for in file and flag for input file OK if exists
                 * check for error case below. If no error then read in file */
                inFile = argv[idx+1];
                in = wolfSSL_BIO_new_file(inFile, "rb");
                if (in == NULL) {
                    wolfCLU_LogError("ERROR: in file \"%s\" does not"
                                     " exist", inFile);
                    ret = INPUT_FILE_ERROR;
                }
                if (ret == WOLFCLU_SUCCESS) {
                    if (access(inFile, F_OK) != 0) {
                        wolfCLU_LogError("ERROR: input file \"%s\" does"
                                         " not exist", inFile);
                        ret = INPUT_FILE_ERROR;
                    }
                }
            }
        }
        if (idx < 0) {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* -in not used, look for stdin for input */
    if (ret == WOLFCLU_SUCCESS && idx <= 0) {
        in = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
        if (in == NULL) {
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            if (wolfSSL_BIO_set_fp(in, stdin, BIO_NOCLOSE)
                    != WOLFSSL_SUCCESS) {
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
    }

/*---------------------------------------------------------------------------*/
/* out file */
/*---------------------------------------------------------------------------*/
    if (ret == WOLFCLU_SUCCESS) {
        idx = wolfCLU_checkForArg("-out", 4, argc, argv);
        if (idx > 0) {
            /* set flag for out file, check for error case below. If no error
             * then write outFile */
            outFile = argv[idx+1];
        }

        if (idx < 0) {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }
/*---------------------------------------------------------------------------*/
/* digest */
/*---------------------------------------------------------------------------*/
    if (ret == WOLFCLU_SUCCESS) {
        int tmp = 0;
        idx = wolfCLU_checkForArg("-sha1", 5, argc, argv);
        if (idx > 0) {
            md = wolfSSL_EVP_sha1();
            tmp = idx;
        }
        idx = wolfCLU_checkForArg("-sha224", 7, argc, argv);
        if (idx > 0 && idx > tmp) {
            md = wolfSSL_EVP_sha224();
            tmp = idx;
        }
        idx = wolfCLU_checkForArg("-sha256", 7, argc, argv);
        if (idx > 0 && idx > tmp) {
            md = wolfSSL_EVP_sha256();
            tmp = idx;
        }
        idx = wolfCLU_checkForArg("-sha384", 7, argc, argv);
        if (idx > 0 && idx > tmp) {
            md = wolfSSL_EVP_sha384();
            tmp = idx;
        }
        idx = wolfCLU_checkForArg("-sha512", 7, argc, argv);
        if (idx > 0 && idx > tmp) {
            md = wolfSSL_EVP_sha512();
        }
    }
/*---------------------------------------------------------------------------*/
/* noout */
/*---------------------------------------------------------------------------*/
    if (ret == WOLFCLU_SUCCESS &&
            wolfCLU_checkForArg("-noout", 6, argc, argv) > 0) {
        /* set flag for no output file */
        nooutFlag = 1;
    } /* Optional flag do not return error */
/*---------------------------------------------------------------------------*/
/* Request */
/*---------------------------------------------------------------------------*/
 if (ret == WOLFCLU_SUCCESS &&
         wolfCLU_checkForArg("-req", 4, argc, argv) > 0) {
        /* set flag for csr file */
        reqFlag = 1;
    }/* Optional flag do not return error */
/*---------------------------------------------------------------------------*/
/* silent */
/*---------------------------------------------------------------------------*/
    if (ret == WOLFCLU_SUCCESS &&
            wolfCLU_checkForArg("-silent", 7, argc, argv) > 0) {
        /* set flag for converting to human readable.
         * return NOT_YET_IMPLEMENTED error
         */
        silentFlag = 1;
	(void)silentFlag;
    } /* Optional flag do not return error */
/*---------------------------------------------------------------------------*/
/* modulus */
/*---------------------------------------------------------------------------*/
    if (ret == WOLFCLU_SUCCESS &&
            wolfCLU_checkForArg("-modulus", 8, argc, argv) > 0) {
        /* set flag for viewing modulus */
        modulus = 1;
    } /* Optional flag do not return error */
/*---------------------------------------------------------------------------*/
/* END ARG PROCESSING */
/*---------------------------------------------------------------------------*/

    if (ret == WOLFCLU_SUCCESS) {
        char read;

        /* In case input is stdin, we need to read byte by byte. */
        inMem = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
        while (wolfSSL_BIO_read(in, &read, 1) == 1) {
             wolfSSL_BIO_write(inMem, &read, 1);
        }

        inBufSz = wolfSSL_BIO_get_len(inMem);
        if (inBufSz <= 0) {
            wolfCLU_LogError("wolfSSL_BIO_get_len failed.");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            inBufRaw = (byte*)XMALLOC(inBufSz, HEAP_HINT,
                                      DYNAMIC_TYPE_TMP_BUFFER);
            if (inBufRaw == NULL) {
                ret = WOLFCLU_FATAL_ERROR;
            }
            else {
                if (wolfSSL_BIO_read(inMem, inBufRaw, inBufSz) != inBufSz) {
                    wolfCLU_LogError("Failed to read input.");
                    ret = WOLFCLU_FATAL_ERROR;
                }
                else {
                    if (inForm == PEM_FORM) {
                        /* Find the PEM certificate header. */
                        if (reqFlag) {
                             inBufCertBegin = (byte*)XSTRSTR((char*)inBufRaw,
                                                        BEGIN_CERT_REQ);
                        }
                        else {
                            inBufCertBegin = (byte*)XSTRSTR((char*)inBufRaw,
                                                        PEM_BEGIN_CERT);
                        }
                        if (inBufCertBegin == NULL) {
                            wolfCLU_LogError("Failed to find PEM "
                                             "certificate header.");
                            ret = WOLFCLU_FATAL_ERROR;
                        }
                        else {
                            inBufSz -= inBufCertBegin - inBufRaw;
                            inBuf = inBufCertBegin;
                        }
                    }
                    else {
                        inBuf = inBufRaw;
                    }
                }
            }
        }
    }

    wolfSSL_BIO_free(in);
    wolfSSL_BIO_free(inMem);

    if (ret == WOLFCLU_SUCCESS) {
        if (inForm == PEM_FORM) {
            if (reqFlag) {
                tmpInBufSz = wc_PemToDer(inBuf, inBufSz, CERTREQ_TYPE, &derObj, HEAP_HINT, NULL, NULL);
            }
            else {
                tmpInBufSz = wc_PemToDer(inBuf, inBufSz, CERT_TYPE, &derObj, HEAP_HINT, NULL, NULL);
            }
            if (tmpInBufSz != 0) {
                wolfCLU_LogError("wc_PemToDer failed");
                ret = WOLFCLU_FATAL_ERROR;
            }
            else if (reqFlag) {
                derBufPtr = derObj->buffer;
                x509 = wolfSSL_X509_REQ_d2i(NULL, derBufPtr, derObj->length);
            }
            else {
                derBufPtr = derObj->buffer;
                x509 = wolfSSL_d2i_X509(NULL, &derBufPtr, derObj->length);
            }
        }
        else if (inForm == DER_FORM) {
            derBufPtr = inBuf;
            x509 = wolfSSL_d2i_X509(NULL, &derBufPtr, inBufSz);
        }

        if (x509 == NULL) {
            wolfCLU_LogError("unable to parse input file");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS && md == NULL) {
        md = wolfSSL_EVP_sha256();
    }

    /* try to open self signeky file if set */
    if (ret == WOLFCLU_SUCCESS && keyIn != NULL) {
        privkey = wolfSSL_PEM_read_bio_PrivateKey(keyIn, NULL, NULL, NULL);
        if (privkey == NULL) {
            wolfCLU_LogError("Error reading key from file");
            ret = USER_INPUT_ERROR;
        }
        wolfSSL_BIO_free(keyIn);
    }

    if (ret == WOLFCLU_SUCCESS && extFile != NULL) {
        WOLFSSL_CONF *conf = NULL;
        long line = 0;

        conf = wolfSSL_NCONF_new(NULL);
        wolfSSL_NCONF_load(conf, extFile, &line);
        if (wolfSSL_NCONF_get_section(conf, ext) == NULL) {
            wolfCLU_LogError("Unable to find certificate extension "
                    "section %s", ext);
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            ret = wolfCLU_setExtensions(x509, conf, ext);
        }
        wolfSSL_NCONF_free(conf);
    }

    /*default to version 3 which supports extensions */
    if (ret == WOLFCLU_SUCCESS &&
           wolfSSL_X509_set_version(x509, WOLFSSL_X509_V3) != WOLFSSL_SUCCESS && reqFlag  ) {
        wolfCLU_LogError("Unable to set version 3 for cert");
        ret = WOLFCLU_FATAL_ERROR;
    }

    if (ret == WOLFCLU_SUCCESS && reqFlag) {
        if (wolfSSL_X509_check_private_key(x509, privkey) !=
                WOLFSSL_SUCCESS) {
            wolfCLU_LogError("Private key does not match with certificate");
            ret = WOLFCLU_FATAL_ERROR;
        }
        if (ret == WOLFCLU_SUCCESS && md != NULL) {
            if (wolfSSL_X509_sign(x509, privkey, md) <= 0) {
                wolfCLU_LogError("Error signing certificate");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
        wolfSSL_EVP_PKEY_free(privkey);
    }

    /* try to open output file if set */
    if (ret == WOLFCLU_SUCCESS && outFile != NULL) {
        out = wolfSSL_BIO_new_file(outFile, "wb");
        if (out == NULL) {
            wolfCLU_LogError("unable to open/create output file");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* write to stdout if out is not set */
    if (ret == WOLFCLU_SUCCESS && out == NULL) {
        out = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
        if (out == NULL) {
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            if (wolfSSL_BIO_set_fp(out, stdout, BIO_NOCLOSE)
                    != WOLFSSL_SUCCESS) {
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
    }

    /* Print out specific parts as requested */
    if (ret == WOLFCLU_SUCCESS) {
        if (wolfCLU_checkForArg("-subject", 8, argc, argv) != 0) {
            printSubject = 1;
        }
    }

    if (ret == WOLFCLU_SUCCESS && printSubject) {
        char* subject;

        subject = wolfSSL_X509_NAME_oneline(
                                     wolfSSL_X509_get_subject_name(x509), 0, 0);
        if (subject != NULL) {
            wolfSSL_BIO_write(out, subject, (int)XSTRLEN(subject));
            wolfSSL_BIO_write(out, "\n", (int)XSTRLEN("\n"));
            XFREE(subject, 0, DYNAMIC_TYPE_OPENSSL);
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        if (wolfCLU_checkForArg("-issuer", 7, argc, argv) != 0) {
            printIssuer = 1;
        }
    }

    if (ret == WOLFCLU_SUCCESS && printIssuer) {
        char* issuer;

        issuer = wolfSSL_X509_NAME_oneline(
                                     wolfSSL_X509_get_issuer_name(x509), 0, 0);
        if (issuer != NULL) {
            wolfSSL_BIO_write(out, issuer, (int)XSTRLEN(issuer));
            wolfSSL_BIO_write(out, "\n", (int)XSTRLEN("\n"));
            XFREE(issuer, 0, DYNAMIC_TYPE_OPENSSL);
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        if (wolfCLU_checkForArg("-serial", 7, argc, argv) != 0) {
            printSerial = 1;
        }
    }

    if (ret == WOLFCLU_SUCCESS && printSerial) {
        unsigned char serial[EXTERNAL_SERIAL_SIZE];
        int  sz;
        int  i;

        sz = (int)sizeof(serial);
        if (wolfSSL_X509_get_serial_number(x509, serial, &sz) ==
                WOLFSSL_SUCCESS) {
            if (wolfSSL_BIO_write(out, "serial=", (int)XSTRLEN("serial="))
                    <= 0) {
                ret = WOLFCLU_FATAL_ERROR;
            }

            for (i = 0; i < sz; i++) {
                char scratch[3];
                XSNPRINTF(scratch, 3, "%02X", serial[i]);
                if (ret == WOLFCLU_SUCCESS &&
                        wolfSSL_BIO_write(out, scratch, 2) <= 0) {
                    ret = WOLFCLU_FATAL_ERROR;
                    break;
                }
            }
            if (ret == WOLFCLU_SUCCESS &&
                    wolfSSL_BIO_write(out, "\n", (int)XSTRLEN("\n")) <= 0) {
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        if (wolfCLU_checkForArg("-dates", 6, argc, argv) != 0) {
            printDates = 1;
        }
    }

    if (ret == WOLFCLU_SUCCESS && printDates) {
        char notBefore[] = "notBefore=";
        char notAfter[] = "notAfter=";

        if (wolfSSL_BIO_write(out, notBefore, (int)XSTRLEN(notBefore)) < 0) {
            ret = WOLFCLU_FATAL_ERROR;
        }
        if (ret == WOLFCLU_SUCCESS &&
                wolfSSL_ASN1_TIME_print(out, wolfSSL_X509_get_notBefore(x509))
                    != WOLFSSL_SUCCESS) {
            ret = WOLFCLU_FATAL_ERROR;
        }
        if (ret == WOLFCLU_SUCCESS &&
                wolfSSL_BIO_write(out, "\n", (int)XSTRLEN("\n")) < 0) {
            ret = WOLFCLU_FATAL_ERROR;
        }
        if (ret == WOLFCLU_SUCCESS &&
                wolfSSL_BIO_write(out, notAfter, (int)XSTRLEN(notAfter)) < 0) {
            ret = WOLFCLU_FATAL_ERROR;
        }
        if (ret == WOLFCLU_SUCCESS &&
                wolfSSL_ASN1_TIME_print(out, wolfSSL_X509_get_notAfter(x509))
                != WOLFSSL_SUCCESS) {
            ret = WOLFCLU_FATAL_ERROR;
        }
        if (ret == WOLFCLU_SUCCESS &&
                wolfSSL_BIO_write(out, "\n", (int)XSTRLEN("\n")) < 0) {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        if (wolfCLU_checkForArg("-email", 6, argc, argv) != 0) {
            printEmail = 1;
        }
    }

    if (ret == WOLFCLU_SUCCESS && printEmail) {
        int emailSz;
        char* emailBuf = NULL;
        WOLFSSL_X509_NAME* name = NULL;

        name = wolfSSL_X509_get_subject_name(x509);
        if (name != NULL) {
            /* check if there is an email to print out */
            emailSz = wolfSSL_X509_NAME_get_text_by_NID(name, NID_emailAddress,
                NULL, 0);
            if (emailSz > 0) {
                emailSz += 2; /* +2 for \n\0 at the end of string */
                emailBuf = (char*)XMALLOC(emailSz, HEAP_HINT,
                        DYNAMIC_TYPE_TMP_BUFFER);
                if (emailBuf == NULL) {
                    ret = WOLFCLU_FATAL_ERROR;
                }

                if (ret == WOLFCLU_SUCCESS &&
                        wolfSSL_X509_NAME_get_text_by_NID(name,
                        NID_emailAddress, emailBuf, emailSz) <= 0) {
                    ret = WOLFCLU_FATAL_ERROR;
                }

                if (ret == WOLFCLU_SUCCESS) {
                    emailBuf[emailSz-2] = '\n';
                    emailBuf[emailSz-1] = '\0';
                }

                if (ret == WOLFCLU_SUCCESS &&
                        wolfSSL_BIO_write(out, emailBuf, (int)XSTRLEN(emailBuf))
                        < 0) {
                    ret = WOLFCLU_FATAL_ERROR;
                }

                if (emailBuf != NULL) {
                    XFREE(emailBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
                }
            }
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        if (wolfCLU_checkForArg("-fingerprint", 12, argc, argv) != 0) {
            printFinger = 1;
        }
    }

    if (ret == WOLFCLU_SUCCESS && printFinger) {
        int derSz;
        const unsigned char* der;
        byte digest[WC_MAX_DIGEST_SIZE];
        word32 digestSz = WC_MAX_DIGEST_SIZE;
        enum wc_HashType digestType = WC_HASH_TYPE_SHA;

        der = wolfSSL_X509_get_der(x509, &derSz);
        if (der != NULL) {
            digestSz = wc_HashGetDigestSize(digestType);
            if (wc_Hash(digestType, der, derSz, digest, digestSz) == 0) {
                char txt[MAX_TERM_WIDTH];
                word32 i;

                XSNPRINTF(txt, MAX_TERM_WIDTH, "SHA1 of cert. DER : ");
                if (wolfSSL_BIO_write(out, txt, (int)XSTRLEN(txt)) <= 0) {
                    ret = WOLFCLU_FATAL_ERROR;
                }

                for (i = 0; i < digestSz; i++) {
                    XSNPRINTF(txt, MAX_TERM_WIDTH, "%02X", digest[i]);
                    if (wolfSSL_BIO_write(out, txt, (int)XSTRLEN(txt)) <= 0) {
                        ret = WOLFCLU_FATAL_ERROR;
                        break;
                    }
                }
                if (ret == WOLFCLU_SUCCESS &&
                    wolfSSL_BIO_write(out, "\n", (int)XSTRLEN("\n")) < 0) {
                    ret = WOLFCLU_FATAL_ERROR;
                }
            }
        }

    }

    if (ret == WOLFCLU_SUCCESS) {
        if (wolfCLU_checkForArg("-purpose", 8, argc, argv) != 0) {
            printPurpose = 1;
        }
    }

    if (ret == WOLFCLU_SUCCESS && printPurpose) {
    #if LIBWOLFSSL_VERSION_HEX > 0x05001000
        unsigned int keyUsage;

        keyUsage = wolfSSL_X509_get_extended_key_usage(x509);
        if ((int)keyUsage < 0) {
            keyUsage = 0;
        }

        wolfCLU_extKeyUsagePrint(out, keyUsage, 0, 1);
    #else
        wolfCLU_LogError("Extended key function not supported by this"
                         " version of wolfSSL");
        ret = WOLFCLU_FATAL_ERROR;
    #endif
    }

    if (ret == WOLFCLU_SUCCESS) {
        if (wolfCLU_checkForArg("-hash", 5, argc, argv) != 0) {
            printSubjHash = 1;
        }
    }

    if (ret == WOLFCLU_SUCCESS && printSubjHash) {
    #if LIBWOLFSSL_VERSION_HEX > 0x05001000
        WOLFSSL_X509_NAME* name;
        unsigned long h;
        char txt[MAX_TERM_WIDTH];

        name = wolfSSL_X509_get_subject_name(x509);
        if (name != NULL) {
            h = wolfSSL_X509_NAME_hash(name);
            XSNPRINTF(txt, MAX_TERM_WIDTH, "%08lx", h);
            if (wolfSSL_BIO_write(out, txt, (int)XSTRLEN(txt)) <= 0) {
                ret = WOLFCLU_FATAL_ERROR;
            }

            if (ret == WOLFCLU_SUCCESS &&
                wolfSSL_BIO_write(out, "\n", (int)XSTRLEN("\n")) < 0) {
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
    #else
        wolfCLU_LogError("Subject name hash function not supported by"
                         " this version of wolfSSL");
        ret = WOLFCLU_FATAL_ERROR;
    #endif
    }

    /* write out human readable text if set to */
    if (ret == WOLFCLU_SUCCESS && textFlag) {
        if (wolfSSL_X509_print(out, x509) != WOLFSSL_SUCCESS) {
            wolfCLU_LogError("unable to print certificate out");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* print modulus */
    if (ret == WOLFCLU_SUCCESS && modulus) {
        EVP_PKEY *pkey;
        pkey = X509_get0_pubkey(x509);

        if (pkey == NULL) {
            wolfCLU_LogError("Modulus=unavailable");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            if (wolfSSL_EVP_PKEY_id(pkey) == EVP_PKEY_RSA) {
                    const WOLFSSL_BIGNUM *num;
                    char *hex;

                    wolfSSL_RSA_get0_key(EVP_PKEY_get0_RSA(pkey), &num, NULL, NULL);
                    hex = wolfSSL_BN_bn2hex(num);

                    if (hex != NULL) {
                        if (wolfSSL_BIO_write(out, "Modulus=", (int)XSTRLEN("Modulus="))
                                <= 0) {
                            ret = WOLFCLU_FATAL_ERROR;
                        }

                        if (ret == WOLFCLU_SUCCESS &&
                                wolfSSL_BIO_write(out, hex, (int)XSTRLEN(hex)) <= 0) {
                            ret = WOLFCLU_FATAL_ERROR;
                        }
                        XFREE(hex, NULL, DYNAMIC_TYPE_OPENSSL);
                    }

                    wolfSSL_BIO_write(out, "\n", (int)XSTRLEN("\n"));
            }
            else {
                char info[] = "Wrong Algorithm type";
                wolfSSL_BIO_write(out, info, (int)XSTRLEN(info));

            }
            wolfSSL_EVP_PKEY_free(pkey);
        }
    }

    /* write out public key if set to */
    if (ret == WOLFCLU_SUCCESS && textPubkey) {
        ret = wolfCLU_printX509PubKey(x509, out);
    }

    /* write out certificate */
    if (ret == WOLFCLU_SUCCESS && !nooutFlag) {
        byte* derBuf   = inBuf;
        int   derBufSz = inBufSz;

        /* if inform is PEM we convert to DER for excluding input that is not
         * part of the certificate */
        if (inForm == PEM_FORM) {
            if (reqFlag) {
                derBufSz = wolfSSL_i2d_X509(x509, &derBuf);
            }
            else {
                derBuf   = derObj->buffer;
                derBufSz = derObj->length;
            }
        }

        /* PEM/DER -> DER */
        if (outForm == DER_FORM) {
            if (wolfSSL_BIO_write(out, derBuf, derBufSz) <= 0) {
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
        /* PEM/DER -> PEM */
        else if (outForm == PEM_FORM) {
            tmpOutBufSz = wc_DerToPem(derBuf, derBufSz, NULL, 0, CERT_TYPE);
            if (tmpOutBufSz <= 0) {
                wolfCLU_LogError("wc_DerToPem to get necessary length failed");
                ret = WOLFCLU_FATAL_ERROR;
            }
            else {
                tmpOutBuf = (byte*)XMALLOC(tmpOutBufSz, HEAP_HINT,
                                           DYNAMIC_TYPE_TMP_BUFFER);
                if (tmpOutBuf == NULL) {
                    ret = WOLFCLU_FATAL_ERROR;
                }
                else {
                    if (wc_DerToPem(derBuf, derBufSz, tmpOutBuf, tmpOutBufSz,
                                    CERT_TYPE) <= 0) {
                        wolfCLU_LogError("wc_DerToPem failed");
                        ret = WOLFCLU_FATAL_ERROR;
                    }
                    else {
                        if (wolfSSL_BIO_write(out, tmpOutBuf,
                                              tmpOutBufSz) <= 0) {
                            ret = WOLFCLU_FATAL_ERROR;
                        }
                    }
                }
            }
        }
    }

    if (inBufRaw != NULL) {
        XFREE(inBufRaw, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (tmpOutBuf != NULL) {
        XFREE(tmpOutBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }
    wc_FreeDer(&derObj);
    wolfSSL_BIO_free(out);
    wolfSSL_X509_free(x509);

    return ret;
#else
    (void)argc;
    (void)argv;
    WOLFCLU_LOG(WOLFCLU_E0, "No filesystem support");
    return WOLFCLU_FATAL_ERROR;
#endif
}
