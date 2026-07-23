/* clu_cert_setup.c
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

#include <limits.h>

#include <wolfclu/clu_header_main.h>
#include <wolfclu/clu_log.h>
#include <wolfclu/clu_error_codes.h>
#include <wolfclu/clu_optargs.h>
#include <wolfclu/x509/clu_cert.h>
#include <wolfclu/x509/clu_parse.h>

#define PEM_BEGIN_CERT "-----BEGIN CERTIFICATE-----"
#define BEGIN_CERT_REQ "-----BEGIN CERTIFICATE REQUEST-----"

void wolfCLU_certHelp(void)
{
    WOLFCLU_LOG(WOLFCLU_L0, "\n");
    WOLFCLU_LOG(WOLFCLU_L0, "-inform pem or der in format");
    WOLFCLU_LOG(WOLFCLU_L0, "-in the file to read from");
    WOLFCLU_LOG(WOLFCLU_L0, "-outform pem or der out format");
    WOLFCLU_LOG(WOLFCLU_L0, "-out output file to write to");
    WOLFCLU_LOG(WOLFCLU_L0, "-req input file is a CSR file");
    WOLFCLU_LOG(WOLFCLU_L0, "-signkey a key for signing");
    WOLFCLU_LOG(WOLFCLU_L0, "-* supported digests for signing");
    WOLFCLU_LOG(WOLFCLU_L0, "-extfile config file");
    WOLFCLU_LOG(WOLFCLU_L0, "-extensions section of the config file to use");
    WOLFCLU_LOG(WOLFCLU_L0, "-noout no output");
    WOLFCLU_LOG(WOLFCLU_L0, "-subject print out the subject name");
    WOLFCLU_LOG(WOLFCLU_L0, "-issuer  print out the issuer name");
    WOLFCLU_LOG(WOLFCLU_L0, "-serial  print out the serial number in hex");
    WOLFCLU_LOG(WOLFCLU_L0, "-dates   print out the valid dates of cert");
    WOLFCLU_LOG(WOLFCLU_L0,
                "-email   print out the subject names email address");
    WOLFCLU_LOG(
        WOLFCLU_L0,
        "-fingerprint print out the hash of the certificate in DER form");
    WOLFCLU_LOG(WOLFCLU_L0, "-purpose print out the certificates purpose");
    WOLFCLU_LOG(WOLFCLU_L0,
                "-hash print out the hash of the certificate subject name");
    WOLFCLU_LOG(WOLFCLU_L0, "-text print human readable text of X509");
    WOLFCLU_LOG(WOLFCLU_L0, "-modulus print out the RSA key modulus");
    WOLFCLU_LOG(WOLFCLU_L0, "-pubkey print out the Public Key");
    WOLFCLU_LOG(
        WOLFCLU_L0,
        "***************************************************************");
    WOLFCLU_LOG(
        WOLFCLU_L0,
        "\nX509 USAGE: wolfssl x509 -inform <PEM or DER> -in <filename> "
        "-outform <PEM or DER> -out <output file name> \n");
    WOLFCLU_LOG(
        WOLFCLU_L0,
        "***************************************************************");
    WOLFCLU_LOG(WOLFCLU_L0,
                "\nEXAMPLE: \n\nwolfssl x509 -inform pem -in certs/"
                "ca-cert.pem -outform der -out certs/ca-cert-converted.der"
                "\n");
}

#ifndef WOLFCLU_NO_FILESYSTEM
static const struct option cert_options[] = {
    { "-sha1", no_argument, 0, WOLFCLU_CERT_SHA },
    { "-sha224", no_argument, 0, WOLFCLU_CERT_SHA224 },
    { "-sha256", no_argument, 0, WOLFCLU_CERT_SHA256 },
    { "-sha384", no_argument, 0, WOLFCLU_CERT_SHA384 },
    { "-sha512", no_argument, 0, WOLFCLU_CERT_SHA512 },

    { "-in", required_argument, 0, WOLFCLU_INFILE },
    { "-out", required_argument, 0, WOLFCLU_OUTFILE },
    { "-inform", required_argument, 0, WOLFCLU_INFORM },
    { "-outform", required_argument, 0, WOLFCLU_OUTFORM },
    { "-signkey", required_argument, 0, WOLFCLU_SIGNKEY },
    { "-extfile", required_argument, 0, WOLFCLU_EXTFILE },
    { "-extensions", required_argument, 0, WOLFCLU_EXTENSIONS },

    { "-req", no_argument, 0, WOLFCLU_REQ },
    { "-noout", no_argument, 0, WOLFCLU_NOOUT },
    { "-text", no_argument, 0, WOLFCLU_TEXT_OUT },
    { "-pubkey", no_argument, 0, WOLFCLU_PUBKEY },
    { "-modulus", no_argument, 0, WOLFCLU_MODULUS },
    { "-silent", no_argument, 0, WOLFCLU_SILENT },
    { "-subject", no_argument, 0, WOLFCLU_PRINT_SUBJECT },
    { "-issuer", no_argument, 0, WOLFCLU_PRINT_ISSUER },
    { "-serial", no_argument, 0, WOLFCLU_PRINT_SERIAL },
    { "-dates", no_argument, 0, WOLFCLU_PRINT_DATES },
    { "-email", no_argument, 0, WOLFCLU_PRINT_EMAIL },
    { "-fingerprint", no_argument, 0, WOLFCLU_FINGERPRINT },
    { "-purpose", no_argument, 0, WOLFCLU_PURPOSE },
    { "-hash", no_argument, 0, WOLFCLU_SUBJ_HASH },
    { "-h", no_argument, 0, WOLFCLU_HELP },
    { "-help", no_argument, 0, WOLFCLU_HELP },

    { 0, 0, 0, 0 } /* terminal element */
};
#endif

/* return WOLFCLU_SUCCESS on success */
int wolfCLU_certSetup(int argc, char **argv)
{
#ifndef WOLFCLU_NO_FILESYSTEM
    int option;
    int longIndex = 1;
    int ret = WOLFCLU_SUCCESS;
    int textFlag = 0;   /* does user desire human readable cert info */
    int textPubkey = 0; /* does user desire human readable pubkey info */
    int nooutFlag = 0;  /* are we outputting a file */
    int reqFlag = 0;    /* set to read csr file */
    int silentFlag = 0; /* set to disable echo to command line */
    int modulus = 0;    /* set to view modulus of cert */

    char *inFile = NULL;  /* pointer to the inFile name */
    char *outFile = NULL; /* pointer to the outFile name */
    char *extFile = NULL; /* pointer to the config File name */
    char *ext =
        NULL; /* pointer to the extensions section's name in config File */
    int inForm = PEM_FORM;  /* the input format */
    int outForm = PEM_FORM; /* the output format */

    /* flags for printing out specific parts of the x509 */
    byte printSubject = 0;
    byte printIssuer = 0;
    byte printSerial = 0;
    byte printDates = 0;
    byte printEmail = 0;
    byte printFinger = 0;
    byte printPurpose = 0;
    byte printSubjHash = 0;

    WOLFSSL_BIO *in = NULL;
    WOLFSSL_BIO *keyIn = NULL;
    WOLFSSL_BIO *inMem = NULL;
    WOLFSSL_BIO *out = NULL;
    WOLFSSL_X509 *x509 = NULL;
    WOLFSSL_EVP_PKEY *privkey = NULL;
    const WOLFSSL_EVP_MD *md = NULL;

    byte *inBufRaw = NULL;
    byte *inBuf = NULL;
    int inBufSz = 0;
    byte *inBufCertBegin = NULL;
    byte *tmpOutBuf = NULL;
    word32 tmpInBufSz = 0;
    word32 tmpOutBufSz = 0;
    const byte *derBufPtr = NULL;
    DerBuffer *derObj = NULL;

    opterr = 0; /* do not display unrecognized options */
    optind = 0; /* start at index 0 */
    while ((option = wolfCLU_GetOpt(argc, argv, "", cert_options,
                                    &longIndex)) != END_OF_ARGS) {
        switch (option) {
            case WOLFCLU_HELP:
                wolfCLU_certHelp();
                wolfSSL_BIO_free(keyIn);
                wolfSSL_BIO_free(in);
                return WOLFCLU_SUCCESS;

            case WOLFCLU_TEXT_OUT:
                textFlag = 1;
                break;

            case WOLFCLU_PUBKEY:
                textPubkey = 1;
                break;

            case WOLFCLU_SIGNKEY:
                keyIn = wolfSSL_BIO_new_file(optarg, "rb");
                if (keyIn == NULL) {
                    wolfCLU_LogError("Unable to open private key file");
                    ret = WOLFCLU_FATAL_ERROR;
                }
                break;

            case WOLFCLU_EXTFILE:
                extFile = optarg;
                break;

            case WOLFCLU_EXTENSIONS:
                ext = optarg;
                break;

            case WOLFCLU_INFORM:
                inForm = wolfCLU_checkInform(optarg);
                if (inForm == USER_INPUT_ERROR) {
                    ret = WOLFCLU_FATAL_ERROR;
                }
                break;

            case WOLFCLU_OUTFORM:
                outForm = wolfCLU_checkOutform(optarg);
                if (outForm == USER_INPUT_ERROR) {
                    ret = WOLFCLU_FATAL_ERROR;
                }
                break;

            case WOLFCLU_INFILE:
                inFile = optarg;
                if (inFile == NULL || access(inFile, F_OK) != 0) {
                    wolfCLU_LogError("ERROR: -in file does not exist");
                    ret = INPUT_FILE_ERROR;
                }
                else {
                    in = wolfSSL_BIO_new_file(inFile, "rb");
                    if (in == NULL) {
                        wolfCLU_LogError("Unable to open file passed to -in %s"
                                , inFile);
                        ret = WOLFCLU_FATAL_ERROR;
                    }
                }
                break;

            case WOLFCLU_OUTFILE:
                outFile = optarg;
                break;

            case WOLFCLU_CERT_SHA:
                md = wolfSSL_EVP_sha1();
                break;

            case WOLFCLU_CERT_SHA224:
                md = wolfSSL_EVP_sha224();
                break;

            case WOLFCLU_CERT_SHA256:
                md = wolfSSL_EVP_sha256();
                break;

            case WOLFCLU_CERT_SHA384:
                md = wolfSSL_EVP_sha384();
                break;

            case WOLFCLU_CERT_SHA512:
                md = wolfSSL_EVP_sha512();
                break;

            case WOLFCLU_NOOUT:
                nooutFlag = 1;
                break;

            case WOLFCLU_REQ:
                reqFlag = 1;
                break;

            case WOLFCLU_SILENT:
                silentFlag = 1;
                (void)silentFlag;
                break;

            case WOLFCLU_MODULUS:
                modulus = 1;
                break;

            case WOLFCLU_PRINT_SUBJECT:
                printSubject = 1;
                break;

            case WOLFCLU_PRINT_ISSUER:
                printIssuer = 1;
                break;

            case WOLFCLU_PRINT_SERIAL:
                printSerial = 1;
                break;

            case WOLFCLU_PRINT_DATES:
                printDates = 1;
                break;

            case WOLFCLU_PRINT_EMAIL:
                printEmail = 1;
                break;

            case WOLFCLU_FINGERPRINT:
                printFinger = 1;
                break;

            case WOLFCLU_PURPOSE:
                printPurpose = 1;
                break;

            case WOLFCLU_SUBJ_HASH:
                printSubjHash = 1;
                break;

            case ARG_FOUND_TWICE:
                wolfCLU_LogError("Found duplicate argument");
                ret = WOLFCLU_FATAL_ERROR;
                break;

            case ':':
            case '?':
                break;

            default:
                wolfCLU_LogError("Unsupported argument");
                ret = WOLFCLU_FATAL_ERROR;
        }

        if (ret != WOLFCLU_SUCCESS) {
            break;
        }
    }

    /* -in not used, look for stdin for input */
    if (ret == WOLFCLU_SUCCESS && in == NULL) {
        in = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
        if (in == NULL) {
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            if (wolfSSL_BIO_set_fp(in, stdin, BIO_NOCLOSE) != WOLFSSL_SUCCESS) {
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
    }

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
            inBufRaw = (byte *)XMALLOC(inBufSz + 1, HEAP_HINT,
                                       DYNAMIC_TYPE_TMP_BUFFER);
            if (inBufRaw == NULL) {
                ret = WOLFCLU_FATAL_ERROR;
            }
            else {
                inBufRaw[inBufSz] = '\0';
                if (wolfSSL_BIO_read(inMem, inBufRaw, inBufSz) != inBufSz) {
                    wolfCLU_LogError("Failed to read input.");
                    ret = WOLFCLU_FATAL_ERROR;
                }
                else {
                    if (inForm == PEM_FORM) {
                        /* Find the PEM certificate header. */
                        if (reqFlag) {
                            inBufCertBegin = (byte *)XSTRSTR((char *)inBufRaw,
                                                             BEGIN_CERT_REQ);
                        }
                        else {
                            inBufCertBegin = (byte *)XSTRSTR((char *)inBufRaw,
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
                tmpInBufSz = wc_PemToDer(inBuf, inBufSz, CERTREQ_TYPE, &derObj,
                                         HEAP_HINT, NULL, NULL);
            }
            else {
                tmpInBufSz = wc_PemToDer(inBuf, inBufSz, CERT_TYPE, &derObj,
                                         HEAP_HINT, NULL, NULL);
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
        keyIn = NULL;
    }

    if (ret == WOLFCLU_SUCCESS && extFile != NULL) {
        WOLFSSL_CONF *conf = NULL;
        long line = 0;

        conf = wolfSSL_NCONF_new(NULL);
        wolfSSL_NCONF_load(conf, extFile, &line);
        if (wolfSSL_NCONF_get_section(conf, ext) == NULL) {
            wolfCLU_LogError("Unable to find certificate extension "
                             "section %s",
                             ext);
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            ret = wolfCLU_setExtensions(x509, conf, ext);
        }
        wolfSSL_NCONF_free(conf);
    }

    /*default to version 3 which supports extensions */
    if (ret == WOLFCLU_SUCCESS &&
        wolfSSL_X509_set_version(x509, WOLFSSL_X509_V3) != WOLFSSL_SUCCESS &&
        reqFlag) {
        wolfCLU_LogError("Unable to set version 3 for cert");
        ret = WOLFCLU_FATAL_ERROR;
    }

    if (ret == WOLFCLU_SUCCESS && reqFlag) {
        if (wolfSSL_X509_check_private_key(x509, privkey) != WOLFSSL_SUCCESS) {
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
        privkey = NULL;
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
            if (wolfSSL_BIO_set_fp(out, stdout, BIO_NOCLOSE) !=
                WOLFSSL_SUCCESS) {
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
    }

    if (ret == WOLFCLU_SUCCESS && printSubject) {
        char *subject;

        subject = wolfSSL_X509_NAME_oneline(wolfSSL_X509_get_subject_name(x509),
                                            0, 0);
        if (subject != NULL) {
            wolfSSL_BIO_write(out, subject, (int)XSTRLEN(subject));
            wolfSSL_BIO_write(out, "\n", (int)XSTRLEN("\n"));
            XFREE(subject, 0, DYNAMIC_TYPE_OPENSSL);
        }
    }

    if (ret == WOLFCLU_SUCCESS && printIssuer) {
        char *issuer;

        issuer =
            wolfSSL_X509_NAME_oneline(wolfSSL_X509_get_issuer_name(x509), 0, 0);
        if (issuer != NULL) {
            wolfSSL_BIO_write(out, issuer, (int)XSTRLEN(issuer));
            wolfSSL_BIO_write(out, "\n", (int)XSTRLEN("\n"));
            XFREE(issuer, 0, DYNAMIC_TYPE_OPENSSL);
        }
    }

    if (ret == WOLFCLU_SUCCESS && printSerial) {
        unsigned char serial[EXTERNAL_SERIAL_SIZE];
        int sz;
        int i;

        sz = (int)sizeof(serial);
        if (wolfSSL_X509_get_serial_number(x509, serial, &sz) ==
            WOLFSSL_SUCCESS) {
            if (wolfSSL_BIO_write(out, "serial=", (int)XSTRLEN("serial=")) <=
                0) {
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

    if (ret == WOLFCLU_SUCCESS && printDates) {
        char notBefore[] = "notBefore=";
        char notAfter[] = "notAfter=";

        if (wolfSSL_BIO_write(out, notBefore, (int)XSTRLEN(notBefore)) < 0) {
            ret = WOLFCLU_FATAL_ERROR;
        }
        if (ret == WOLFCLU_SUCCESS &&
            wolfSSL_ASN1_TIME_print(out, wolfSSL_X509_get_notBefore(x509)) !=
                WOLFSSL_SUCCESS) {
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
            wolfSSL_ASN1_TIME_print(out, wolfSSL_X509_get_notAfter(x509)) !=
                WOLFSSL_SUCCESS) {
            ret = WOLFCLU_FATAL_ERROR;
        }
        if (ret == WOLFCLU_SUCCESS &&
            wolfSSL_BIO_write(out, "\n", (int)XSTRLEN("\n")) < 0) {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS && printEmail) {
        int emailSz;
        char *emailBuf = NULL;
        WOLFSSL_X509_NAME *name = NULL;

        name = wolfSSL_X509_get_subject_name(x509);
        if (name != NULL) {
            /* check if there is an email to print out */
            emailSz = wolfSSL_X509_NAME_get_text_by_NID(name, NID_emailAddress,
                                                        NULL, 0);
            if (emailSz > 0) {
                emailSz += 2; /* +2 for \n\0 at the end of string */
                emailBuf = (char *)XMALLOC(emailSz, HEAP_HINT,
                                           DYNAMIC_TYPE_TMP_BUFFER);
                if (emailBuf == NULL) {
                    ret = WOLFCLU_FATAL_ERROR;
                }

                if (ret == WOLFCLU_SUCCESS &&
                    wolfSSL_X509_NAME_get_text_by_NID(name, NID_emailAddress,
                                                      emailBuf, emailSz) <= 0) {
                    ret = WOLFCLU_FATAL_ERROR;
                }

                if (ret == WOLFCLU_SUCCESS) {
                    emailBuf[emailSz - 2] = '\n';
                    emailBuf[emailSz - 1] = '\0';
                }

                if (ret == WOLFCLU_SUCCESS &&
                    wolfSSL_BIO_write(out, emailBuf, (int)XSTRLEN(emailBuf)) <
                        0) {
                    ret = WOLFCLU_FATAL_ERROR;
                }

                if (emailBuf != NULL) {
                    XFREE(emailBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
                }
            }
        }
    }

    if (ret == WOLFCLU_SUCCESS && printFinger) {
        int derSz;
        const unsigned char *der;
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

    if (ret == WOLFCLU_SUCCESS && printSubjHash) {
#if LIBWOLFSSL_VERSION_HEX > 0x05001000
        WOLFSSL_X509_NAME *name;
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
                const WOLFSSL_BIGNUM *num = NULL;
                WOLFSSL_RSA *rsa;
                char *hex;

                rsa = EVP_PKEY_get0_RSA(pkey);
                if (rsa != NULL) {
                    wolfSSL_RSA_get0_key(rsa, &num, NULL, NULL);
                }
                if (num == NULL) {
                    wolfCLU_LogError("Modulus=unavailable");
                    ret = WOLFCLU_FATAL_ERROR;
                }
                hex = (num != NULL) ? wolfSSL_BN_bn2hex(num) : NULL;

                if (hex != NULL) {
                    if (wolfSSL_BIO_write(
                            out, "Modulus=", (int)XSTRLEN("Modulus=")) <= 0) {
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
            /* wolfSSL's X509_get0_pubkey maps to wolfSSL_X509_get_pubkey
             * which allocates, unlike OpenSSL's borrowed-ref convention */
            wolfSSL_EVP_PKEY_free(pkey);
        }
    }

    /* write out public key if set to */
    if (ret == WOLFCLU_SUCCESS && textPubkey) {
        ret = wolfCLU_printX509PubKey(x509, out);
    }

    /* write out certificate */
    if (ret == WOLFCLU_SUCCESS && !nooutFlag) {
        byte *derBuf = inBuf;
        byte *pt; /* use pt with i2d to handle potential pointer increment */
        int derBufSz = inBufSz;

        /* if inform is PEM we convert to DER for excluding input that is not
         * part of the certificate */
        if (inForm == PEM_FORM) {
            if (reqFlag) {
                pt = derBuf;
                derBufSz = wolfSSL_i2d_X509(x509, &pt);
            }
            else {
                derBuf = derObj->buffer;
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
                tmpOutBuf = (byte *)XMALLOC(tmpOutBufSz, HEAP_HINT,
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
                        if (wolfSSL_BIO_write(out, tmpOutBuf, tmpOutBufSz) <=
                            0) {
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
    if (keyIn != NULL)
        wolfSSL_BIO_free(keyIn);
    if (privkey != NULL)
        wolfSSL_EVP_PKEY_free(privkey);
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


#ifdef WOLFSSL_CERT_GEN

/* Native (non-OPENSSL_EXTRA) extension access.
 *
 * Reading extensions is done directly off the DER here to avoid
 * requiring the full OPENSSL_EXTRA/OPENSSL_ALL compatibility layer.
 * Only used by the WOLFSSL_CERT_EXT code below. SAN copying uses
 * wc_SetAltNamesBuffer() directly (see wolfCLU_CopyX509SanToCert).
 */
#ifdef WOLFSSL_CERT_EXT

/* DER content bytes (tag/length already stripped) of the extension OIDs
 * this file recognizes explicitly elsewhere. */
static const byte kOidBasicConstraints[]       = {0x55, 0x1D, 0x13}; /* 2.5.29.19 */
static const byte kOidKeyUsage[]               = {0x55, 0x1D, 0x0F}; /* 2.5.29.15 */
static const byte kOidExtKeyUsage[]            = {0x55, 0x1D, 0x25}; /* 2.5.29.37 */
static const byte kOidSubjectKeyIdentifier[]   = {0x55, 0x1D, 0x0E}; /* 2.5.29.14 */
static const byte kOidAuthorityKeyIdentifier[] = {0x55, 0x1D, 0x23}; /* 2.5.29.35 */
static const byte kOidSubjectAltName[]         = {0x55, 0x1D, 0x11}; /* 2.5.29.17 */

/* One decoded `Extension ::= SEQUENCE { extnID OID, critical BOOLEAN
 * DEFAULT FALSE, extnValue OCTET STRING }` entry. oid/val point into the
 * caller-owned DER buffer; nothing here allocates. */
typedef struct WOLFCLU_X509_EXT {
    const byte* oid;
    word32      oidLen;
    int         critical;
    const byte* val;
    word32      valLen;
} WOLFCLU_X509_EXT;

static int wolfCLU_OidEquals(const byte* oid, word32 oidLen,
        const byte* known, word32 knownLen)
{
    return oid != NULL && oidLen == knownLen &&
            XMEMCMP(oid, known, knownLen) == 0;
}

/* Decode a DER tag+length header at buf[*idx]. On success *idx is advanced
 * past the header, *tag is the raw tag byte, and *len is the content
 * length (already bounds-checked against bufSz). */
static int wolfCLU_DerGetHeader(const byte* buf, word32 bufSz, word32* idx,
        byte* tag, word32* len)
{
    word32 i = *idx;
    byte lenByte;

    if (i >= bufSz) {
        return BUFFER_E;
    }
    *tag = buf[i++];

    if (i >= bufSz) {
        return BUFFER_E;
    }
    lenByte = buf[i++];

    if ((lenByte & 0x80) == 0) {
        *len = lenByte;
    }
    else {
        int nBytes = lenByte & 0x7F;
        word32 l = 0;
        int j;

        if (nBytes == 0 || nBytes > (int)sizeof(word32) ||
                i + (word32)nBytes > bufSz) {
            return ASN_PARSE_E;
        }
        for (j = 0; j < nBytes; j++) {
            l = (l << 8) | buf[i++];
        }
        *len = l;
    }

    if (*len > bufSz - i) {
        return BUFFER_E;
    }
    *idx = i;
    return WOLFCLU_SUCCESS;
}

/* Decode one `Extension` SEQUENCE-OF entry at buf[*idx], advancing *idx
 * past it on success. buf/bufSz cover the whole Extensions content (i.e.
 * DecodedCert::extensions/extensionsSz). */
static int wolfCLU_DerGetExtension(const byte* buf, word32 bufSz,
        word32* idx, WOLFCLU_X509_EXT* ext)
{
    byte tag;
    word32 len;
    word32 seqIdx;
    word32 seqEnd;
    int ret;

    ret = wolfCLU_DerGetHeader(buf, bufSz, idx, &tag, &len);
    if (ret != WOLFCLU_SUCCESS || tag != (ASN_SEQUENCE | ASN_CONSTRUCTED)) {
        return ASN_PARSE_E;
    }
    seqIdx = *idx;
    seqEnd = seqIdx + len;
    *idx = seqEnd;

    ret = wolfCLU_DerGetHeader(buf, seqEnd, &seqIdx, &tag, &len);
    if (ret != WOLFCLU_SUCCESS || tag != ASN_OBJECT_ID) {
        return ASN_PARSE_E;
    }
    ext->oid = buf + seqIdx;
    ext->oidLen = len;
    seqIdx += len;

    ext->critical = 0;
    if (seqIdx < seqEnd && buf[seqIdx] == ASN_BOOLEAN) {
        ret = wolfCLU_DerGetHeader(buf, seqEnd, &seqIdx, &tag, &len);
        if (ret != WOLFCLU_SUCCESS || len != 1) {
            return ASN_PARSE_E;
        }
        ext->critical = (buf[seqIdx] != 0);
        seqIdx += len;
    }

    ret = wolfCLU_DerGetHeader(buf, seqEnd, &seqIdx, &tag, &len);
    if (ret != WOLFCLU_SUCCESS || tag != ASN_OCTET_STRING) {
        return ASN_PARSE_E;
    }
    ext->val = buf + seqIdx;
    ext->valLen = len;

    return WOLFCLU_SUCCESS;
}

/* Given *extensions and *extensionsSz as wc_ParseCert leaves them in
 * DecodedCert::extensions and DecodedCert::extensionsSz -- which may point
 * at the raw `[3] EXPLICIT Extensions` tag (ASN_EXTENSIONS, wrapping a
 * `SEQUENCE OF Extension`) rather than directly at the concatenated
 * Extension entries that wolfCLU_DerGetExtension() expects -- skip the [3]
 * wrapper (if present) and the inner SEQUENCE header so *extensions and
 * *extensionsSz land exactly on the entries. Leaves *extensions and
 * *extensionsSz unchanged if neither a [3] wrapper nor a bare SEQUENCE is
 * found at offset 0, so wolfCLU_DerGetExtension() can fail loudly on truly
 * malformed input rather than silently finding nothing.
 *
 * Split out of wolfCLU_GetX509RawExtensions() (and declared in clu_cert.h
 * instead of kept file-static) purely so the unwrap logic can be unit
 * tested directly against synthetic wrapped/bare-SEQUENCE buffers, without
 * needing a full CERT_TYPE DER to drive it via wc_ParseCert(). */
void wolfCLU_UnwrapX509Extensions(const byte** extensions, int* extensionsSz)
{
    const byte* buf = *extensions;
    word32 bufSz = (word32)*extensionsSz;
    word32 idx = 0;
    byte tag;
    word32 len;

    if (wolfCLU_DerGetHeader(buf, bufSz, &idx, &tag, &len) !=
            WOLFCLU_SUCCESS || tag != ASN_EXTENSIONS) {
        idx = 0; /* not [3]-wrapped; try a bare SEQUENCE at offset 0 */
    }

    if (wolfCLU_DerGetHeader(buf, bufSz, &idx, &tag, &len) ==
            WOLFCLU_SUCCESS && tag == (ASN_SEQUENCE | ASN_CONSTRUCTED)) {
        *extensions = buf + idx;
        *extensionsSz = (int)len;
    }
}

/* Parse x509's raw DER into dCert and point it at its Extensions.
 * On WOLFCLU_SUCCESS the caller must wc_FreeDecodedCert(dCert) once done;
 * dCert->extensions/extensionsSz point into x509's own DER buffer (owned
 * by x509, not by dCert), so dCert must not outlive x509.
 *
 * Uses CERT_TYPE (Certificate/TBSCertificate), not CERTREQ_TYPE
 * (CertificationRequest) -- required, not just currently convenient:
 * wolfCLU_X509FillCert() also runs x509's raw DER through
 * wc_SetAltNamesBuffer() (see wolfCLU_CopyX509SanToCert()), which
 * internally hardcodes CERT_TYPE parsing with no override. So x509 must
 * always be a self-signed placeholder cert (wc_MakeCert + wc_SignCert),
 * never raw, unmodified CSR DER, for this whole fill pipeline to work --
 * switching just this call to CERTREQ_TYPE would still break on genuine
 * CSR input at the SAN-copy step. */
static int wolfCLU_GetX509RawExtensions(WOLFSSL_X509* x509,
        DecodedCert* dCert)
{
    const byte* der;
    int derSz = 0;
    int ret;

    der = wolfSSL_X509_get_der(x509, &derSz);
    if (der == NULL || derSz <= 0) {
        wolfCLU_LogError("Could not get CSR's raw DER");
        return WOLFCLU_FATAL_ERROR;
    }

    wc_InitDecodedCert(dCert, der, (word32)derSz, NULL);
    ret = wc_ParseCert(dCert, CERT_TYPE, NO_VERIFY, NULL);
    if (ret != 0) {
        wolfCLU_LogError("Could not parse CSR's DER to read extensions");
        wc_FreeDecodedCert(dCert);
        return WOLFCLU_FATAL_ERROR;
    }

    if (dCert->extensions != NULL && dCert->extensionsSz > 0) {
        wolfCLU_UnwrapX509Extensions(&dCert->extensions,
                &dCert->extensionsSz);
    }

    return WOLFCLU_SUCCESS;
}

/* Find the first extension in an already-parsed CSR's extensions matching
 * the given OID. Returns WOLFCLU_SUCCESS with *found set, or a fatal error
 * on a malformed CSR. dCert must already be parsed via
 * wolfCLU_GetX509RawExtensions(). */
static int wolfCLU_FindX509Ext(DecodedCert* dCert, const byte* oid,
        word32 oidLen, WOLFCLU_X509_EXT* ext, int* found)
{
    word32 idx = 0;

    *found = 0;

    while (idx < (word32)dCert->extensionsSz) {
        WOLFCLU_X509_EXT cur;

        if (wolfCLU_DerGetExtension(dCert->extensions,
                (word32)dCert->extensionsSz, &idx, &cur) != WOLFCLU_SUCCESS) {
            wolfCLU_LogError("Malformed extension in CSR extensions");
            return WOLFCLU_FATAL_ERROR;
        }
        if (wolfCLU_OidEquals(cur.oid, cur.oidLen, oid, oidLen)) {
            *ext = cur;
            *found = 1;
            break;
        }
    }

    return WOLFCLU_SUCCESS;
}

/* DER content bytes of the standard extKeyUsage purpose OIDs
 * (id-kp-* under 1.3.6.1.5.5.7.3.* and anyExtendedKeyUsage). */
static const byte kOidEkuServerAuth[]   = {0x2B,0x06,0x01,0x05,0x05,0x07,0x03,0x01};
static const byte kOidEkuClientAuth[]   = {0x2B,0x06,0x01,0x05,0x05,0x07,0x03,0x02};
static const byte kOidEkuCodeSigning[]  = {0x2B,0x06,0x01,0x05,0x05,0x07,0x03,0x03};
static const byte kOidEkuEmailProt[]    = {0x2B,0x06,0x01,0x05,0x05,0x07,0x03,0x04};
static const byte kOidEkuTimeStamping[] = {0x2B,0x06,0x01,0x05,0x05,0x07,0x03,0x08};
static const byte kOidEkuOcspSigning[]  = {0x2B,0x06,0x01,0x05,0x05,0x07,0x03,0x09};
static const byte kOidEkuAny[]          = {0x55,0x1D,0x25,0x00}; /* 2.5.29.37.0 */

/* Decode an extKeyUsage extnValue (`ExtKeyUsageSyntax ::= SEQUENCE OF
 * KeyPurposeId`) into wolfcrypt's EXTKEYUSE_* bitmask. Unrecognized
 * purpose OIDs (e.g. SGC, DVCS) are silently skipped, matching how they
 * had no EXTKEYUSE_* bit to map to previously either. */
static byte wolfCLU_DerGetExtKeyUsageBits(const byte* val, word32 valLen)
{
    byte eku = 0;
    byte tag;
    word32 len;
    word32 idx = 0;
    word32 seqEnd;

    if (wolfCLU_DerGetHeader(val, valLen, &idx, &tag, &len) !=
                WOLFCLU_SUCCESS ||
            tag != (ASN_SEQUENCE | ASN_CONSTRUCTED)) {
        return 0;
    }
    seqEnd = idx + len;

    while (idx < seqEnd) {
        word32 oidIdx = idx;
        const byte* oid;

        if (wolfCLU_DerGetHeader(val, seqEnd, &oidIdx, &tag, &len) !=
                    WOLFCLU_SUCCESS ||
                tag != ASN_OBJECT_ID) {
            break;
        }
        oid = val + oidIdx;

        if (wolfCLU_OidEquals(oid, len, kOidEkuServerAuth,
                (word32)sizeof(kOidEkuServerAuth))) {
            eku |= EXTKEYUSE_SERVER_AUTH;
        }
        else if (wolfCLU_OidEquals(oid, len, kOidEkuClientAuth,
                (word32)sizeof(kOidEkuClientAuth))) {
            eku |= EXTKEYUSE_CLIENT_AUTH;
        }
        else if (wolfCLU_OidEquals(oid, len, kOidEkuEmailProt,
                (word32)sizeof(kOidEkuEmailProt))) {
            eku |= EXTKEYUSE_EMAILPROT;
        }
        else if (wolfCLU_OidEquals(oid, len, kOidEkuCodeSigning,
                (word32)sizeof(kOidEkuCodeSigning))) {
            eku |= EXTKEYUSE_CODESIGN;
        }
        else if (wolfCLU_OidEquals(oid, len, kOidEkuOcspSigning,
                (word32)sizeof(kOidEkuOcspSigning))) {
            eku |= EXTKEYUSE_OCSP_SIGN;
        }
        else if (wolfCLU_OidEquals(oid, len, kOidEkuTimeStamping,
                (word32)sizeof(kOidEkuTimeStamping))) {
            eku |= EXTKEYUSE_TIMESTAMP;
        }
        else if (wolfCLU_OidEquals(oid, len, kOidEkuAny,
                (word32)sizeof(kOidEkuAny))) {
            eku |= EXTKEYUSE_ANY;
        }

        idx = oidIdx + len;
    }

    return eku;
}
#endif /* WOLFSSL_CERT_EXT */

int wolfCLU_SetCertNameFieldByNid(CertName* dst, int nid, const char* val,
        int valLen)
{
    char* field = NULL;

    if (dst == NULL || val == NULL || valLen <= 0) {
        return BAD_FUNC_ARG;
    }

    switch (nid) {
        case NID_countryName:
            field = dst->country;
            break;
        case NID_stateOrProvinceName:
            field = dst->state;
            break;
        case NID_localityName:
            field = dst->locality;
            break;
        case NID_organizationName:
            field = dst->org;
            break;
        case NID_organizationalUnitName:
            field = dst->unit;
            break;
        case NID_commonName:
            field = dst->commonName;
            break;
        case NID_emailAddress:
            field = dst->email;
            break;
        case NID_streetAddress:
            field = dst->street;
            break;
        case NID_surname:
            field = dst->sur;
            break;
        case NID_serialNumber:
            field = dst->serialDev;
            break;
        case NID_userId:
            field = dst->userId;
            break;
        case NID_postalCode:
            field = dst->postalCode;
            break;
#ifdef WOLFSSL_CERT_NAME_ALL
        case NID_givenName:
            field = dst->givenName;
            break;
        case NID_dnQualifier:
            field = dst->dnQualifier;
            break;
#endif
#ifdef WOLFSSL_CERT_EXT
        case NID_businessCategory:
            field = dst->busCat;
            break;
#endif
        default:
            /* No CertName field for this NID: the DN component is
             * dropped from the issued certificate's subject/issuer. */
            wolfCLU_Log(WOLFCLU_L0,
                    "Warning: DN field (nid %d) has no destination in "
                    "the issued certificate and was dropped", nid);
            break;
    }

    if (field != NULL) {
        /* Reject rather than silently truncate: earlier code here copied
         * oversized DN values into the fixed CTC_NAME_SIZE buffer with
         * XSTRLCPY, so a subject/issuer field over 63 bytes would be
         * cut short and signing would continue anyway. That silently
         * issues a certificate with a corrupted identity field, which is
         * worse than failing loudly -- callers that relied on the old
         * truncate-and-continue behavior for long -subj values will now
         * need to shorten them. */
        if (valLen > CTC_NAME_SIZE - 1) {
            wolfCLU_LogError("DN field (nid %d) exceeds %d-byte limit",
                    nid, CTC_NAME_SIZE - 1);
            return WOLFCLU_FATAL_ERROR;
        }
        XMEMCPY(field, val, (size_t)valLen);
        field[valLen] = '\0';
    }

    return WOLFCLU_SUCCESS;
}

int wolfCLU_CopyX509NameToCert(WOLFSSL_X509_NAME* name, CertName* dst)
{
    int i;

    if (name == NULL || dst == NULL) {
        return BAD_FUNC_ARG;
    }

    for (i = 0; i < wolfSSL_X509_NAME_entry_count(name); i++) {
        WOLFSSL_X509_NAME_ENTRY* e;
        WOLFSSL_ASN1_OBJECT* obj;
        WOLFSSL_ASN1_STRING* str;
        const char* val;
        int nid;
        int valLen;
        int ret;

        e = wolfSSL_X509_NAME_get_entry(name, i);
        if (e == NULL) {
            continue;
        }
        obj = wolfSSL_X509_NAME_ENTRY_get_object(e);
        str = wolfSSL_X509_NAME_ENTRY_get_data(e);
        if (obj == NULL || str == NULL) {
            continue;
        }

        nid    = wolfSSL_OBJ_obj2nid(obj);
        val    = (const char*)wolfSSL_ASN1_STRING_data(str);
        valLen = wolfSSL_ASN1_STRING_length(str);
        if (val == NULL || valLen <= 0) {
            continue;
        }

        ret = wolfCLU_SetCertNameFieldByNid(dst, nid, val, valLen);
        if (ret != WOLFCLU_SUCCESS) {
            return ret;
        }
    }

    return WOLFCLU_SUCCESS;
}

/* Re-encode a WOLFSSL_ASN1_TIME as a DER tag+length+value suitable for
 * Cert->beforeDate/afterDate. Returns the encoded length or a negative
 * error code. */
int wolfCLU_Asn1TimeToCertDate(byte* out, int outSz,
        const WOLFSSL_ASN1_TIME* t)
{
    int sz, i;

    /* Sanity bound on t->length vs ASN1_TIME's own buffer; not the output
     * capacity check -- that's the t->length + 2 > outSz check below. */
    if (out == NULL || t == NULL || t->length <= 0 ||
            t->length > CTC_DATE_SIZE) {
        return BUFFER_E;
    }
    /* Validate DER tag: UTCTime (23) or GeneralizedTime (24) expected. */
    if (t->type != V_ASN1_UTCTIME && t->type != V_ASN1_GENERALIZEDTIME) {
        return BUFFER_E;
    }
    if (outSz <= 0) {
        return BUFFER_E;
    }
    /* t->length <= 32 always DER-encodes with a 1-byte tag + 1-byte
     * short-form length; this is the real output-capacity check. */
    if (t->length + 2 > outSz) {
        return BUFFER_E;
    }

    sz = (int)wolfCLU_DerSetLength((word32)t->length, out + 1) + 1;
    if (sz + t->length > outSz) {
        return BUFFER_E;
    }

    out[0] = (byte)t->type;
    for (i = 0; i < t->length; i++) {
        out[sz + i] = t->data[i];
    }
    return t->length + sz;
}

/* Copy subjectAltName from an already-parsed dCert onto cert. dCert must
 * have been parsed with SAN extensions decoded (dCert->altNames populated
 * regardless of whether it was parsed as CERT_TYPE or CERTREQ_TYPE -- SAN
 * decoding happens at the extension level and doesn't care about the
 * outer structure type). Lets a caller that already has a parsed dCert
 * (e.g. wolfCLU_X509FillCert) avoid the second, independent re-parse that
 * wc_SetAltNamesBuffer()'s own wc_SetCert_LoadDer() would otherwise do. */
#if defined(WOLFSSL_ALT_NAMES) && defined(HAVE_WC_SET_ALT_NAMES_FROM_LIST)
static int wolfCLU_CopyX509SanToCertFromDCert(DecodedCert* dCert, Cert* cert)
{
    if (dCert == NULL || cert == NULL) {
        return BAD_FUNC_ARG;
    }
    if (cert->altNamesSz > 0) {
        wolfCLU_Log(WOLFCLU_L0, "Warning: wolfCLU_CopyX509SanToCert called "
                "on a Cert that already has altNames; skipping to avoid "
                "double-population");
        return WOLFCLU_SUCCESS;
    }

    if (wc_SetAltNamesFromList(cert, dCert->altNames) != 0) {
        wolfCLU_LogError("Error copying subjectAltName from CSR");
        return WOLFCLU_FATAL_ERROR;
    }

    return WOLFCLU_SUCCESS;
}
#endif /* WOLFSSL_ALT_NAMES && HAVE_WC_SET_ALT_NAMES_FROM_LIST */

/* Copy subjectAltName from CSR to cert. Returns WOLFCLU_SUCCESS or error. */
#if defined(WOLFSSL_ALT_NAMES)
int wolfCLU_CopyX509SanToCert(WOLFSSL_X509* x509, Cert* cert)
{
#if defined(HAVE_WC_SET_ALT_NAMES_FROM_LIST) && defined(WOLFSSL_CERT_EXT)
    /* Parse just for dCert->altNames -- avoids wc_SetAltNamesBuffer()'s
     * own internal, CERT_TYPE-only re-parse of x509's whole raw DER. */
    DecodedCert dCert;
    int ret;

    if (x509 == NULL || cert == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = wolfCLU_GetX509RawExtensions(x509, &dCert);
    if (ret != WOLFCLU_SUCCESS) {
        return ret;
    }

    ret = wolfCLU_CopyX509SanToCertFromDCert(&dCert, cert);
    wc_FreeDecodedCert(&dCert);
    return ret;
#else
    /* wc_SetAltNamesFromList() unavailable in this wolfSSL build (or
     * wolfCLU_GetX509RawExtensions() isn't compiled in without
     * WOLFSSL_CERT_EXT); fall back to wc_SetAltNamesBuffer(), which takes
     * the CSR's whole raw DER (not just the SAN extension bytes) and
     * re-parses it with wolfCrypt's own SAN decoder internally -- reusing
     * that instead of hand-rolling SAN parsing here avoids
     * re-implementing GeneralName-type handling (dNSName, iPAddress,
     * dirName, ...) and needs nothing from OPENSSL_EXTRA. */
    const byte* der;
    int derSz = 0;

    if (x509 == NULL || cert == NULL) {
        return BAD_FUNC_ARG;
    }
    if (cert->altNamesSz > 0) {
        wolfCLU_Log(WOLFCLU_L0, "Warning: wolfCLU_CopyX509SanToCert called "
                "on a Cert that already has altNames; skipping to avoid "
                "double-population");
        return WOLFCLU_SUCCESS;
    }

    der = wolfSSL_X509_get_der(x509, &derSz);
    if (der == NULL || derSz <= 0) {
        wolfCLU_LogError("Could not get CSR's raw DER");
        return WOLFCLU_FATAL_ERROR;
    }

    if (wc_SetAltNamesBuffer(cert, der, derSz) != 0) {
        wolfCLU_LogError("Error copying subjectAltName from CSR");
        return WOLFCLU_FATAL_ERROR;
    }

    return WOLFCLU_SUCCESS;
#endif /* HAVE_WC_SET_ALT_NAMES_FROM_LIST && WOLFSSL_CERT_EXT */
}
#endif /* WOLFSSL_ALT_NAMES */

#ifdef WOLFSSL_CERT_EXT
/* Extensions that wolfCLU_X509FillCert already handles explicitly. */
typedef struct {
    int         nid;
    const byte* oid;
    word32      oidLen;
} wolfCLU_HandledExt;

static const wolfCLU_HandledExt kHandledExts[] = {
    { NID_basic_constraints,        kOidBasicConstraints,
            (word32)sizeof(kOidBasicConstraints) },
    { NID_key_usage,                kOidKeyUsage,
            (word32)sizeof(kOidKeyUsage) },
    { NID_ext_key_usage,            kOidExtKeyUsage,
            (word32)sizeof(kOidExtKeyUsage) },
    { NID_subject_key_identifier,   kOidSubjectKeyIdentifier,
            (word32)sizeof(kOidSubjectKeyIdentifier) },
    { NID_authority_key_identifier, kOidAuthorityKeyIdentifier,
            (word32)sizeof(kOidAuthorityKeyIdentifier) },
#if defined(WOLFSSL_ALT_NAMES)
    /* Only claim SAN as handled when wolfCLU_CopyX509SanToCert actually
     * runs to copy it (guarded the same way, see clu_cert.h). */
    { NID_subject_alt_name,         kOidSubjectAltName,
            (word32)sizeof(kOidSubjectAltName) },
#endif
};
#define WOLFCLU_NUM_HANDLED_EXTS \
        (sizeof(kHandledExts) / sizeof(kHandledExts[0]))

int wolfCLU_ExtHandledNid(int nid)
{
    size_t i;

    for (i = 0; i < WOLFCLU_NUM_HANDLED_EXTS; i++) {
        if (kHandledExts[i].nid == nid) {
            return 1;
        }
    }
    return 0;
}

/* Look up handled extensions by raw OID DER. */
static int wolfCLU_ExtHandledOid(const byte* oid, word32 oidLen)
{
    size_t i;

    for (i = 0; i < WOLFCLU_NUM_HANDLED_EXTS; i++) {
        if (wolfCLU_OidEquals(oid, oidLen, kHandledExts[i].oid,
                kHandledExts[i].oidLen)) {
            return 1;
        }
    }
    return 0;
}

#if defined(WOLFSSL_ASN_TEMPLATE) && defined(WOLFSSL_CUSTOM_OID) && \
    defined(HAVE_OID_ENCODING)
/* Decode DER-encoded OID content bytes into a NUL-terminated dotted-decimal string. */
static int wolfCLU_OidDerToDotted(const byte* oid, word32 oidLen,
        char* out, size_t outSz)
{
    word32 i;
    int written;
    int firstArc;
    unsigned long arc;
    size_t len;

    if (oid == NULL || oidLen == 0 || out == NULL || outSz == 0) {
        return BAD_FUNC_ARG;
    }
    /* last base-128 group must be complete (continuation bit clear). */
    if ((oid[oidLen - 1] & 0x80) != 0) {
        return ASN_PARSE_E;
    }

    /* The first identifier component (encoding the first two arcs as
     * 40*X+Y) is itself base-128 encoded just like every later arc, so it
     * must be accumulated across continuation bytes before being split
     * back into X/Y -- a single-byte read here mis-decodes any OID whose
     * first two arcs combine to >= 128 (e.g. 2.100.3 is {0x81,0x34,0x03}). */
    arc = 0;
    firstArc = -1;
    i = 0;
    while (i < oidLen) {
        /* reject a run of continuation bytes long enough to shift bits
         * out of arc, rather than silently wrapping into a bogus arc
         * value. */
        if (arc > (ULONG_MAX >> 7)) {
            return ASN_PARSE_E;
        }
        arc = (arc << 7) | (unsigned long)(oid[i] & 0x7F);
        if ((oid[i] & 0x80) == 0) {
            firstArc = 1;
            i++;
            break;
        }
        i++;
    }
    if (firstArc < 0) {
        return ASN_PARSE_E;
    }

    if (arc < 40) {
        written = XSNPRINTF(out, outSz, "0.%lu", arc);
    }
    else if (arc < 80) {
        written = XSNPRINTF(out, outSz, "1.%lu", arc - 40);
    }
    else {
        written = XSNPRINTF(out, outSz, "2.%lu", arc - 80);
    }
    if (written < 0 || (size_t)written >= outSz) {
        return BUFFER_E;
    }

    arc = 0;
    for (; i < oidLen; i++) {
        if (arc > (ULONG_MAX >> 7)) {
            return ASN_PARSE_E;
        }
        arc = (arc << 7) | (unsigned long)(oid[i] & 0x7F);
        if ((oid[i] & 0x80) == 0) {
            len = XSTRLEN(out);
            written = XSNPRINTF(out + len, outSz - len, ".%lu", arc);
            if (written < 0 || (size_t)written >= outSz - len) {
                return BUFFER_E;
            }
            arc = 0;
        }
    }
    return WOLFCLU_SUCCESS;
}
#endif /* WOLFSSL_ASN_TEMPLATE && WOLFSSL_CUSTOM_OID && HAVE_OID_ENCODING */

/* Carry unhandled CSR extensions onto the wolfcrypt Cert. */
static int wolfCLU_CopyX509ExtsToCertFromDCert(DecodedCert* dCert, Cert* cert,
        int* extsDropped)
{
    int ret = WOLFCLU_SUCCESS;
    int uncopied = 0;
    word32 idx = 0;

    if (extsDropped != NULL) {
        *extsDropped = 0;
    }
    if (dCert == NULL || cert == NULL) {
        return BAD_FUNC_ARG;
    }

    while (ret == WOLFCLU_SUCCESS && idx < (word32)dCert->extensionsSz) {
        WOLFCLU_X509_EXT ext;

        if (wolfCLU_DerGetExtension(dCert->extensions,
                (word32)dCert->extensionsSz, &idx, &ext) != WOLFCLU_SUCCESS) {
            wolfCLU_LogError("Malformed extension in CSR extensions");
            ret = WOLFCLU_FATAL_ERROR;
            continue;
        }
        if (wolfCLU_ExtHandledOid(ext.oid, ext.oidLen)) {
            continue; /* already copied explicitly by wolfCLU_X509FillCert */
        }

#if defined(WOLFSSL_ASN_TEMPLATE) && defined(WOLFSSL_CUSTOM_OID) && \
    defined(HAVE_OID_ENCODING)
        {
            char oid[80];

            if (wolfCLU_OidDerToDotted(ext.oid, ext.oidLen, oid,
                    sizeof(oid)) != WOLFCLU_SUCCESS) {
                if (ext.critical) {
                    wolfCLU_LogError("Could not encode a critical "
                            "extension's OID; refusing to issue");
                    ret = WOLFCLU_FATAL_ERROR;
                    continue;
                }
                wolfCLU_Log(WOLFCLU_L0,
                        "Warning: could not encode an extension "
                        "OID; not copied to the certificate");
                uncopied = 1;
                continue;
            }
            /* wc_SetCustomExtension keeps these pointers as-is, and both
             * point into x509's DER buffer; heap-copy so cert doesn't
             * depend on x509 outliving encoding. */
            {
                char* oidHeap = (char*)XMALLOC(XSTRLEN(oid) + 1, HEAP_HINT,
                        DYNAMIC_TYPE_TMP_BUFFER);
                byte* valHeap = NULL;

                if (oidHeap == NULL) {
                    ret = MEMORY_E;
                }
                else {
                    /* +1 so a legitimately empty (zero-length) extnValue
                     * doesn't turn into a 0-byte XMALLOC() call, which some
                     * allocators return NULL for -- that would otherwise be
                     * mistaken for a real out-of-memory failure below. */
                    valHeap = (byte*)XMALLOC((size_t)ext.valLen + 1, HEAP_HINT,
                            DYNAMIC_TYPE_TMP_BUFFER);
                    if (valHeap == NULL) {
                        XFREE(oidHeap, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
                        ret = MEMORY_E;
                    }
                }

                if (ret == WOLFCLU_SUCCESS) {
                    XMEMCPY(oidHeap, oid, XSTRLEN(oid) + 1);
                    if (ext.valLen > 0) {
                        XMEMCPY(valHeap, ext.val, (size_t)ext.valLen);
                    }
                    if (wc_SetCustomExtension(cert, ext.critical, oidHeap,
                                valHeap, ext.valLen) < 0) {
                        XFREE(oidHeap, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
                        XFREE(valHeap, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
                        if (ext.critical) {
                            wolfCLU_LogError("Failed to copy a critical "
                                    "extension (OID %s); refusing to issue",
                                    oid);
                            ret = WOLFCLU_FATAL_ERROR;
                        }
                        else {
                            wolfCLU_Log(WOLFCLU_L0,
                                    "Warning: failed to copy extension "
                                    "(OID %s) to the certificate", oid);
                            uncopied = 1;
                        }
                    }
                }
            }
        }
#else
        if (ext.critical) {
            wolfCLU_LogError("This build cannot copy a critical CSR "
                    "extension; refusing to issue");
            ret = WOLFCLU_FATAL_ERROR;
            continue;
        }
        uncopied = 1; /* this build cannot copy arbitrary extensions */
#endif /* WOLFSSL_ASN_TEMPLATE && WOLFSSL_CUSTOM_OID && HAVE_OID_ENCODING */
    }

    if (ret == WOLFCLU_SUCCESS && uncopied) {
        wolfCLU_Log(WOLFCLU_L0,
                "Warning: this build only carries basicConstraints, "
                "keyUsage, extKeyUsage, subjectKeyIdentifier, "
                "authorityKeyIdentifier and subjectAltName; other CSR "
                "extensions were not copied (build wolfSSL with "
                "WOLFSSL_CUSTOM_OID + HAVE_OID_ENCODING to carry arbitrary "
                "extensions)");
        if (extsDropped != NULL) {
            *extsDropped = 1;
        }
    }

    return ret;
}

/* Carry CSR extensions that wolfCLU_X509FillCert does not handle explicitly
 * onto the wolfcrypt Cert. */
int wolfCLU_CopyX509ExtsToCert(WOLFSSL_X509* x509, Cert* cert,
        int* extsDropped)
{
    int ret;
    DecodedCert dCert;

    if (x509 == NULL || cert == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = wolfCLU_GetX509RawExtensions(x509, &dCert);
    if (ret != WOLFCLU_SUCCESS) {
        return ret;
    }

    ret = wolfCLU_CopyX509ExtsToCertFromDCert(&dCert, cert, extsDropped);
    if (ret != WOLFCLU_SUCCESS) {
        /* Free any custom-extension buffers a partial copy already
         * attached to cert before returning the failure. */
        wolfCLU_FreeCertCustomExts(cert);
    }
    wc_FreeDecodedCert(&dCert);
    return ret;
}

/* Frees the oid/val buffers allocated by wolfCLU_CopyX509ExtsToCert; call
 * once the Cert is done being used (after signing/encoding). */
void wolfCLU_FreeCertCustomExts(Cert* cert)
{
#ifdef WOLFSSL_CUSTOM_OID
    int i;

    if (cert == NULL) {
        return;
    }
    for (i = 0; i < cert->customCertExtCount; i++) {
        if (cert->customCertExt[i].oid != NULL) {
            XFREE((void*)cert->customCertExt[i].oid, HEAP_HINT,
                    DYNAMIC_TYPE_TMP_BUFFER);
            cert->customCertExt[i].oid = NULL;
        }
        if (cert->customCertExt[i].val != NULL) {
            XFREE((void*)cert->customCertExt[i].val, HEAP_HINT,
                    DYNAMIC_TYPE_TMP_BUFFER);
            cert->customCertExt[i].val = NULL;
        }
    }
#else
    (void)cert;
#endif /* WOLFSSL_CUSTOM_OID */
}
#endif /* WOLFSSL_CERT_EXT */

/* Populate a wolfcrypt Cert from a CSR for CA signing. */
int wolfCLU_X509FillCert(WOLFSSL_X509* x509, Cert* cert, int sigType,
        void* subjWcKey, int subjWcKeyType,
        void* caWcKey, int caWcKeyType, WOLFSSL_X509* caCert,
        int policySanitized, int* extsDropped)
{
    int ret = WOLFCLU_SUCCESS;
    int ku;
    int isCA;
    WOLFSSL_X509_NAME* name;
    const WOLFSSL_ASN1_TIME* nb;
    const WOLFSSL_ASN1_TIME* na;
#ifdef WOLFSSL_CERT_EXT
    DecodedCert dCert;
    int dCertValid = 0;
#endif

    if (extsDropped != NULL) {
        *extsDropped = 0;
    }

    if (x509 == NULL || cert == NULL || subjWcKey == NULL) {
        return BAD_FUNC_ARG;
    }

    /* x509's basicConstraints/keyUsage can be attacker-controlled CSR content;
     * refuse to sign unless policySanitized says it's safe. */
    if (!policySanitized) {
        wolfCLU_LogError("CSR policy not sanitized; refusing to sign");
        return WOLFCLU_FATAL_ERROR;
    }

    ku = wolfSSL_X509_get_keyUsage(x509);
    /* Use get_isCA() to read the in-memory isCA field, which correctly
     * reflects any config overrides applied via wolfSSL_X509_add_ext(). */
    isCA = wolfSSL_X509_get_isCA(x509);

    if (wc_InitCert(cert) != 0) {
        return WOLFCLU_FATAL_ERROR;
    }
    cert->version = 2; /* X.509 v3; wc_InitCert default */
    cert->sigType = sigType;

    cert->isCA = isCA ? 1 : 0;
    cert->pathLen = 0;
    cert->pathLenSet = 0;
    /* Propagate the CSR/config's pathLenConstraint if set. */
    if (isCA && wolfSSL_X509_get_isSet_pathLength(x509)) {
        cert->pathLen = wolfSSL_X509_get_pathLength(x509);
        cert->pathLenSet = 1;
    }

#ifdef WOLFSSL_CERT_EXT
    if (isCA) {
        /* A CA cert's keyUsage is always exactly keyCertSign/cRLSign; the
         * CSR's requested keyUsage (ku) is intentionally ignored here so a
         * CSR cannot grant itself extra key usages on a CA certificate. */
        cert->keyUsage = KU_KEY_CERT_SIGN | KU_CRL_SIGN;
    }
    else {
        /* Only RSA keys are also used for key encipherment; other types
         * are signature-only. subjWcKeyType is the CertType space
         * (RSA_TYPE/ECC_TYPE/...) also used below by
         * wc_SetSubjectKeyIdFromPublicKey_ex(). */
        cert->keyUsage = (subjWcKeyType == RSA_TYPE) ?
                (KU_DIGITAL_SIGNATURE | KU_KEY_ENCIPHERMENT) :
                KU_DIGITAL_SIGNATURE;
        /* CSR keyUsage can only add bits on top of the default, never
         * narrow it; CA-only bits are masked out so a leaf CSR can't grant
         * itself keyCertSign/cRLSign. */
        if (ku >= 0) {
            int leafKu = ku & ~(KU_KEY_CERT_SIGN | KU_CRL_SIGN);
            if (leafKu > 0)
                cert->keyUsage |= (word16)leafKu;
        }
    }

    /* Parse the CSR's DER once and reuse it for every wolfCLU_FindX509Ext()
     * lookup below, instead of each lookup re-parsing the same DER. */
    if (ret == WOLFCLU_SUCCESS) {
        ret = wolfCLU_GetX509RawExtensions(x509, &dCert);
        dCertValid = (ret == WOLFCLU_SUCCESS);
    }

    if (ret == WOLFCLU_SUCCESS) {
        /* wolfSSL_X509_get_extended_key_usage() needs full OPENSSL_EXTRA;
         * read the extKeyUsage extension natively instead. */
        WOLFCLU_X509_EXT ext;
        int found = 0;

        ret = wolfCLU_FindX509Ext(&dCert, kOidExtKeyUsage,
                (word32)sizeof(kOidExtKeyUsage), &ext, &found);
        cert->extKeyUsage = (ret == WOLFCLU_SUCCESS && found) ?
                wolfCLU_DerGetExtKeyUsageBits(ext.val, ext.valLen) : 0;
    }
#else
    (void)isCA;
    (void)ku;
#endif /* WOLFSSL_CERT_EXT */

    nb = wolfSSL_X509_get_notBefore(x509);
    na = wolfSSL_X509_get_notAfter(x509);
    if (ret == WOLFCLU_SUCCESS && nb != NULL) {
        cert->beforeDateSz = wolfCLU_Asn1TimeToCertDate(cert->beforeDate,
                CTC_DATE_SIZE, nb);
        if (cert->beforeDateSz <= 0) {
            wolfCLU_LogError("Error converting notBefore date");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }
    if (ret == WOLFCLU_SUCCESS && na != NULL) {
        cert->afterDateSz = wolfCLU_Asn1TimeToCertDate(cert->afterDate,
                CTC_DATE_SIZE, na);
        if (cert->afterDateSz <= 0) {
            wolfCLU_LogError("Error converting notAfter date");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        byte serial[EXTERNAL_SERIAL_SIZE];
        int serialSz = EXTERNAL_SERIAL_SIZE;

        if (wolfSSL_X509_get_serial_number(x509, serial, &serialSz) !=
                WOLFSSL_SUCCESS || serialSz <= 0) {
            wolfCLU_LogError("Error reading serial number");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else if (serialSz > CTC_SERIAL_SIZE) {
            wolfCLU_LogError("Serial number too large");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            XMEMCPY(cert->serial, serial, (size_t)serialSz);
            cert->serialSz = serialSz;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        name = wolfSSL_X509_get_subject_name(x509);
        if (name == NULL) {
            wolfCLU_LogError("CSR has no subject name");
            ret = BAD_FUNC_ARG;
        }
        else {
            ret = wolfCLU_CopyX509NameToCert(name, &cert->subject);
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        /*CA-signed: issuer is CA's subject. */
        name = (caCert != NULL)
                ? wolfSSL_X509_get_subject_name(caCert)
                : wolfSSL_X509_get_subject_name(x509);
        cert->selfSigned = (caCert == NULL) ? 1 : 0;
        if (name != NULL) {
            ret = wolfCLU_CopyX509NameToCert(name, &cert->issuer);
        }
        else if (caCert != NULL) {
            wolfCLU_LogError("CA certificate has no subject name");
            ret = BAD_FUNC_ARG;
        }
    }

#ifdef WOLFSSL_CERT_EXT
    if (ret == WOLFCLU_SUCCESS) {
        WOLFCLU_X509_EXT ext;
        int found = 0;

        ret = wolfCLU_FindX509Ext(&dCert, kOidSubjectKeyIdentifier,
                (word32)sizeof(kOidSubjectKeyIdentifier), &ext, &found);
        if (ret == WOLFCLU_SUCCESS && found) {
            /* subjWcKey != NULL is enforced by the parameter validation
             * above. */
            if (wc_SetSubjectKeyIdFromPublicKey_ex(cert, subjWcKeyType,
                        subjWcKey) < 0) {
                wolfCLU_LogError("Error setting subject key identifier");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
    }

    if (ret == WOLFCLU_SUCCESS && caWcKey != NULL) {
        WOLFCLU_X509_EXT ext;
        int found = 0;

        ret = wolfCLU_FindX509Ext(&dCert, kOidAuthorityKeyIdentifier,
                (word32)sizeof(kOidAuthorityKeyIdentifier), &ext, &found);
        if (ret == WOLFCLU_SUCCESS && found) {
            if (wc_SetAuthKeyIdFromPublicKey_ex(cert, caWcKeyType,
                        caWcKey) < 0) {
                wolfCLU_LogError("Error setting authority key identifier");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
    }

    /* Carry any remaining CSR extensions (or warn that they were dropped),
     * reusing the dCert parsed above instead of paying for a second
     * wc_ParseCert() over the identical CSR DER. */
    if (ret == WOLFCLU_SUCCESS) {
        ret = wolfCLU_CopyX509ExtsToCertFromDCert(&dCert, cert, extsDropped);
    }

#if defined(WOLFSSL_ALT_NAMES) && defined(HAVE_WC_SET_ALT_NAMES_FROM_LIST)
    /* Also reuse dCert for SAN copying, avoiding wc_SetAltNamesBuffer()'s
     * own independent CERT_TYPE-only re-parse of the same CSR DER. */
    if (ret == WOLFCLU_SUCCESS) {
        ret = wolfCLU_CopyX509SanToCertFromDCert(&dCert, cert);
    }
#endif

    if (dCertValid) {
        wc_FreeDecodedCert(&dCert);
        dCertValid = 0;
    }
#endif /* WOLFSSL_CERT_EXT */

#if defined(WOLFSSL_ALT_NAMES) && \
        !(defined(WOLFSSL_CERT_EXT) && defined(HAVE_WC_SET_ALT_NAMES_FROM_LIST))
    if (ret == WOLFCLU_SUCCESS) {
        ret = wolfCLU_CopyX509SanToCert(x509, cert);
    }
#endif

#ifdef WOLFSSL_CERT_EXT
    /* On failure, free any buffers a partial wolfCLU_CopyX509ExtsToCert()
     * already handed to cert. On success, the caller owns cert and must
     * call wolfCLU_FreeCertCustomExts() itself. */
    if (ret != WOLFCLU_SUCCESS) {
        wolfCLU_FreeCertCustomExts(cert);
    }
#endif /* WOLFSSL_CERT_EXT */

    return ret;
}
#endif /* WOLFSSL_CERT_GEN */
