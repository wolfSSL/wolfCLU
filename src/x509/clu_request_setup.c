/* clu_request_setup.c
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
#include <wolfclu/x509/clu_request.h>
#include <wolfclu/x509/clu_cert.h>
#include <wolfclu/pkey/clu_pkey.h>
#include <wolfclu/certgen/clu_certgen.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/types.h>
#include <time.h> /* for time() / time_t, not pulled in by a wolfSSL header */
#include <limits.h> /* for LONG_MAX */

/* Accepted "-newkey rsa:<bits>" sizes: only the three standard steps, since
 * anything below 2048 is no longer an acceptable strength. A list rather than
 * a range so a typo such as "rsa:20488" never reaches keygen. */
#define WOLFCLU_RSA_BITS_2048 2048
#define WOLFCLU_RSA_BITS_3072 3072
#define WOLFCLU_RSA_BITS_4096 4096

#if defined(WOLFSSL_CERT_REQ) && !defined(WOLFCLU_NO_FILESYSTEM)

#ifndef _WIN32
    #include <sys/stat.h> /* for the -keyout / -out same file check */
#endif

/* Do 'a' and 'b' name the same file? A plain string compare misses the same
 * file spelled two ways ("out.pem" and "./out.pem"), so where stat() is
 * available the device and inode decide it.
 * returns 1 when both name one file, 0 otherwise */
static int wolfCLU_isSameFile(const char* a, const char* b)
{
    if (a == NULL || b == NULL) {
        return 0;
    }

    if (XSTRCMP(a, b) == 0) {
        return 1;
    }

#ifndef _WIN32
    {
        struct stat sa, sb;

        /* only meaningful once both exist; the caller has already created the
         * -keyout file by this point */
        if (stat(a, &sa) == 0 && stat(b, &sb) == 0) {
            return sa.st_dev == sb.st_dev && sa.st_ino == sb.st_ino;
        }
    }
#endif

    return 0;
}


static void wolfCLU_certgenHelp(void) {
    WOLFCLU_LOG(WOLFCLU_L0, "Arguments:");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-in input file to read from");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-out file to write to (default stdout)");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-inform der or pem format for '-in'");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-outform der or pem format for '-out'");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-config file to parse for certificate configuration");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-days number of days should be valid for (default: 20 days)");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-x509 generate self signed certificate");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-CA    Parent ca of new cert");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-CAkey Ca key for signing new cert");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-set_serial Input a serial number for the cert to use if not set one will be generated at random");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-extensions overwrite the section to get extensions from");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-addext add an extension, ie \"subjectAltName=IP:192.168.1.2,DNS:example.com\"");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-nodes no DES encryption on private key output");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-newkey generate the private key to use with "
            "req, as <type>:<bits> i.e. rsa:2048 (rsa 2048/3072/4096 only)");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-inkey private key to use with req");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-keyout file to output key to");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-subj use a specified subject name, ie O=wolfSSL/C=US/ST=WA/L=Seattle/CN=wolfSSL/OU=org-unit");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-verify verify the signature of a req");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-key public key to put into certificate request");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-text output human readable text of req");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-noout do not print out the generated results");
}

static const struct option req_options[] = {

    {"-sha",       no_argument,       0, WOLFCLU_CERT_SHA   },
    {"-sha1",      no_argument,       0, WOLFCLU_CERT_SHA   },
    {"-sha224",    no_argument,       0, WOLFCLU_CERT_SHA224},
    {"-sha256",    no_argument,       0, WOLFCLU_CERT_SHA256},
    {"-sha384",    no_argument,       0, WOLFCLU_CERT_SHA384},
    {"-sha512",    no_argument,       0, WOLFCLU_CERT_SHA512},

    /* key gen algorithms */
    {"-rsa",       no_argument,       0, WOLFCLU_RSA       },
    {"-ecc",       no_argument,       0, WOLFCLU_ECC       },
    {"-ed25519",   no_argument,       0, WOLFCLU_ED25519   },

    {"-in",        required_argument, 0, WOLFCLU_INFILE    },
    {"-out",       required_argument, 0, WOLFCLU_OUTFILE   },
    {"-key",       required_argument, 0, WOLFCLU_KEY       },
    {"-CA",        required_argument, 0, WOLFCLU_CA       },
    {"-CAkey",     required_argument, 0, WOLFCLU_CAKEY    },
    {"-newkey",    required_argument, 0, WOLFCLU_NEWKEY },
    {"-inkey",     required_argument, 0, WOLFCLU_INKEY     },
    {"-set_serial",required_argument, 0, WOLFCLU_SERIAL},
    {"-keyout",    required_argument, 0, WOLFCLU_OUTKEY     },
    {"-inform",    required_argument, 0, WOLFCLU_INFORM    },
    {"-outform",   required_argument, 0, WOLFCLU_OUTFORM   },
    {"-config",    required_argument, 0, WOLFCLU_CONFIG },
    {"-days",      required_argument, 0, WOLFCLU_DAYS },
    {"-x509",      no_argument,       0, WOLFCLU_X509 },
    {"-new",       no_argument,       0, WOLFCLU_NEW },
    {"-subj",      required_argument, 0, WOLFCLU_SUBJECT },
    {"-verify",    no_argument,       0, WOLFCLU_VERIFY },
    {"-text",      no_argument,       0, WOLFCLU_TEXT_OUT },
    {"-passout",   required_argument, 0, WOLFCLU_PASSWORD_OUT },
    {"-noout",     no_argument,       0, WOLFCLU_NOOUT },
    {"-extensions",required_argument, 0, WOLFCLU_EXTENSIONS},
    {"-addext",    required_argument, 0, WOLFCLU_ADDEXT },
    {"-nodes",     no_argument,       0, WOLFCLU_NODES },
    {"-h",         no_argument,       0, WOLFCLU_HELP },
    {"-help",      no_argument,       0, WOLFCLU_HELP },

    {0, 0, 0, 0} /* terminal element */
};


#define MAX_WIDTH 80
#ifdef NO_WOLFSSL_REQ_PRINT
/* print serial number out
 * return WOLFSSL_SUCCESS on success
 */
static int _wolfSSL_X509_print_serial(WOLFSSL_BIO* bio, WOLFSSL_X509* x509,
        int indent)
{
    unsigned char serial[32];
    int  sz = sizeof(serial);
    char scratch[MAX_WIDTH];

    XMEMSET(serial, 0, sz);
    if (wolfSSL_X509_get_serial_number(x509, serial, &sz) == WOLFSSL_SUCCESS) {

        XSNPRINTF(scratch, MAX_WIDTH, "%*s%s", indent, "",
                "Serial Number:");
        if (wolfSSL_BIO_write(bio, scratch, (int)XSTRLEN(scratch)) <= 0) {
            return WOLFSSL_FAILURE;
        }

        if (sz > (int)sizeof(byte)) {
            int i;
            char tmp[100];
            int  tmpSz = 100;
            char val[5];
            int  valSz = 5;

            /* serial is larger than int size so print off hex values */
            XSNPRINTF(scratch, MAX_WIDTH, "\n%*s", indent, "");
            if (wolfSSL_BIO_write(bio, scratch, (int)XSTRLEN(scratch))
                    <= 0) {
                return WOLFSSL_FAILURE;
            }
            tmp[0] = '\0';
            for (i = 0; i < sz - 1 && (3 * i) < tmpSz - valSz; i++) {
                XSNPRINTF(val, sizeof(val) - 1, "%02x:", serial[i]);
                val[3] = '\0'; /* make sure is null terminated */
                XSTRNCAT(tmp, val, valSz);
            }
            XSNPRINTF(val, sizeof(val) - 1, "%02x\n", serial[i]);
            val[3] = '\0'; /* make sure is null terminated */
            XSTRNCAT(tmp, val, valSz);
            if (wolfSSL_BIO_write(bio, tmp, (int)XSTRLEN(tmp)) <= 0) {
                return WOLFSSL_FAILURE;
            }
        }

        /* if serial can fit into byte than print on the same line */
        else if (sz <= (int)sizeof(byte)) {
            XSNPRINTF(scratch, MAX_WIDTH, " %d (0x%x)\n", serial[0],
                    serial[0]);
            if (wolfSSL_BIO_write(bio, scratch, (int)XSTRLEN(scratch))
                    <= 0) {
                return WOLFSSL_FAILURE;
            }
        }

    }
    return WOLFSSL_SUCCESS;
}


/* convert key usage type to human readable print out
 * return WOLFSSL_SUCCESS on success
 */
static int _keyUsagePrint(WOLFSSL_BIO* bio, int keyUsage, int indent)
{
    char scratch[MAX_WIDTH];

    if (keyUsage > 0) {
        if (keyUsage & KEYUSE_KEY_ENCIPHER) {
            XSNPRINTF(scratch, MAX_WIDTH, "%*s%s\n", indent, "",
                    "keyEncipherment");
            wolfSSL_BIO_write(bio, scratch, (int)XSTRLEN(scratch));
        }

        if (keyUsage & KEYUSE_DIGITAL_SIG) {
            XSNPRINTF(scratch, MAX_WIDTH, "%*s%s\n", indent, "",
                    "digitalSignature");
            wolfSSL_BIO_write(bio, scratch, (int)XSTRLEN(scratch));
        }

        if (keyUsage & KEYUSE_CONTENT_COMMIT) {
            XSNPRINTF(scratch, MAX_WIDTH, "%*s%s\n", indent, "",
                    "nonRepudiation");
            wolfSSL_BIO_write(bio, scratch, (int)XSTRLEN(scratch));
        }

        if (keyUsage & KEYUSE_DATA_ENCIPHER) {
            XSNPRINTF(scratch, MAX_WIDTH, "%*s%s\n", indent, "",
                    "dataEncipherment");
            wolfSSL_BIO_write(bio, scratch, (int)XSTRLEN(scratch));
        }

        if (keyUsage & KEYUSE_KEY_AGREE) {
            XSNPRINTF(scratch, MAX_WIDTH, "%*s%s\n", indent, "",
                    "keyAgreement");
            wolfSSL_BIO_write(bio, scratch, (int)XSTRLEN(scratch));
        }

        if (keyUsage & KEYUSE_KEY_CERT_SIGN) {
            XSNPRINTF(scratch, MAX_WIDTH, "%*s%s\n", indent, "", "keyCertSign");
            wolfSSL_BIO_write(bio, scratch, (int)XSTRLEN(scratch));
        }

        if (keyUsage & KEYUSE_CRL_SIGN) {
            XSNPRINTF(scratch, MAX_WIDTH, "%*s%s\n", indent, "", "cRLSign");
            wolfSSL_BIO_write(bio, scratch, (int)XSTRLEN(scratch));
        }

        if (keyUsage & KEYUSE_ENCIPHER_ONLY) {
            XSNPRINTF(scratch, MAX_WIDTH, "%*s%s\n", indent, "",
                    "encipherOnly");
            wolfSSL_BIO_write(bio, scratch, (int)XSTRLEN(scratch));
        }

        if (keyUsage & KEYUSE_DECIPHER_ONLY) {
            XSNPRINTF(scratch, MAX_WIDTH, "%*s%s\n", indent, "",
                    "decipherOnly");
            wolfSSL_BIO_write(bio, scratch, (int)XSTRLEN(scratch));
        }
    }

    return WOLFSSL_SUCCESS;
}


/* iterate through certificate extensions printing them out in human readable
 * form
 * return WOLFSSL_SUCCESS on success
 */
static int _wolfSSL_X509_extensions_print(WOLFSSL_BIO* bio, WOLFSSL_X509* x509,
        int indent)
{
    char scratch[MAX_WIDTH];
    int count, i;

    count = wolfSSL_X509_get_ext_count(x509);
    if (count > 0) {
        XSNPRINTF(scratch, MAX_WIDTH, "%*s%s\n", indent, "",
                "Requested extensions:");
        if (wolfSSL_BIO_write(bio, scratch, (int)XSTRLEN(scratch)) <= 0) {
            return WOLFSSL_FAILURE;
        }

        for (i = 0; i < count; i++) {
            WOLFSSL_X509_EXTENSION* ext = wolfSSL_X509_get_ext(x509, i);
            if (ext != NULL) {
                WOLFSSL_ASN1_OBJECT* obj;
                char buf[MAX_WIDTH];
                char* altName;
                int nid;

                obj = wolfSSL_X509_EXTENSION_get_object(ext);
                wolfSSL_OBJ_obj2txt(buf, MAX_WIDTH, obj, 0);
                XSNPRINTF(scratch, MAX_WIDTH, "%*s", indent + 4, "");
                XSTRLCAT(scratch, buf, MAX_WIDTH);

                int crit = wolfSSL_X509_EXTENSION_get_critical(ext) ? 1 : 0;
                XSTRLCAT(scratch, crit ? ": Critical\n" : ":\n", MAX_WIDTH);
                (void)crit;

                wolfSSL_BIO_write(bio, scratch, (int)XSTRLEN(scratch));
                nid = wolfSSL_OBJ_obj2nid(obj);
                switch (nid) {
                    case NID_subject_alt_name:
                        while ((altName = wolfSSL_X509_get_next_altname(x509))
                                != NULL) {
                            XSNPRINTF(scratch, MAX_WIDTH, "%*s%s\n", indent + 8,
                                    "", altName);
                            wolfSSL_BIO_write(bio, scratch,
                                    (int)XSTRLEN(scratch));
                        }
                        break;
                #if LIBWOLFSSL_VERSION_HEX > 0x05001000
                    case NID_key_usage:
                        _keyUsagePrint(bio, wolfSSL_X509_get_key_usage(x509),
                                indent + 8);
                        break;
                #endif
                    default:
                        /* extension nid not yet supported. 'buf' holds the
                         * name obj2txt just produced; the nid itself is
                         * wolfSSL's internal OID sum, a ten digit number that
                         * means nothing to the reader */
                        XSNPRINTF(scratch, MAX_WIDTH,
                                "%*s%s print not yet supported\n",
                                indent + 8, "", buf);
                        wolfSSL_BIO_write(bio, scratch, (int)XSTRLEN(scratch));
                }
            }
        }
    }
    return WOLFSSL_SUCCESS;
}


/* @TODO print out of REQ attributes
 * return WOLFSSL_SUCCESS on success
 */
static int _wolfSSL_X509_REQ_attributes_print(WOLFSSL_BIO* bio,
        WOLFSSL_X509* x509, int indent)
{
    WOLFSSL_X509_ATTRIBUTE* attr;
    char scratch[MAX_WIDTH];
    int i = 0;

    XSNPRINTF(scratch, MAX_WIDTH, "%*s%s", indent, "", "Attributes: \n");
    if (wolfSSL_BIO_write(bio, scratch, (int)XSTRLEN(scratch)) <= 0) {
        return WOLFSSL_FAILURE;
    }

    attr = wolfSSL_X509_REQ_get_attr(x509, i);
    while (attr != NULL) {
        char longName[NAME_SZ/4]; /* NAME_SZ default is 80 */
        int longNameSz = NAME_SZ/4;
        const byte* data;

        wolfSSL_OBJ_obj2txt(longName, longNameSz, attr->object, 0);
        longNameSz = (int)XSTRLEN(longName);
        data = wolfSSL_ASN1_STRING_get0_data(
                attr->value->value.asn1_string);
        if (data == NULL) {
            wolfCLU_LogError("No REQ attribute found when "
                    "expected");
            return WOLFSSL_FAILURE;
        }
        XSNPRINTF(scratch, MAX_WIDTH, "%*s%s%*s:%s\n", indent+4, "",
                longName, (NAME_SZ/4)-longNameSz, "", data);
        if (wolfSSL_BIO_write(bio, scratch, (int)XSTRLEN(scratch))
                <= 0) {
            wolfCLU_LogError("Error writing REQ attribute");
            return WOLFSSL_FAILURE;
        }

        i++;
        attr = wolfSSL_X509_REQ_get_attr(x509, i);
    }

    return WOLFSSL_SUCCESS;
}


/* print out the signature in human readable format for use with
 * wolfSSL_X509_print()
 * return WOLFSSL_SUCCESS on success
 */
static int _wolfSSL_X509_signature_print_ex(WOLFSSL_BIO* bio,
        WOLFSSL_X509* x509, int indent)
{
    char scratch[MAX_WIDTH];
    int sigSz = 0;

    wolfSSL_X509_get_signature(x509, NULL, &sigSz);
    if (sigSz > 0) {
        unsigned char* sig;
        int i;
        char tmp[100];
        int sigNid = wolfSSL_X509_get_signature_nid(x509);
        WOLFSSL_ASN1_OBJECT* obj;

        XSNPRINTF(scratch, MAX_WIDTH, "%*s%s", indent, "",
                "Signature Algorithm: ");
        if (wolfSSL_BIO_write(bio, scratch, (int)XSTRLEN(scratch)) <= 0) {
            return WOLFSSL_FAILURE;
        }
        obj = wolfSSL_OBJ_nid2obj(sigNid);
        wolfSSL_OBJ_obj2txt(scratch, MAX_WIDTH, obj, 0);
        wolfSSL_ASN1_OBJECT_free(obj);
        XSNPRINTF(tmp, sizeof(tmp) - 1,"%s\n", scratch);
        tmp[sizeof(tmp) - 1] = '\0';
        if (wolfSSL_BIO_write(bio, tmp, (int)XSTRLEN(tmp)) <= 0) {
            return WOLFSSL_FAILURE;
        }

        sig = (unsigned char*)XMALLOC(sigSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (sig == NULL) {
            return WOLFSSL_FAILURE;
        }

        if (wolfSSL_X509_get_signature(x509, sig, &sigSz) <= 0) {
            XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return WOLFSSL_FAILURE;
        }
        XSNPRINTF(tmp, sizeof(tmp) - 1,"        ");
        tmp[sizeof(tmp) - 1] = '\0';
        for (i = 0; i < sigSz; i++) {
            char val[5];
            int valSz = 5;

            if (i == 0) {
                XSNPRINTF(val, valSz - 1, "%02x", sig[i]);
            }
            else if (((i % 18) == 0)) {
                tmp[sizeof(tmp) - 1] = '\0';
                if (wolfSSL_BIO_write(bio, tmp, (int)XSTRLEN(tmp))
                        <= 0) {
                    XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                    return WOLFSSL_FAILURE;
                }
                XSNPRINTF(tmp, sizeof(tmp) - 1,
                        ":\n        ");
                XSNPRINTF(val, valSz - 1, "%02x", sig[i]);
            }
            else {
                XSNPRINTF(val, valSz - 1, ":%02x", sig[i]);
            }
            XSTRNCAT(tmp, val, valSz);
        }
        XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);

        /* print out remaining sig values */
        if ((i > 0) && (((i - 1) % 18) != 0)) {
                tmp[sizeof(tmp) - 1] = '\0';
                if (wolfSSL_BIO_write(bio, tmp, (int)XSTRLEN(tmp))
                        <= 0) {
                    return WOLFSSL_FAILURE;
                }
        }
    }
    return WOLFSSL_SUCCESS;
}


/* print out the public key in human readable format for use with
 * wolfSSL_X509_print()
 * return WOLFSSL_SUCCESS on success
 */
static int _wolfSSL_X509_pubkey_print(WOLFSSL_BIO* bio, WOLFSSL_X509* x509,
        int indent)
{
    char scratch[MAX_WIDTH];
    WOLFSSL_EVP_PKEY* pubKey;

    XSNPRINTF(scratch, MAX_WIDTH, "%*sPublic Key:\n", indent, "");
    wolfSSL_BIO_write(bio, scratch, (int)XSTRLEN(scratch));

    pubKey = wolfSSL_X509_get_pubkey(x509);
    wolfSSL_EVP_PKEY_print_public(bio, pubKey, indent + 4, NULL);
    wolfSSL_EVP_PKEY_free(pubKey);
    return WOLFSSL_SUCCESS;
}


/* human readable print out of x509 name formatted for use with
 * wolfSSL_X509_print()
 * return WOLFSSL_SUCCESS on success
 */
static int _X509_name_print(WOLFSSL_BIO* bio, WOLFSSL_X509_NAME* name,
        char* type, int indent)
{
    char scratch[MAX_WIDTH];
    if (name != NULL) {
        XSNPRINTF(scratch, MAX_WIDTH, "%*s%s", indent, "", type);
        wolfSSL_BIO_write(bio, scratch, (int)XSTRLEN(scratch));
        wolfSSL_X509_NAME_print_ex(bio, name, 1, 0);
        wolfSSL_BIO_write(bio, "\n", (int)XSTRLEN("\n"));
    }
    return WOLFSSL_SUCCESS;
}


/* human readable print out of x509 or CSR version
 * return WOLFSSL_SUCCESS on success
 */
static int _wolfSSL_X509_version_print(WOLFSSL_BIO* bio, WOLFSSL_X509* x509,
                                       int indent, byte isCSR)
{
    int version;
    byte version_value;
    char scratch[MAX_WIDTH];

    if ((version = wolfSSL_X509_version(x509)) < 0) {
        return WOLFSSL_FAILURE;
    }

    if (isCSR) {
        version_value = (byte)wolfSSL_X509_REQ_get_version(x509);
    } else {
        version_value = (byte)wolfSSL_X509_get_version(x509);
    }

    XSNPRINTF(scratch, MAX_WIDTH, "%*s%s", indent, "", "Version:");
    if (wolfSSL_BIO_write(bio, scratch, (int)XSTRLEN(scratch)) <= 0) {
        return WOLFSSL_FAILURE;
    }

    XSNPRINTF(scratch, MAX_WIDTH, " %d (0x%x)\n", version, version_value);
    if (wolfSSL_BIO_write(bio, scratch, (int)XSTRLEN(scratch)) <= 0) {
        return WOLFSSL_FAILURE;
    }
    return WOLFSSL_SUCCESS;
}

/* This should work its way into wolfSSL master @TODO
 * For now placing the implementation here so that wolfCLU can be used with
 * the current wolfSSL release.
 * return WOLFSSL_SUCCESS on success
 */
static int wolfSSL_X509_REQ_print(WOLFSSL_BIO* bio, WOLFSSL_X509* x509,
                                  byte isCSR)
{
    char subjType[] = "Subject: ";

    if (bio == NULL || x509 == NULL) {
        return WOLFSSL_FAILURE;
    }

    if (wolfSSL_BIO_write(bio, "Certificate Request:\n",
                  (int)XSTRLEN("Certificate Request:\n")) <= 0) {
            return WOLFSSL_FAILURE;
    }

    if (wolfSSL_BIO_write(bio, "    Data:\n",
                  (int)XSTRLEN("    Data:\n")) <= 0) {
            return WOLFSSL_FAILURE;
    }

    /* print version of cert */
    if (_wolfSSL_X509_version_print(bio, x509, 8, isCSR) != WOLFSSL_SUCCESS) {
        return WOLFSSL_FAILURE;
    }

    if (_wolfSSL_X509_print_serial(bio, x509, 8) != WOLFSSL_SUCCESS) {
        return WOLFSSL_FAILURE;
    }

    /* print subject */
    if (_X509_name_print(bio, wolfSSL_X509_get_subject_name(x509), subjType, 8)
            != WOLFSSL_SUCCESS) {
        return WOLFSSL_FAILURE;
    }

    /* get and print public key */
    if (_wolfSSL_X509_pubkey_print(bio, x509, 8) != WOLFSSL_SUCCESS) {
        return WOLFSSL_FAILURE;
    }

    /* print out extensions */
    if (_wolfSSL_X509_extensions_print(bio, x509, 4) != WOLFSSL_SUCCESS) {
        return WOLFSSL_FAILURE;
    }

    /* print out req attributes */
    if (_wolfSSL_X509_REQ_attributes_print(bio, x509, 4) != WOLFSSL_SUCCESS) {
        return WOLFSSL_FAILURE;
    }

    /* print out signature */
    if (_wolfSSL_X509_signature_print_ex(bio, x509, 4) != WOLFSSL_SUCCESS) {
        return WOLFSSL_FAILURE;
    }

    /* done with print out */
    if (wolfSSL_BIO_write(bio, "\n\0", (int)XSTRLEN("\n\0")) <= 0) {
        return WOLFSSL_FAILURE;
    }

    return WOLFSSL_SUCCESS;
}
#endif /* NO_WOLFSSL_REQ_PRINT */

/* crash on null args because they are statically allocated by the calling
 * func make it easy to debug. */
static void mapOptionToMd(int option, const WOLFSSL_EVP_MD** md)
{
    switch (option) {
        case WOLFCLU_CERT_SHA:
            *md = wolfSSL_EVP_sha1();
            break;
        case WOLFCLU_CERT_SHA224:
            *md = wolfSSL_EVP_sha224();
            break;
        case WOLFCLU_CERT_SHA384:
            *md = wolfSSL_EVP_sha384();
            break;
        case WOLFCLU_CERT_SHA512:
            *md = wolfSSL_EVP_sha512();
            break;
        case WOLFCLU_CERT_SHA256:
            /* sha256 is the default and fallthrough is intentional */
        default:
            *md = wolfSSL_EVP_sha256();
            break;
    }
}

static int verifyX509(WOLFSSL_BIO* keyBio, WOLFSSL_X509* x509, int isCSR)
{
    int ret = WOLFCLU_SUCCESS;
    WOLFSSL_EVP_PKEY* pkey = NULL;

    /* A request is self-signed, so the key that verifies it is the public key
     * it carries. Prefer that over -key: it is the correct key by definition,
     * and it is a public key, which is what REQ_verify wants. -key is only a
     * fallback for a request that carries no usable public key. */
    pkey = wolfSSL_X509_get_pubkey(x509);

    if (pkey == NULL && keyBio != NULL) {
        /* the key may already have been read once to sign with, rewind so
         * this read starts at the beginning of the file again */
        wolfSSL_BIO_reset(keyBio);

        pkey = wolfSSL_PEM_read_bio_PrivateKey(keyBio, NULL, NULL, NULL);
        if (pkey == NULL) {
            wolfCLU_LogError("Unable to read the key to verify with from the "
                    "file passed to -key");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }
    else if (pkey == NULL) {
        wolfCLU_LogError("Unable to get public key to verify with from "
                "req that was passed in");
        ret = WOLFCLU_FATAL_ERROR;
    }

    if (ret == WOLFCLU_SUCCESS && isCSR) {
        if (wolfSSL_X509_REQ_verify(x509, pkey) != 1) {
            wolfCLU_LogError("verify failed");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            WOLFCLU_LOG(WOLFCLU_L0, "verify OK");
        }
    }
    else if (ret == WOLFCLU_SUCCESS) {
        if (wolfSSL_X509_verify(x509, pkey) != 1) {
            wolfCLU_LogError("verify failed");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            WOLFCLU_LOG(WOLFCLU_L0, "verify OK");
        }
    }

    /* prepare BIO for future use */
    if (keyBio != NULL) {
        wolfSSL_BIO_reset(keyBio);
    }
    wolfSSL_EVP_PKEY_free(pkey);
    return ret;
}

/* 'passwordCap' is the buffer capacity the stdin prompt needs, not the current
 * password length; conflating the two gave "-passout pass:" a capacity of 0.
 * 'havePassword' keeps an explicitly empty -passout from becoming a prompt. */
static int writeOutPkey(WOLFSSL_BIO* keyOutBio, WOLFSSL_EVP_PKEY* pkey,
        int useDes, char* password, word32 passwordCap, int havePassword)
{
    int ret = WOLFCLU_SUCCESS;
    WOLFSSL_BIO* localBio = NULL;

    /* only fall back to stdout when the caller had no -keyout; the caller
     * retains ownership of any BIO it passed in */
    if (keyOutBio == NULL) {
        localBio = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
        keyOutBio = localBio;
        if (keyOutBio != NULL) {
            if (wolfSSL_BIO_set_fp(keyOutBio, stdout, BIO_NOCLOSE)
                != WOLFSSL_SUCCESS) {
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
        else {
            wolfCLU_LogError("Could not open file object for stdout");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        if (useDes) {
            if (!havePassword) {
                word32 promptSz = passwordCap;

                if (wolfCLU_GetStdinPassword((byte*)password, &promptSz)
                        != WOLFCLU_SUCCESS) {
                    wolfCLU_LogError("Unable to read a password from stdin");
                    ret = WOLFCLU_FATAL_ERROR;
                }
            }

            /* an empty password encrypts nothing, whether it came from the
             * prompt or from "-passout pass:" */
            if (ret == WOLFCLU_SUCCESS && password[0] == '\0') {
                wolfCLU_LogError("Please enter a password");
                ret = WOLFCLU_FATAL_ERROR;
            }

            if (ret == WOLFCLU_SUCCESS) {
                ret = wolfCLU_pKeyPEMtoPriKeyEnc(keyOutBio, pkey, DES3b,
                        (byte*)password, (int)XSTRLEN(password));
            }
        }
        else {
            ret = wolfCLU_pKeyPEMtoPriKey(keyOutBio, pkey);
        }
    }

    wolfSSL_BIO_free(localBio);
    return ret;
}

 /* return WOLFCLU_SUCCESS on success */
/* Write the signed request or certificate out to 'outBio'.
 *
 * Kept out of makeReq()/selfSignCert()/caSignCert() so the caller can emit
 * -text (and run -verify) after signing but before the encoded body, which is
 * the order OpenSSL uses.
 * return WOLFCLU_SUCCESS on success */
static int writeOutX509(WOLFSSL_BIO* outBio, WOLFSSL_X509* x509, int outForm,
        int isCSR)
{
    int ret;

    if (outBio == NULL || x509 == NULL) {
        return WOLFCLU_FATAL_ERROR;
    }

    if (isCSR) {
        ret = (outForm == DER_FORM) ? wolfSSL_i2d_X509_REQ_bio(outBio, x509)
                                    : wolfSSL_PEM_write_bio_X509_REQ(outBio,
                                            x509);
    }
    else {
        ret = (outForm == DER_FORM) ? wolfSSL_i2d_X509_bio(outBio, x509)
                                    : wolfSSL_PEM_write_bio_X509(outBio, x509);
    }

    if (ret != WOLFSSL_SUCCESS) {
        wolfCLU_LogError("Error %d writing out %s", ret,
                isCSR ? "cert req" : "x509 cert");
        return WOLFCLU_FATAL_ERROR;
    }

    return WOLFCLU_SUCCESS;
}


static int makeReq(WOLFSSL_X509* x509, WOLFSSL_EVP_PKEY* pkey,
        const WOLFSSL_EVP_MD* md, byte reSign)
{
    int ret = WOLFCLU_SUCCESS;

    if (reSign && pkey == NULL) {
        wolfCLU_LogError("The request has been altered and requires a resign. "
                          "But no key was passed to sign with");
        ret = WOLFCLU_FATAL_ERROR;
    }

    if (ret == WOLFCLU_SUCCESS) {
        if (wolfSSL_X509_REQ_set_version(x509, WOLFSSL_X509_V1) !=
                WOLFSSL_SUCCESS) {
            wolfCLU_LogError("Error setting CSR version");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS && pkey != NULL) {
        if (wolfSSL_X509_REQ_sign(x509, pkey, md) != WOLFSSL_SUCCESS) {
            wolfCLU_LogError("Unable to sign request");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* the caller writes the encoded form out, after -text / -verify */

    return ret;
}

 /* return WOLFCLU_SUCCESS on success */
static int selfSignCert(WOLFSSL_X509* x509, WOLFSSL_EVP_PKEY* pkey,
        const WOLFSSL_EVP_MD* md, long days, long serial)
{
    int ret = WOLFCLU_SUCCESS;

    if (pkey == NULL) {
        wolfCLU_LogError("A key for signing is required to create a selfsigned "
                "cert");
        return WOLFCLU_FATAL_ERROR;
    }

    /* Bump to v3 so extensions are honored: */
    if (ret == WOLFCLU_SUCCESS) {
        if (wolfSSL_X509_set_version(x509, WOLFSSL_X509_V3) !=
                WOLFSSL_SUCCESS) {
            wolfCLU_LogError("Error setting CSR version");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* Issuer == subject (self-signed) */
    if (ret == WOLFCLU_SUCCESS) {
        if (wolfSSL_X509_set_issuer_name(x509,
                wolfSSL_X509_get_subject_name(x509)) != WOLFSSL_SUCCESS) {
            wolfCLU_LogError("Error setting issuer name");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* Set validity window from days */
    if (ret == WOLFCLU_SUCCESS && days > 0) {
        WOLFSSL_ASN1_TIME *notBefore, *notAfter;
        time_t t;

        if ((t = time(NULL)) == (time_t)-1) {
            wolfCLU_LogError("Error fetching time");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            notBefore = wolfSSL_ASN1_TIME_adj(NULL, t, 0, 0);
            notAfter = wolfSSL_ASN1_TIME_adj(NULL, t, days, 0);
            if (notBefore == NULL || notAfter == NULL) {
                wolfCLU_LogError("Error creating not before/after dates");
                ret = WOLFCLU_FATAL_ERROR;
            }
            else {
                wolfSSL_X509_set_notBefore(x509, notBefore);
                wolfSSL_X509_set_notAfter(x509, notAfter);
            }

            wolfSSL_ASN1_TIME_free(notBefore);
            wolfSSL_ASN1_TIME_free(notAfter);
        }
    }

    /* Set the serial number. */
    if (ret == WOLFCLU_SUCCESS && serial > 0) {
        WOLFSSL_ASN1_INTEGER* asn1SerialNum = wolfSSL_ASN1_INTEGER_new();
        if (asn1SerialNum != NULL) {
            /* wolfSSL statuses stay out of 'ret', which carries the WOLFCLU
             * status; the two only happen to agree on success */
            if (wolfSSL_ASN1_INTEGER_set(asn1SerialNum, serial)
                        != WOLFSSL_SUCCESS ||
                    wolfSSL_X509_set_serialNumber(x509, asn1SerialNum)
                        != WOLFSSL_SUCCESS) {
                wolfCLU_LogError("Unable to set serial number");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
        else {
            wolfCLU_LogError("Unable to set serial number");
            ret = WOLFCLU_FATAL_ERROR;
        }
        wolfSSL_ASN1_INTEGER_free(asn1SerialNum);
    }

#if defined(WOLFSSL_CERT_EXT) && !defined(NO_SHA)

    /*  Default Basic Constraints to CA:TRUE when not already set */
    if (ret == WOLFCLU_SUCCESS &&
            !wolfSSL_X509_ext_isSet_by_NID(x509, NID_basic_constraints)) {
        WOLFSSL_X509_EXTENSION *newExt;
        WOLFSSL_ASN1_OBJECT *obj;

        newExt = wolfSSL_X509_EXTENSION_new();
        obj = wolfCLU_extenstionGetObjectNID(newExt, NID_basic_constraints, 1);

        if (obj == NULL || newExt == NULL) {
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            obj->ca = 1; /* CA:TRUE -- req -x509 makes a self-signed root */
            if (wolfSSL_X509_add_ext(x509, newExt, -1) != WOLFSSL_SUCCESS) {
                WOLFCLU_LOG(WOLFCLU_E0,
                        "error adding Basic Constraints extension");
                ret = WOLFCLU_FATAL_ERROR;
            }
            wolfSSL_X509_EXTENSION_free(newExt);
        }
    }

#else
    if (ret == WOLFCLU_SUCCESS) {
        WOLFCLU_LOG(WOLFCLU_L0, "Skipping basicConstaints "
                "WOLFSSL_CERT_EXT or SHA-1 disabled");
    }
#endif

    /* NOTE: wolfSSL_X509_sign() returns the cert LENGTH on success, not
     * WOLFSSL_SUCCESS, so it is checked for > 0 and kept in a local. */
    if (ret == WOLFCLU_SUCCESS) {
        int signSz = wolfSSL_X509_sign(x509, pkey, md);

        if (signSz <= 0) {
            wolfCLU_LogError("Error signing certificate");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* the caller writes the encoded form out, after -text / -verify */

    return ret;
}

 /* return WOLFCLU_SUCCESS on success */
static int caSignCert(WOLFSSL_X509* x509, WOLFSSL_BIO* caBio,
        WOLFSSL_BIO* caKeyBio, const WOLFSSL_EVP_MD* md, long days,
        long serial, int doVerify)
{
    int ret = WOLFCLU_SUCCESS;
    WOLFSSL_EVP_PKEY* caKey = NULL;
    WOLFSSL_X509* caCert = NULL;

    /* Load the CA material */
    if (caBio == NULL || caKeyBio == NULL)
        return WOLFCLU_FATAL_ERROR;

     caCert = wolfSSL_PEM_read_bio_X509(caBio, NULL, NULL, NULL);
     if (caCert == NULL) {
        wolfCLU_LogError("Unable to read ca cert passed to -CA");
        ret = WOLFCLU_FATAL_ERROR;
     }

     if (ret == WOLFCLU_SUCCESS) {
        caKey  = wolfSSL_PEM_read_bio_PrivateKey(caKeyBio, NULL, NULL, NULL);
        if (caKey == NULL) {
           wolfCLU_LogError("Unable to read ca key passed to -CAkey");
           ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* Confirm the CA cert can issue. wolfSSL_X509_check_ca() answers 1 for
     * CA:TRUE but also 4 for a leaf that merely carries a critical
     * extendedKeyUsage, so only the CA bit may be accepted here. */
     if (ret == WOLFCLU_SUCCESS) {
        if (wolfSSL_X509_check_ca(caCert) != 1) {
            wolfCLU_LogError("The certificate passed to -CA is not a CA "
                    "(basicConstraints CA:TRUE) and cannot issue");
            ret = WOLFCLU_FATAL_ERROR;
        }
     }

    /* A published keyUsage has to include keyCertSign (RFC 5280 4.2.1.3).
     * wolfSSL_X509_get_key_usage() returns all bits set when the extension is
     * absent, so an unrestricted CA needs no special case. */
    if (ret == WOLFCLU_SUCCESS) {
        if ((wolfSSL_X509_get_key_usage(caCert) & KEYUSE_KEY_CERT_SIGN) == 0) {
            wolfCLU_LogError("The certificate passed to -CA has a keyUsage "
                    "extension without keyCertSign and cannot issue");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* -CAkey has to be the key -CA was issued under, otherwise the
     * certificate would carry the CA's issuer name over a signature that
     * does not chain to it. Caught here rather than after signing so the
     * failure names the option the operator got wrong. */
    if (ret == WOLFCLU_SUCCESS) {
        if (wolfSSL_X509_check_private_key(caCert, caKey) != WOLFSSL_SUCCESS) {
            wolfCLU_LogError("The key passed to -CAkey does not match the "
                    "certificate passed to -CA");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* Verify the incoming request before certifying it */
     if (ret == WOLFCLU_SUCCESS) {
        WOLFSSL_EVP_PKEY* reqPub = wolfSSL_X509_get_pubkey(x509);
        if (reqPub == NULL) {
            wolfCLU_LogError("Req did not have a public key to verify it with");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            if (wolfSSL_X509_REQ_verify(x509, reqPub) < 1) {
                wolfCLU_LogError("Req Failed verification");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
        wolfSSL_EVP_PKEY_free(reqPub);
     }


    /* Bump to v3 */
    if (ret == WOLFCLU_SUCCESS) {
        if (wolfSSL_X509_set_version(x509, WOLFSSL_X509_V3) !=
                WOLFSSL_SUCCESS) {
            wolfCLU_LogError("Error setting CSR version");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* Issuer == the CA's subject */
    if (ret == WOLFCLU_SUCCESS) {
        if (wolfSSL_X509_set_issuer_name(x509,
                wolfSSL_X509_get_subject_name(caCert)) != WOLFSSL_SUCCESS) {
            wolfCLU_LogError("Error setting issuer name");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* Set validity from days */
    if (ret == WOLFCLU_SUCCESS && days > 0) {
        WOLFSSL_ASN1_TIME *notBefore, *notAfter;
        time_t t;

        if ((t = time(NULL)) == (time_t)-1) {
            wolfCLU_LogError("Error fetching time");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            notBefore = wolfSSL_ASN1_TIME_adj(NULL, t, 0, 0);
            notAfter = wolfSSL_ASN1_TIME_adj(NULL, t, days, 0);
            if (notBefore == NULL || notAfter == NULL) {
                wolfCLU_LogError("Error creating not before/after dates");
                ret = WOLFCLU_FATAL_ERROR;
            }
            else {
                wolfSSL_X509_set_notBefore(x509, notBefore);
                wolfSSL_X509_set_notAfter(x509, notAfter);
            }

            wolfSSL_ASN1_TIME_free(notBefore);
            wolfSSL_ASN1_TIME_free(notAfter);
        }
    }

    /* Assign the CA-chosen serial */
    if (ret == WOLFCLU_SUCCESS && serial > 0) {
        WOLFSSL_ASN1_INTEGER* asn1SerialNum = wolfSSL_ASN1_INTEGER_new();
        if (asn1SerialNum != NULL) {
            /* wolfSSL statuses are kept out of 'ret', which carries the
             * WOLFCLU status; the two only happen to agree on success */
            if (wolfSSL_ASN1_INTEGER_set(asn1SerialNum, serial)
                        != WOLFSSL_SUCCESS ||
                    wolfSSL_X509_set_serialNumber(x509, asn1SerialNum)
                        != WOLFSSL_SUCCESS) {
                wolfCLU_LogError("Unable to set serial number");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
        else {
            wolfCLU_LogError("Unable to set serial number");
            ret = WOLFCLU_FATAL_ERROR;
        }
        wolfSSL_ASN1_INTEGER_free(asn1SerialNum);
    }


    /* Chaining extensions for a leaf cert:
     *      - Basic Constraints CA:FALSE, overriding whatever the req carried
     *      - Subject Key Id derived from this cert's own public key
     *      - Authority Key Id copied from the CA cert's Subject Key Id */
    if (ret == WOLFCLU_SUCCESS &&
            wolfSSL_X509_ext_isSet_by_NID(x509, NID_basic_constraints) &&
            wolfSSL_X509_check_ca(x509) == 1) {
        WOLFCLU_LOG(WOLFCLU_L0, "Warning: request asked for Basic Constraints "
                "CA:TRUE; issuing a leaf with CA:FALSE");
    }

#if defined(WOLFSSL_CERT_EXT) && !defined(NO_SHA)

    if (ret == WOLFCLU_SUCCESS) {
        WOLFSSL_X509_EXTENSION* ext = wolfSSL_X509_EXTENSION_new();
        WOLFSSL_ASN1_OBJECT* obj = wolfCLU_extenstionGetObjectNID(ext,
                NID_basic_constraints, 1);

        if (obj == NULL) {
            /* wolfCLU_extenstionGetObjectNID() frees ext on failure, so it
             * must not be freed again here */
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            obj->ca = 0; /* CA:FALSE -- this is a leaf, not a CA */
            if (wolfSSL_X509_add_ext(x509, ext, -1) != WOLFSSL_SUCCESS) {
                WOLFCLU_LOG(WOLFCLU_E0,
                        "error adding Basic Constraints extension");
                ret = WOLFCLU_FATAL_ERROR;
            }
            wolfSSL_X509_EXTENSION_free(ext);
        }
    }


    /* Subject Key Id from this cert's own public key */
    if (ret == WOLFCLU_SUCCESS) {
        if (wolfSSL_X509_set_subject_key_id_ex(x509) != WOLFSSL_SUCCESS) {
            wolfCLU_LogError("Error setting Subject Key Identifier");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* Authority Key Id = the CA cert's Subject Key Id (links the chain) */
    if (ret == WOLFCLU_SUCCESS) {
        if (wolfSSL_X509_set_authority_key_id_ex(x509, caCert) !=
                WOLFSSL_SUCCESS) {
            wolfCLU_LogError("Error setting Authority Key Identifier");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }
#else
    if (ret == WOLFCLU_SUCCESS) {
        WOLFCLU_LOG(WOLFCLU_L0, "Skipping basicConstaints AKI and SKI "
                "WOLFSSL_CERT_EXT or SHA-1 disabled");
    }
#endif

    /* Sign with the CA key. wolfSSL_X509_sign() hands back the cert length
     * on success rather than WOLFSSL_SUCCESS, so it is kept in a local. */
    if (ret == WOLFCLU_SUCCESS) {
        int signSz = wolfSSL_X509_sign(x509, caKey, md);

        if (signSz <= 0) {
            wolfCLU_LogError("Error signing certificate");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* Check the certificate just signed against the CA's public key. The
     * caller's -verify path can not do this: it only holds the subject's key,
     * which is the wrong key once the cert is issued by someone else. */
    if (ret == WOLFCLU_SUCCESS) {
        WOLFSSL_EVP_PKEY* pubKey = wolfSSL_X509_get_pubkey(caCert);

        if (pubKey == NULL) {
            wolfCLU_LogError("Could not get the public key out of the "
                    "certificate passed to -CA");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            if (wolfSSL_X509_verify(x509, pubKey) != 1) {
                wolfCLU_LogError("New x509 ca signed cert could not be "
                        "verified");
                ret = WOLFCLU_FATAL_ERROR;
            }
            else if (doVerify) {
                WOLFCLU_LOG(WOLFCLU_L0, "verify OK");
            }
            wolfSSL_EVP_PKEY_free(pubKey);
        }
    }
    /* the caller writes the encoded form out, after -text / -verify */

    wolfSSL_X509_free(caCert);
    wolfSSL_EVP_PKEY_free(caKey);

    return ret;
}


/* A WOLFSSL_X509 read in from a request carries an internal "is a CSR" flag,
 * and wolfSSL uses that flag to pick the type it re-parses the DER as when
 * walking extensions. Once -CA/-x509 has signed the request into a
 * certificate the flag is stale, and it makes wolfSSL_X509_print() decode the
 * new certificate as a request, fail, and silently drop the whole extension
 * section. Round tripping the signed DER back through d2i hands back a plain
 * certificate object with the flag clear.
 *
 * return WOLFCLU_SUCCESS on success */
static int reloadAsCert(WOLFSSL_X509** x509)
{
    int ret = WOLFCLU_SUCCESS;
    int derSz;
    byte* der = NULL;
    byte* pt; /* use pt with i2d/d2i to handle the pointer increment */
    WOLFSSL_X509* cert = NULL;

    if (x509 == NULL || *x509 == NULL) {
        return WOLFCLU_FATAL_ERROR;
    }

    derSz = wolfSSL_i2d_X509(*x509, NULL);
    if (derSz <= 0) {
        wolfCLU_LogError("Unable to get size of the signed certificate");
        ret = WOLFCLU_FATAL_ERROR;
    }

    if (ret == WOLFCLU_SUCCESS) {
        der = (byte*)XMALLOC(derSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (der == NULL) {
            wolfCLU_LogError("Could not allocate space for the signed "
                    "certificate");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        pt = der;
        if (wolfSSL_i2d_X509(*x509, &pt) != derSz) {
            wolfCLU_LogError("Unable to encode the signed certificate");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        pt = der;
        cert = wolfSSL_d2i_X509(NULL, (const unsigned char**)&pt, derSz);
        if (cert == NULL) {
            wolfCLU_LogError("Unable to parse the signed certificate");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            wolfSSL_X509_free(*x509);
            *x509 = cert;
        }
    }

    XFREE(der, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}

#endif

/* return WOLFCLU_SUCCESS on success */
int wolfCLU_requestSetup(int argc, char** argv)
{
#ifndef WOLFSSL_CERT_REQ
    wolfCLU_LogError("wolfSSL not compiled with --enable-certreq");
     /* silence unused variable warnings */
    (void) argc;
    (void) argv;
    return NOT_COMPILED_IN;
#elif defined(WOLFCLU_NO_FILESYSTEM)
    WOLFCLU_LOG(WOLFCLU_E0, "No Filesystem Support.");
     /* silence unused variable warnings */
    (void) argc;
    (void) argv;
    return NOT_COMPILED_IN;
#else

    char*        caFile       = NULL;
    char*        caKeyFile    = NULL;
    char*        outFile      = NULL;
    char*        keyFile      = NULL;
    char*        reqFile      = NULL;
    char*        configFile   = NULL;
    char*        outKeyFile   = NULL;

    const WOLFSSL_EVP_MD *md  = wolfSSL_EVP_sha256();

    long serialNumber = -1;

    int     ret = WOLFCLU_SUCCESS;
    char*   subj = NULL;
    char*   ext = NULL;
    char*   addExt = NULL;
    int     keyType = 0;
    int     keyInfo = 0;

    int     algCheck =   0;     /* algorithm type */
    int     outForm = PEM_FORM; /* default to PEM format */
    int     inForm  = PEM_FORM;
    int     option;
    int     longIndex = 1;
    int     days = 0;
    int     genX509 = 0;
    int     mdSet = 0;

    char password[MAX_PASSWORD_SIZE] = {0};
    /* the length wolfCLU_GetPassword() parsed, not the buffer capacity;
     * writeOutPkey() is handed sizeof(password) for that */
    int passwordLen = MAX_PASSWORD_SIZE;
    int passoutSet = 0;

    byte doVerify  = 0;
    byte doTextOut = 0;
    byte noOut     = 0;
    byte useDes    = 1;
    /* -help prints and stops; tracked so the password wipe still runs */
    byte helpOnly  = 0;
    /* cleared once the run has produced a certificate rather than a request,
     * so -text prints the right object regardless of which printer is used */
    byte isCSR     = 1;

    /* Multiple -addext is not yet supported. Detect it up front and fail
     * instead of silently dropping the extension and exiting success. */
    {
        int i, addExtCount = 0;
        for (i = 1; i < argc; i++) {
            if (argv[i] != NULL && XSTRCMP(argv[i], "-addext") == 0) {
                addExtCount++;
            }
        }
        if (addExtCount > 1) {
            wolfCLU_LogError("only one -addext arg is currently supported");
            return USER_INPUT_ERROR;
        }
    }

    opterr = 0; /* do not display unrecognized options */
    optind = 0; /* start at indent 0 */
    while (ret == WOLFCLU_SUCCESS && !helpOnly &&
            (option = wolfCLU_GetOpt(argc, argv, "",
                    req_options, &longIndex )) != END_OF_ARGS) {

        switch (option) {
            case WOLFCLU_EXTENSIONS:
                ext = optarg;
                break;

            case WOLFCLU_ADDEXT:
                addExt = optarg;
                break;

            case WOLFCLU_NODES:
                useDes = 0;
                break;


            case WOLFCLU_NEWKEY:
                if (keyFile != NULL) {
                    wolfCLU_LogError("-key/-inkey was set with -newkey "
                            "which is invalid");
                    ret = WOLFCLU_FATAL_ERROR;
                    break;
                }
                {
                    char* split;
                    if (optarg == NULL) {
                        wolfCLU_LogError("-newkey needs an arg");
                        ret = WOLFCLU_FATAL_ERROR;
                        break;
                    }
                    if ((split = XSTRSTR(optarg, ":")) == NULL) {
                        wolfCLU_LogError("-newkey needs form <type>:<info> "
                                "saw: %s", optarg);
                        ret = WOLFCLU_FATAL_ERROR;
                        break;
                    }
                    /* match the whole name before the ':', so "rsafoo:2048"
                     * is not accepted as rsa */
                    keyType = ((split - optarg) == 3 &&
                            XSTRNCMP("rsa", optarg, 3) == 0) ?
                                                EVP_PKEY_RSA : 0;
                    if (keyType == 0) {
                        wolfCLU_LogError("-newkey only supports rsa generation "
                                "saw request for %.*s, "
                            "please provide pre-generated key via commandline",
                            (int)(split - optarg), optarg);
                        ret = WOLFCLU_FATAL_ERROR;
                        break;
                    }
                    /* the agreement check against -rsa/-ecc/-ed25519 runs
                     * after the loop, where both values are final */
                    {
                    long bits = 0;

                    /* parsed like -days and -set_serial below; a bare XATOI
                     * accepts "-5" and hands it to the keygen bit setter */
                    if (wolfCLU_parseDecimalBounded(split+1,
                                WOLFCLU_RSA_BITS_2048, WOLFCLU_RSA_BITS_4096,
                                &bits) != WOLFCLU_SUCCESS ||
                            (bits != WOLFCLU_RSA_BITS_2048 &&
                             bits != WOLFCLU_RSA_BITS_3072 &&
                             bits != WOLFCLU_RSA_BITS_4096)) {
                        wolfCLU_LogError("-newkey rsa expects a key size of "
                                "%d, %d or %d, i.e. rsa:2048, got %s",
                                WOLFCLU_RSA_BITS_2048, WOLFCLU_RSA_BITS_3072,
                                WOLFCLU_RSA_BITS_4096, split+1);
                        ret = WOLFCLU_FATAL_ERROR;
                        break;
                    }
                    keyInfo = (int)bits;
                    }
                }
                break;

            case WOLFCLU_INFILE:
                reqFile = optarg;
                break;

            case WOLFCLU_INKEY: /* alias for -key, both are advertised */
            case WOLFCLU_KEY:
                if (keyFile != NULL) {
                    wolfCLU_LogError("-key/-inkey was already set");
                    ret = WOLFCLU_FATAL_ERROR;
                    break;
                }
                if (keyInfo != 0 && keyType != 0) {
                    wolfCLU_LogError("-newkey was set with -key/-inkey "
                            "this is invalid");
                    ret = WOLFCLU_FATAL_ERROR;
                    break;
                }
                keyFile = optarg;
                break;

            case WOLFCLU_OUTFILE:
                outFile = optarg;
                break;

            case WOLFCLU_OUTKEY:
                outKeyFile = optarg;
                break;

            case WOLFCLU_CA:
                caFile = optarg;
                break;

            case WOLFCLU_CAKEY:
                caKeyFile = optarg;
                break;

            case WOLFCLU_INFORM:
                inForm = wolfCLU_checkInform(optarg);
                if (inForm == USER_INPUT_ERROR || inForm == RAW_FORM) {
                    wolfCLU_LogError("must pass pem or der to -inform");
                    ret = WOLFCLU_FATAL_ERROR;
                }
                break;

            case WOLFCLU_OUTFORM:
                outForm = wolfCLU_checkOutform(optarg);
                if (outForm == USER_INPUT_ERROR || outForm == RAW_FORM) {
                    wolfCLU_LogError("must pass pem or der to -outform");
                    ret = WOLFCLU_FATAL_ERROR;
                }
                break;

            case WOLFCLU_SUBJECT:
                subj = optarg;
                break;

            case WOLFCLU_HELP:
                /* -passout is parsed before a later -help, so returning
                 * here would leave a password on the stack */
                wolfCLU_certgenHelp();
                helpOnly = 1;
                break;

            case WOLFCLU_RSA:
                if (algCheck != 0) {
                    wolfCLU_LogError("More than one key algorithm passed in");
                    ret = WOLFCLU_FATAL_ERROR;
                    break;
                }
                algCheck = WC_EVP_PKEY_RSA;
                break;

            /* Only keygen is unsupported for these. -key may still come
              * later in argv, so the check waits until parsing is done. */
            case WOLFCLU_ECC:
                if (algCheck != 0) {
                    wolfCLU_LogError("More than one key algorithm passed in");
                    ret = WOLFCLU_FATAL_ERROR;
                    break;
                }
                algCheck = WC_EVP_PKEY_EC;
                break;

            case WOLFCLU_ED25519:
                if (algCheck != 0) {
                    wolfCLU_LogError("More than one key algorithm passed in");
                    ret = WOLFCLU_FATAL_ERROR;
                    break;
                }
                algCheck = WC_EVP_PKEY_ED25519;
                break;

            case WOLFCLU_CONFIG:
                configFile = optarg;
                break;

            case WOLFCLU_DAYS:
                {
                long d = 0;

                if (optarg == NULL || wolfCLU_parseDecimalBounded(optarg, 1,
                            WOLFCLU_MAX_VALIDITY, &d) != WOLFCLU_SUCCESS) {
                    wolfCLU_LogError("-days expects a positive integer, got %s",
                            optarg != NULL ? optarg : "(nothing)");
                    ret = WOLFCLU_FATAL_ERROR;
                    break;
                }
                days = (int)d;
                break;
            }

            case WOLFCLU_CERT_SHA:
            case WOLFCLU_CERT_SHA224:
            case WOLFCLU_CERT_SHA256:
            case WOLFCLU_CERT_SHA384:
            case WOLFCLU_CERT_SHA512:
                /* GetOpt only spots a repeat of the same option name, and
                 * -sha/-sha1 are two names for one digest, so the exclusion
                 * is tracked here the way the key algorithms track algCheck */
                if (mdSet) {
                    wolfCLU_LogError("More than one digest passed in");
                    ret = WOLFCLU_FATAL_ERROR;
                    break;
                }
                mapOptionToMd(option, &md);
                mdSet = 1;
                break;

            case WOLFCLU_X509:
                genX509 = 1;
                break;

            case WOLFCLU_VERIFY:
                doVerify = 1;
                break;

            case WOLFCLU_TEXT_OUT:
                doTextOut = 1;
                break;

            case WOLFCLU_PASSWORD_OUT:
                ret = wolfCLU_GetPassword(password, &passwordLen, optarg);
                passoutSet = 1;
                break;

            case WOLFCLU_NOOUT:
                noOut = 1;
                break;

            case WOLFCLU_SERIAL:
                if (optarg == NULL) {
                    wolfCLU_LogError("-set_serial has no arg");
                    ret = WOLFCLU_FATAL_ERROR;
                    break;
                }
                if (wolfCLU_parseDecimalBounded(optarg, 1, LONG_MAX,
                        &serialNumber) != WOLFCLU_SUCCESS) {
                    wolfCLU_LogError("-set_serial expects a positive integer, "
                            "got %s", optarg);
                    ret = WOLFCLU_FATAL_ERROR;
                }
                break;

            case WOLFCLU_NEW:
                break;

            case ARG_FOUND_TWICE:
                ret = WOLFCLU_FATAL_ERROR;
                break;

            case ':':
            case '?':
                wolfCLU_LogError("Unexpected argument");
                ret = WOLFCLU_FATAL_ERROR;
                wolfCLU_certgenHelp();
                break;

            default:
                wolfCLU_LogError("Unsupported argument");
                ret = WOLFCLU_FATAL_ERROR;
                wolfCLU_certgenHelp();
        }
    }

    /* usage has been printed; the password buffer still has to be wiped */
    if (helpOnly) {
        wolfCLU_ForceZero(password, sizeof(password));
        return WOLFCLU_SUCCESS;
    }

    /* Checked after the loop rather than inside the -newkey case, so it holds
     * however the two options were ordered on the command line. */
    if (ret == WOLFCLU_SUCCESS && keyType != 0 && algCheck != 0 &&
            algCheck != keyType) {
        wolfCLU_LogError("-newkey asks to generate an rsa key but a different "
                "algorithm flag was also given");
        ret = WOLFCLU_FATAL_ERROR;
    }

    /* wolfCLU cannot generate an ECC or ED25519 key yet, but it can build a
     * request around one given by -key or carried by -in, so this only fails
     * when a key would actually have to be generated. */
    if (ret == WOLFCLU_SUCCESS &&
            (algCheck == WC_EVP_PKEY_EC || algCheck == WC_EVP_PKEY_ED25519) &&
            keyFile == NULL && reqFile == NULL) {
        wolfCLU_LogError("%s key generation is not yet supported; pass a "
                "pre-generated key with -key",
                algCheck == WC_EVP_PKEY_EC ? "ECC" : "ED25519");
        ret = WOLFCLU_FATAL_ERROR;
    }

    /* -CA certifies an existing request; without -in there is nothing to
     * certify. Caught here so the operator is told which option is missing,
     * rather than by the signature check inside caSignCert on an empty
     * request, which reports "Req Failed verification". */
    if (ret == WOLFCLU_SUCCESS && caFile != NULL && reqFile == NULL) {
        wolfCLU_LogError("-in was not set but -CA was passed; -CA signs a "
                "request that already exists");
        ret = WOLFCLU_FATAL_ERROR;
    }

    /* the two ask for mutually exclusive artifacts: a self signed root vs a
     * CA issued leaf. The signing dispatch takes -CA first, so left unchecked
     * this hands back a certificate the operator did not ask for, at exit 0 */
    if (ret == WOLFCLU_SUCCESS && caFile != NULL && genX509) {
        wolfCLU_LogError("-x509 and -CA cannot be used together; -x509 self "
                "signs while -CA signs with another certificate's key");
        ret = WOLFCLU_FATAL_ERROR;
    }

    /* without -CA there is nothing to pair -CAkey with, the run would fall
     * through to the CSR / -x509 path and hand back the wrong object */
    if (ret == WOLFCLU_SUCCESS && caKeyFile != NULL && caFile == NULL) {
        wolfCLU_LogError("-CAkey was passed without -CA; -CAkey names the key "
                "for the certificate given to -CA");
        ret = WOLFCLU_FATAL_ERROR;
    }

    /* -CA passes the request through untouched, so reject anything that would
     * alter it. Done here so -newkey cannot truncate -keyout before failing. */
    if (ret == WOLFCLU_SUCCESS && caFile != NULL &&
            (subj != NULL || configFile != NULL || addExt != NULL ||
             keyFile != NULL || keyType != 0)) {
        wolfCLU_LogError("-subj, -config, -addext, -key/-inkey and -newkey "
                "are not applied when signing with -CA");
        wolfCLU_LogError("create the request with those options first, then "
                "sign it");
        ret = WOLFCLU_FATAL_ERROR;
    }

    /* A PKCS#10 request has neither field, so say so rather than dropping
     * the value silently, matching the cross-option checks above. */
    if (ret == WOLFCLU_SUCCESS && caFile == NULL && !genX509 &&
            (serialNumber >= 0 || days != 0)) {
        WOLFCLU_LOG(WOLFCLU_L0, "Ignoring %s, a certificate request carries "
                "neither; they apply to -x509 and -CA",
                (serialNumber >= 0 && days != 0) ? "-set_serial and -days" :
                    (serialNumber >= 0 ? "-set_serial" : "-days"));
    }

    if (ret == WOLFCLU_SUCCESS && serialNumber < 0 && (caFile != NULL
            || genX509)) {
        WC_RNG rng = {0};
        if (wc_InitRng(&rng) != 0) {
            wolfCLU_LogError("Unable to initialize RNG for serial number");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            /* Fill a whole long with random bytes, accumulated separately
             * because serialNumber still holds the all-ones -1 sentinel that
             * OR-ing into would be a no-op. 'unsigned long' is the unsigned
             * twin of the long the setters take, so the byte count, mask and
             * final cast are one width on every target -- word64 matches long
             * only on LP64 and does not exist without a 64-bit type. */
            word32 index = 0;
            unsigned long serial = 0;
            byte randBytes[sizeof(unsigned long)];

            /* wolfCrypt returns 0 on success, not WOLFSSL_SUCCESS */
            if (wc_RNG_GenerateBlock(&rng, randBytes, (word32)sizeof(randBytes))
                    != 0) {
                wolfCLU_LogError("Unable to generate serial number");
                ret = WOLFCLU_FATAL_ERROR;
            }
            else {
                for (; index < (word32)sizeof(randBytes); index++) {
                    serial = (serial << 8) | randBytes[index];
                }
            }
            wc_FreeRng(&rng);

            if (ret == WOLFCLU_SUCCESS) {
                /* Clear the sign bit: a serial has to be a positive integer
                 * (RFC 5280 4.1.2.2), and the setters below take a signed
                 * long. Zero is then steered away from because both signing
                 * helpers gate on "serial > 0" and would otherwise skip
                 * wolfSSL_X509_set_serialNumber entirely, silently emitting
                 * wolfSSL's default serial instead of the one drawn here. */
                serial &= ~0UL >> 1;
                if (serial == 0) {
                    serial = 1;
                }
                serialNumber = (long)serial;
            }
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        WOLFSSL_BIO*  outBio    = NULL;
        /* -keyout is opened later, immediately before the generated key is
         * written. Opening it here would truncate the file even on the paths
         * that never generate a key -- including the case where -keyout names
         * the same file as -key, which destroyed the user's private key
         * before it had been read. */
        WOLFSSL_BIO*  outKeyBio = NULL;
        WOLFSSL_BIO*  keyBio    = NULL;
        WOLFSSL_BIO*  reqBio    = NULL;
        WOLFSSL_BIO*  caBio     = NULL;
        WOLFSSL_BIO*  caKeyBio  = NULL;
        WOLFSSL_X509* x509      = NULL;
        /* -out names the same file as -keyout: one stream, one free */
        byte sharedOutBio = 0;


        if (ret == WOLFCLU_SUCCESS && keyFile != NULL) {
            keyBio = wolfSSL_BIO_new_file(keyFile, "rb");
            if (keyBio == NULL) {
                wolfCLU_LogError("Could not open -key file %s", keyFile);
                ret = WOLFCLU_FATAL_ERROR;
            }
        }

        if (ret == WOLFCLU_SUCCESS && reqFile != NULL) {
            reqBio = wolfSSL_BIO_new_file(reqFile, "rb");
            if (reqBio == NULL) {
                wolfCLU_LogError("Could not open -in file %s", reqFile);
                ret = WOLFCLU_FATAL_ERROR;
            }
        }

        if (ret == WOLFCLU_SUCCESS && caFile != NULL) {
            caBio = wolfSSL_BIO_new_file(caFile, "rb");
            if (caBio == NULL) {
                wolfCLU_LogError("Could not open -CA file %s", caFile);
                ret = WOLFCLU_FATAL_ERROR;
            }
        }

        if (ret == WOLFCLU_SUCCESS && caKeyFile != NULL) {
            caKeyBio = wolfSSL_BIO_new_file(caKeyFile, "rb");
            if (caKeyBio == NULL) {
                wolfCLU_LogError("Could not open -CAkey file %s", caKeyFile);
                ret = WOLFCLU_FATAL_ERROR;
            }
        }

        /* gated on 'ret' like the BIO opens above, so a failure there is not
         * followed by an unrelated parse error naming the wrong option */
        if (ret == WOLFCLU_SUCCESS && reqBio != NULL) {
            if (inForm == PEM_FORM) {
                wolfSSL_PEM_read_bio_X509_REQ(reqBio, &x509, NULL, NULL);
                if (x509 == NULL) {
                    wolfCLU_LogError("Unable to create x509 object from PEM "
                            "req");
                    ret = WOLFCLU_FATAL_ERROR;
                }
            }
            else {
                wolfSSL_d2i_X509_REQ_bio(reqBio, &x509);
                if (x509 == NULL) {
                    wolfCLU_LogError("Unable to create x509 object from DER "
                            "req");
                    ret = WOLFCLU_FATAL_ERROR;
                }
            }
        }
        else if (ret == WOLFCLU_SUCCESS) {
            x509 = wolfSSL_X509_new();
            if (x509 == NULL) {
                wolfCLU_LogError("Unable to create empty x509 object");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }

        /* Default the request to v1 */
        if (ret == WOLFCLU_SUCCESS) {
            if (wolfSSL_X509_REQ_set_version(x509, WOLFSSL_X509_V1) !=
                    WOLFSSL_SUCCESS) {
                wolfCLU_LogError("Error setting CSR version");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }

        if (ret == WOLFCLU_SUCCESS) {
            /* pkey is hoisted to the create-block scope so it stays alive for the
             * dispatch below (makeReq/selfSignCert sign with it). Freed once at the
             * end of this block. */
            byte reSign = 0;

            /* Setting up public key for x509 cert */
            WOLFSSL_EVP_PKEY *pkey = NULL;
            if (ret == WOLFCLU_SUCCESS ) {
                WOLFSSL_EVP_PKEY_CTX* ctx = NULL;
                if (keyBio != NULL) {
                    pkey = wolfSSL_PEM_read_bio_PrivateKey(keyBio, NULL, NULL, NULL);
                    if (pkey == NULL) {
                        wolfCLU_LogError("Error reading key from file");
                        ret = USER_INPUT_ERROR;
                    }
                }
                else if (keyType != 0 && keyInfo != 0) {
                    ctx = wolfSSL_EVP_PKEY_CTX_new_id(keyType, NULL);

                    if (ctx == NULL) {
                        wolfCLU_LogError("Unknown/unsupported algo name");
                        ret = WOLFCLU_FATAL_ERROR;
                    }
                    else if (wolfSSL_EVP_PKEY_CTX_set_rsa_keygen_bits(ctx,
                            keyInfo) != WOLFSSL_SUCCESS) {
                        wolfCLU_LogError("Error setting rsa keygen bits to %d",
                                keyInfo);
                        ret = WOLFCLU_FATAL_ERROR;
                    }

                    if (ret == WOLFCLU_SUCCESS) {
                        if (wolfSSL_EVP_PKEY_keygen(ctx, &pkey) != WOLFSSL_SUCCESS) {
                            wolfCLU_LogError("Error with keygen");
                            ret = WOLFCLU_FATAL_ERROR;
                        }
                    }


                }
                else if (wolfSSL_X509_get_pubkey_type(x509) <= 0) {
                    wolfCLU_LogError("No public key provided for x509, "
                            "use -newkey, -key, or pass in a req");
                    ret = WOLFCLU_FATAL_ERROR;
                }

                if (ret == WOLFCLU_SUCCESS && pkey != NULL) {
                    if (wolfSSL_X509_set_pubkey(x509, pkey)
                            != WOLFSSL_SUCCESS) {
                        ret = WOLFCLU_FATAL_ERROR;
                    }
                    else if (reqBio != NULL) {
                        /* -newkey/-key replaced an existing request's public
                         * key, so its old signature no longer covers it */
                        reSign = 1;
                    }
                }

                /* new key was made so we must write it out */
                if (ret == WOLFCLU_SUCCESS && keyType != 0 && keyInfo != 0) {
                    if (outKeyFile != NULL) {
                        outKeyBio = wolfSSL_BIO_new_file(outKeyFile, "wb");
                        if (outKeyBio == NULL) {
                            wolfCLU_LogError("Could not open out -keyout "
                                    "file %s", outKeyFile);
                            ret = WOLFCLU_FATAL_ERROR;
                        }
                    }
                    if (ret == WOLFCLU_SUCCESS) {
                        ret = writeOutPkey(outKeyBio, pkey, useDes, password,
                                (word32)sizeof(password), passoutSet);
                    }
                }
                else if (ret == WOLFCLU_SUCCESS && outKeyFile != NULL) {
                    /* no key was generated, so there is nothing to write out */
                    WOLFCLU_LOG(WOLFCLU_L0, "Ignoring -keyout, it only applies "
                            "when -newkey generates a key");
                }

                wolfSSL_EVP_PKEY_CTX_free(ctx);
            }

            /* Handle extensions in this block. The -CA case never gets here
             * with any of these set, it was rejected up front before a key
             * was read or generated. */
            if (ret == WOLFCLU_SUCCESS && caBio == NULL) {

                if (ret == WOLFCLU_SUCCESS && configFile != NULL) {
                    ret = wolfCLU_readConfig(x509, configFile, (char*)"req", ext);
                    reSign = 1;
                }

                /*  If subj was provided, parse it */
                if (ret == WOLFCLU_SUCCESS && subj != NULL) {
                    WOLFSSL_X509_NAME *name;
                    name = wolfCLU_ParseX509NameString(subj, (int)XSTRLEN(subj));
                    if (name != NULL) {
                        wolfSSL_X509_REQ_set_subject_name(x509, name);
                        wolfSSL_X509_NAME_free(name);
                    }
                    else {
                        wolfCLU_LogError("Failed to parse -subj string");
                        wolfCLU_certgenHelp();
                        ret = USER_INPUT_ERROR;
                    }
                    reSign = 1;
                }

                /* apply the -addext extension, if present */
                if (ret == WOLFCLU_SUCCESS && addExt != NULL) {
                    reSign = 1;
                    ret = wolfCLU_parseAddExt(x509, addExt);
                }

                /* last try to source a subject name from stdin -- only when
                 * building a brand-new request. If a request was read in via -in,
                 * its subject must be preserved (e.g. a plain format conversion),
                 * so don't prompt/overwrite it here. */
                if (ret == WOLFCLU_SUCCESS && reqFile == NULL && subj == NULL &&
                        configFile == NULL) {
                    WOLFSSL_X509_NAME *name;

                    name = wolfSSL_X509_NAME_new();
                    if (name == NULL) {
                        ret = MEMORY_E;
                    }
                    else {
                        ret = wolfCLU_CreateX509Name(name);
                        if (ret == WOLFCLU_SUCCESS) {
                            wolfSSL_X509_REQ_set_subject_name(x509, name);
                        }
                        wolfSSL_X509_NAME_free(name);
                    }
                    reSign = 1;
                }
            }

            if (ret == WOLFCLU_SUCCESS) {
                if (caBio != NULL) {
                    /* -CA: issue a CA-signed cert. caSignCert reads */
                    if (caKeyFile == NULL) {
                        wolfCLU_LogError("-CAkey was not set but -ca "
                                "was passed");
                        ret = WOLFCLU_FATAL_ERROR;
                    }
                    if (ret == WOLFCLU_SUCCESS) {
                        ret = caSignCert(x509, caBio, caKeyBio, md,
                                days == 0 ? WOLFCLU_DEFAULT_VALIDITY : days,
                                serialNumber, doVerify);
                        isCSR = 0;
                    }
                }
                else if (genX509) {
                    /* -x509: self-signed cert, own key is issuer + signer */
                    ret = selfSignCert(x509, pkey, md,
                            days == 0 ? WOLFCLU_DEFAULT_VALIDITY : days,
                            serialNumber);
                    isCSR = 0;
                }
                else if (reqBio == NULL || reSign) {
                    /* CSR: sign with the subject's own key. An -in request
                     * altered by -subj/-config/-addext must be re-signed. */
                    ret = makeReq(x509, pkey, md, reSign);
                }

                /* the request has become a certificate, so hand the rest of
                 * the flow an object that knows it is one */
                if (ret == WOLFCLU_SUCCESS && !isCSR) {
                    ret = reloadAsCert(&x509);
                }
            }

            wolfSSL_EVP_PKEY_free(pkey);
        }

        /* -verify checks the signature, so it has to run after the dispatch
         * above has signed the request or certificate. It also has to run
         * after isCSR has been cleared by the -x509/-CA arms, otherwise a
         * certificate would be handed to the request verifier. CA signed
         * certs are already verified */
        if (ret == WOLFCLU_SUCCESS && doVerify && caBio == NULL) {
            ret = verifyX509(keyBio, x509, isCSR);
        }

         /* Nothing is opened when there is nothing to write: "wb" truncates,
          * so "-noout -out f" used to leave f an empty file. */
        if (ret == WOLFCLU_SUCCESS && (!noOut || doTextOut)) {
            if (outFile != NULL) {
                /* "-keyout f -out f" appends both objects to one file, as
                 * OpenSSL's req does. Reopening with "wb" would truncate the
                 * key and leave both BIOs flushing from offset 0. */
                if (outKeyBio != NULL &&
                        wolfCLU_isSameFile(outKeyFile, outFile)) {
                    outBio = outKeyBio;
                    sharedOutBio = 1;
                }
                else {
                    outBio = wolfSSL_BIO_new_file(outFile, "wb");
                    if (outBio == NULL) {
                        wolfCLU_LogError("Could not open -out file %s",
                                outFile);
                        ret = WOLFCLU_FATAL_ERROR;
                    }
                }
            }
            else {
                outBio = wolfSSL_BIO_new_fp(stdout, BIO_NOCLOSE);
                if (outBio == NULL) {
                    wolfCLU_LogError("Could open stdout as default output");
                    ret = WOLFCLU_FATAL_ERROR;
                }
            }
        }

        if (ret == WOLFCLU_SUCCESS && doTextOut) {
            int printRet;

            if (isCSR) {
#ifdef NO_WOLFSSL_REQ_PRINT
                printRet = wolfSSL_X509_REQ_print(outBio, x509, isCSR);
#else
                printRet = wolfSSL_X509_REQ_print(outBio, x509);
#endif
            }
            else {
                /* -CA/-x509 produced a certificate, not a request. Both
                 * request printers label their output "Certificate Request:",
                 * so print it as the certificate it is instead. */
                printRet = wolfSSL_X509_print(outBio, x509);
            }

            if (printRet != WOLFSSL_SUCCESS) {
                ret = WOLFCLU_FATAL_ERROR;
            }
        }

        /* the encoded body goes last so that -text reads before it, matching
         * OpenSSL */
        if (ret == WOLFCLU_SUCCESS && !noOut) {
            ret = writeOutX509(outBio, x509, outForm, isCSR);
        }

        wolfSSL_BIO_free(reqBio);
        wolfSSL_BIO_free(keyBio);
        if (!sharedOutBio) {
            wolfSSL_BIO_free(outBio);
        }
        wolfSSL_BIO_free(caBio);
        wolfSSL_BIO_free(caKeyBio);
        wolfSSL_BIO_free(outKeyBio);
        wolfSSL_X509_free(x509);
    }

    wolfCLU_ForceZero(password, sizeof(password));

    return ret;
#endif
}

