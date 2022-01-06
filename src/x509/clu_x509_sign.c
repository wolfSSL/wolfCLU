/* clu_x509_sign.c
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
#include <wolfclu/clu_error_codes.h>
#include <wolfclu/x509/clu_parse.h>
#include <wolfclu/x509/clu_x509_sign.h>

struct WOLFCLU_CERT_SIGN {
    int days;
    int keyType;
    enum wc_HashType hashType;
    char* outDir;
    WOLFSSL_BIO* serialFile;
    WOLFSSL_BIO* dataBase;
    WOLFSSL_X509* ca;
    WOLFSSL_CONF* config;
    union caKey {
        WOLFSSL_EVP_PKEY* pkey;
        /* other key options*/
    } caKey;
};


WOLFCLU_CERT_SIGN* wolfCLU_CertSignNew()
{
    WOLFCLU_CERT_SIGN* ret;

    ret = (WOLFCLU_CERT_SIGN*)XMALLOC(sizeof(WOLFCLU_CERT_SIGN), HEAP_HINT,
            DYNAMIC_TYPE_CERT);
    if (ret != NULL) {
        XMEMSET(ret, 0, sizeof(WOLFCLU_CERT_SIGN));
        wolfCLU_CertSignSetHash(ret, WC_HASH_TYPE_SHA256);
        wolfCLU_CertSignSetDate(ret, 365);
    }
    return ret;
}


void wolfCLU_CertSignFree(WOLFCLU_CERT_SIGN* csign)
{
    if (csign != NULL) {
        if (csign->outDir != NULL) {
            XFREE(csign->outDir, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            csign->outDir = NULL;
        }

        if (csign->config != NULL) {
            wolfSSL_NCONF_free(csign->config);
            csign->config = NULL;
        }

        wolfSSL_BIO_free(csign->dataBase);
        wolfSSL_BIO_free(csign->serialFile);
        wolfSSL_X509_free(csign->ca);
        if (csign->keyType == RSAk || csign->keyType == ECDSAk) {
            wolfSSL_EVP_PKEY_free(csign->caKey.pkey);
        }
    }
}


void wolfCLU_CertSignSetDate(WOLFCLU_CERT_SIGN* csign, int d)
{
    if (csign != NULL) {
        csign->days = d;
    }
}


void wolfCLU_CertSignSetHash(WOLFCLU_CERT_SIGN* csign,
        enum wc_HashType hashType)
{
    if (csign != NULL) {
        csign->hashType = hashType;
    }
}


/* take ownership of 'ca' or 'key' passed in */
void wolfCLU_CertSignSetCA(WOLFCLU_CERT_SIGN* csign, WOLFSSL_X509* ca,
        void* key, int keyType)
{
    if (csign != NULL) {
        if (ca != NULL) {
            csign->ca = ca;
        }

        if (key != NULL) {
            switch (keyType) {
                case RSAk:
                case ECDSAk:
                    csign->caKey.pkey = (WOLFSSL_EVP_PKEY*)key;
                    break;

                default:
                    printf("keytype needs added to wolfCLU_CertSignSetCA\n");
            }
            csign->keyType = keyType;
        }
    }
}


void wolfCLU_CertSignSetSerial(WOLFCLU_CERT_SIGN* csign, WOLFSSL_BIO* s)
{
    if (csign != NULL) {
        csign->serialFile = s;
    }
}


enum wc_HashType wolfCLU_StringToHashType(char* in)
{
    enum wc_HashType ret = WC_HASH_TYPE_NONE;

    if (XSTRNCMP(in, "md5", 3) == 0) {
        ret = WC_HASH_TYPE_MD5;
    }

    if (XSTRNCMP(in, "sha", 3) == 0) {
        ret = WC_HASH_TYPE_SHA;
    }

    if (XSTRNCMP(in, "sha224", 6) == 0) {
        ret = WC_HASH_TYPE_SHA256;
    }

    if (XSTRNCMP(in, "sha256", 6) == 0) {
        ret = WC_HASH_TYPE_SHA256;
    }

    if (XSTRNCMP(in, "sha384", 6) == 0) {
        ret = WC_HASH_TYPE_SHA384;
    }

    if (XSTRNCMP(in, "sha512", 6) == 0) {
        ret = WC_HASH_TYPE_SHA512;
    }
    return ret;
}


static int _wolfCLU_CertSetDate(WOLFSSL_X509* x509, int days)
{
    int ret = WOLFCLU_SUCCESS;

    if (x509 != NULL && days > 0) {
        WOLFSSL_ASN1_TIME *notBefore, *notAfter;
        time_t t;

        t = time(NULL);
        notBefore = wolfSSL_ASN1_TIME_adj(NULL, t, 0, 0);
        notAfter = wolfSSL_ASN1_TIME_adj(NULL, t, days, 0);
        if (notBefore == NULL || notAfter == NULL) {
            WOLFCLU_LOG(WOLFCLU_E0, "Error creating not before/after dates");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            wolfSSL_X509_set_notBefore(x509, notBefore);
            wolfSSL_X509_set_notAfter(x509, notAfter);
        }

        wolfSSL_ASN1_TIME_free(notBefore);
        wolfSSL_ASN1_TIME_free(notAfter);
    }
    return ret;
}


/* takes over ownership of out buffer
 * returns WOLFCLU_SUCCESS on success
 */
int wolfCLU_CertSignSetOut(WOLFCLU_CERT_SIGN* csign, char* out)
{
    int ret = WOLFCLU_SUCCESS;

    if (csign == NULL) {
        ret = WOLFCLU_FATAL_ERROR;
    }

    if (ret == WOLFCLU_SUCCESS && csign->outDir != NULL) {
        XFREE(csign->outDir, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        csign->outDir = NULL;
    }

    if (ret == WOLFCLU_SUCCESS) {
        csign->outDir = out;
    }
    return ret;
}


int wolfCLU_CertSignAppendOut(WOLFCLU_CERT_SIGN* csign, char* out)
{
    int ret = WOLFCLU_SUCCESS;
    int outSz;
    char* s = NULL;

    if (csign == NULL) {
        ret = WOLFCLU_FATAL_ERROR;
    }

    if (ret == WOLFCLU_SUCCESS && out != NULL) {
        outSz = (int)XSTRLEN(out);
    }

    /* case 1 where no dir is set and just using 'out' */
    if (ret == WOLFCLU_SUCCESS && csign->outDir == NULL && out != NULL) {
        s = (char*)XMALLOC(outSz + 1, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (s == NULL) {
            ret = MEMORY_E;
        }
        else {
            XMEMCPY(s, out, outSz);
            s[outSz] = '\0';
        }
    }

    /* case 2 where dir is set and appending 'out' */
    if (ret == WOLFCLU_SUCCESS && csign->outDir != NULL && out != NULL) {
        int currentSz = (int)XSTRLEN(csign->outDir);

        s = (char*)XMALLOC(outSz + currentSz + 1, HEAP_HINT,
                DYNAMIC_TYPE_TMP_BUFFER);
        if (s == NULL) {
            ret = MEMORY_E;
        }
        else {
            XMEMCPY(s, csign->outDir, currentSz);
            XMEMCPY(s + currentSz, out, outSz);
            s[outSz + currentSz] = '\0';
        }
    }

    /* case 3 where dir is set and 'out' is not set does not need 'csign' to
     * be updated */

    /* if a new string was made then update 'csign' with it */
    if (ret == WOLFCLU_SUCCESS && s != NULL) {
        ret = wolfCLU_CertSignSetOut(csign, s);
    }

    return ret;
}


static int wolfCLU_CertSignLog(WOLFCLU_CERT_SIGN* csign, WOLFSSL_X509* x509)
{
    int ret = WOLFCLU_SUCCESS;
    const byte* date = NULL;

    if (csign == NULL || x509 == NULL) {
        ret = WOLFCLU_FATAL_ERROR;
    }

    if (ret == WOLFCLU_SUCCESS) {
        date = wolfSSL_X509_notAfter(x509);
    }

    if (ret == WOLFCLU_SUCCESS && date != NULL) {
        wolfSSL_BIO_write(csign->dataBase, date+2,
                (int)XSTRLEN((char*)date)-2);
        wolfSSL_BIO_write(csign->dataBase, "\t", (int)XSTRLEN("\t"));
    }

    if (ret == WOLFCLU_SUCCESS) {
        char* subject;

        subject = wolfSSL_X509_NAME_oneline(wolfSSL_X509_get_subject_name(x509),
               NULL, 0); 
        wolfSSL_BIO_write(csign->dataBase, subject, (int)XSTRLEN(subject));
        wolfSSL_BIO_write(csign->dataBase, "\n", (int)XSTRLEN("\n"));
        XFREE(subject, NULL, DYNAMIC_TYPE_OPENSSL);
    }

    return ret;
}


/* sign the certificate 'x509' using info from 'csign'
 * 'ext' is an optional extensions section in the 'csign's config file loaded
 * return WOLFCLU_SUCCESS on success
 */
int wolfCLU_CertSign(WOLFCLU_CERT_SIGN* csign, WOLFSSL_X509* x509, char* ext)
{
    const WOLFSSL_EVP_MD* md;
    WOLFSSL_BIO* out = NULL;

    int ret = WOLFCLU_SUCCESS;

    if (csign == NULL || x509 == NULL) {
        WOLFCLU_LOG(WOLFCLU_E0, "Bad argument to certificate sign");
        ret = WOLFCLU_FATAL_ERROR;
    }

    if (ret == WOLFCLU_SUCCESS && csign->ca == NULL) {
        WOLFCLU_LOG(WOLFCLU_E0, "Bad argument no signing certificate");
        ret = WOLFCLU_FATAL_ERROR;
    }

    /* set cert date */
    if (ret == WOLFCLU_SUCCESS) {
        ret = _wolfCLU_CertSetDate(x509, csign->days);
    }

    /* set cert issuer */
    if (ret == WOLFCLU_SUCCESS) {
        WOLFSSL_X509_NAME* name;

        name = wolfSSL_X509_get_subject_name(csign->ca);
        if (name == NULL) {
            WOLFCLU_LOG(WOLFCLU_E0, "Error getting issuer name");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            if (wolfSSL_X509_set_issuer_name(x509, name) != WOLFSSL_SUCCESS) {
                WOLFCLU_LOG(WOLFCLU_E0, "Error setting issuer name");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
    }

    /* set hash for signature */
    if (ret == WOLFCLU_SUCCESS) {
        switch (csign->hashType) {
            case WC_HASH_TYPE_MD5:
                md  = wolfSSL_EVP_md5();
                break;

            case WC_HASH_TYPE_SHA:
                md  = wolfSSL_EVP_sha1();
                break;

            case WC_HASH_TYPE_SHA224:
                md  = wolfSSL_EVP_sha224();
                break;

            case WC_HASH_TYPE_SHA256:
                md  = wolfSSL_EVP_sha256();
                break;

            case WC_HASH_TYPE_SHA384:
                md  = wolfSSL_EVP_sha384();
                break;

            case WC_HASH_TYPE_SHA512:
                md  = wolfSSL_EVP_sha512();
                break;

            case WC_HASH_TYPE_NONE:
            case WC_HASH_TYPE_MD2:
            case WC_HASH_TYPE_MD4:
            case WC_HASH_TYPE_MD5_SHA:
            case WC_HASH_TYPE_SHA3_224:
            case WC_HASH_TYPE_SHA3_256:
            case WC_HASH_TYPE_SHA3_384:
            case WC_HASH_TYPE_SHA3_512:
            case WC_HASH_TYPE_BLAKE2B:
            case WC_HASH_TYPE_BLAKE2S:
            case WC_HASH_TYPE_MAX:
            case WC_HASH_TYPE_SHA512_224:
            case WC_HASH_TYPE_SHA512_256:
            case WC_HASH_TYPE_SHAKE128:
            default:
                WOLFCLU_LOG(WOLFCLU_E0, "Unsupported hash type");
                ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* set serial number of certificate */
    if (ret == WOLFCLU_SUCCESS) {
        WOLFSSL_ASN1_INTEGER* s;
        char buf[EXTERNAL_SERIAL_SIZE*2];
        int size = EXTERNAL_SERIAL_SIZE*2;

        if (csign->serialFile != NULL) {
            s = wolfSSL_ASN1_INTEGER_new();
            wolfSSL_a2i_ASN1_INTEGER(csign->serialFile, s, buf, size);
        }
        else {
            int defaultSerialSz = 20;
            WOLFSSL_BIGNUM* bn;

            bn = wolfSSL_BN_new();
            if (wolfSSL_BN_rand(bn, (defaultSerialSz*WOLFSSL_BIT_SIZE), 0, 0)
                    != WOLFSSL_SUCCESS) {
            }

            /* make positive */
            wolfSSL_BN_clear_bit(bn, (defaultSerialSz*WOLFSSL_BIT_SIZE)-1);

            s = wolfSSL_BN_to_ASN1_INTEGER(bn, NULL);
            wolfSSL_BN_free(bn);
        }
        wolfSSL_X509_set_serialNumber(x509, s);
        wolfSSL_ASN1_INTEGER_free(s);
    }

    /* set extensions */
    if (ext != NULL) {
        wolfCLU_setExtensions(x509, csign->config, ext);
    }

    /* sign the certificate */
    if (csign->keyType == RSAk || csign->keyType == ECDSAk) {
        if (ret == WOLFCLU_SUCCESS) {
            if (wolfSSL_X509_check_private_key(csign->ca, csign->caKey.pkey) !=
                    WOLFSSL_SUCCESS) {
                WOLFCLU_LOG(WOLFCLU_E0, "Private key does not match with CA");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }

        if (ret == WOLFCLU_SUCCESS) {
            if (wolfSSL_X509_sign(x509, csign->caKey.pkey, md) <= 0) {
                WOLFCLU_LOG(WOLFCLU_E0, "Error signing certificate");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
    } /* @TODO else case here could get the tbs buffer or just the der of the
       * x509 struct and use a different method for signing and creating the
       * certificate */

    /* create WOLFSSL_BIO for output */
    if (ret == WOLFCLU_SUCCESS) {
        out = wolfSSL_BIO_new_file(csign->outDir, "wb");
        if (out == NULL) {
            WOLFCLU_LOG(WOLFCLU_E0, "Could not open output file %s",
                    csign->outDir);
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* write out the certificate */
    if (ret == WOLFCLU_SUCCESS && out != NULL) {
        if (wolfSSL_PEM_write_bio_X509(out, x509) != WOLFSSL_SUCCESS) {
            WOLFCLU_LOG(WOLFCLU_E0, "Error writing out certificate");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* write results to data base */
    if (ret == WOLFCLU_SUCCESS && csign->dataBase != NULL) {
        ret = wolfCLU_CertSignLog(csign, x509);
    }

    return ret;
}


/* returns a new WOLFSSL_CERT_SIGN on success and NULL on failure */
WOLFCLU_CERT_SIGN* wolfCLU_readSignConfig(char* config, char* sect)
{
    int keyType = 0;
    WOLFCLU_CERT_SIGN* ret = NULL;
    WOLFSSL_CONF* conf = NULL;
    WOLFSSL_X509* ca = NULL;
    WOLFSSL_EVP_PKEY* caKey = NULL;
    long line = 0;
    long defaultDays;
    char* CAsection;
    char* dir = NULL;
    char* serial;
    char* defaultMD;
    char* tmp;

    ret = wolfCLU_CertSignNew();
    if (ret != NULL) {
        ret->config = wolfSSL_NCONF_new(NULL);
        if (ret->config == NULL) {
            WOLFCLU_LOG(WOLFCLU_E0, "Unable to create new config struct");
            wolfCLU_CertSignFree(ret);
            ret = NULL;
        }
    }

    if (ret != NULL) {
        if (wolfSSL_NCONF_load(ret->config, config, &line) != WOLFSSL_SUCCESS) {
            WOLFCLU_LOG(WOLFCLU_E0, "Unable to open config file %s", config);
            wolfCLU_CertSignFree(ret);
            ret = NULL;
        }
        conf = ret->config;
    }

    if (ret != NULL) {
        CAsection = wolfSSL_NCONF_get_string(conf, sect, "default_ca");
        if (CAsection == NULL) {
            CAsection = sect;
        }

        dir = wolfSSL_NCONF_get_string(conf, CAsection, "dir");
        tmp = wolfSSL_NCONF_get_string(conf, CAsection, "new_certs_dir");
        if (wolfCLU_CertSignAppendOut(ret, tmp) != WOLFCLU_SUCCESS) {
            WOLFCLU_LOG(WOLFCLU_E0, "Unable to set output locate %s", tmp);
            wolfCLU_CertSignFree(ret);
            ret = NULL;
        }
    }

    if (ret != NULL) {
        tmp = wolfSSL_NCONF_get_string(conf, CAsection, "database");
        if (tmp != NULL) {
            ret->dataBase = wolfSSL_BIO_new_file(tmp, "wb");
            if (ret->dataBase == NULL) {
                WOLFCLU_LOG(WOLFCLU_E0, "Unable to open data base file %s",
                        tmp);
                wolfCLU_CertSignFree(ret);
                ret = NULL;
            }
        }
    }

    /* set signing issuer */
    if (ret != NULL) {
        tmp = wolfSSL_NCONF_get_string(conf, CAsection, "certificate");
        if (tmp != NULL) {
            ca = wolfSSL_X509_load_certificate_file(tmp, WOLFSSL_FILETYPE_PEM);
            if (ca == NULL) {
                WOLFCLU_LOG(WOLFCLU_E0, "Unable to open CA file %s", tmp);
                wolfCLU_CertSignFree(ret);
                ret = NULL;
            }
        }
    }

    /* check on setting serial */
    if (ret != NULL) {
        serial = wolfSSL_NCONF_get_string(conf, CAsection, "serial");
        if (serial != NULL) {
            WOLFSSL_BIO* s;

            s = wolfSSL_BIO_new_file(serial, "rb");
            if (s == NULL) {
                WOLFCLU_LOG(WOLFCLU_E0, "Unable to open serial file %s",
                        serial);
                wolfCLU_CertSignFree(ret);
                ret = NULL;
            }
            else {
                wolfCLU_CertSignSetSerial(ret, s);
            }
        }
    }

    if (ret != NULL) {
        if (wolfSSL_NCONF_get_number(conf, CAsection, "default_days",
                    &defaultDays) == WOLFSSL_SUCCESS) {
            wolfCLU_CertSignSetDate(ret, (int)defaultDays);
        }

        defaultMD = wolfSSL_NCONF_get_string(conf, CAsection, "default_md");
        if (defaultMD != NULL) {
            wolfCLU_CertSignSetHash(ret, wolfCLU_StringToHashType(defaultMD));
        }

        /* get signing key */
        tmp = wolfSSL_NCONF_get_string(conf, CAsection, "private_key");
        if (tmp != NULL) {
            WOLFSSL_BIO* in = wolfSSL_BIO_new_file(tmp, "rb");
            if (in == NULL) {
                WOLFCLU_LOG(WOLFCLU_E0, "Unable to open private key file %s",
                        tmp);
                wolfCLU_CertSignFree(ret);
                ret = NULL;
            }
            else {
                caKey = wolfSSL_PEM_read_bio_PrivateKey(in, NULL, NULL, NULL);
                wolfSSL_BIO_free(in);
            }
        }
    }

    if (caKey != NULL) {
        keyType = wolfCLU_GetTypeFromPKEY(caKey);
    }

    wolfCLU_CertSignSetCA(ret, ca, caKey, keyType);
    return ret;
}


