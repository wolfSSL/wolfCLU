/* clu_x509_sign.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
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
#include <wolfclu/clu_log.h>
#include <wolfclu/clu_error_codes.h>
#include <wolfclu/x509/clu_parse.h>
#include <wolfclu/x509/clu_x509_sign.h>
#include <wolfclu/x509/clu_mldsa.h>
#include <wolfclu/x509/clu_cert.h>

#include <ctype.h>
#ifdef WOLFCLU_HAVE_MLDSA
    #include <wolfssl/wolfcrypt/dilithium.h>
#endif  /* WOLFCLU_HAVE_MLDSA */
#include <wolfssl/wolfcrypt/asn_public.h>

/* For wolfCLU_GetTypeFromPKEY and ML-DSA detection */
#include <wolfclu/pkey/clu_pkey.h>
#include <wolfclu/sign-verify/clu_sign.h>

#define WOLFCLU_CN_MATCH    0x00000001 /* country name must match */
#define WOLFCLU_CN_SUPPLIED 0x00000002 /* country name must be set */
#define WOLFCLU_SN_MATCH    0x00000004 /* state name must match */
#define WOLFCLU_SN_SUPPLIED 0x00000008 /* state name must be set */
#define WOLFCLU_LN_MATCH    0x00000010 /* locality name must match */
#define WOLFCLU_LN_SUPPLIED 0x00000020 /* locality name must be set */
#define WOLFCLU_ON_MATCH    0x00000040 /* org name must match */
#define WOLFCLU_ON_SUPPLIED 0x00000080 /* org name must be set */
#define WOLFCLU_UN_MATCH    0x00000100 /* org unit name must match */
#define WOLFCLU_UN_SUPPLIED 0x00000200 /* org unit name must be set */
#define WOLFCLU_CM_MATCH    0x00000400 /* common name must match */
#define WOLFCLU_CM_SUPPLIED 0x00000800 /* common name must be set */
#define WOLFCLU_EA_MATCH    0x00001000 /* email must match */
#define WOLFCLU_EA_SUPPLIED 0x00002000 /* email must be set */

#ifndef WOLFCLU_NO_FILESYSTEM

struct WOLFCLU_CERT_SIGN {
    char* outDir;
    char* ext; /* location of extensions to use */
    WOLFSSL_BIO* serialFile;
    WOLFSSL_BIO* dataBase;
    WOLFSSL_BIO* randFile;
    WOLFSSL_X509* ca;
    WOLFSSL_CONF* config;
    char* crl;
    char* crlDir;
    union caKey {
        WOLFSSL_EVP_PKEY* pkey;
#if defined(WOLFCLU_HAVE_MLDSA)
        MlDsaKey* mldsa;
#endif
        /* other key options*/
    } caKey;
    int days;
    int keyType;
    int outForm;
    int crlNumber;
    word32 policy; /* bitmap of policy restrictions */
    enum wc_HashType hashType;
    byte unique; /* flag if subject needs to be unique */
};


WOLFCLU_CERT_SIGN* wolfCLU_CertSignNew(void)
{
    WOLFCLU_CERT_SIGN* ret;

    ret = (WOLFCLU_CERT_SIGN*)XMALLOC(sizeof(WOLFCLU_CERT_SIGN), HEAP_HINT,
            DYNAMIC_TYPE_CERT);
    if (ret != NULL) {
        XMEMSET(ret, 0, sizeof(WOLFCLU_CERT_SIGN));
        wolfCLU_CertSignSetHash(ret, WC_HASH_TYPE_SHA256);
        wolfCLU_CertSignSetDate(ret, 365);
        ret->outForm = PEM_FORM;
    }
    return ret;
}


int wolfCLU_CertSignFree(WOLFCLU_CERT_SIGN* csign)
{
    int ret = WOLFCLU_SUCCESS;

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

        /* write out new 256 bytes of random data */
        if (csign->randFile) {
            byte seed[256];
            int  seedSz = 256;

            if (wolfSSL_RAND_bytes(seed, seedSz) != WOLFSSL_SUCCESS) {
                wolfCLU_LogError("Unable to generate new random data");
                ret = WOLFCLU_FATAL_ERROR;
            }
            else {
                if (wolfSSL_BIO_write(csign->randFile, seed, seedSz)
                        != seedSz) {
                    wolfCLU_LogError("Unable to write new random data");
                    ret = WOLFCLU_FATAL_ERROR;
                }
            }
        }
        wolfSSL_BIO_free(csign->randFile);
        wolfSSL_X509_free(csign->ca);
        /* DSA/DH keys rejected by CertSignSetCA; only RSA/ECDSA use pkey */
        if (csign->keyType == RSAk || csign->keyType == ECDSAk) {
            wolfSSL_EVP_PKEY_free(csign->caKey.pkey);
        }
#if defined(WOLFCLU_HAVE_MLDSA)
        if (wolfCLU_IsMLDSAKeyType(csign->keyType)) {
            wolfCLU_FreeMLDSAKeyHeap(&csign->caKey.mldsa);
        }
#endif
        XFREE(csign, HEAP_HINT, DYNAMIC_TYPE_CERT);
    }
    return ret;
}

#ifdef HAVE_CRL
void wolfCLU_CertSignSetCrl(WOLFCLU_CERT_SIGN* csign, char* crl, char* crlDir,
        int crlNumber)
{
    if (csign != NULL) {
        csign->crl    = crl;
        csign->crlDir = crlDir;
        csign->crlNumber = crlNumber;
    }
}
#endif /* HAVE_CRL */

static void wolfCLU_CertSignSetRandFile(WOLFCLU_CERT_SIGN* csign, char* f)
{
    if (csign != NULL) {
        wolfSSL_BIO_free(csign->randFile);
        csign->randFile = wolfSSL_BIO_new_file(f, "wb+");
        if (csign->randFile == NULL) {
            wolfCLU_LogError("Error reading rand file");
        }
        else {
            byte seed[256];
            int  seedSz = 256;

            seedSz = wolfSSL_BIO_read(csign->randFile, seed, seedSz);
            wolfSSL_RAND_add(seed, seedSz, 0);
            /* estimating randomness of 0, wolfSSL seeds internally */
        }
    }
}

void wolfCLU_CertSignSetExt(WOLFCLU_CERT_SIGN* csign, char* ext)
{
    if (csign != NULL) {
        csign->ext = ext;
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


int wolfCLU_CertSignSetOutForm(WOLFCLU_CERT_SIGN* csign, int outForm)
{
    if (csign == NULL) {
        return BAD_FUNC_ARG;
    }

    csign->outForm = outForm;
    return WOLFCLU_SUCCESS;
}


/* Take ownership of CA cert. Skip key update if key is NULL. */
int wolfCLU_CertSignSetCA(WOLFCLU_CERT_SIGN* csign, WOLFSSL_X509* ca,
        void* key, int keyType)
{
    if (csign == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Validate keyType before accepting any input. */
    if (key != NULL) {
        int validKeyType = (keyType == RSAk || keyType == ECDSAk);
#if defined(WOLFCLU_HAVE_MLDSA)
        if (!validKeyType) {
            validKeyType = wolfCLU_IsMLDSAKeyType(keyType);
        }
#endif
        if (!validKeyType) {
            wolfCLU_LogError("Unsupported key type in CertSignSetCA");
            return WOLFCLU_FATAL_ERROR;
        }
    }

    /* Keep old CA cert until key switch succeeds to prevent leaks. */
    {
        WOLFSSL_X509* oldCa = csign->ca;

        if (key != NULL) {
            int oldKeyType = csign->keyType;

#if defined(WOLFCLU_HAVE_MLDSA)
            if (wolfCLU_IsMLDSAKeyType(oldKeyType)) {
                wolfCLU_FreeMLDSAKeyHeap(&csign->caKey.mldsa);
            }
            else
#endif
            if (oldKeyType == RSAk || oldKeyType == ECDSAk) {
                wolfSSL_EVP_PKEY_free(csign->caKey.pkey);
                csign->caKey.pkey = NULL;
            }

            switch (keyType) {
                case RSAk:
                case ECDSAk:
                    csign->caKey.pkey = (WOLFSSL_EVP_PKEY*)key;
                    csign->keyType = keyType;
                    break;

#if defined(WOLFCLU_HAVE_MLDSA)
                case DILITHIUM_LEVEL2k:
                case DILITHIUM_LEVEL3k:
                case DILITHIUM_LEVEL5k:
                case ML_DSA_44k:
                case ML_DSA_65k:
                case ML_DSA_87k:
                    csign->caKey.mldsa = (MlDsaKey*)key;
                    csign->keyType = keyType;
                    break;
#endif

                default:
                    /* csign->ca still == oldCa; caller's 'ca' not consumed. */
                    return WOLFCLU_FATAL_ERROR;
            }
        }

        /* Key switch succeeded (or key==NULL); safe to swap cert. */
        if (ca != NULL) {
            wolfSSL_X509_free(oldCa);
            csign->ca = ca;
        }
    }
    return WOLFCLU_SUCCESS;
}

/* ref: https://github.com/wolfssl/wolfssl-examples/X9.146/gen_ecdsa_mldsa_dual_keysig_cert.c */
int wolfCLU_GenChimeraCertSign(WOLFSSL_BIO *bioCaKey, WOLFSSL_BIO *bioAltCaKey,
        WOLFSSL_BIO *bioAltSubjPubKey, WOLFSSL_BIO *bioSubjKey,
        WOLFSSL_X509 *caCert, const char *subject,
        const char *outFileName, int outForm)
{
#if defined(WOLFSSL_DUAL_ALG_CERTS) && defined(WOLFCLU_HAVE_MLDSA)
    int ret = WOLFCLU_SUCCESS;
    int isCA = 0;

    WC_RNG   rng;
    ecc_key  caKey;
    ecc_key  serverKey;
    MlDsaKey altCaKey;
    word32 idx = 0;
    byte level = 0;

    Cert newCert;
    DecodedCert preTBS;

    int initRNG       = 0;
    int initCaKey     = 0;
    int initServerKey = 0;
    int initAltCaKey  = 0;
    int initPreTBS    = 0;

    XFILE caKeyFp       = NULL;
    XFILE altCaKeyFp    = NULL;
    XFILE altCaPubKeyFp = NULL;
    XFILE serverKeyFp   = NULL;
    WOLFSSL_BIO *out    = NULL;

    char *token   = NULL;
    char *key     = NULL;
    char *value   = NULL;
    char *saveptr = NULL;
    char *slash   = NULL;
    char *subj    = NULL;
    int  subjSz   = 0;

    /* custom cert extension oid */
    const char *subjectAltPubKeyOid = "2.5.29.72";
    const char *altSigAlgOid        = "2.5.29.73";
    const char *altSigValOid        = "2.5.29.74";

    /*
     * LARGE_TEMP_SZ defines the size of temporary buffers used for signature key,
     * verification key and signature value buffers.
     * The value 11264 is enough for P-521 and ML-DSA-87 PEM certs.
    */
    const int LARGE_TEMP_SZ = 11264;
    byte* caKeyBuf = NULL;
    int  caKeySz   = LARGE_TEMP_SZ;
    byte* altCaKeyBuf = NULL;
    int  altCaKeySz = LARGE_TEMP_SZ;
    byte* sapkiBuf = NULL;
    int  sapkiSz = LARGE_TEMP_SZ;
    byte* altSigAlgBuf = NULL;
    int  altSigAlgSz = LARGE_TEMP_SZ;
    byte* scratchBuf = NULL;
    int  scratchSz = LARGE_TEMP_SZ;
    byte* preTbsBuf = NULL;
    int  preTbsSz = LARGE_TEMP_SZ;
    byte* altSigValBuf = NULL;
    int  altSigValSz = LARGE_TEMP_SZ;
    byte* derBuf = NULL;
    int  derSz = LARGE_TEMP_SZ;
    byte* outBuf = NULL;
    int  outSz = LARGE_TEMP_SZ;
    DerBuffer *derObj = NULL;

    /* if generate server cert */
    byte* caCertBuf = NULL;
    int  caCertSz = LARGE_TEMP_SZ;
    byte* serverKeyBuf = NULL;
    int  serverKeySz = LARGE_TEMP_SZ;

    if (bioCaKey == NULL || bioAltCaKey == NULL || bioAltSubjPubKey == NULL
        || subject == NULL || outFileName == NULL) {
        wolfCLU_LogError("Error invalid argument wolfCLU_GenChimeraCertSign");
        ret = BAD_FUNC_ARG;
    }
    else if (bioSubjKey == NULL && caCert == NULL) {
        isCA = 1;
    }
    else if (bioSubjKey != NULL && caCert != NULL) {
        isCA = 0;
    }
    else {
        wolfCLU_LogError("Error invalid argument wolfCLU_GenChimeraCertSign");
        ret = BAD_FUNC_ARG;
    }

    if (ret == WOLFCLU_SUCCESS) {
        caKeyBuf     = (byte*)XMALLOC(LARGE_TEMP_SZ, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        altCaKeyBuf  = (byte*)XMALLOC(LARGE_TEMP_SZ, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        sapkiBuf     = (byte*)XMALLOC(LARGE_TEMP_SZ, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        altSigAlgBuf = (byte*)XMALLOC(LARGE_TEMP_SZ, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        scratchBuf   = (byte*)XMALLOC(LARGE_TEMP_SZ, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        preTbsBuf    = (byte*)XMALLOC(LARGE_TEMP_SZ, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        altSigValBuf = (byte*)XMALLOC(LARGE_TEMP_SZ, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        derBuf       = (byte*)XMALLOC(LARGE_TEMP_SZ, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        outBuf       = (byte*)XMALLOC(LARGE_TEMP_SZ, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        caCertBuf    = (byte*)XMALLOC(LARGE_TEMP_SZ, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        serverKeyBuf = (byte*)XMALLOC(LARGE_TEMP_SZ, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

        if (caKeyBuf == NULL || altCaKeyBuf == NULL || sapkiBuf == NULL ||
            altSigAlgBuf == NULL || scratchBuf == NULL || preTbsBuf == NULL ||
            altSigValBuf == NULL || derBuf == NULL || outBuf == NULL ||
            caCertBuf == NULL || serverKeyBuf == NULL) {
            ret = MEMORY_E;
        }
        else {
            XMEMSET(caKeyBuf,     0, LARGE_TEMP_SZ);
            XMEMSET(altCaKeyBuf,  0, LARGE_TEMP_SZ);
            XMEMSET(sapkiBuf,     0, LARGE_TEMP_SZ);
            XMEMSET(altSigAlgBuf, 0, LARGE_TEMP_SZ);
            XMEMSET(scratchBuf,   0, LARGE_TEMP_SZ);
            XMEMSET(preTbsBuf,    0, LARGE_TEMP_SZ);
            XMEMSET(altSigValBuf, 0, LARGE_TEMP_SZ);
            XMEMSET(derBuf,       0, LARGE_TEMP_SZ);
            XMEMSET(outBuf,       0, LARGE_TEMP_SZ);
            XMEMSET(caCertBuf,    0, LARGE_TEMP_SZ);
            XMEMSET(serverKeyBuf, 0, LARGE_TEMP_SZ);
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = wc_InitRng(&rng);
        if (ret != 0) {
            wolfCLU_LogError("Error init RNG");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            initRNG = 1;
            ret = WOLFCLU_SUCCESS;
        }
    }

    /* open the CA der certificate */
    if (ret == WOLFCLU_SUCCESS && !isCA) {
        const byte *tmpBuf = wolfSSL_X509_get_der(caCert, &caCertSz);
        if (tmpBuf == NULL || caCertSz <= 0) {
            wolfCLU_LogError("Error getting DER from CA cert");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            XMEMCPY(caCertBuf, tmpBuf, caCertSz);
            ret = WOLFCLU_SUCCESS;
        }
    }

    /* open CA ecc private key */
    if (ret == WOLFCLU_SUCCESS) {
        ret = (int)wolfSSL_BIO_get_fp(bioCaKey, &caKeyFp);
        if (ret != WOLFCLU_SUCCESS) {
            wolfCLU_LogError("Error cannot get CA key fd");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            XFSEEK(caKeyFp, 0, SEEK_SET);
            ret = (int)XFREAD(caKeyBuf, 1, caKeySz, caKeyFp);
            if (ret <= 0) {
                wolfCLU_LogError("Error reading CA key");
                ret = WOLFCLU_FATAL_ERROR;
            }
            else {
                caKeySz = ret;
                ret = WOLFCLU_SUCCESS;
            }
        }
    }

    /* open server ecc private key */
    if (ret == WOLFCLU_SUCCESS && !isCA) {
        ret = (int)wolfSSL_BIO_get_fp(bioSubjKey, &serverKeyFp);
        if (ret != WOLFCLU_SUCCESS) {
            wolfCLU_LogError("Error cannot get server key fd");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            XFSEEK(serverKeyFp, 0, SEEK_SET);
            ret = (int)XFREAD(serverKeyBuf, 1, serverKeySz, serverKeyFp);
            if (ret <= 0) {
                wolfCLU_LogError("Error reading server key");
                ret = WOLFCLU_FATAL_ERROR;
            }
            else {
                serverKeySz = ret;
                ret = WOLFCLU_SUCCESS;
            }
        }
    }

    /* open CA ecc private key */
    if (ret == WOLFCLU_SUCCESS) {
        /* Try EC PRIVATE KEY format first */
        ret = wc_PemToDer(caKeyBuf, caKeySz, ECC_PRIVATEKEY_TYPE,
                            &derObj, HEAP_HINT, NULL, NULL);
        if (ret < 0) {
            /* Try PRIVATE KEY format (PKCS#8) */
            ret = wc_PemToDer(caKeyBuf, caKeySz, PRIVATEKEY_TYPE,
                                &derObj, HEAP_HINT, NULL, NULL);
            if (ret != 0) {
                wolfCLU_LogError("Error convert pem to der");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }

        if (ret == 0) {
            XMEMSET(caKeyBuf, 0, caKeySz); /* clear original buffer */
            caKeySz = derObj->length;
            XMEMCPY(caKeyBuf, derObj->buffer, caKeySz);
            wc_FreeDer(&derObj);
            ret = WOLFCLU_SUCCESS;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = wc_ecc_init(&caKey);
        if (ret != 0) {
            wolfCLU_LogError("Error init ecc key");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            initCaKey = 1;
            ret = WOLFCLU_SUCCESS;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        idx = 0;
        ret = wc_EccPrivateKeyDecode(caKeyBuf, &idx, &caKey, caKeySz);
        if (ret != 0) {
            wolfCLU_LogError("Error decoding ECC key");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            ret = WOLFCLU_SUCCESS;
        }
    }

    /* load server ecc private key */
    if (ret == WOLFCLU_SUCCESS && !isCA) {
        ret = wc_PemToDer(serverKeyBuf, serverKeySz, ECC_PRIVATEKEY_TYPE,
                            &derObj, HEAP_HINT, NULL, NULL);
        if (ret < 0) {
            /* Try PRIVATE KEY format (PKCS#8) */
            ret = wc_PemToDer(serverKeyBuf, serverKeySz, PRIVATEKEY_TYPE,
                                &derObj, HEAP_HINT, NULL, NULL);
            if (ret < 0) {
                wolfCLU_LogError("Error convert pem to der");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }

        if (ret == 0) {
            XMEMSET(serverKeyBuf, 0, serverKeySz); /* clear original buffer */
            serverKeySz = derObj->length;
            XMEMCPY(serverKeyBuf, derObj->buffer, serverKeySz);
            wc_FreeDer(&derObj);
            ret = WOLFCLU_SUCCESS;
        }
    }

    if (ret == WOLFCLU_SUCCESS && !isCA) {
        ret = wc_ecc_init(&serverKey);
        if (ret != 0) {
            wolfCLU_LogError("Error init server key");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            initServerKey = 1;
            ret = WOLFCLU_SUCCESS;
        }
    }

    if (ret == WOLFCLU_SUCCESS && !isCA) {
        idx = 0;
        ret = wc_EccPrivateKeyDecode(serverKeyBuf, &idx,
                                        &serverKey, serverKeySz);
        if (ret != 0) {
            wolfCLU_LogError("Error decoding server key");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            ret = WOLFCLU_SUCCESS;
        }
    }

    /* load alternative CA public key */
    if (ret == WOLFCLU_SUCCESS) {
        ret = (int)wolfSSL_BIO_get_fp(bioAltSubjPubKey, &altCaPubKeyFp);
        if (ret != WOLFCLU_SUCCESS) {
            wolfCLU_LogError("Error get AltCAkey fd");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            XFSEEK(altCaPubKeyFp, 0, SEEK_SET);
            ret = (int)XFREAD(sapkiBuf, 1, sapkiSz, altCaPubKeyFp);
            if (ret <= 0) {
                wolfCLU_LogError("Error cannot read ML-DSA key");
                ret = WOLFCLU_FATAL_ERROR;
            }
            else {
                sapkiSz = ret;
                ret = WOLFCLU_SUCCESS;
            }
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = wc_PemToDer(sapkiBuf, sapkiSz, PUBLICKEY_TYPE,
                            &derObj, HEAP_HINT, NULL, NULL);
        if (ret < 0) {
            wolfCLU_LogError("Error convert file pem to der");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            XMEMSET(sapkiBuf, 0, sapkiSz); /* clear original buffer */
            sapkiSz = derObj->length;
            XMEMCPY(sapkiBuf, derObj->buffer, sapkiSz);
            wc_FreeDer(&derObj);
            ret = WOLFCLU_SUCCESS;
        }
    }

    /* load alternative CA private key */
    if (ret == WOLFCLU_SUCCESS) {
        ret = wc_MlDsaKey_Init(&altCaKey, NULL, 0);
        if (ret != 0) {
            wolfCLU_LogError("Error init ML-DSA key");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            initAltCaKey = 1;
            ret = WOLFCLU_SUCCESS;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = (int)wolfSSL_BIO_get_fp(bioAltCaKey, &altCaKeyFp);
        if (ret != WOLFCLU_SUCCESS) {
            wolfCLU_LogError("Error cannot get AltCA key fd");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            XFSEEK(altCaKeyFp, 0, SEEK_SET);
            ret = (int)XFREAD(altCaKeyBuf, 1, altCaKeySz, altCaKeyFp);
            if (ret <= 0) {
                wolfCLU_LogError("Error reading alternative CA key");
                ret = WOLFCLU_FATAL_ERROR;
            }
            else {
                altCaKeySz = ret;
                ret = WOLFCLU_SUCCESS;
            }
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = wc_PemToDer(altCaKeyBuf, altCaKeySz, PKCS8_PRIVATEKEY_TYPE,
                            &derObj, HEAP_HINT, NULL, NULL);
        if (ret < 0) {
            wolfCLU_LogError("Error convert pem to der");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            XMEMSET(altCaKeyBuf, 0, altCaKeySz); /* clear original buffer */
            altCaKeySz = derObj->length;
            XMEMCPY(altCaKeyBuf, derObj->buffer, altCaKeySz);
            wc_FreeDer(&derObj);
            ret = WOLFCLU_SUCCESS;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        idx = 0;
        ret = wc_Dilithium_PrivateKeyDecode(altCaKeyBuf, &idx,
                                            &altCaKey, (word32)altCaKeySz);
        if (ret != 0) {
            wolfCLU_LogError("Error decoding ML-DSA key");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            wc_MlDsaKey_GetParams(&altCaKey, &level);
            ret = WOLFCLU_SUCCESS;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        switch (level) {
            case 2:
                altSigAlgSz = SetAlgoID(CTC_ML_DSA_LEVEL2,
                                        altSigAlgBuf, oidSigType, 0);
                break;
            case 3:
                altSigAlgSz = SetAlgoID(CTC_ML_DSA_LEVEL3,
                                        altSigAlgBuf, oidSigType, 0);
                break;
            case 5:
                altSigAlgSz = SetAlgoID(CTC_ML_DSA_LEVEL5,
                                        altSigAlgBuf, oidSigType, 0);
                break;
            default:
                wolfCLU_LogError("Error Invalid ML-DSA level %d", level);
                altSigAlgSz = 0;
                break;
        }

        if (altSigAlgSz <= 0) {
            wolfCLU_LogError("Error SetAlgoID(%d) returned: %d\n",
                            level, altSigAlgSz);
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = wc_InitCert(&newCert);
        if (ret != 0) {
            wolfCLU_LogError("Error init newCert");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            ret = WOLFCLU_SUCCESS;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        subjSz = (int)XSTRLEN(subject) + 1;
        subj = (char*)XMALLOC(subjSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (subj == NULL) {
            wolfCLU_LogError("Failed to allocate memory for subject");
            ret = MEMORY_E;
        }
        else {
            XMEMCPY(subj, subject, subjSz);
            token = XSTRTOK(subj, "/", &slash);
            while (token != NULL && ret == WOLFCLU_SUCCESS) {
                saveptr = NULL;
                key   = XSTRTOK(token, "=", &saveptr);
                value = XSTRTOK(NULL,  "=", &saveptr);

                if (key == NULL || value == NULL) {
                    wolfCLU_LogError("Malformed subject component in -subj: "
                            "expected key=value");
                    ret = WOLFCLU_FATAL_ERROR;
                    break;
                }

                if (XSTRCMP(key, "C") == 0) {
                    XSTRLCPY(newCert.subject.country, value, CTC_NAME_SIZE);
                }
                else if (XSTRCMP(key, "ST") == 0) {
                    XSTRLCPY(newCert.subject.state, value, CTC_NAME_SIZE);
                }
                else if (XSTRCMP(key, "L") == 0) {
                    XSTRLCPY(newCert.subject.locality, value, CTC_NAME_SIZE);
                }
                else if (XSTRCMP(key, "O") == 0) {
                    XSTRLCPY(newCert.subject.org, value, CTC_NAME_SIZE);
                }
                else if (XSTRCMP(key, "OU") == 0) {
                    XSTRLCPY(newCert.subject.unit, value, CTC_NAME_SIZE);
                }
                else if (XSTRCMP(key, "CN") == 0) {
                    XSTRLCPY(newCert.subject.commonName, value, CTC_NAME_SIZE);
                }
                else if (XSTRCMP(key, "emailAddress") == 0) {
                    XSTRLCPY(newCert.subject.email, value, CTC_NAME_SIZE);
                }

                token = XSTRTOK(NULL, "/", &slash);
            }

            XMEMSET(subj, 0, subjSz);
            XFREE(subj, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            subj = NULL;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        switch (level) {
            case 2:
                newCert.sigType = CTC_SHA256wECDSA;
                break;
            case 3:
                newCert.sigType = CTC_SHA384wECDSA;
                break;
            case 5:
                newCert.sigType = CTC_SHA512wECDSA;
                break;
        }

        if (isCA) {
            newCert.isCA = 1;
        }
        else {
            newCert.isCA = 0;
            ret = wc_SetIssuerBuffer(&newCert, caCertBuf, caCertSz);
            if (ret != 0) {
                wolfCLU_LogError("Error setting issuer buffer");
                ret = WOLFCLU_FATAL_ERROR;
            }
            else {
                ret = WOLFCLU_SUCCESS;
            }
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = wc_SetCustomExtension(&newCert, 0, subjectAltPubKeyOid,
                                    sapkiBuf, sapkiSz);
        if (ret < 0) {
            wolfCLU_LogError("Error setting custom extension");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            ret = wc_SetCustomExtension(&newCert, 0, altSigAlgOid,
                                        altSigAlgBuf, altSigAlgSz);
            if (ret < 0) {
                wolfCLU_LogError("Error setting custom extension");
                ret = WOLFCLU_FATAL_ERROR;
            }
            else {
                ret = WOLFCLU_SUCCESS;
            }
        }
    }

    if (ret == WOLFCLU_SUCCESS && isCA) {
        ret = wc_MakeCert(&newCert, scratchBuf,
                            scratchSz, NULL, &caKey, &rng);
        if (ret <= 0) {
            wolfCLU_LogError("Error making certificate");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            ret = wc_SignCert(newCert.bodySz, newCert.sigType, scratchBuf,
                                scratchSz, NULL, &caKey, &rng);
            if (ret <= 0) {
                wolfCLU_LogError("Error signing certificate");
                ret = WOLFCLU_FATAL_ERROR;
            }
            else {
                scratchSz = ret;
                ret = WOLFCLU_SUCCESS;
            }
        }
    }
    else if (ret == WOLFCLU_SUCCESS && !isCA) {
        ret = wc_MakeCert(&newCert, scratchBuf, scratchSz,
                            NULL, &serverKey, &rng);
        if (ret <= 0) {
            wolfCLU_LogError("Error making server certificate");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            ret = wc_SignCert(newCert.bodySz, newCert.sigType, scratchBuf,
                                scratchSz, NULL, &caKey, &rng);
            if (ret <= 0) {
                wolfCLU_LogError("Error signing server certificate");
                ret = WOLFCLU_FATAL_ERROR;
            }
            else {
                scratchSz = ret;
                ret = WOLFCLU_SUCCESS;
            }
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        wc_InitDecodedCert(&preTBS, scratchBuf, scratchSz, 0);
        initPreTBS = 1;
        ret = wc_ParseCert(&preTBS, CERT_TYPE, NO_VERIFY, NULL);
        if (ret < 0) {
            wolfCLU_LogError("Error parsing certificate");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            ret = wc_GeneratePreTBS(&preTBS, preTbsBuf, preTbsSz);
            if (ret < 0) {
                wolfCLU_LogError("Error generating preTBS");
                ret = WOLFCLU_FATAL_ERROR;
            }
            else {
                preTbsSz = ret;
                ret = WOLFCLU_SUCCESS;
            }
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        switch (level) {
            case 2:
                ret = wc_MakeSigWithBitStr(altSigValBuf, altSigValSz,
                                        CTC_ML_DSA_LEVEL2, preTbsBuf, preTbsSz,
                                        ML_DSA_LEVEL2_TYPE, &altCaKey, &rng);
                break;
            case 3:
                ret = wc_MakeSigWithBitStr(altSigValBuf, altSigValSz,
                                        CTC_ML_DSA_LEVEL3, preTbsBuf, preTbsSz,
                                        ML_DSA_LEVEL3_TYPE, &altCaKey, &rng);
                break;
            case 5:
                ret = wc_MakeSigWithBitStr(altSigValBuf, altSigValSz,
                                        CTC_ML_DSA_LEVEL5, preTbsBuf, preTbsSz,
                                        ML_DSA_LEVEL5_TYPE, &altCaKey, &rng);
                break;
        }

        if (ret < 0) {
            wolfCLU_LogError("Error making signature with bit string");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            altSigValSz = ret;
            ret = WOLFCLU_SUCCESS;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = wc_SetCustomExtension(&newCert, 0, altSigValOid,
                                    altSigValBuf, altSigValSz);
        if (ret < 0) {
            wolfCLU_LogError("Error setting custom extension");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            ret = WOLFCLU_SUCCESS;
        }
    }

    if (ret == WOLFCLU_SUCCESS && isCA) {
        ret = wc_MakeCert(&newCert, derBuf, derSz, NULL, &caKey, &rng);
        if (ret < 0) {
            wolfCLU_LogError("Error making certificate");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            ret = wc_SignCert(newCert.bodySz, newCert.sigType,
                                derBuf, derSz, NULL, &caKey, &rng);
            if (ret < 0) {
                wolfCLU_LogError("Error signing certificate");
                ret = WOLFCLU_FATAL_ERROR;
            }
            else {
                derSz = ret;
                ret = WOLFCLU_SUCCESS;
            }
        }
    }
    else if (ret == WOLFCLU_SUCCESS && !isCA) {
        ret = wc_MakeCert(&newCert, derBuf, derSz, NULL, &serverKey, &rng);
        if (ret < 0) {
            wolfCLU_LogError("Error making server certificate");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            ret = wc_SignCert(newCert.bodySz, newCert.sigType,
                                derBuf, derSz, NULL, &caKey, &rng);
            if (ret < 0) {
                wolfCLU_LogError("Error signing server certificate");
                ret = WOLFCLU_FATAL_ERROR;
            }
            else {
                derSz = ret;
                ret = WOLFCLU_SUCCESS;
            }
        }
    }

    if (ret == WOLFCLU_SUCCESS && outForm == PEM_FORM) {
        ret = wc_DerToPem(derBuf, derSz, outBuf, outSz, CERT_TYPE);
        if (ret < 0) {
            wolfCLU_LogError("Error converting DER to PEM");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            outSz = ret;
            ret = WOLFCLU_SUCCESS;
        }
    }
    else if (ret == WOLFCLU_SUCCESS && outForm == DER_FORM) {
        outSz = derSz;
        XMEMCPY(outBuf, derBuf, outSz);
    }

    if (ret == WOLFCLU_SUCCESS) {
        out = wolfSSL_BIO_new_file(outFileName, "wb");
        if (out == NULL) {
            wolfCLU_LogError("Unable to open out file %s", outFileName);
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            wolfSSL_BIO_write(out, outBuf, outSz);
        }
    }

    if (initRNG) {
        wc_FreeRng(&rng);
    }
    if (initCaKey) {
        wc_ecc_free(&caKey);
    }
    if (initServerKey) {
        wc_ecc_free(&serverKey);
    }
    if (initAltCaKey) {
        wc_MlDsaKey_Free(&altCaKey);
    }
    if (initPreTBS) {
        wc_FreeDecodedCert(&preTBS);
    }
    if (out != NULL) {
        wolfSSL_BIO_free(out);
    }

    if (caKeyBuf != NULL)
        wolfCLU_ForceZero(caKeyBuf, LARGE_TEMP_SZ);
    if (altCaKeyBuf != NULL)
        wolfCLU_ForceZero(altCaKeyBuf, LARGE_TEMP_SZ);
    if (serverKeyBuf != NULL)
        wolfCLU_ForceZero(serverKeyBuf, LARGE_TEMP_SZ);
    XFREE(caKeyBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(altCaKeyBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(sapkiBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(altSigAlgBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(scratchBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(preTbsBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(altSigValBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(outBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(caCertBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(serverKeyBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

    if (ret != WOLFCLU_SUCCESS) {
        wolfCLU_LogError("Error in wolfCLU_ChimeraCertSignSetCA: %d", ret);
    }

    return ret;

#else
    (void)bioCaKey;
    (void)bioAltCaKey;
    (void)bioAltSubjPubKey;
    (void)bioSubjKey;
    (void)caCert;
    (void)subject;
    (void)outFileName;
    (void)outForm;

    wolfCLU_LogError("Please compile wolfSSL with --enable-dual-alg-certs "
           "--enable-experimental --enable-dilithium\n");

    return NOT_COMPILED_IN;
#endif /* WOLFSSL_DUAL_ALG_CERTS && WOLFCLU_HAVE_MLDSA */
}

void wolfCLU_CertSignSetSerial(WOLFCLU_CERT_SIGN* csign, WOLFSSL_BIO* s)
{
    if (csign != NULL) {
        wolfSSL_BIO_free(csign->serialFile);
        csign->serialFile = s;
    }
}


enum wc_HashType wolfCLU_StringToHashType(char* in)
{
    enum wc_HashType ret = WC_HASH_TYPE_NONE;

    if (XSTRNCMP(in, "md5", 3) == 0) {
        ret = WC_HASH_TYPE_MD5;
    }
    else if (XSTRNCMP(in, "sha512", 6) == 0) {
        ret = WC_HASH_TYPE_SHA512;
    }
    else if (XSTRNCMP(in, "sha384", 6) == 0) {
        ret = WC_HASH_TYPE_SHA384;
    }
    else if (XSTRNCMP(in, "sha256", 6) == 0) {
        ret = WC_HASH_TYPE_SHA256;
    }
    else if (XSTRNCMP(in, "sha224", 6) == 0) {
        ret = WC_HASH_TYPE_SHA224;
    }
    else if (XSTRNCMP(in, "sha", 3) == 0) {
        ret = WC_HASH_TYPE_SHA;
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
    int outSz = 0;
    char* s = NULL;

    if (csign == NULL) {
        ret = WOLFCLU_FATAL_ERROR;
    }

    if (ret == WOLFCLU_SUCCESS && out != NULL) {
        outSz = (int)XSTRLEN(out);
    }
    /* case where outDir is set to an empty string we want to treat it as
     * a null pointer in the rest of the function logic so free it
     * then set it to a null ptr.*/
    if (ret == WOLFCLU_SUCCESS && csign->outDir != NULL
            && csign->outDir[0] == '\0') {
        ret = wolfCLU_CertSignSetOut(csign, NULL);
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

        /* If out is an absolute path, use it directly instead of appending.
         * Matches OpenSSL's ossl_is_absolute_path() behaviour. A drive-letter
         * path (e.g. "C:\" or "C:/") requires at least 3 characters, so guard
         * the indexing with an explicit length check. */
        if (out[0] == '/'
#ifdef _WIN32
                || out[0] == '\\'
                || (outSz >= 3 && isalpha((unsigned char)out[0])
                    && out[1] == ':'
                    && (out[2] == '\\' || out[2] == '/'))
#endif
                ) {
            s = (char*)XMALLOC(outSz + 1, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            if (s == NULL) {
                ret = MEMORY_E;
            }
            else {
                XMEMCPY(s, out, outSz);
                s[outSz] = '\0';
            }
        }
        else {
            /* Relative path: append with separator if needed */
            int needSep = (csign->outDir[currentSz - 1] != '/') ? 1 : 0;

            s = (char*)XMALLOC(outSz + currentSz + needSep + 1, HEAP_HINT,
                    DYNAMIC_TYPE_TMP_BUFFER);
            if (s == NULL) {
                ret = MEMORY_E;
            }
            else {
                XMEMCPY(s, csign->outDir, currentSz);
                if (needSep) {
                    s[currentSz] = '/';
                }
                XMEMCPY(s + currentSz + needSep, out, outSz);
                s[outSz + currentSz + needSep] = '\0';
            }
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
        if (subject == NULL) {
            wolfCLU_LogError("Unable to get subject name");
            ret = WOLFCLU_FATAL_ERROR;
        }

        if (ret == WOLFCLU_SUCCESS &&
                wolfSSL_BIO_write(csign->dataBase, subject,
                    (int)XSTRLEN(subject)) <= 0) {
            wolfCLU_LogError("Unable to write to data base");
            ret = WOLFCLU_FATAL_ERROR;
        }

        if (ret == WOLFCLU_SUCCESS &&
                wolfSSL_BIO_write(csign->dataBase, "\n", (int)XSTRLEN("\n"))
                <= 0) {
            wolfCLU_LogError("Unable to write to data base");
            ret = WOLFCLU_FATAL_ERROR;
        }

        XFREE(subject, NULL, DYNAMIC_TYPE_OPENSSL);
    }

    return ret;
}


static int _checkPolicy(WOLFSSL_X509_NAME* issuer, WOLFSSL_X509_NAME* subject,
        int nid, word32 supplied, word32 match)
{
    char* current = NULL;
    int   currentSz;
    int   ret = WOLFCLU_SUCCESS;

    currentSz = wolfSSL_X509_NAME_get_text_by_NID(subject, nid, NULL, 0);
    if (currentSz <= 0 && (supplied != 0 || match != 0)) {
        return WOLFCLU_FAILURE;
    }

    /* if required to match then check it here */
    if (match != 0 && currentSz > 0) {
        char* expected = NULL;
        int   expectedSz;

        expectedSz = wolfSSL_X509_NAME_get_text_by_NID(issuer, nid, NULL, 0);
        if (expectedSz != currentSz) {
            WOLFSSL_MSG("Size of expected policy does not match");
            return WOLFCLU_FAILURE;
        }

        current  = (char*)XMALLOC(currentSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        expected = (char*)XMALLOC(expectedSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (current == NULL || expected == NULL) {
            ret = WOLFCLU_FAILURE;
        }

        if (ret == WOLFCLU_SUCCESS &&
                wolfSSL_X509_NAME_get_text_by_NID(subject, nid, current,
                currentSz) <= 0) {
            ret = WOLFCLU_FAILURE;
        }

        if (ret == WOLFCLU_SUCCESS &&
                wolfSSL_X509_NAME_get_text_by_NID(issuer, nid, expected,
                expectedSz) <= 0) {
            ret = WOLFCLU_FAILURE;
        }

        if (ret == WOLFCLU_SUCCESS &&
                XSTRNCMP(expected, current, currentSz) != 0) {
            WOLFSSL_MSG("Policy mismatch with subject and issuer");
            ret = WOLFCLU_FAILURE;
        }

        if (current != NULL)
            XFREE(current, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (expected != NULL)
            XFREE(expected, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    return ret;
}


/* sign the certificate 'x509' using info from 'csign'
 * 'ext' is an optional extensions section in the 'csign's config file loaded
 * return WOLFCLU_SUCCESS on success
 */
int wolfCLU_CertSign(WOLFCLU_CERT_SIGN* csign, WOLFSSL_X509* x509)
{
    const WOLFSSL_EVP_MD* md = NULL;
    WOLFSSL_BIO* out = NULL;
#if defined(WOLFCLU_HAVE_MLDSA)
    byte*         mldsaOut   = NULL;
    int           mldsaOutSz = 0;
    WOLFSSL_X509* signedX509 = NULL; /* pre-parsed for DB logging */
#endif

    int ret = WOLFCLU_SUCCESS;

    if (csign == NULL || x509 == NULL) {
        wolfCLU_LogError("Bad argument to certificate sign");
        ret = WOLFCLU_FATAL_ERROR;
    }

    if (ret == WOLFCLU_SUCCESS && csign->ca == NULL) {
        wolfCLU_LogError("Bad argument no signing certificate");
        ret = WOLFCLU_FATAL_ERROR;
    }

    /* fail fast before any x509 mutations */
    if (ret == WOLFCLU_SUCCESS && csign->outDir == NULL) {
        wolfCLU_LogError("No output file specified");
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
            wolfCLU_LogError("Error getting issuer name");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            if (wolfSSL_X509_set_issuer_name(x509, name) != WOLFSSL_SUCCESS) {
                wolfCLU_LogError("Error setting issuer name");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
    }

    /* set hash for signature (RSA/ECDSA only; ML-DSA uses a fixed sig OID) */
    if (ret == WOLFCLU_SUCCESS
            && (csign->keyType == RSAk || csign->keyType == ECDSAk)) {
        if (csign->hashType == WC_HASH_TYPE_MD5) {
        #ifndef NO_MD5
            md = wolfSSL_EVP_md5();
        #else
            wolfCLU_LogError("MD5 not compiled in");
            ret = WOLFCLU_FATAL_ERROR;
        #endif
        }
        else if (csign->hashType == WC_HASH_TYPE_SHA) {
            md = wolfSSL_EVP_sha1();
        }
        else if (csign->hashType == WC_HASH_TYPE_SHA224) {
            md = wolfSSL_EVP_sha224();
        }
        else if (csign->hashType == WC_HASH_TYPE_SHA256) {
            md = wolfSSL_EVP_sha256();
        }
        else if (csign->hashType == WC_HASH_TYPE_SHA384) {
            md = wolfSSL_EVP_sha384();
        }
        else if (csign->hashType == WC_HASH_TYPE_SHA512) {
            md = wolfSSL_EVP_sha512();
        }
        else {
            wolfCLU_LogError("Unsupported hash type");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* set serial number of certificate */
    if (ret == WOLFCLU_SUCCESS) {
        WOLFSSL_ASN1_INTEGER* s = NULL;
        char buf[EXTERNAL_SERIAL_SIZE*2];
        int size = EXTERNAL_SERIAL_SIZE*2;

        if (csign->serialFile != NULL) {
            s = wolfSSL_ASN1_INTEGER_new();
            if (wolfSSL_a2i_ASN1_INTEGER(csign->serialFile, s, buf, size)
                    != WOLFSSL_SUCCESS) {
                wolfCLU_LogError("Issue reading serial number from file");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
        else {
            WOLFSSL_BIGNUM* bn;
            int numBits;

            do {
                bn = wolfSSL_BN_new();
                if (wolfSSL_BN_rand(bn, (CTC_GEN_SERIAL_SZ*WOLFSSL_BIT_SIZE),
                    WOLFSSL_BN_RAND_TOP_ANY, WOLFSSL_BN_RAND_BOTTOM_ODD)
                    != WOLFSSL_SUCCESS) {
                    wolfCLU_LogError("Creating a random serial number fail");
                    ret = WOLFCLU_FATAL_ERROR;
                    wolfSSL_BN_free(bn);
                    break;
                }

                /* work around BN_to_ASN1_INTEGER check */
                numBits = wolfSSL_BN_num_bits(bn);
                if ((numBits % 8) != 7) {
                    s = wolfSSL_BN_to_ASN1_INTEGER(bn, NULL);
                }
                wolfSSL_BN_free(bn);
            } while ((numBits % 8) == 7);
        }
        if (ret == WOLFCLU_SUCCESS && s != NULL) {
            wolfSSL_X509_set_serialNumber(x509, s);
        }
        else if (ret == WOLFCLU_SUCCESS) {
            wolfCLU_LogError("Failed to create serial number");
            ret = WOLFCLU_FATAL_ERROR;
        }
        wolfSSL_ASN1_INTEGER_free(s);
    }

    /* set extensions */
    if (ret == WOLFCLU_SUCCESS && csign->ext != NULL) {
        ret = wolfCLU_setExtensions(x509, csign->config, csign->ext);
    }

#if defined(WOLFCLU_HAVE_MLDSA)
    /* Without operator extensions, clear any CSR-supplied CA:TRUE. */
    if (ret == WOLFCLU_SUCCESS && wolfCLU_IsMLDSAKeyType(csign->keyType)
            && csign->ext == NULL) {
        int bcIdx = wolfSSL_X509_get_ext_by_NID(x509, NID_basic_constraints,
                -1);
        if (bcIdx >= 0) {
            WOLFSSL_X509_EXTENSION* bcExt = wolfSSL_X509_get_ext(x509, bcIdx);
            if (bcExt != NULL) {
                WOLFSSL_ASN1_OBJECT* obj =
                        wolfSSL_X509_EXTENSION_get_object(bcExt);
                if (obj != NULL)
                    obj->ca = 0;
            }
        }
    }
#endif /* WOLFCLU_HAVE_MLDSA */

    /* check if unique subject name is required (before signing: cheap read) */
    if (ret == WOLFCLU_SUCCESS && csign->unique == 1) {
        char line[MAX_TERM_WIDTH];
        WOLFSSL_X509_NAME* subject;
        subject = wolfSSL_X509_get_subject_name(x509);

        /* for now using a dumb brute force approach */
        wolfSSL_BIO_reset(csign->dataBase);
        while (wolfSSL_BIO_gets(csign->dataBase, line, MAX_TERM_WIDTH) > 0) {
            int i = 0;
            char* word, *end;
            char* deli = (char*)"\t";
            char* subj = NULL;
            WOLFSSL_X509_NAME* current = NULL;

            for (word = strtok_r(line, deli, &end); word != NULL;
                    word = strtok_r(NULL, deli, &end)) {
                    if (i == 1) {
                        subj = word;
                    }
                    i++;
            }

            if (subj == NULL) {
                wolfCLU_LogError("Error parsing out subject name");
                ret = WOLFCLU_FATAL_ERROR;
                break;
            }

            current = wolfCLU_ParseX509NameString(subj, (int)XSTRLEN(subj));
            if (current == NULL) {
                wolfCLU_LogError("Error parsing existing subject name from "
                        "database");
                ret = WOLFCLU_FATAL_ERROR;
                break;
            }
            if (wolfSSL_X509_NAME_cmp(subject, current) == 0) {
                wolfSSL_X509_NAME_free(current);
                wolfCLU_LogError("Subject name already exists");
                ret = WOLFCLU_FATAL_ERROR;
                break;
            }
            wolfSSL_X509_NAME_free(current);
        }
    }

    /* check policy constraints (before signing: cheap read) */
    if (ret == WOLFCLU_SUCCESS && csign->policy > 0) {
        WOLFSSL_X509_NAME *issuer, *subject;

        subject = wolfSSL_X509_get_subject_name(x509);
        issuer  = wolfSSL_X509_get_issuer_name(x509);

        if (ret == WOLFCLU_SUCCESS) {
            ret = _checkPolicy(issuer, subject, NID_countryName,
                    (csign->policy & WOLFCLU_CN_SUPPLIED),
                    (csign->policy & WOLFCLU_CN_MATCH));
            if (ret != WOLFCLU_SUCCESS) {
                wolfCLU_LogError("Bad country name in certificate");
            }
        }

        if (ret == WOLFCLU_SUCCESS) {
            ret = _checkPolicy(issuer, subject, NID_stateOrProvinceName,
                    (csign->policy & WOLFCLU_SN_SUPPLIED),
                    (csign->policy & WOLFCLU_SN_MATCH));
            if (ret != WOLFCLU_SUCCESS) {
                wolfCLU_LogError("Bad state name in certificate");
            }
        }

        if (ret == WOLFCLU_SUCCESS) {
            ret = _checkPolicy(issuer, subject, NID_localityName,
                    (csign->policy & WOLFCLU_LN_SUPPLIED),
                    (csign->policy & WOLFCLU_LN_MATCH));
            if (ret != WOLFCLU_SUCCESS) {
                wolfCLU_LogError("Bad locality name in certificate");
            }
        }

        if (ret == WOLFCLU_SUCCESS) {
            ret = _checkPolicy(issuer, subject, NID_organizationName,
                    (csign->policy & WOLFCLU_ON_SUPPLIED),
                    (csign->policy & WOLFCLU_ON_MATCH));
            if (ret != WOLFCLU_SUCCESS) {
                wolfCLU_LogError("Bad org. name in certificate");
            }
        }

        if (ret == WOLFCLU_SUCCESS) {
            ret = _checkPolicy(issuer, subject, NID_organizationalUnitName,
                    (csign->policy & WOLFCLU_UN_SUPPLIED),
                    (csign->policy & WOLFCLU_UN_MATCH));
            if (ret != WOLFCLU_SUCCESS) {
                wolfCLU_LogError("Bad org. unit name in certificate");
            }
        }

        if (ret == WOLFCLU_SUCCESS) {
            ret = _checkPolicy(issuer, subject, NID_commonName,
                    (csign->policy & WOLFCLU_CM_SUPPLIED),
                    (csign->policy & WOLFCLU_CM_MATCH));
            if (ret != WOLFCLU_SUCCESS) {
                wolfCLU_LogError("Bad common name in certificate");
            }
        }

        if (ret == WOLFCLU_SUCCESS) {
            ret = _checkPolicy(issuer, subject, NID_emailAddress,
                    (csign->policy & WOLFCLU_EA_SUPPLIED),
                    (csign->policy & WOLFCLU_EA_MATCH));
            if (ret != WOLFCLU_SUCCESS) {
                wolfCLU_LogError("Bad email address in certificate");
            }
        }
    }

    /* sign the certificate */
    if (ret == WOLFCLU_SUCCESS &&
            (csign->keyType == RSAk || csign->keyType == ECDSAk)) {
        if (wolfSSL_X509_check_private_key(csign->ca, csign->caKey.pkey) !=
                WOLFSSL_SUCCESS) {
            wolfCLU_LogError("Private key does not match with CA");
            ret = WOLFCLU_FATAL_ERROR;
        }

        if (ret == WOLFCLU_SUCCESS &&
                wolfSSL_X509_sign(x509, csign->caKey.pkey, md) <= 0) {
            wolfCLU_LogError("Error signing certificate");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }
    /* ML-DSA CA signing needs wc_SignCert_ex (WOLFSSL_CERT_GEN) and the
     * CERT_GEN-only helpers below. */
#if defined(WOLFCLU_HAVE_MLDSA)
    else if (ret == WOLFCLU_SUCCESS && wolfCLU_IsMLDSAKeyType(csign->keyType)) {
#if defined(WOLFSSL_CERT_GEN)
        byte mldsaLevel = 0;

        if (csign->caKey.mldsa == NULL ||
                wc_MlDsaKey_GetParams(csign->caKey.mldsa, &mldsaLevel) != 0) {
            wolfCLU_LogError("Failed to get ML-DSA key level");
            ret = WOLFCLU_FATAL_ERROR;
        }
        if (ret == WOLFCLU_SUCCESS && mldsaLevel == 0) {
            wolfCLU_LogError("Invalid ML-DSA key level 0 from GetParams "
                    "(supported: 2, 3, 5)");
            ret = WOLFCLU_FATAL_ERROR;
        }

#ifndef NO_CHECK_PRIVATE_KEY
        if (ret == WOLFCLU_SUCCESS && csign->ca != NULL &&
                csign->caKey.mldsa != NULL &&
                wolfCLU_MLDSACheckPrivateKeyCert(csign->ca,
                        csign->caKey.mldsa) != WOLFCLU_SUCCESS) {
            /* error logged by wolfCLU_MLDSACheckPrivateKeyCert */
            ret = WOLFCLU_FATAL_ERROR;
        }
#endif /* NO_CHECK_PRIVATE_KEY */

        if (ret == WOLFCLU_SUCCESS) {
            ret = wolfCLU_MLDSACertSign(x509, csign->caKey.mldsa, mldsaLevel,
                    csign->ca, csign->outForm, &mldsaOut, &mldsaOutSz);
        }
#else
    wolfCLU_LogError("WOLFSSL_CERT_GEN is required to generate a ML-DSA "
            "certificate.");
    ret = WOLFCLU_FATAL_ERROR;
#endif /* WOLFSSL_CERT_GEN */
    }
#endif /* WOLFCLU_HAVE_MLDSA */
    else if (ret == WOLFCLU_SUCCESS) {
        wolfCLU_LogError("Unsupported or missing CA signing key");
        ret = WOLFCLU_FATAL_ERROR;
    }

#if defined(WOLFCLU_HAVE_MLDSA)
    /* Pre-parse the signed cert before the irreversible write and serial-
     * increment steps so a parse failure cannot leave the DB out of sync. */
    if (ret == WOLFCLU_SUCCESS && mldsaOut != NULL &&
            csign->dataBase != NULL) {
        if (csign->outForm == DER_FORM) {
            const byte* p = mldsaOut;
            signedX509 = wolfSSL_d2i_X509(NULL, &p, mldsaOutSz);
        }
        else {
            WOLFSSL_BIO* logBio = wolfSSL_BIO_new_mem_buf(
                    (void*)mldsaOut, mldsaOutSz);
            if (logBio != NULL) {
                signedX509 = wolfSSL_PEM_read_bio_X509(logBio, NULL,
                        NULL, NULL);
                wolfSSL_BIO_free(logBio);
            }
        }
        if (signedX509 == NULL) {
            wolfCLU_LogError("Failed to parse signed ML-DSA cert for "
                    "DB logging");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }
#endif

    /* create WOLFSSL_BIO for output */
    if (ret == WOLFCLU_SUCCESS) {
        out = wolfSSL_BIO_new_file(csign->outDir, "wb");
        if (out == NULL) {
            wolfCLU_LogError("Could not open output file %s",
                    csign->outDir);
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* write out the certificate */
    if (ret == WOLFCLU_SUCCESS && out != NULL) {
#if defined(WOLFCLU_HAVE_MLDSA)
        if (mldsaOut != NULL) {
            /* mldsaOut was already encoded per csign->outForm */
            if (wolfSSL_BIO_write(out, mldsaOut, mldsaOutSz) != mldsaOutSz) {
                wolfCLU_LogError("Error writing out certificate");
                wolfSSL_BIO_free(out);
                out = NULL;
                (void)remove(csign->outDir);
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
        else
#endif
        if (csign->outForm == DER_FORM) {
            if (wolfSSL_i2d_X509_bio(out, x509) != WOLFSSL_SUCCESS) {
                wolfCLU_LogError("Error writing out certificate");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
        else if (wolfSSL_PEM_write_bio_X509(out, x509) != WOLFSSL_SUCCESS) {
            wolfCLU_LogError("Error writing out certificate");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* increment the serial number in the file */
    if (ret == WOLFCLU_SUCCESS && csign->serialFile != NULL) {
        WOLFSSL_ASN1_INTEGER* s;
        char buf[EXTERNAL_SERIAL_SIZE*2];
        int size = EXTERNAL_SERIAL_SIZE*2;
        long cur;

        s = wolfSSL_ASN1_INTEGER_new();
        wolfSSL_BIO_reset(csign->serialFile);
        if (wolfSSL_a2i_ASN1_INTEGER(csign->serialFile, s, buf, size)
                != WOLFSSL_SUCCESS) {
            wolfCLU_LogError("Issue reading serial number from file");
            ret = WOLFCLU_FATAL_ERROR;
        }

        if (ret == WOLFCLU_SUCCESS) {
            cur = wolfSSL_ASN1_INTEGER_get(s);
            if (cur < 0) {
                ret = WOLFCLU_FATAL_ERROR;
            }
        }

        if (ret == WOLFCLU_SUCCESS &&
                wolfSSL_ASN1_INTEGER_set(s, cur + 1) != WOLFSSL_SUCCESS) {
            wolfCLU_LogError("Issue incrementing serial number");
            ret = WOLFCLU_FATAL_ERROR;
        }

        wolfSSL_BIO_reset(csign->serialFile);
        if (ret == WOLFCLU_SUCCESS &&
                wolfSSL_i2a_ASN1_INTEGER(csign->serialFile, s) <= 0) {
            wolfCLU_LogError("Issue writing serial number");
            ret = WOLFCLU_FATAL_ERROR;
        }
        wolfSSL_ASN1_INTEGER_free(s);
    }

    if (ret == WOLFCLU_SUCCESS && csign->dataBase != NULL) {
#if defined(WOLFCLU_HAVE_MLDSA)
        if (mldsaOut != NULL) {
            /* signedX509 was pre-parsed before write/serial steps. */
            ret = wolfCLU_CertSignLog(csign, signedX509);
            wolfSSL_X509_free(signedX509);
            signedX509 = NULL;
        }
        else
#endif
        ret = wolfCLU_CertSignLog(csign, x509);
    }
#if defined(WOLFCLU_HAVE_MLDSA)
    if (mldsaOut != NULL) {
        wolfCLU_ForceZero(mldsaOut, (unsigned int)mldsaOutSz);
        XFREE(mldsaOut, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }
    wolfSSL_X509_free(signedX509); /* NULL-safe; covers pre-parse on error path */
#endif
    wolfSSL_BIO_free(out);

    return ret;
}


static void _setPolicy(word32* ret, char* str, word32 matchMask,
        word32 suppliedMask)
{
    const char* match    = "match";
    const char* supplied = "supplied";
    const char* optional = "optional";

    if (str != NULL) {
        if (XSTRNCMP(str, match, XSTRLEN(match)) == 0) {
            *ret |= matchMask;
        }
        else if (XSTRNCMP(str, supplied, XSTRLEN(supplied)) == 0) {
            *ret |= suppliedMask;
        }
        else if (XSTRNCMP(str, optional, XSTRLEN(optional)) == 0) {
            /* leave as 0 for optional */
        }
        else {
            /* unknown argument */
        }
    }
}


static int wolfCLU_ParsePolicy(WOLFCLU_CERT_SIGN* csigner, char* sect)
{
    WOLFSSL_CONF* conf;
    char* tmp;
    word32 mask = 0;

    conf = csigner->config;
    tmp = wolfSSL_NCONF_get_string(conf, sect, "countryName");
    _setPolicy(&mask, tmp, WOLFCLU_CN_MATCH, WOLFCLU_CN_SUPPLIED);
    tmp = wolfSSL_NCONF_get_string(conf, sect, "stateOrProvinceName");
    _setPolicy(&mask, tmp, WOLFCLU_SN_MATCH, WOLFCLU_SN_SUPPLIED);
    tmp = wolfSSL_NCONF_get_string(conf, sect, "localityName");
    _setPolicy(&mask, tmp, WOLFCLU_LN_MATCH, WOLFCLU_LN_SUPPLIED);
    tmp = wolfSSL_NCONF_get_string(conf, sect, "organizationName");
    _setPolicy(&mask, tmp, WOLFCLU_ON_MATCH, WOLFCLU_ON_SUPPLIED);
    tmp = wolfSSL_NCONF_get_string(conf, sect, "organizationalUnitName");
    _setPolicy(&mask, tmp, WOLFCLU_UN_MATCH, WOLFCLU_UN_SUPPLIED);
    tmp = wolfSSL_NCONF_get_string(conf, sect, "emailAddress");
    _setPolicy(&mask, tmp, WOLFCLU_EA_MATCH, WOLFCLU_EA_SUPPLIED);
    tmp = wolfSSL_NCONF_get_string(conf, sect, "commonName");
    _setPolicy(&mask, tmp, WOLFCLU_CM_MATCH, WOLFCLU_CM_SUPPLIED);
    csigner->policy = mask;
    return WOLFCLU_SUCCESS;
}


/* returns a new WOLFSSL_CERT_SIGN on success and NULL on failure */
WOLFCLU_CERT_SIGN* wolfCLU_readSignConfig(char* config, char* sect)
{
    int keyType = 0;
    WOLFCLU_CERT_SIGN* ret = NULL;
    WOLFSSL_CONF* conf = NULL;
    WOLFSSL_X509* ca = NULL;
    WOLFSSL_EVP_PKEY* caKey = NULL;
#if defined(WOLFCLU_HAVE_MLDSA)
    MlDsaKey* mldsaCaKey = NULL;
    byte mldsaLevel = 0;
    int mldsaKeyType = 0;
    int oom = 0;
#endif
    long line = 0;
    long defaultDays;
    char* CAsection;
    char* serial;
    char* defaultMD;
    char* tmp;

    ret = wolfCLU_CertSignNew();
    if (ret != NULL) {
        ret->config = wolfSSL_NCONF_new(NULL);
        if (ret->config == NULL) {
            wolfCLU_LogError("Unable to create new config struct");
            wolfCLU_CertSignFree(ret);
            ret = NULL;
        }
    }

    if (ret != NULL) {
        if (wolfSSL_NCONF_load(ret->config, config, &line) != WOLFSSL_SUCCESS) {
            wolfCLU_LogError("Unable to open config file %s", config);
            (void)wolfCLU_CertSignFree(ret);
            ret = NULL;
        }

        if (ret != NULL)
            /* conf aliases ret->config, which was set above. Every error path
             * that calls wolfCLU_CertSignFree(ret) therefore frees conf via
             * ret->config, so the subsequent conf = NULL prevents a double-
             * free in the final failure block at the bottom of the function.
             */
            conf = ret->config;
    }

    if (ret != NULL) {
        CAsection = wolfSSL_NCONF_get_string(conf, sect, "default_ca");
        if (CAsection == NULL) {
            CAsection = sect;
        }

        tmp = wolfSSL_NCONF_get_string(conf, CAsection, "new_certs_dir");
        if (tmp == NULL) {
            /* if NULL try searching for 'certs' key word instead */
            tmp = wolfSSL_NCONF_get_string(conf, CAsection, "certs");
        }
        if (tmp == NULL ||
                wolfCLU_CertSignAppendOut(ret, tmp) != WOLFCLU_SUCCESS) {
            wolfCLU_LogError("Unable to set output certificate location "
                   "%s", tmp);
            (void)wolfCLU_CertSignFree(ret);
            ret = NULL;
            conf = NULL;
        }
    }

    if (ret != NULL) {
        tmp = wolfSSL_NCONF_get_string(conf, CAsection, "database");
        if (tmp != NULL) {
            ret->dataBase = wolfSSL_BIO_new_file(tmp, "ab+");
            if (ret->dataBase == NULL) {
                wolfCLU_LogError("Unable to open data base file %s",
                        tmp);
                (void)wolfCLU_CertSignFree(ret);
                ret = NULL;
                conf = NULL;
            }
        }
    }

    /* set signing issuer */
    if (ret != NULL) {
        tmp = wolfSSL_NCONF_get_string(conf, CAsection, "certificate");
        if (tmp != NULL) {
            ca = wolfSSL_X509_load_certificate_file(tmp, WOLFSSL_FILETYPE_PEM);
            if (ca == NULL) {
                wolfCLU_LogError("Unable to open CA file %s", tmp);
                (void)wolfCLU_CertSignFree(ret);
                ret = NULL;
                conf = NULL;
            }
        }
    }

    /* does the subject need to be unique? */
    if (ret != NULL) {
        tmp = wolfSSL_NCONF_get_string(conf, CAsection, "unique_subject");
        if (tmp != NULL && XSTRNCMP(tmp, "yes", 3) == 0) {
            ret->unique = 1;
        }
    }

    /* check on setting serial */
    if (ret != NULL) {
        serial = wolfSSL_NCONF_get_string(conf, CAsection, "serial");
        if (serial != NULL) {
            WOLFSSL_BIO* s;

            s = wolfSSL_BIO_new_file(serial, "rb+");
            if (s == NULL) {
                wolfCLU_LogError("Unable to open serial file %s",
                        serial);
                (void)wolfCLU_CertSignFree(ret);
                ret = NULL;
                conf = NULL;
            }
            else {
                wolfCLU_CertSignSetSerial(ret, s);
            }
        }
    }

    /* look for a private random file (loads on start and writes 256 byte to on
     * close) */
    if (ret != NULL) {
        tmp = wolfSSL_NCONF_get_string(conf, CAsection, "RANDFILE");
        if (tmp != NULL) {
            wolfCLU_CertSignSetRandFile(ret, tmp);
        }
    }

    if (ret != NULL) {
        tmp = wolfSSL_NCONF_get_string(conf, CAsection, "x509_extensions");
        if (tmp != NULL) {
            wolfCLU_CertSignSetExt(ret, tmp);
        }

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
                wolfCLU_LogError("Unable to open private key file %s",
                        tmp);
                (void)wolfCLU_CertSignFree(ret);
                ret = NULL;
                conf = NULL;
            }
            else {
                caKey = wolfSSL_PEM_read_bio_PrivateKey(in, NULL, NULL, NULL);
                wolfSSL_BIO_free(in);
#if defined(WOLFCLU_HAVE_MLDSA)
                if (caKey == NULL) {
                    mldsaCaKey = (MlDsaKey*)XMALLOC(sizeof(MlDsaKey), HEAP_HINT,
                            DYNAMIC_TYPE_TMP_BUFFER);
                    if (mldsaCaKey == NULL) {
                        wolfCLU_LogError("Memory allocation failed for ML-DSA "
                                "CA key");
                        oom = 1;
                        (void)wolfCLU_CertSignFree(ret);
                        ret = NULL;
                        conf = NULL;
                    }
                    else {
                        XMEMSET(mldsaCaKey, 0, sizeof(MlDsaKey));
                    }
                    if (!oom) {
                        if (wolfCLU_LoadMLDSAKey(tmp, mldsaCaKey,
                                    &mldsaLevel, 0) == WOLFCLU_SUCCESS) {
                            mldsaKeyType =
                                wolfCLU_MLDSALevelToKeyOid(mldsaLevel);
                            if (mldsaKeyType == 0) {
                                wolfCLU_LogError("Unsupported ML-DSA level %d "
                                        "from key file; supported: 2, 3, 5",
                                        (int)mldsaLevel);
                                wolfCLU_FreeMLDSAKeyHeap(&mldsaCaKey);
                            }
                        }
                        else {
                            wolfCLU_FreeMLDSAKeyHeap(&mldsaCaKey);
                        }
                    }
                }
#endif
                if (caKey == NULL
#if defined(WOLFCLU_HAVE_MLDSA)
                        && mldsaCaKey == NULL && !oom
#endif
                        ) {
                    wolfCLU_LogError("Unable to load private key %s", tmp);
                    (void)wolfCLU_CertSignFree(ret);
                    ret = NULL;
                    conf = NULL;
                }
            }
        }
    }

    /* get policy constraints */
    if (ret != NULL) {
        tmp = wolfSSL_NCONF_get_string(conf, CAsection, "policy");
        if (tmp != NULL && wolfCLU_ParsePolicy(ret, tmp) != WOLFCLU_SUCCESS) {
            wolfCLU_LogError("Error parsing policy section");
            (void)wolfCLU_CertSignFree(ret);
            ret = NULL;
            conf = NULL;
        }
    }

    /* read CRL information */
#ifdef HAVE_CRL
    if (ret != NULL) {
        char* crl       = NULL;
        char* crlDir    = NULL;
        int   crlNumber = 0;

        crlDir = wolfSSL_NCONF_get_string(conf, CAsection, "crl_dir");
        crl    = wolfSSL_NCONF_get_string(conf, CAsection, "crl");
        if (wolfSSL_NCONF_get_number(conf, CAsection, "crlnumber",
                    &defaultDays) != WOLFSSL_SUCCESS) {
            crlNumber = 0;
        }

        wolfCLU_CertSignSetCrl(ret, crl, crlDir, crlNumber);
    }
#endif /* HAVE_CRL */

    if (ret != NULL) {
#if defined(WOLFCLU_HAVE_MLDSA)
        if (mldsaCaKey != NULL) {
            if (wolfCLU_CertSignSetCA(ret, ca, mldsaCaKey, mldsaKeyType) !=
                    WOLFCLU_SUCCESS) {
                wolfCLU_FreeMLDSAKeyHeap(&mldsaCaKey);
                wolfSSL_X509_free(ca);
                ca = NULL;
                (void)wolfCLU_CertSignFree(ret);
                ret = NULL;
                conf = NULL;
            }
            else {
                mldsaCaKey = NULL;
            }
        }
        else
#endif
        {
            if (caKey != NULL) {
                keyType = wolfCLU_GetTypeFromPKEY(caKey);
            }

            if (wolfCLU_CertSignSetCA(ret, ca, caKey, keyType) !=
                    WOLFCLU_SUCCESS) {
                wolfSSL_EVP_PKEY_free(caKey);
                caKey = NULL;
                wolfSSL_X509_free(ca);
                ca = NULL;
                (void)wolfCLU_CertSignFree(ret);
                ret = NULL;
                conf = NULL;
            }
        }
    }

    /* in fail case free up memory */
    if (ret == NULL) {
        /* every error path above sets conf=NULL after
         * calling wolfCLU_CertSignFree */
        wolfSSL_NCONF_free(conf);
        wolfSSL_X509_free(ca);
        wolfSSL_EVP_PKEY_free(caKey);
#if defined(WOLFCLU_HAVE_MLDSA)
        wolfCLU_FreeMLDSAKeyHeap(&mldsaCaKey);
#endif
    }
    return ret;
}

#endif /* WOLFCLU_NO_FILESYSTEM */
