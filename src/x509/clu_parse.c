/* clu_parse.c
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <stdio.h>

#include <wolfclu/clu_header_main.h>
#include <wolfclu/clu_log.h>
#include <wolfclu/clu_error_codes.h>
#include <wolfclu/x509/clu_parse.h>
#include <wolfclu/x509/clu_cert.h>

#define MAX_CERT_SIZE 16384

enum {
    PEM = 0,
    DER = 1,
    TEXT = 2,
};

int wolfCLU_inpemOutpem(char* inFile, char* outFile, int silentFlag)
{
    int ret;
    ret = wolfCLU_parseFile(inFile, PEM, outFile, PEM, silentFlag);
    return ret;
}

int wolfCLU_inpemOutder(char* inFile, char* outFile, int silentFlag)
{
    int ret;
    ret = wolfCLU_parseFile(inFile, PEM, outFile, DER, silentFlag);
    return ret;
}

int wolfCLU_inderOutpem(char* inFile, char* outFile, int silentFlag)
{
    int ret;
    ret = wolfCLU_parseFile(inFile, DER, outFile, PEM, silentFlag);
    return ret;
}

int wolfCLU_inderOutder(char* inFile, char* outFile, int silentFlag)
{
    int ret;
    ret = wolfCLU_parseFile(inFile, DER, outFile, DER, silentFlag);
    return ret;
}

int wolfCLU_inpemOuttext(char* inFile, char* outFile, int silentFlag) {
    int ret;
    ret = wolfCLU_parseFile(inFile, PEM, outFile, TEXT, silentFlag);
    return ret;
}


/* returns alloc'd WOLFSSL_X509 structure on success */
static WOLFSSL_X509* wolfCLU_parseX509(char* inFile, int inForm)
{
    int type;

    type = (inForm == DER_FORM)? WOLFSSL_FILETYPE_ASN1 : WOLFSSL_FILETYPE_PEM;

    return wolfSSL_X509_load_certificate_file(inFile, type);
}


/* return 0 on success */
int wolfCLU_printDerPubKey(WOLFSSL_BIO* bio, unsigned char* der, int derSz)
{
    int ret = 0;

    unsigned char *pem = NULL;
    int pemSz = 0;

    if (bio == NULL) {
        ret = -1;
    }

    /* get pem size alloc buffer and convert to pem format */
    if (ret == 0) {
        pemSz = wc_DerToPemEx(der, derSz, NULL, 0, NULL, PUBLICKEY_TYPE);
        if (pemSz > 0) {
            pem = (unsigned char*)XMALLOC(pemSz, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
            if (pem == NULL) {
                ret = -1;
            }
            else {
                if (wc_DerToPemEx(der, derSz, pem, pemSz, NULL, PUBLICKEY_TYPE)
                        <= 0) {
                    ret = -1;
                }
            }
        }
        else {
            ret = -1;
        }
    }

    if (ret == 0) {
        if (wolfSSL_BIO_write(bio, pem, pemSz) != pemSz) {
            ret = -1;
        }
    }

    if (pem != NULL)
        XFREE(pem, NULL, DYNAMIC_TYPE_PUBLIC_KEY);

    return ret;
}


/* returns 0 on success */
int wolfCLU_printX509PubKey(char* inFile, int inForm, char* outFile,
        int silentFlag)
{
    int ret = 0;
    WOLFSSL_X509 *x509 = NULL;
    WOLFSSL_BIO  *bio  = NULL;

    unsigned char *der = NULL;
    int derSz = 0;

    x509 = wolfCLU_parseX509(inFile, inForm);
    if (x509 == NULL) {
        WOLFCLU_LOG(WOLFCLU_L0, "unable to parse file %s", inFile);
        ret = -1;
    }

    /* use stdout if outFile is null */
    if (ret == 0 && outFile == NULL) {
        bio = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
        if (bio == NULL) {
            ret = -1;
        }
        else {
            if (wolfSSL_BIO_set_fp(bio, stdout, BIO_NOCLOSE)
                    != WOLFSSL_SUCCESS) {
                ret = -1;
            }
        }
    }

    if (ret == 0 && outFile != NULL) {
        bio = wolfSSL_BIO_new_file(outFile, "wb");
    }

    /* get the size of the pubkey der buffer and alloc it */
    if (ret == 0) {
        if (wolfSSL_X509_get_pubkey_buffer(x509, NULL, &derSz)
                == WOLFSSL_SUCCESS) {
            der = (unsigned char*)XMALLOC(derSz, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
            if (der == NULL) {
                ret = -1;
            }
            else {
                if (wolfSSL_X509_get_pubkey_buffer(x509, der, &derSz)
                        != WOLFSSL_SUCCESS) {
                    ret = -1;
                }
            }
        }
        else {
            ret = -1;
        }
    }

    if (ret == 0)
        ret = wolfCLU_printDerPubKey(bio, der, derSz);

    wolfSSL_X509_free(x509);
    wolfSSL_BIO_free(bio);

    if (der != NULL)
        XFREE(der, NULL, DYNAMIC_TYPE_PUBLIC_KEY);

    (void)silentFlag;
    return ret;
}


/* returns 0 on success */
int wolfCLU_parseFile(char* inFile, int inForm, char* outFile, int outForm,
                                                                int silentFlag)
{
    int i, ret, inBufSz, outBufSz;
    FILE* inStream;
    FILE* outStream;
    byte* inBuf = NULL;
    byte* outBuf = NULL;

    if (inFile == NULL || outFile == NULL)
        return BAD_FUNC_ARG;

    /* MALLOC buffer for the certificate to be processed */
    inBuf = (byte*) XMALLOC(MAX_CERT_SIZE, HEAP_HINT,
                                                   DYNAMIC_TYPE_TMP_BUFFER);

    if (inBuf == NULL) return MEMORY_E;
    XMEMSET(inBuf, 0, MAX_CERT_SIZE);

    inStream    = fopen(inFile, "rb");
    if (XSTRNCMP(outFile, "stdout", 6) == 0) {
        outStream = stdout;
    }
    else {
        outStream  = fopen(outFile, "wb");
    }

/*----------------------------------------------------------------------------*/
/* read in der, output der */
/*----------------------------------------------------------------------------*/
    if ( (inForm & outForm) == 1) {
        WOLFCLU_LOG(WOLFCLU_L0, "in parse: in = der, out = der");
    }
/*----------------------------------------------------------------------------*/
/* read in pem, output pem formatted human-readable-text */
/*----------------------------------------------------------------------------*/
    else if ( inForm == PEM && outForm == TEXT ) {
        WOLFSSL_X509* x509;
        WOLFSSL_BIO* bio;

        x509 = wolfSSL_X509_load_certificate_file(inFile, SSL_FILETYPE_PEM);
        bio = wolfSSL_BIO_new(wolfSSL_BIO_s_file());

        /* checking if output file was given, if not write to stdout */
        wolfSSL_BIO_set_fp(bio, outStream, BIO_NOCLOSE);

        if (x509 == NULL){
            WOLFCLU_LOG(WOLFCLU_L0, "x509 Failure Still Null");
        }

        if (bio == NULL){
            WOLFCLU_LOG(WOLFCLU_L0, "BIO Failure Still Null");
        }

        ret = wolfSSL_X509_print(bio, x509);
        if (ret == WOLFSSL_FAILURE) {
            WOLFCLU_LOG(WOLFCLU_L0, "Failed to write x509 cert.");
            goto clu_parse_cleanup;
        }
        wolfSSL_BIO_free(bio);
        wolfSSL_X509_free(x509);
    }
/*----------------------------------------------------------------------------*/
/* read in der, output pem */
/*----------------------------------------------------------------------------*/
    else if ( (inForm && !outForm) ) {
        /* read in the certificate to be processed */
        inBufSz = (int)fread(inBuf, 1, MAX_CERT_SIZE, inStream);
        if (inBufSz <= 0) {
            ret = FREAD_ERROR;
            goto clu_parse_cleanup;
        }

        /* MALLOC buffer for the result of conversion from der to pem */
        outBuf = (byte*) XMALLOC(MAX_CERT_SIZE, HEAP_HINT,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
        if (outBuf == NULL) {
            XFREE(inBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            ret = MEMORY_E;
            goto clu_parse_cleanup;
        }
        XMEMSET(outBuf, 0, MAX_CERT_SIZE);

        /* convert inBuf from der to pem, store result in outBuf  */
        outBufSz = wc_DerToPem(inBuf, inBufSz, outBuf, MAX_CERT_SIZE,
                                                                     CERT_TYPE);
        if (outBufSz < 0) {
            wolfCLU_freeBins(inBuf, outBuf, NULL, NULL, NULL);
            ret = DER_TO_PEM_ERROR;
            goto clu_parse_cleanup;
        }

        /* write the result of conversion to the outFile specified */
        ret = (int)fwrite(outBuf, 1, outBufSz, outStream);
        if (ret <= 0) {
            wolfCLU_freeBins(inBuf, outBuf, NULL, NULL, NULL);
            ret = FWRITE_ERROR;
            goto clu_parse_cleanup;
        }

        if (!silentFlag) {
           for (i = 0; i < outBufSz; i++) {
                WOLFCLU_LOG(WOLFCLU_L0, "%c", outBuf[i]);
            }
        }

        /* success cleanup */
        wolfCLU_freeBins(inBuf, outBuf, NULL, NULL, NULL);
   }
/*----------------------------------------------------------------------------*/
/* read in pem, output der */
/*----------------------------------------------------------------------------*/
    else if ( (!inForm && outForm) ) {
        inBufSz = (int)fread(inBuf, 1, MAX_CERT_SIZE, inStream);
        if (inBufSz <= 0) {
            ret = FREAD_ERROR;
            goto clu_parse_cleanup;
        }

        /* MALLOC buffer for the result of converstion from pem to der */
        outBuf = (byte*) XMALLOC(MAX_CERT_SIZE, HEAP_HINT,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
        if (outBuf == NULL) {
            XFREE(inBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            ret = MEMORY_E;
            goto clu_parse_cleanup;
        }
        XMEMSET(outBuf, 0, MAX_CERT_SIZE);

        /* convert inBuf from pem to der, store result in outBuf */
        outBufSz = wolfSSL_CertPemToDer(inBuf, inBufSz, outBuf, MAX_CERT_SIZE,
                                                                     CERT_TYPE);
        if (outBufSz < 0) {
            wolfCLU_freeBins(inBuf, outBuf, NULL, NULL, NULL);
            ret = PEM_TO_DER_ERROR;
            goto clu_parse_cleanup;
        }

        /* write the result of conversion to the outFile specified */
        ret = (int)fwrite(outBuf, 1, outBufSz, outStream);
        if (ret <= 0) {
            wolfCLU_freeBins(inBuf, outBuf, NULL, NULL, NULL);
            ret = FWRITE_ERROR;
            goto clu_parse_cleanup;
        }

        /* success cleanup */
        wolfCLU_freeBins(inBuf, outBuf, NULL, NULL, NULL);
    }
/*----------------------------------------------------------------------------*/
/* read in pem, output pem */
/*----------------------------------------------------------------------------*/
    else {
        WOLFCLU_LOG(WOLFCLU_L0, "in parse: in = pem, out = pem");
    }
    ret = 0;

clu_parse_cleanup:

    fclose(outStream);
    fclose(inStream);

    return ret;
}
