/* clu_cert.h
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

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#define PEM_FORM 1
#define DER_FORM 2
#define RAW_FORM 3

/* handles incoming arguments for certificate generation */
int wolfCLU_certSetup(int argc, char** argv);

/* print help info */
void wolfCLU_certHelp(void);


#ifdef WOLFSSL_CERT_GEN
int wolfCLU_CopyX509NameToCert(WOLFSSL_X509_NAME* name, CertName* dst);
int wolfCLU_SetCertNameFieldByNid(CertName* dst, int nid, const char* val, int valLen);
int wolfCLU_Asn1TimeToCertDate(byte* out, int outSz, const WOLFSSL_ASN1_TIME* t);

#if defined(WOLFSSL_ALT_NAMES)
int wolfCLU_CopyX509SanToCert(WOLFSSL_X509* x509, Cert* cert);
#endif /* WOLFSSL_ALT_NAMES */

#ifdef WOLFSSL_CERT_EXT
int wolfCLU_ExtHandledNid(int nid);
int wolfCLU_CopyX509ExtsToCert(WOLFSSL_X509* x509, Cert* cert,
        int* extsDropped);
void wolfCLU_FreeCertCustomExts(Cert* cert);

/* Internal helper: extracts raw Extensions DER for testing. Do not use outside src/x509/clu_cert_setup.c. */
void wolfCLU_UnwrapX509Extensions(const byte** extensions, int* extensionsSz);
#endif /* WOLFSSL_CERT_EXT */

int wolfCLU_X509FillCert(WOLFSSL_X509* x509, Cert* cert, int sigType,
        void* subjWcKey, int subjWcKeyType,
        void* caWcKey, int caWcKeyType, WOLFSSL_X509* caCert,
        int policySanitized, int* extsDropped);
#endif /* WOLFSSL_CERT_GEN */
