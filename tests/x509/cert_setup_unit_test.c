/* cert_setup_unit_test.c
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

/* Unit test for the Cert <- WOLFSSL_X509 helpers in clu_cert_setup.c.
 * No CLI entry point reaches them yet (only the unwired CSR->cert
 * ML-DSA CA-signing path does), so call them directly. */

#include <stdio.h>
#include <string.h>
#ifdef _WIN32
    #include <process.h>
    #define GETPID _getpid
#else
    #include <unistd.h>
    #include <sys/stat.h>
    #define GETPID getpid
#endif

#include <wolfclu/clu_header_main.h>
#include <wolfclu/clu_log.h>
#include <wolfclu/clu_error_codes.h>
#include <wolfclu/x509/clu_cert.h>
#include <wolfclu/x509/clu_x509_sign.h>

#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/ecc.h>

/* skip tests on builds without WOLFSSL_CERT_GEN */
#ifdef WOLFSSL_CERT_GEN

static int fail = 0;

#define CHECK(cond, msg)                                                    \
    do {                                                                    \
        if (!(cond)) {                                                      \
            printf("FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__);          \
            fail++;                                                         \
        }                                                                   \
    } while (0)

/* build and parse a self-signed DER cert to exercise getters */
static WOLFSSL_X509* buildFixtureX509Ex(RsaKey* key, WC_RNG* rng,
        byte* derBuf, int derBufSz, int* outDerSz, int isCA,
        word16 keyUsage)
{
    Cert cert;
    int ret;
    int certSz;

    if (wc_InitRsaKey(key, HEAP_HINT) != 0) {
        printf("FAIL: wc_InitRsaKey\n");
        return NULL;
    }

    if (wc_MakeRsaKey(key, 2048, 65537, rng) != 0) {
        printf("FAIL: wc_MakeRsaKey\n");
        wc_FreeRsaKey(key);
        return NULL;
    }

    if (wc_InitCert(&cert) != 0) {
        printf("FAIL: wc_InitCert\n");
        wc_FreeRsaKey(key);
        return NULL;
    }

    XSTRNCPY(cert.subject.country, "US", CTC_NAME_SIZE - 1);
    XSTRNCPY(cert.subject.state, "Washington", CTC_NAME_SIZE - 1);
    XSTRNCPY(cert.subject.locality, "Seattle", CTC_NAME_SIZE - 1);
    XSTRNCPY(cert.subject.org, "wolfSSL", CTC_NAME_SIZE - 1);
    XSTRNCPY(cert.subject.unit, "Testing", CTC_NAME_SIZE - 1);
    XSTRNCPY(cert.subject.commonName, "wolfCLU Cert Setup Test",
            CTC_NAME_SIZE - 1);

    cert.isCA = isCA;
    cert.keyUsage = keyUsage;
    cert.sigType = CTC_SHA256wRSA;

    ret = wc_SetSubjectKeyIdFromPublicKey_ex(&cert, RSA_TYPE, key);
    if (ret < 0) {
        printf("FAIL: wc_SetSubjectKeyIdFromPublicKey_ex: %d\n", ret);
        wc_FreeRsaKey(key);
        return NULL;
    }

    certSz = wc_MakeCert(&cert, derBuf, derBufSz, key, NULL, rng);
    if (certSz <= 0) {
        printf("FAIL: wc_MakeCert: %d\n", certSz);
        wc_FreeRsaKey(key);
        return NULL;
    }

    certSz = wc_SignCert(cert.bodySz, cert.sigType, derBuf, derBufSz, key,
            NULL, rng);
    if (certSz <= 0) {
        printf("FAIL: wc_SignCert: %d\n", certSz);
        wc_FreeRsaKey(key);
        return NULL;
    }

    *outDerSz = certSz;

    {
        const byte* p = derBuf;
        WOLFSSL_X509* x509 = wolfSSL_d2i_X509(NULL, &p, certSz);
        if (x509 == NULL) {
            printf("FAIL: wolfSSL_d2i_X509\n");
            wc_FreeRsaKey(key);
        }
        return x509;
    }
}

static WOLFSSL_X509* buildFixtureX509(RsaKey* key, WC_RNG* rng,
        byte* derBuf, int derBufSz, int* outDerSz)
{
    return buildFixtureX509Ex(key, rng, derBuf, derBufSz, outDerSz, 1,
            KU_KEY_CERT_SIGN | KU_CRL_SIGN);
}

static void testSetCertNameFieldByNid(void)
{
    CertName name;
    int ret;
    char longVal[CTC_NAME_SIZE + 10];

    XMEMSET(&name, 0, sizeof(name));

    /* valid nid/value populates the field and NUL-terminates */
    ret = wolfCLU_SetCertNameFieldByNid(&name, NID_commonName, "wolfSSL", 7);
    CHECK(ret == WOLFCLU_SUCCESS, "SetCertNameFieldByNid valid CN");
    CHECK(XSTRCMP(name.commonName, "wolfSSL") == 0,
            "SetCertNameFieldByNid CN value");

    ret = wolfCLU_SetCertNameFieldByNid(&name, NID_countryName, "US", 2);
    CHECK(ret == WOLFCLU_SUCCESS, "SetCertNameFieldByNid valid C");
    CHECK(XSTRCMP(name.country, "US") == 0, "SetCertNameFieldByNid C value");

    /* NULL dst */
    ret = wolfCLU_SetCertNameFieldByNid(NULL, NID_commonName, "wolfSSL", 7);
    CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            "SetCertNameFieldByNid NULL dst");

    /* NULL val */
    ret = wolfCLU_SetCertNameFieldByNid(&name, NID_commonName, NULL, 7);
    CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            "SetCertNameFieldByNid NULL val");

    /* valLen <= 0 */
    ret = wolfCLU_SetCertNameFieldByNid(&name, NID_commonName, "wolfSSL", 0);
    CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            "SetCertNameFieldByNid valLen 0");

    ret = wolfCLU_SetCertNameFieldByNid(&name, NID_commonName, "wolfSSL", -1);
    CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            "SetCertNameFieldByNid valLen -1");

    /* value too long */
    XMEMSET(longVal, 'A', sizeof(longVal));
    longVal[sizeof(longVal) - 1] = '\0';
    ret = wolfCLU_SetCertNameFieldByNid(&name, NID_organizationName, longVal,
            CTC_NAME_SIZE);
    CHECK(ret == WOLFCLU_FATAL_ERROR, "SetCertNameFieldByNid too long");
    CHECK(name.org[0] == '\0', "SetCertNameFieldByNid too-long org untouched");

    /* recognized NID with no CertName destination: rejected, because
     * dropping an RDN would issue a subject other than the one requested */
    ret = wolfCLU_SetCertNameFieldByNid(&name, NID_pkcs9_contentType,
            "1.2.3.4", 7);
    CHECK(ret == WOLFCLU_FATAL_ERROR, "SetCertNameFieldByNid unmapped nid");

#ifdef WOLFSSL_CERT_NAME_ALL
    ret = wolfCLU_SetCertNameFieldByNid(&name, NID_initials, "AB", 2);
    CHECK(ret == WOLFCLU_SUCCESS, "SetCertNameFieldByNid initials");
    CHECK(XSTRCMP(name.initials, "AB") == 0,
            "SetCertNameFieldByNid initials value");
#endif
}

#ifdef WOLFSSL_CERT_EXT
static void testExtHandledNid(void)
{
    CHECK(wolfCLU_ExtHandledNid(NID_basic_constraints) == 1,
            "ExtHandledNid basic_constraints");
    CHECK(wolfCLU_ExtHandledNid(NID_key_usage) == 1,
            "ExtHandledNid key_usage");
    CHECK(wolfCLU_ExtHandledNid(NID_ext_key_usage) == 1,
            "ExtHandledNid ext_key_usage");
    CHECK(wolfCLU_ExtHandledNid(NID_subject_key_identifier) == 1,
            "ExtHandledNid subject_key_identifier");
    CHECK(wolfCLU_ExtHandledNid(NID_authority_key_identifier) == 1,
            "ExtHandledNid authority_key_identifier");
#ifdef WOLFSSL_ALT_NAMES
    /* SAN handling uses wc_SetAltNamesBuffer natively */
    CHECK(wolfCLU_ExtHandledNid(NID_subject_alt_name) == 1,
            "ExtHandledNid subject_alt_name");
#endif
    CHECK(wolfCLU_ExtHandledNid(NID_commonName) == 0,
            "ExtHandledNid commonName not handled");
}

/* Exercises wolfCLU_UnwrapX509Extensions() on synthetic buffers. */
static const byte kOneExt[] = {
    0x30, 0x09, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x04, 0x02, 0x30, 0x00
};

static void checkUnwrapLandsOnExtension(const byte* buf, int bufSz,
        const char* label)
{
    const byte* extensions = buf;
    int extensionsSz = bufSz;
    char msg[128];

    (void)wolfCLU_UnwrapX509Extensions(&extensions, &extensionsSz);

    XSNPRINTF(msg, sizeof(msg), "UnwrapX509Extensions %s: size", label);
    CHECK(extensionsSz == (int)sizeof(kOneExt), msg);

    XSNPRINTF(msg, sizeof(msg), "UnwrapX509Extensions %s: bytes match "
            "(first extension's OID, not the wrapper's tag bytes)", label);
    CHECK(extensionsSz == (int)sizeof(kOneExt) &&
            XMEMCMP(extensions, kOneExt, sizeof(kOneExt)) == 0, msg);
}

static void testUnwrapX509Extensions(void)
{
    /* bare "SEQUENCE OF Extension" (no [3] wrapper): 30 0B <kOneExt> */
    byte bare[2 + sizeof(kOneExt)];
    /* "[3] EXPLICIT Extensions" wrapping the same bare form: A3 0D <bare> */
    byte wrapped[2 + sizeof(bare)];
    /* Ensure untouched if no [3] tag or SEQUENCE at offset 0 */
    static const byte garbage[] = { 0x02, 0x01, 0x00 }; /* INTEGER 0 */
    const byte* extensions;
    int extensionsSz;

    bare[0] = 0x30;
    bare[1] = (byte)sizeof(kOneExt);
    XMEMCPY(bare + 2, kOneExt, sizeof(kOneExt));
    checkUnwrapLandsOnExtension(bare, (int)sizeof(bare), "bare SEQUENCE");

    wrapped[0] = 0xA3; /* ASN_EXTENSIONS, [3] EXPLICIT constructed */
    wrapped[1] = (byte)sizeof(bare);
    XMEMCPY(wrapped + 2, bare, sizeof(bare));
    checkUnwrapLandsOnExtension(wrapped, (int)sizeof(wrapped),
            "[3]-wrapped");

    extensions = garbage;
    extensionsSz = (int)sizeof(garbage);
    (void)wolfCLU_UnwrapX509Extensions(&extensions, &extensionsSz);
    CHECK(extensions == garbage && extensionsSz == (int)sizeof(garbage),
            "UnwrapX509Extensions: non-SEQUENCE/non-[3] input left "
            "untouched");
}
#endif /* WOLFSSL_CERT_EXT */

static void testAsn1TimeToCertDate(WOLFSSL_X509* x509)
{
    const WOLFSSL_ASN1_TIME* t;
    byte buf[CTC_DATE_SIZE];
    int ret;
    WOLFSSL_ASN1_TIME bad;

    t = wolfSSL_X509_get_notBefore(x509);
    CHECK(t != NULL, "Asn1TimeToCertDate fixture notBefore present");
    if (t == NULL) {
        return;
    }

    XMEMSET(buf, 0, sizeof(buf));
    ret = wolfCLU_Asn1TimeToCertDate(buf, (int)sizeof(buf), t);
    CHECK(ret > 0, "Asn1TimeToCertDate round trip success");
    if (ret > 0) {
        int lenPrefixSz = ret - t->length;
        CHECK(lenPrefixSz >= 2, "Asn1TimeToCertDate sane length prefix");
        CHECK(buf[0] == (byte)t->type, "Asn1TimeToCertDate tag byte");
        CHECK(XMEMCMP(buf + lenPrefixSz, t->data, (size_t)t->length) == 0,
                "Asn1TimeToCertDate value bytes");
    }

    /* bad tag */
    XMEMSET(&bad, 0, sizeof(bad));
    bad.type = 99; /* not UTCTime or GeneralizedTime */
    bad.length = 13;
    XMEMSET(bad.data, '0', 12);
    bad.data[12] = 'Z';
    ret = wolfCLU_Asn1TimeToCertDate(buf, (int)sizeof(buf), &bad);
    CHECK(ret < 0, "Asn1TimeToCertDate bad tag rejected");

    /* outSz too small */
    bad.type = V_ASN1_UTCTIME;
    ret = wolfCLU_Asn1TimeToCertDate(buf, 2, &bad);
    CHECK(ret < 0, "Asn1TimeToCertDate outSz too small rejected");
}

static void testCopyX509NameToCert(WOLFSSL_X509* x509)
{
    WOLFSSL_X509_NAME* name;
    CertName dst;
    int ret;

    XMEMSET(&dst, 0, sizeof(dst));
    name = wolfSSL_X509_get_subject_name(x509);
    CHECK(name != NULL, "CopyX509NameToCert fixture subject present");
    if (name == NULL) {
        return;
    }

    ret = wolfCLU_CopyX509NameToCert(name, &dst);
    CHECK(ret == WOLFCLU_SUCCESS, "CopyX509NameToCert success");
    CHECK(XSTRCMP(dst.commonName, "wolfCLU Cert Setup Test") == 0,
            "CopyX509NameToCert commonName matches");
    CHECK(XSTRCMP(dst.country, "US") == 0,
            "CopyX509NameToCert country matches");
    CHECK(XSTRCMP(dst.org, "wolfSSL") == 0, "CopyX509NameToCert org matches");

    /* NULL args */
    ret = wolfCLU_CopyX509NameToCert(NULL, &dst);
    CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "CopyX509NameToCert NULL name");
    ret = wolfCLU_CopyX509NameToCert(name, NULL);
    CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "CopyX509NameToCert NULL dst");
}

#ifdef WOLFSSL_ALT_NAMES
static void testCopyX509SanToCert(WOLFSSL_X509* x509)
{
    Cert cert;
    int ret;

    if (wc_InitCert(&cert) != 0) {
        CHECK(0, "CopyX509SanToCert wc_InitCert");
        return;
    }

    ret = wolfCLU_CopyX509SanToCert(NULL, &cert);
    CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "CopyX509SanToCert NULL x509");
    ret = wolfCLU_CopyX509SanToCert(x509, NULL);
    CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "CopyX509SanToCert NULL cert");

    ret = wolfCLU_CopyX509SanToCert(x509, &cert);
    CHECK(ret == WOLFCLU_SUCCESS, "CopyX509SanToCert no-SAN success");
    CHECK(cert.altNamesSz == 0, "CopyX509SanToCert no-SAN leaves altNamesSz 0");
}

/* tests SAN reading from parsed DER */
static void testCopyX509SanToCertWithSan(void)
{
    RsaKey key;
    WC_RNG rng;
    WOLFSSL_X509* x509 = NULL;
    byte* derBuf = NULL;
    int derBufSz = 8192;
    int certSz;
    Cert cert;
    int ret;
    WOLFSSL_X509_EXTENSION* ext;
    WOLFSSL_ASN1_STRING* sanData;
    /* GeneralNames SEQUENCE with one dNSName entry */
    static const byte sanDer[] = {
        0x30, 0x12, 0x82, 0x10,
        't', 'e', 's', 't', '.', 'w', 'o', 'l', 'f', 's', 's', 'l', '.',
        'c', 'o', 'm'
    };

    if (wc_InitRng(&rng) != 0) {
        CHECK(0, "CopyX509SanToCertWithSan: wc_InitRng");
        return;
    }
    derBuf = (byte*)XMALLOC((size_t)derBufSz, HEAP_HINT,
            DYNAMIC_TYPE_TMP_BUFFER);
    if (derBuf == NULL) {
        CHECK(0, "CopyX509SanToCertWithSan: malloc derBuf");
        wc_FreeRng(&rng);
        return;
    }

    if (wc_InitRsaKey(&key, HEAP_HINT) != 0) {
        CHECK(0, "CopyX509SanToCertWithSan: wc_InitRsaKey");
        XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRng(&rng);
        return;
    }
    if (wc_MakeRsaKey(&key, 2048, 65537, &rng) != 0) {
        CHECK(0, "CopyX509SanToCertWithSan: wc_MakeRsaKey");
        wc_FreeRsaKey(&key);
        XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRng(&rng);
        return;
    }
    if (wc_InitCert(&cert) != 0) {
        CHECK(0, "CopyX509SanToCertWithSan: wc_InitCert (fixture)");
        wc_FreeRsaKey(&key);
        XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRng(&rng);
        return;
    }
    XSTRNCPY(cert.subject.country, "US", CTC_NAME_SIZE - 1);
    XSTRNCPY(cert.subject.commonName, "wolfCLU Cert Setup Test SAN",
            CTC_NAME_SIZE - 1);
    cert.isCA = 0;
    cert.keyUsage = KU_DIGITAL_SIGNATURE;
    cert.sigType = CTC_SHA256wRSA;
    XMEMCPY(cert.altNames, sanDer, sizeof(sanDer));
    cert.altNamesSz = (int)sizeof(sanDer);

    if (wc_SetSubjectKeyIdFromPublicKey_ex(&cert, RSA_TYPE, &key) < 0) {
        CHECK(0, "CopyX509SanToCertWithSan: "
                "wc_SetSubjectKeyIdFromPublicKey_ex");
        wc_FreeRsaKey(&key);
        XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRng(&rng);
        return;
    }
    certSz = wc_MakeCert(&cert, derBuf, (word32)derBufSz, &key, NULL, &rng);
    if (certSz <= 0) {
        CHECK(0, "CopyX509SanToCertWithSan: wc_MakeCert");
        wc_FreeRsaKey(&key);
        XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRng(&rng);
        return;
    }
    certSz = wc_SignCert(cert.bodySz, cert.sigType, derBuf, (word32)derBufSz,
            &key, NULL, &rng);
    if (certSz <= 0) {
        CHECK(0, "CopyX509SanToCertWithSan: wc_SignCert");
        wc_FreeRsaKey(&key);
        XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRng(&rng);
        return;
    }

    {
        const byte* p = derBuf;
        x509 = wolfSSL_d2i_X509(NULL, &p, certSz);
    }
    if (x509 == NULL) {
        CHECK(0, "CopyX509SanToCertWithSan: wolfSSL_d2i_X509");
        wc_FreeRsaKey(&key);
        XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRng(&rng);
        return;
    }

    /* fresh output Cert distinct from the fixture-building 'cert' above */
    {
        Cert outCert;

        if (wc_InitCert(&outCert) != 0) {
            CHECK(0, "CopyX509SanToCertWithSan: wc_InitCert (output)");
        }
        else {
            ret = wolfCLU_CopyX509SanToCert(x509, &outCert);
            CHECK(ret == WOLFCLU_SUCCESS,
                    "CopyX509SanToCertWithSan: copy success");
            CHECK(outCert.altNamesSz > 0,
                    "CopyX509SanToCertWithSan: altNamesSz populated");

            ext = wolfSSL_X509_get_ext(x509,
                    wolfSSL_X509_get_ext_by_NID(x509, NID_subject_alt_name,
                            -1));
            CHECK(ext != NULL,
                    "CopyX509SanToCertWithSan: SAN ext present on x509");
            if (ext != NULL) {
                sanData = wolfSSL_X509_EXTENSION_get_data(ext);
                CHECK(sanData != NULL,
                        "CopyX509SanToCertWithSan: SAN ext data present");
                if (sanData != NULL) {
                    CHECK(outCert.altNamesSz == sanData->length,
                            "CopyX509SanToCertWithSan: altNamesSz matches "
                            "source extension length");
                    CHECK(XMEMCMP(outCert.altNames, sanData->data,
                                (size_t)sanData->length) == 0,
                            "CopyX509SanToCertWithSan: altNames bytes match "
                            "source extension");
                }
            }
        }
    }

    wolfSSL_X509_free(x509);
    wc_FreeRsaKey(&key);
    XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    wc_FreeRng(&rng);
}
#endif /* WOLFSSL_ALT_NAMES */

#ifdef WOLFSSL_CERT_EXT
static void testCopyX509ExtsToCert(WOLFSSL_X509* x509)
{
    Cert cert;
    int ret;
    int extsDropped = 1;

    if (wc_InitCert(&cert) != 0) {
        CHECK(0, "CopyX509ExtsToCert wc_InitCert");
        return;
    }

    ret = wolfCLU_CopyX509ExtsToCert(x509, &cert, &extsDropped);
    CHECK(ret == WOLFCLU_SUCCESS, "CopyX509ExtsToCert success/no-crash");
    CHECK(extsDropped == 0,
            "CopyX509ExtsToCert: no extensions dropped for this fixture");

    /* no-crash smoke check; nothing custom was added for this fixture */
    (void)wolfCLU_FreeCertCustomExts(&cert);
}

#if defined(WOLFSSL_ASN_TEMPLATE) && defined(WOLFSSL_CUSTOM_OID) && \
    defined(HAVE_OID_ENCODING)
/* Non-standard OID extensions must fall back to the generic
 * custom-extension copy. */
static void testCopyX509ExtsToCertCustomExt(void)
{
    WC_RNG rng;
    RsaKey key;
    WOLFSSL_X509* x509 = NULL;
    byte* derBuf = NULL;
    int derBufSz = 8192;
    int outDerSz = 0;
    Cert cert;
    int ret;
    int extsDropped = 1;
    /* Arbitrary, non-standard OID: 1.2.3.4.5 */
    static const char customOid[] = "1.2.3.4.5";
    static const byte customVal[] = { 0x04, 0x03, 'a', 'b', 'c' };
    int i;

    if (wc_InitRng(&rng) != 0) {
        CHECK(0, "CopyX509ExtsToCert custom ext: wc_InitRng");
        return;
    }

    derBuf = (byte*)XMALLOC((size_t)derBufSz, HEAP_HINT,
            DYNAMIC_TYPE_TMP_BUFFER);
    if (derBuf == NULL) {
        CHECK(0, "CopyX509ExtsToCert custom ext: malloc derBuf");
        wc_FreeRng(&rng);
        return;
    }

    if (wc_InitRsaKey(&key, HEAP_HINT) != 0) {
        CHECK(0, "CopyX509ExtsToCert custom ext: wc_InitRsaKey");
        XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRng(&rng);
        return;
    }
    if (wc_MakeRsaKey(&key, 2048, 65537, &rng) != 0) {
        CHECK(0, "CopyX509ExtsToCert custom ext: wc_MakeRsaKey");
        wc_FreeRsaKey(&key);
        XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRng(&rng);
        return;
    }

    {
        Cert fixture;

        if (wc_InitCert(&fixture) != 0) {
            CHECK(0, "CopyX509ExtsToCert custom ext: wc_InitCert (fixture)");
            wc_FreeRsaKey(&key);
            XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            wc_FreeRng(&rng);
            return;
        }
        XSTRNCPY(fixture.subject.commonName, "wolfCLU Cert Setup Test",
                CTC_NAME_SIZE - 1);
        fixture.isCA = 0;
        fixture.keyUsage = KU_DIGITAL_SIGNATURE;
        fixture.sigType = CTC_SHA256wRSA;

        ret = wc_SetCustomExtension(&fixture, 0, customOid, customVal,
                (word32)sizeof(customVal));
        if (ret < 0) {
            CHECK(0, "CopyX509ExtsToCert custom ext: wc_SetCustomExtension");
            wc_FreeRsaKey(&key);
            XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            wc_FreeRng(&rng);
            return;
        }

        outDerSz = wc_MakeCert(&fixture, derBuf, derBufSz, &key, NULL, &rng);
        if (outDerSz <= 0) {
            CHECK(0, "CopyX509ExtsToCert custom ext: wc_MakeCert");
            wc_FreeRsaKey(&key);
            XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            wc_FreeRng(&rng);
            return;
        }
        outDerSz = wc_SignCert(fixture.bodySz, fixture.sigType, derBuf,
                derBufSz, &key, NULL, &rng);
        if (outDerSz <= 0) {
            CHECK(0, "CopyX509ExtsToCert custom ext: wc_SignCert");
            wc_FreeRsaKey(&key);
            XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            wc_FreeRng(&rng);
            return;
        }
    }

    {
        const byte* p = derBuf;
        x509 = wolfSSL_d2i_X509(NULL, &p, outDerSz);
    }
    if (x509 == NULL) {
        CHECK(0, "CopyX509ExtsToCert custom ext: wolfSSL_d2i_X509");
        wc_FreeRsaKey(&key);
        XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRng(&rng);
        return;
    }

    if (wc_InitCert(&cert) != 0) {
        CHECK(0, "CopyX509ExtsToCert custom ext: wc_InitCert");
        wolfSSL_X509_free(x509);
        wc_FreeRsaKey(&key);
        XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRng(&rng);
        return;
    }

    ret = wolfCLU_CopyX509ExtsToCert(x509, &cert, &extsDropped);
    CHECK(ret == WOLFCLU_SUCCESS,
            "CopyX509ExtsToCert custom ext: success");
    CHECK(extsDropped == 0,
            "CopyX509ExtsToCert custom ext: not dropped");
    CHECK(cert.customCertExtCount == 1,
            "CopyX509ExtsToCert custom ext: exactly one custom ext copied");

    {
        int found = 0;

        for (i = 0; i < cert.customCertExtCount; i++) {
            if (cert.customCertExt[i].oid != NULL &&
                    XSTRCMP((const char*)cert.customCertExt[i].oid,
                            customOid) == 0 &&
                    cert.customCertExt[i].valSz == sizeof(customVal) &&
                    XMEMCMP(cert.customCertExt[i].val, customVal,
                            sizeof(customVal)) == 0) {
                found = 1;
                break;
            }
        }
        CHECK(found, "CopyX509ExtsToCert custom ext: OID and value match");
    }

    (void)wolfCLU_FreeCertCustomExts(&cert);
    wolfSSL_X509_free(x509);
    wc_FreeRsaKey(&key);
    XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    wc_FreeRng(&rng);
}
#endif /* WOLFSSL_ASN_TEMPLATE && WOLFSSL_CUSTOM_OID && HAVE_OID_ENCODING */
#endif /* WOLFSSL_CERT_EXT */

static void testX509FillCert(WOLFSSL_X509* x509, RsaKey* key)
{
    Cert outCert;
    int ret;

    ret = wolfCLU_X509FillCert(x509, &outCert, CTC_SHA256wRSA, key, RSA_TYPE,
            NULL, 0, NULL, 1, NULL);
    CHECK(ret == WOLFCLU_SUCCESS, "X509FillCert success");
    if (ret == WOLFCLU_SUCCESS) {
        CHECK(outCert.isCA == 1, "X509FillCert isCA");
        CHECK(outCert.keyUsage == (KU_KEY_CERT_SIGN | KU_CRL_SIGN),
                "X509FillCert keyUsage carries CA bits verbatim");
        CHECK(XSTRCMP(outCert.subject.commonName,
                    "wolfCLU Cert Setup Test") == 0,
                "X509FillCert subject commonName");
        CHECK(outCert.selfSigned == 1, "X509FillCert selfSigned (no caCert)");
#ifdef WOLFSSL_CERT_EXT
        (void)wolfCLU_FreeCertCustomExts(&outCert);
#endif
    }

    /* Test with caCert == x509 (self-signing via the CA-signing path) */
    ret = wolfCLU_X509FillCert(x509, &outCert, CTC_SHA256wRSA, key, RSA_TYPE,
            key, RSA_TYPE, x509, 1, NULL);
    CHECK(ret == WOLFCLU_SUCCESS, "X509FillCert with caCert==x509 success");
    if (ret == WOLFCLU_SUCCESS) {
        CHECK(outCert.selfSigned == 1,
                "X509FillCert with caCert==x509 is treated as self-signed");
        CHECK(XSTRCMP(outCert.issuer.commonName, "wolfCLU Cert Setup Test") ==
                0,
                "X509FillCert with caCert==x509 issuer commonName");
#ifdef WOLFSSL_CERT_EXT
        (void)wolfCLU_FreeCertCustomExts(&outCert);
#endif
    }

    /* Test with a distinct caCert (real CA-signing case) */
    {
        WC_RNG caRng;
        RsaKey caKey;
        WOLFSSL_X509* caX509 = NULL;
        byte* caDerBuf = NULL;
        int caDerBufSz = 8192;
        int caOutDerSz = 0;

        if (wc_InitRng(&caRng) != 0) {
            CHECK(0, "X509FillCert distinct caCert: wc_InitRng");
        }
        else {
            caDerBuf = (byte*)XMALLOC((size_t)caDerBufSz, HEAP_HINT,
                    DYNAMIC_TYPE_TMP_BUFFER);
            if (caDerBuf == NULL) {
                CHECK(0, "X509FillCert distinct caCert: malloc derBuf");
            }
            else {
                caX509 = buildFixtureX509Ex(&caKey, &caRng, caDerBuf,
                        caDerBufSz, &caOutDerSz, 1,
                        KU_KEY_CERT_SIGN | KU_CRL_SIGN);
                if (caX509 == NULL) {
                    CHECK(0, "X509FillCert distinct caCert: fixture CA X509");
                }
                else {
                    ret = wolfCLU_X509FillCert(x509, &outCert,
                            CTC_SHA256wRSA, key, RSA_TYPE, &caKey, RSA_TYPE,
                            caX509, 1, NULL);
                    CHECK(ret == WOLFCLU_SUCCESS,
                            "X509FillCert with distinct caCert success");
                    if (ret == WOLFCLU_SUCCESS) {
                        CHECK(outCert.selfSigned == 0,
                                "X509FillCert with distinct caCert "
                                "selfSigned == 0");
                        CHECK(outCert.isCA == 1,
                                "X509FillCert with distinct caCert: CA:TRUE "
                            "is preserved (rejection logic moved "
                            "upstream)");
#ifdef WOLFSSL_CERT_EXT
                        (void)wolfCLU_FreeCertCustomExts(&outCert);
#endif
                    }
                    wolfSSL_X509_free(caX509);
                    wc_FreeRsaKey(&caKey);
                }
                XFREE(caDerBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            }
            wc_FreeRng(&caRng);
        }
    }

    /* policySanitized == 0 must be refused */
    ret = wolfCLU_X509FillCert(x509, &outCert, CTC_SHA256wRSA, key, RSA_TYPE,
            NULL, 0, NULL, 0, NULL);
    CHECK(ret == WOLFCLU_FATAL_ERROR,
            "X509FillCert refuses unsanitized policy");

    /* NULL x509 */
    ret = wolfCLU_X509FillCert(NULL, &outCert, CTC_SHA256wRSA, key, RSA_TYPE,
            NULL, 0, NULL, 1, NULL);
    CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "X509FillCert NULL x509");

    /* NULL subjWcKey must be rejected */
    ret = wolfCLU_X509FillCert(x509, &outCert, CTC_SHA256wRSA, NULL, RSA_TYPE,
            NULL, 0, NULL, 1, NULL);
    CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "X509FillCert NULL subjWcKey");
}

/* Non-CA CSR must retain RSA defaults and extra bits */
static void testX509FillCertLeafKeyUsageMerge(void)
{
    WC_RNG rng;
    RsaKey key;
    WOLFSSL_X509* x509 = NULL;
    byte* derBuf = NULL;
    int derBufSz = 8192;
    int outDerSz = 0;
    Cert outCert;
    int ret;

    if (wc_InitRng(&rng) != 0) {
        CHECK(0, "leaf keyUsage merge: wc_InitRng");
        return;
    }

    derBuf = (byte*)XMALLOC((size_t)derBufSz, HEAP_HINT,
            DYNAMIC_TYPE_TMP_BUFFER);
    if (derBuf == NULL) {
        CHECK(0, "leaf keyUsage merge: malloc derBuf");
        wc_FreeRng(&rng);
        return;
    }

    x509 = buildFixtureX509Ex(&key, &rng, derBuf, derBufSz, &outDerSz, 0,
            KU_DIGITAL_SIGNATURE | KU_NON_REPUDIATION);
    if (x509 == NULL) {
        CHECK(0, "leaf keyUsage merge: could not build fixture X509");
        XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRng(&rng);
        return;
    }

    ret = wolfCLU_X509FillCert(x509, &outCert, CTC_SHA256wRSA, &key,
            RSA_TYPE, NULL, 0, NULL, 1, NULL);
    CHECK(ret == WOLFCLU_SUCCESS, "leaf keyUsage merge: X509FillCert success");
    if (ret == WOLFCLU_SUCCESS) {
        CHECK(outCert.keyUsage ==
                (KU_DIGITAL_SIGNATURE | KU_KEY_ENCIPHERMENT |
                 KU_NON_REPUDIATION),
                "leaf keyUsage merge: RSA default keyEncipherment kept, "
                "CSR nonRepudiation added");
#ifdef WOLFSSL_CERT_EXT
        (void)wolfCLU_FreeCertCustomExts(&outCert);
#endif
    }

    wolfSSL_X509_free(x509);
    wc_FreeRsaKey(&key);
    XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    wc_FreeRng(&rng);
}

#ifdef WOLFSSL_CERT_EXT
/* ExtKeyUsage extension must carry over EXTKEYUSE_* bits. */
static void testX509FillCertExtKeyUsage(void)
{
    WC_RNG rng;
    RsaKey key;
    WOLFSSL_X509* x509 = NULL;
    byte* derBuf = NULL;
    int derBufSz = 8192;
    int outDerSz = 0;
    Cert fixture;
    Cert outCert;
    int ret;

    if (wc_InitRng(&rng) != 0) {
        CHECK(0, "extKeyUsage: wc_InitRng");
        return;
    }

    derBuf = (byte*)XMALLOC((size_t)derBufSz, HEAP_HINT,
            DYNAMIC_TYPE_TMP_BUFFER);
    if (derBuf == NULL) {
        CHECK(0, "extKeyUsage: malloc derBuf");
        wc_FreeRng(&rng);
        return;
    }

    if (wc_InitRsaKey(&key, HEAP_HINT) != 0) {
        CHECK(0, "extKeyUsage: wc_InitRsaKey");
        XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRng(&rng);
        return;
    }
    if (wc_MakeRsaKey(&key, 2048, 65537, &rng) != 0) {
        CHECK(0, "extKeyUsage: wc_MakeRsaKey");
        wc_FreeRsaKey(&key);
        XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRng(&rng);
        return;
    }

    if (wc_InitCert(&fixture) != 0) {
        CHECK(0, "extKeyUsage: wc_InitCert (fixture)");
        wc_FreeRsaKey(&key);
        XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRng(&rng);
        return;
    }
    XSTRNCPY(fixture.subject.commonName, "wolfCLU Cert Setup Test",
            CTC_NAME_SIZE - 1);
    fixture.isCA = 0;
    fixture.keyUsage = KU_DIGITAL_SIGNATURE;
    fixture.sigType = CTC_SHA256wRSA;

    ret = wc_SetExtKeyUsage(&fixture, "serverAuth,clientAuth");
    if (ret != 0) {
        CHECK(0, "extKeyUsage: wc_SetExtKeyUsage");
        wc_FreeRsaKey(&key);
        XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRng(&rng);
        return;
    }

    outDerSz = wc_MakeCert(&fixture, derBuf, derBufSz, &key, NULL, &rng);
    if (outDerSz <= 0) {
        CHECK(0, "extKeyUsage: wc_MakeCert");
        wc_FreeRsaKey(&key);
        XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRng(&rng);
        return;
    }
    outDerSz = wc_SignCert(fixture.bodySz, fixture.sigType, derBuf, derBufSz,
            &key, NULL, &rng);
    if (outDerSz <= 0) {
        CHECK(0, "extKeyUsage: wc_SignCert");
        wc_FreeRsaKey(&key);
        XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRng(&rng);
        return;
    }

    {
        const byte* p = derBuf;
        x509 = wolfSSL_d2i_X509(NULL, &p, outDerSz);
    }
    if (x509 == NULL) {
        CHECK(0, "extKeyUsage: wolfSSL_d2i_X509");
        wc_FreeRsaKey(&key);
        XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRng(&rng);
        return;
    }

    ret = wolfCLU_X509FillCert(x509, &outCert, CTC_SHA256wRSA, &key,
            RSA_TYPE, NULL, 0, NULL, 1, NULL);
    CHECK(ret == WOLFCLU_SUCCESS, "extKeyUsage: X509FillCert success");
    if (ret == WOLFCLU_SUCCESS) {
        CHECK(outCert.extKeyUsage ==
                (EXTKEYUSE_SERVER_AUTH | EXTKEYUSE_CLIENT_AUTH),
                "extKeyUsage: serverAuth+clientAuth bits carried onto cert");
        (void)wolfCLU_FreeCertCustomExts(&outCert);
    }

    wolfSSL_X509_free(x509);
    wc_FreeRsaKey(&key);
    XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    wc_FreeRng(&rng);
}

/* CA branch must drop CSR extKeyUsage (same lockdown as keyUsage). */
static void testX509FillCertCaExtKeyUsageDropped(void)
{
    WC_RNG rng;
    RsaKey key;
    WOLFSSL_X509* x509 = NULL;
    byte* derBuf = NULL;
    int derBufSz = 8192;
    int outDerSz = 0;
    Cert fixture;
    Cert outCert;
    int ret;

    if (wc_InitRng(&rng) != 0) {
        CHECK(0, "CA extKeyUsage: wc_InitRng");
        return;
    }

    derBuf = (byte*)XMALLOC((size_t)derBufSz, HEAP_HINT,
            DYNAMIC_TYPE_TMP_BUFFER);
    if (derBuf == NULL) {
        CHECK(0, "CA extKeyUsage: malloc derBuf");
        wc_FreeRng(&rng);
        return;
    }

    if (wc_InitRsaKey(&key, HEAP_HINT) != 0) {
        CHECK(0, "CA extKeyUsage: wc_InitRsaKey");
        XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRng(&rng);
        return;
    }
    if (wc_MakeRsaKey(&key, 2048, 65537, &rng) != 0) {
        CHECK(0, "CA extKeyUsage: wc_MakeRsaKey");
        wc_FreeRsaKey(&key);
        XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRng(&rng);
        return;
    }

    if (wc_InitCert(&fixture) != 0) {
        CHECK(0, "CA extKeyUsage: wc_InitCert (fixture)");
        wc_FreeRsaKey(&key);
        XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRng(&rng);
        return;
    }
    XSTRNCPY(fixture.subject.commonName, "wolfCLU Cert Setup Test CA",
            CTC_NAME_SIZE - 1);
    fixture.isCA = 1;
    fixture.keyUsage = KU_KEY_CERT_SIGN | KU_CRL_SIGN;
    fixture.sigType = CTC_SHA256wRSA;

    ret = wc_SetExtKeyUsage(&fixture, "serverAuth,clientAuth");
    if (ret != 0) {
        CHECK(0, "CA extKeyUsage: wc_SetExtKeyUsage");
        wc_FreeRsaKey(&key);
        XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRng(&rng);
        return;
    }

    outDerSz = wc_MakeCert(&fixture, derBuf, derBufSz, &key, NULL, &rng);
    if (outDerSz <= 0) {
        CHECK(0, "CA extKeyUsage: wc_MakeCert");
        wc_FreeRsaKey(&key);
        XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRng(&rng);
        return;
    }
    outDerSz = wc_SignCert(fixture.bodySz, fixture.sigType, derBuf, derBufSz,
            &key, NULL, &rng);
    if (outDerSz <= 0) {
        CHECK(0, "CA extKeyUsage: wc_SignCert");
        wc_FreeRsaKey(&key);
        XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRng(&rng);
        return;
    }

    {
        const byte* p = derBuf;
        x509 = wolfSSL_d2i_X509(NULL, &p, outDerSz);
    }
    if (x509 == NULL) {
        CHECK(0, "CA extKeyUsage: wolfSSL_d2i_X509");
        wc_FreeRsaKey(&key);
        XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRng(&rng);
        return;
    }

    ret = wolfCLU_X509FillCert(x509, &outCert, CTC_SHA256wRSA, &key,
            RSA_TYPE, NULL, 0, NULL, 1, NULL);
    CHECK(ret == WOLFCLU_SUCCESS, "CA extKeyUsage: X509FillCert success");
    if (ret == WOLFCLU_SUCCESS) {
        CHECK(outCert.isCA == 1, "CA extKeyUsage: isCA set");
        CHECK(outCert.extKeyUsage == 0,
                "CA extKeyUsage: CSR EKU bits dropped on CA cert");
        (void)wolfCLU_FreeCertCustomExts(&outCert);
    }

    wolfSSL_X509_free(x509);
    wc_FreeRsaKey(&key);
    XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    wc_FreeRng(&rng);
}
#endif /* WOLFSSL_CERT_EXT */

/* CA CSR must only retain keyCertSign/cRLSign on CA branch. */
static void testX509FillCertCaKeyUsageMask(void)
{
    WC_RNG rng;
    RsaKey key;
    WOLFSSL_X509* x509 = NULL;
    byte* derBuf = NULL;
    int derBufSz = 8192;
    int outDerSz = 0;
    Cert outCert;
    int ret;

    if (wc_InitRng(&rng) != 0) {
        CHECK(0, "CA keyUsage mask: wc_InitRng");
        return;
    }

    derBuf = (byte*)XMALLOC((size_t)derBufSz, HEAP_HINT,
            DYNAMIC_TYPE_TMP_BUFFER);
    if (derBuf == NULL) {
        CHECK(0, "CA keyUsage mask: malloc derBuf");
        wc_FreeRng(&rng);
        return;
    }

    x509 = buildFixtureX509Ex(&key, &rng, derBuf, derBufSz, &outDerSz, 1,
            KU_KEY_CERT_SIGN | KU_CRL_SIGN | KU_DIGITAL_SIGNATURE |
            KU_DATA_ENCIPHERMENT);
    if (x509 == NULL) {
        CHECK(0, "CA keyUsage mask: could not build fixture X509");
        XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRng(&rng);
        return;
    }

    ret = wolfCLU_X509FillCert(x509, &outCert, CTC_SHA256wRSA, &key,
            RSA_TYPE, NULL, 0, NULL, 1, NULL);
    CHECK(ret == WOLFCLU_SUCCESS, "CA keyUsage mask: X509FillCert success");
    if (ret == WOLFCLU_SUCCESS) {
        CHECK(outCert.keyUsage == (KU_KEY_CERT_SIGN | KU_CRL_SIGN),
                "CA keyUsage mask: non-CA CSR keyUsage bits dropped, only "
                "keyCertSign/cRLSign carried onto issued CA cert");
#ifdef WOLFSSL_CERT_EXT
        (void)wolfCLU_FreeCertCustomExts(&outCert);
#endif
    }

    wolfSSL_X509_free(x509);
    wc_FreeRsaKey(&key);
    XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    wc_FreeRng(&rng);
}

/* Non-RSA leaf keys get digitalSignature, not keyEncipherment */
static void testX509FillCertLeafKeyUsageNonRsa(void)
{
    WC_RNG rng;
    ecc_key key;
    WOLFSSL_X509* x509 = NULL;
    byte* derBuf = NULL;
    int derBufSz = 8192;
    int certSz;
    Cert cert;
    Cert outCert;
    int ret;

    if (wc_InitRng(&rng) != 0) {
        CHECK(0, "leaf keyUsage non-RSA: wc_InitRng");
        return;
    }

    derBuf = (byte*)XMALLOC((size_t)derBufSz, HEAP_HINT,
            DYNAMIC_TYPE_TMP_BUFFER);
    if (derBuf == NULL) {
        CHECK(0, "leaf keyUsage non-RSA: malloc derBuf");
        wc_FreeRng(&rng);
        return;
    }

    if (wc_ecc_init(&key) != 0) {
        CHECK(0, "leaf keyUsage non-RSA: wc_ecc_init");
        XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRng(&rng);
        return;
    }
    if (wc_ecc_make_key(&rng, 32, &key) != 0) {
        CHECK(0, "leaf keyUsage non-RSA: wc_ecc_make_key");
        wc_ecc_free(&key);
        XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRng(&rng);
        return;
    }

    if (wc_InitCert(&cert) != 0) {
        CHECK(0, "leaf keyUsage non-RSA: wc_InitCert");
        wc_ecc_free(&key);
        XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRng(&rng);
        return;
    }
    XSTRNCPY(cert.subject.country, "US", CTC_NAME_SIZE - 1);
    XSTRNCPY(cert.subject.commonName, "wolfCLU Cert Setup Test ECC",
            CTC_NAME_SIZE - 1);
    cert.isCA = 0;
    cert.keyUsage = KU_DIGITAL_SIGNATURE;
    cert.sigType = CTC_SHA256wECDSA;

    if (wc_SetSubjectKeyIdFromPublicKey_ex(&cert, ECC_TYPE, &key) < 0) {
        CHECK(0, "leaf keyUsage non-RSA: wc_SetSubjectKeyIdFromPublicKey_ex");
        wc_ecc_free(&key);
        XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRng(&rng);
        return;
    }

    certSz = wc_MakeCert(&cert, derBuf, (word32)derBufSz, NULL, &key, &rng);
    if (certSz <= 0) {
        CHECK(0, "leaf keyUsage non-RSA: wc_MakeCert");
        wc_ecc_free(&key);
        XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRng(&rng);
        return;
    }
    certSz = wc_SignCert(cert.bodySz, cert.sigType, derBuf, (word32)derBufSz,
            NULL, &key, &rng);
    if (certSz <= 0) {
        CHECK(0, "leaf keyUsage non-RSA: wc_SignCert");
        wc_ecc_free(&key);
        XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRng(&rng);
        return;
    }

    {
        const byte* p = derBuf;
        x509 = wolfSSL_d2i_X509(NULL, &p, certSz);
    }
    if (x509 == NULL) {
        CHECK(0, "leaf keyUsage non-RSA: wolfSSL_d2i_X509");
        wc_ecc_free(&key);
        XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRng(&rng);
        return;
    }

    ret = wolfCLU_X509FillCert(x509, &outCert, CTC_SHA256wECDSA, &key,
            ECC_TYPE, NULL, 0, NULL, 1, NULL);
    CHECK(ret == WOLFCLU_SUCCESS,
            "leaf keyUsage non-RSA: X509FillCert success");
    if (ret == WOLFCLU_SUCCESS) {
        CHECK(outCert.keyUsage == KU_DIGITAL_SIGNATURE,
                "leaf keyUsage non-RSA: plain digitalSignature, no "
                "RSA-only keyEncipherment");
#ifdef WOLFSSL_CERT_EXT
        (void)wolfCLU_FreeCertCustomExts(&outCert);
#endif
    }

    wolfSSL_X509_free(x509);
    wc_ecc_free(&key);
    XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    wc_FreeRng(&rng);
}

#if defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_CERT_EXT)
/* Portable byte-buffer substring search (memmem() isn't available on all
 * of this project's target platforms). */
static int containsBytes(const byte* haystack, size_t haystackSz,
        const char* needle)
{
    size_t needleSz = XSTRLEN(needle);
    size_t i;

    if (needleSz == 0 || needleSz > haystackSz) {
        return 0;
    }
    for (i = 0; i <= haystackSz - needleSz; i++) {
        if (XMEMCMP(haystack + i, needle, needleSz) == 0) {
            return 1;
        }
    }
    return 0;
}

/* Confirms a DER buffer parses as a structurally valid cert/CSR. */
static void checkParsesAsDer(const byte* der, int derSz, int certType,
        const char* label)
{
    struct DecodedCert dCert;
    int ret;
    char msg[128];

    wc_InitDecodedCert(&dCert, der, (word32)derSz, HEAP_HINT);
    ret = wc_ParseCert(&dCert, certType, NO_VERIFY, NULL);
    wc_FreeDecodedCert(&dCert);

    XSNPRINTF(msg, sizeof(msg), "%s: parses as valid DER", label);
    CHECK(ret == 0, msg);
}

/* Confirms certDer's signature verifies against caDer as a trusted root. */
static void checkSignatureVerifies(const byte* caDer, int caDerSz,
        const byte* certDer, int certDerSz, const char* label)
{
    WOLFSSL_CERT_MANAGER* cm;
    char msg[128];

    cm = wolfSSL_CertManagerNew();
    if (cm == NULL) {
        CHECK(0, "checkSignatureVerifies: wolfSSL_CertManagerNew");
        return;
    }

    XSNPRINTF(msg, sizeof(msg), "%s: CA loads as trust anchor", label);
    CHECK(wolfSSL_CertManagerLoadCABuffer(cm, caDer, (long)caDerSz,
                WOLFSSL_FILETYPE_ASN1) == WOLFSSL_SUCCESS, msg);

    XSNPRINTF(msg, sizeof(msg), "%s: signature verifies against CA", label);
    CHECK(wolfSSL_CertManagerVerifyBuffer(cm, certDer, (long)certDerSz,
                WOLFSSL_FILETYPE_ASN1) == WOLFSSL_SUCCESS, msg);

    wolfSSL_CertManagerFree(cm);
}

/* A CSR-derived (or freshly-created) X509 carries no notBefore/notAfter --
 * wolfSSL_X509_get_notBefore()/_notAfter() still return a non-NULL pointer
 * to the zeroed embedded ASN1_TIME in that case (length == 0), which must
 * NOT be treated as a fatal date-conversion error. */
static void testX509FillCertDateUnset(WOLFSSL_X509* x509, RsaKey* key)
{
    Cert outCert;
    int ret;
    WOLFSSL_ASN1_TIME* nb;
    WOLFSSL_ASN1_TIME* na;
    WOLFSSL_ASN1_TIME savedNb;
    WOLFSSL_ASN1_TIME savedNa;
    byte* outDer = NULL;
    int outDerSz = 0;

    nb = wolfSSL_X509_get_notBefore(x509);
    na = wolfSSL_X509_get_notAfter(x509);
    if (nb == NULL || na == NULL) {
        CHECK(0, "X509FillCert date-unset: fixture missing notBefore/notAfter");
        return;
    }
    savedNb = *nb;
    savedNa = *na;
    nb->length = 0;
    na->length = 0;

    ret = wolfCLU_X509FillCert(x509, &outCert, CTC_SHA256wRSA, key, RSA_TYPE,
            NULL, 0, NULL, 1, NULL);
    CHECK(ret == WOLFCLU_SUCCESS,
            "X509FillCert date-unset does not fail");
    if (ret == WOLFCLU_SUCCESS) {
        CHECK(outCert.beforeDateSz == 0,
                "X509FillCert date-unset leaves beforeDateSz at 0");
        CHECK(outCert.afterDateSz == 0,
                "X509FillCert date-unset leaves afterDateSz at 0");
#ifdef WOLFSSL_CERT_EXT
        (void)wolfCLU_FreeCertCustomExts(&outCert);
#endif
    }

#if defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_CERT_EXT)
    /* MakeAndSignCertDer must fall back to a days-valid default rather
     * than failing when the source x509 has no dates set. */
    ret = wolfCLU_MakeAndSignCertDer(x509, 0, CTC_SHA256wRSA, 8192, key,
            RSA_TYPE, key, RSA_TYPE, NULL, 1, 365, &outDer, &outDerSz);
    CHECK(ret == WOLFCLU_SUCCESS,
            "MakeAndSignCertDer date-unset falls back to daysValid");
    if (ret == WOLFCLU_SUCCESS) {
        checkParsesAsDer(outDer, outDerSz, CERT_TYPE,
                "MakeAndSignCertDer date-unset");
        XFREE(outDer, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }
#else
    (void)outDer;
    (void)outDerSz;
#endif /* WOLFSSL_CERT_GEN && WOLFSSL_CERT_EXT */

    *nb = savedNb;
    *na = savedNa;
}

static void testMakeAndSignCertDer(WOLFSSL_X509* x509, RsaKey* key)
{
    byte* outDer = NULL;
    int outDerSz = 0;
    int ret;

    /* self-signed cert */
    ret = wolfCLU_MakeAndSignCertDer(x509, 0, CTC_SHA256wRSA, 8192, key,
            RSA_TYPE, key, RSA_TYPE, NULL, 1, 365, &outDer, &outDerSz);
    CHECK(ret == WOLFCLU_SUCCESS, "MakeAndSignCertDer self-signed success");
    if (ret == WOLFCLU_SUCCESS) {
        checkParsesAsDer(outDer, outDerSz, CERT_TYPE,
                "MakeAndSignCertDer self-signed");
        checkSignatureVerifies(outDer, outDerSz, outDer, outDerSz,
                "MakeAndSignCertDer self-signed");
        XFREE(outDer, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        outDer = NULL;
    }

    /* CSR */
    ret = wolfCLU_MakeAndSignCertDer(x509, 1, CTC_SHA256wRSA, 8192, key,
            RSA_TYPE, key, RSA_TYPE, NULL, 1, -1, &outDer, &outDerSz);
    CHECK(ret == WOLFCLU_SUCCESS, "MakeAndSignCertDer CSR success");
    if (ret == WOLFCLU_SUCCESS) {
        checkParsesAsDer(outDer, outDerSz, CERTREQ_TYPE,
                "MakeAndSignCertDer CSR");
        XFREE(outDer, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        outDer = NULL;
    }

    /* arg validation */
    ret = wolfCLU_MakeAndSignCertDer(NULL, 0, CTC_SHA256wRSA, 8192, key,
            RSA_TYPE, key, RSA_TYPE, NULL, 1, 365, &outDer, &outDerSz);
    CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "MakeAndSignCertDer NULL x509");

    ret = wolfCLU_MakeAndSignCertDer(x509, 0, CTC_SHA256wRSA, 8192, NULL,
            RSA_TYPE, key, RSA_TYPE, NULL, 1, 365, &outDer, &outDerSz);
    CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            "MakeAndSignCertDer NULL subjKey");

    ret = wolfCLU_MakeAndSignCertDer(x509, 0, CTC_SHA256wRSA, 8192, key,
            RSA_TYPE, NULL, RSA_TYPE, NULL, 1, 365, &outDer, &outDerSz);
    CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            "MakeAndSignCertDer NULL caKey");

    ret = wolfCLU_MakeAndSignCertDer(x509, 0, CTC_SHA256wRSA, 8192, key,
            RSA_TYPE, key, RSA_TYPE, NULL, 1, 365, NULL, &outDerSz);
    CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            "MakeAndSignCertDer NULL outDer");
}

static void testBuildAndSignNative(WOLFSSL_X509* x509, RsaKey* key)
{
    WOLFSSL_BIO* bio;
    byte* data = NULL;
    int dataSz;
    int ret;

    /* self-signed cert, DER form, via BIO */
    bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    CHECK(bio != NULL, "BuildAndSignNative: BIO_new");
    if (bio != NULL) {
        ret = wolfCLU_BuildAndSignNative(key, RSA_TYPE, CTC_SHA256wRSA, 8192,
                x509, 365, 0, DER_FORM, bio, 0);
        CHECK(ret == WOLFCLU_SUCCESS, "BuildAndSignNative self-signed success");
        if (ret == WOLFCLU_SUCCESS) {
            dataSz = wolfSSL_BIO_get_mem_data(bio, &data);
            CHECK(dataSz > 0 && data != NULL,
                    "BuildAndSignNative self-signed: BIO has data");
            if (dataSz > 0 && data != NULL) {
                checkParsesAsDer(data, dataSz, CERT_TYPE,
                        "BuildAndSignNative self-signed");
                checkSignatureVerifies(data, dataSz, data, dataSz,
                        "BuildAndSignNative self-signed");
            }
        }
        wolfSSL_BIO_free(bio);
    }

    /* CSR, PEM form, via BIO */
    bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    CHECK(bio != NULL, "BuildAndSignNative CSR: BIO_new");
    if (bio != NULL) {
        ret = wolfCLU_BuildAndSignNative(key, RSA_TYPE, CTC_SHA256wRSA, 8192,
                x509, 0, 1, PEM_FORM, bio, 0);
        CHECK(ret == WOLFCLU_SUCCESS, "BuildAndSignNative CSR success");
        if (ret == WOLFCLU_SUCCESS) {
            dataSz = wolfSSL_BIO_get_mem_data(bio, &data);
            CHECK(dataSz > 0 && data != NULL &&
                    containsBytes(data, (size_t)dataSz,
                            "CERTIFICATE REQUEST"),
                    "BuildAndSignNative CSR: PEM contains CSR header");
        }
        wolfSSL_BIO_free(bio);
    }

    /* noOut path: build+sign without writing anywhere */
    ret = wolfCLU_BuildAndSignNative(key, RSA_TYPE, CTC_SHA256wRSA, 8192,
            x509, 365, 0, DER_FORM, NULL, 1);
    CHECK(ret == WOLFCLU_SUCCESS, "BuildAndSignNative noOut success");

    /* arg validation */
    ret = wolfCLU_BuildAndSignNative(NULL, RSA_TYPE, CTC_SHA256wRSA, 8192,
            x509, 365, 0, DER_FORM, NULL, 1);
    CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "BuildAndSignNative NULL key");

    ret = wolfCLU_BuildAndSignNative(key, RSA_TYPE, CTC_SHA256wRSA, 8192,
            NULL, 365, 0, DER_FORM, NULL, 1);
    CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "BuildAndSignNative NULL x509");

    ret = wolfCLU_BuildAndSignNative(key, RSA_TYPE, CTC_SHA256wRSA, 8192,
            x509, 365, 0, DER_FORM, NULL, 0);
    CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            "BuildAndSignNative NULL bioOut with noOut=0");
}

static void testCertSignNative(WOLFSSL_X509* x509, RsaKey* key)
{
    WC_RNG caRng;
    RsaKey caKey;
    WOLFSSL_X509* caX509 = NULL;
    byte* caDerBuf = NULL;
    int caDerBufSz = 8192;
    int caOutDerSz = 0;
    byte* outData = NULL;
    int outDataSz = 0;
    int ret;

    if (wc_InitRng(&caRng) != 0) {
        CHECK(0, "CertSignNative: wc_InitRng");
        return;
    }

    caDerBuf = (byte*)XMALLOC((size_t)caDerBufSz, HEAP_HINT,
            DYNAMIC_TYPE_TMP_BUFFER);
    if (caDerBuf == NULL) {
        CHECK(0, "CertSignNative: malloc caDerBuf");
        wc_FreeRng(&caRng);
        return;
    }

    caX509 = buildFixtureX509Ex(&caKey, &caRng, caDerBuf, caDerBufSz,
            &caOutDerSz, 1, KU_KEY_CERT_SIGN | KU_CRL_SIGN);
    if (caX509 == NULL) {
        CHECK(0, "CertSignNative: fixture CA X509");
        XFREE(caDerBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRng(&caRng);
        return;
    }

    /* CA-signed cert, DER form */
    ret = wolfCLU_CertSignNative(x509, &caKey, RSA_TYPE, CTC_SHA256wRSA, 8192,
            caX509, DER_FORM, &outData, &outDataSz, 1, key, RSA_TYPE);
    CHECK(ret == WOLFCLU_SUCCESS, "CertSignNative DER success");
    if (ret == WOLFCLU_SUCCESS) {
        checkParsesAsDer(outData, outDataSz, CERT_TYPE, "CertSignNative DER");
        checkSignatureVerifies(caDerBuf, caOutDerSz, outData, outDataSz,
                "CertSignNative DER");
        XFREE(outData, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        outData = NULL;
    }

    /* CA-signed cert, PEM form */
    ret = wolfCLU_CertSignNative(x509, &caKey, RSA_TYPE, CTC_SHA256wRSA, 8192,
            caX509, PEM_FORM, &outData, &outDataSz, 1, key, RSA_TYPE);
    CHECK(ret == WOLFCLU_SUCCESS, "CertSignNative PEM success");
    if (ret == WOLFCLU_SUCCESS) {
        CHECK(outDataSz > 0 && outData != NULL &&
                containsBytes(outData, (size_t)outDataSz,
                        "BEGIN CERTIFICATE"),
                "CertSignNative PEM: output has cert header");
        XFREE(outData, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        outData = NULL;
    }

    /* arg validation */
    ret = wolfCLU_CertSignNative(NULL, &caKey, RSA_TYPE, CTC_SHA256wRSA, 8192,
            caX509, DER_FORM, &outData, &outDataSz, 1, key, RSA_TYPE);
    CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "CertSignNative NULL x509");

    ret = wolfCLU_CertSignNative(x509, NULL, RSA_TYPE, CTC_SHA256wRSA, 8192,
            caX509, DER_FORM, &outData, &outDataSz, 1, key, RSA_TYPE);
    CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "CertSignNative NULL caKey");

    ret = wolfCLU_CertSignNative(x509, &caKey, RSA_TYPE, CTC_SHA256wRSA, 8192,
            caX509, DER_FORM, NULL, &outDataSz, 1, key, RSA_TYPE);
    CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "CertSignNative NULL outData");

    ret = wolfCLU_CertSignNative(x509, &caKey, RSA_TYPE, CTC_SHA256wRSA, 8192,
            caX509, DER_FORM, &outData, &outDataSz, 1, NULL, RSA_TYPE);
    CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "CertSignNative NULL subjKey");

    wolfSSL_X509_free(caX509);
    wc_FreeRsaKey(&caKey);
    XFREE(caDerBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    wc_FreeRng(&caRng);
}
#endif /* WOLFSSL_CERT_GEN && WOLFSSL_CERT_EXT */

static void testReadFileToBuffer(void)
{
    byte* buf = NULL;
    int bufSz = 0;
    int ret;
    char testFile[64];
    FILE* f;

    XSNPRINTF(testFile, sizeof(testFile), "test_read_file_%d.tmp",
            (int)GETPID());

    /* NULL args */
    ret = wolfCLU_ReadFileToBuffer(NULL, 100, &buf, &bufSz);
    CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "ReadFileToBuffer NULL path");
    ret = wolfCLU_ReadFileToBuffer(testFile, 100, NULL, &bufSz);
    CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "ReadFileToBuffer NULL outBuf");
    ret = wolfCLU_ReadFileToBuffer(testFile, 100, &buf, NULL);
    CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "ReadFileToBuffer NULL outSz");
    ret = wolfCLU_ReadFileToBuffer(testFile, 0, &buf, &bufSz);
    CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "ReadFileToBuffer maxSz <= 0");

    /* Missing file */
    remove(testFile); /* Ensure it doesn't exist */
    ret = wolfCLU_ReadFileToBuffer(testFile, 100, &buf, &bufSz);
    CHECK(ret == WOLFCLU_FATAL_ERROR, "ReadFileToBuffer missing file");

    /* Empty file */
    f = fopen(testFile, "wb");
    if (f) {
        fclose(f);
        ret = wolfCLU_ReadFileToBuffer(testFile, 100, &buf, &bufSz);
        CHECK(ret == WOLFCLU_FATAL_ERROR, "ReadFileToBuffer empty file");
        remove(testFile);
    } else {
        CHECK(0, "ReadFileToBuffer empty file: fopen failed");
    }

    /* File exceeds maxSz */
    f = fopen(testFile, "wb");
    if (f) {
        if (fwrite("12345", 1, 5, f) == 5) {
            fclose(f);
            ret = wolfCLU_ReadFileToBuffer(testFile, 4, &buf, &bufSz);
            CHECK(ret == WOLFCLU_FATAL_ERROR, "ReadFileToBuffer exceeds maxSz");
        } else {
            fclose(f);
            CHECK(0, "ReadFileToBuffer exceeds maxSz: fwrite failed");
        }
        remove(testFile);
    } else {
        CHECK(0, "ReadFileToBuffer exceeds maxSz: fopen failed");
    }

    /* Valid read */
    f = fopen(testFile, "wb");
    if (f) {
        if (fwrite("12345", 1, 5, f) == 5) {
            fclose(f);
            ret = wolfCLU_ReadFileToBuffer(testFile, 10, &buf, &bufSz);
            CHECK(ret == WOLFCLU_SUCCESS, "ReadFileToBuffer valid read");
            CHECK(bufSz == 5, "ReadFileToBuffer size");
            if (buf) {
                CHECK(XMEMCMP(buf, "12345", 5) == 0,
                        "ReadFileToBuffer content");
                CHECK(buf[5] == '\0', "ReadFileToBuffer null terminated");
                XFREE(buf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            }
        } else {
            fclose(f);
            CHECK(0, "ReadFileToBuffer valid read: fwrite failed");
        }
        remove(testFile);
    } else {
        CHECK(0, "ReadFileToBuffer valid read: fopen failed");
    }
}

static void testPathsRefEqual(void)
{
    FILE* f;
    char relPath[64];
    char dotRelPath[80];

    CHECK(wolfCLU_PathsRefEqual(NULL, NULL) == 0, "PathsRefEqual NULLs");
    CHECK(wolfCLU_PathsRefEqual("a", NULL) == 0, "PathsRefEqual one NULL");
    CHECK(wolfCLU_PathsRefEqual("same.txt", "same.txt") == 1,
            "PathsRefEqual identical");
    CHECK(wolfCLU_PathsRefEqual("a.txt", "b.txt") == 0,
            "PathsRefEqual different");

    XSNPRINTF(relPath, sizeof(relPath), "test_ref_equal_%d.tmp",
            (int)GETPID());
    XSNPRINTF(dotRelPath, sizeof(dotRelPath), "./%s", relPath);

    f = fopen(relPath, "wb");
    if (f) {
        fclose(f);
        CHECK(wolfCLU_PathsRefEqual(relPath, dotRelPath) == 1,
              "PathsRefEqual absolute/relative");
        remove(relPath);
    }
}

#ifndef _WIN32
/* wolfCLU_OpenOutFile() must stay usable for the -out targets fopen() has
 * always accepted, while wolfCLU_OpenKeyFile() must never write key material
 * through a symlink nor destroy the link. */
static void testOpenOutAndKeyFile(void)
{
    char  target[64];
    char  link[64];
    FILE* f;
    struct stat st;

    XSNPRINTF(target, sizeof(target), "test_openfile_%d.tmp", (int)GETPID());
    XSNPRINTF(link, sizeof(link), "test_openlink_%d.tmp", (int)GETPID());
    remove(target);
    remove(link);

    /* Non-secret output writes through a symlink and leaves it in place. */
    f = fopen(target, "wb");
    if (f == NULL) {
        CHECK(0, "OpenOutFile fixture create target");
        return;
    }
    fclose(f);
    if (symlink(target, link) != 0) {
        /* Filesystem without symlink support; nothing to assert. */
        remove(target);
        return;
    }

    f = wolfCLU_OpenOutFile(link);
    CHECK(f != NULL, "OpenOutFile follows symlink");
    if (f != NULL) {
        fputs("data", f);
        fclose(f);
    }
    CHECK(lstat(link, &st) == 0 && S_ISLNK(st.st_mode),
            "OpenOutFile leaves symlink intact");
    CHECK(stat(target, &st) == 0 && st.st_size == 4,
            "OpenOutFile wrote through symlink");

    /* Key output refuses the same symlink rather than following it. */
    f = wolfCLU_OpenKeyFile(link);
    CHECK(f == NULL, "OpenKeyFile refuses symlink");
    if (f != NULL) {
        fclose(f);
    }
    CHECK(lstat(link, &st) == 0 && S_ISLNK(st.st_mode),
            "OpenKeyFile leaves symlink intact");
    CHECK(stat(target, &st) == 0 && st.st_size == 4,
            "OpenKeyFile did not truncate symlink target");

    remove(link);

    /* Key output re-tightens permissions on an existing loose file. */
    CHECK(chmod(target, 0666) == 0, "OpenKeyFile fixture chmod");
    f = wolfCLU_OpenKeyFile(target);
    CHECK(f != NULL, "OpenKeyFile plain path");
    if (f != NULL) {
        fclose(f);
        CHECK(stat(target, &st) == 0 &&
                (st.st_mode & (S_IRWXG | S_IRWXO)) == 0,
                "OpenKeyFile is owner-only");
    }

    remove(target);
}
#endif /* !_WIN32 */

static void testParseDaysArg(void)
{
    int days = -1;

    CHECK(wolfCLU_ParseDaysArg(NULL, &days) == USER_INPUT_ERROR,
            "ParseDaysArg NULL s");
    CHECK(wolfCLU_ParseDaysArg("1", NULL) == USER_INPUT_ERROR,
            "ParseDaysArg NULL out");
    CHECK(wolfCLU_ParseDaysArg("", &days) == USER_INPUT_ERROR,
            "ParseDaysArg empty");
    CHECK(wolfCLU_ParseDaysArg("0", &days) == USER_INPUT_ERROR,
            "ParseDaysArg zero");
    CHECK(wolfCLU_ParseDaysArg("-1", &days) == USER_INPUT_ERROR,
            "ParseDaysArg negative");
    CHECK(wolfCLU_ParseDaysArg("abc", &days) == USER_INPUT_ERROR,
            "ParseDaysArg non-numeric");
    CHECK(wolfCLU_ParseDaysArg("12x", &days) == USER_INPUT_ERROR,
            "ParseDaysArg trailing junk");
    CHECK(wolfCLU_ParseDaysArg("36501", &days) == USER_INPUT_ERROR,
            "ParseDaysArg above max");

    days = -1;
    CHECK(wolfCLU_ParseDaysArg("1", &days) == WOLFCLU_SUCCESS && days == 1,
            "ParseDaysArg 1");
    days = -1;
    CHECK(wolfCLU_ParseDaysArg("365", &days) == WOLFCLU_SUCCESS &&
            days == 365, "ParseDaysArg 365");
    days = -1;
    CHECK(wolfCLU_ParseDaysArg("36500", &days) == WOLFCLU_SUCCESS &&
            days == WOLFCLU_MAX_CERT_DAYS, "ParseDaysArg max");

    days = -1;
    CHECK(wolfCLU_ParseDaysArg("01", &days) == WOLFCLU_SUCCESS && days == 1,
            "ParseDaysArg leading zero");
    CHECK(wolfCLU_ParseDaysArg(" 365", &days) == USER_INPUT_ERROR,
            "ParseDaysArg leading space");
    CHECK(wolfCLU_ParseDaysArg("365 ", &days) == USER_INPUT_ERROR,
            "ParseDaysArg trailing space");
}

static void testDerSetLength(void)
{
    byte out[8];
    word32 sz;

    /* size-only mode (output == NULL) */
    CHECK(wolfCLU_DerSetLength(0, NULL) == 1, "DerSetLength size-only 0");
    CHECK(wolfCLU_DerSetLength(127, NULL) == 1, "DerSetLength size-only 127");
    CHECK(wolfCLU_DerSetLength(128, NULL) == 2, "DerSetLength size-only 128");
    CHECK(wolfCLU_DerSetLength(255, NULL) == 2, "DerSetLength size-only 255");
    CHECK(wolfCLU_DerSetLength(256, NULL) == 3, "DerSetLength size-only 256");
    CHECK(wolfCLU_DerSetLength(65535, NULL) == 3,
            "DerSetLength size-only 65535");
    CHECK(wolfCLU_DerSetLength(65536, NULL) == 4,
            "DerSetLength size-only 65536");

    /* short-form: length < 0x80 encodes as a single byte */
    XMEMSET(out, 0, sizeof(out));
    sz = wolfCLU_DerSetLength(0, out);
    CHECK(sz == 1 && out[0] == 0x00, "DerSetLength encode 0");

    XMEMSET(out, 0, sizeof(out));
    sz = wolfCLU_DerSetLength(127, out);
    CHECK(sz == 1 && out[0] == 0x7F, "DerSetLength encode 127");

    /* long-form boundary: 128 requires 0x81 0x80 */
    XMEMSET(out, 0, sizeof(out));
    sz = wolfCLU_DerSetLength(128, out);
    CHECK(sz == 2 && out[0] == 0x81 && out[1] == 0x80,
            "DerSetLength encode 128");

    XMEMSET(out, 0, sizeof(out));
    sz = wolfCLU_DerSetLength(255, out);
    CHECK(sz == 2 && out[0] == 0x81 && out[1] == 0xFF,
            "DerSetLength encode 255");

    /* long-form boundary: 256 requires 0x82 0x01 0x00 */
    XMEMSET(out, 0, sizeof(out));
    sz = wolfCLU_DerSetLength(256, out);
    CHECK(sz == 3 && out[0] == 0x82 && out[1] == 0x01 && out[2] == 0x00,
            "DerSetLength encode 256");

    XMEMSET(out, 0, sizeof(out));
    sz = wolfCLU_DerSetLength(65535, out);
    CHECK(sz == 3 && out[0] == 0x82 && out[1] == 0xFF && out[2] == 0xFF,
            "DerSetLength encode 65535");

    /* long-form boundary: 65536 requires 0x83 0x01 0x00 0x00 */
    XMEMSET(out, 0, sizeof(out));
    sz = wolfCLU_DerSetLength(65536, out);
    CHECK(sz == 4 && out[0] == 0x83 && out[1] == 0x01 &&
            out[2] == 0x00 && out[3] == 0x00, "DerSetLength encode 65536");
}

int main(void)
{
    WC_RNG rng;
    RsaKey key;
    WOLFSSL_X509* x509 = NULL;
    byte* derBuf = NULL;
    int derBufSz = 8192;
    int outDerSz = 0;

    if (wolfCrypt_Init() != 0) {
        printf("FAIL: wolfCrypt_Init\n");
        return 1;
    }

    /* FIPS builds require the RNG seed source to be registered explicitly;
     * wolfSSL_Init() does this for the main wolfCLU binary, but this test
     * only calls wolfCrypt_Init(). */
#ifdef WC_RNG_SEED_CB
    wc_SetSeed_Cb(WC_GENERATE_SEED_DEFAULT);
#endif

    if (wc_InitRng(&rng) != 0) {
        printf("FAIL: wc_InitRng\n");
        return 1;
    }

    derBuf = (byte*)XMALLOC((size_t)derBufSz, HEAP_HINT,
            DYNAMIC_TYPE_TMP_BUFFER);
    if (derBuf == NULL) {
        printf("FAIL: malloc derBuf\n");
        wc_FreeRng(&rng);
        return 1;
    }

    x509 = buildFixtureX509(&key, &rng, derBuf, derBufSz, &outDerSz);
    if (x509 == NULL) {
        printf("FAIL: could not build fixture X509\n");
        XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRng(&rng);
        return 1;
    }

    testSetCertNameFieldByNid();
#ifdef WOLFSSL_CERT_EXT
    testExtHandledNid();
    testUnwrapX509Extensions();
#endif
    testAsn1TimeToCertDate(x509);
    testCopyX509NameToCert(x509);
#ifdef WOLFSSL_ALT_NAMES
    testCopyX509SanToCert(x509);
    testCopyX509SanToCertWithSan();
#endif
#ifdef WOLFSSL_CERT_EXT
    testCopyX509ExtsToCert(x509);
#if defined(WOLFSSL_ASN_TEMPLATE) && defined(WOLFSSL_CUSTOM_OID) && \
    defined(HAVE_OID_ENCODING)
    testCopyX509ExtsToCertCustomExt();
#endif
#endif
    testX509FillCert(x509, &key);
    testX509FillCertDateUnset(x509, &key);
    testX509FillCertLeafKeyUsageMerge();
#ifdef WOLFSSL_CERT_EXT
    testX509FillCertExtKeyUsage();
    testX509FillCertCaExtKeyUsageDropped();
#endif
    testX509FillCertCaKeyUsageMask();
    testX509FillCertLeafKeyUsageNonRsa();
#if defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_CERT_EXT)
    testMakeAndSignCertDer(x509, &key);
    testBuildAndSignNative(x509, &key);
    testCertSignNative(x509, &key);
#endif
    testReadFileToBuffer();
    testPathsRefEqual();
#ifndef _WIN32
    testOpenOutAndKeyFile();
#endif
    testParseDaysArg();
    testDerSetLength();

    wolfSSL_X509_free(x509);
    wc_FreeRsaKey(&key);
    XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    wc_FreeRng(&rng);

    wolfCrypt_Cleanup();

    if (fail == 0) {
        printf("All cert_setup_unit_test tests passed.\n");
    }
    else {
        printf("%d cert_setup_unit_test test(s) FAILED.\n", fail);
    }

    return fail ? 1 : 0;
}

#else /* !WOLFSSL_CERT_GEN */

int main(void)
{
    printf("Skipping cert_setup_unit_test: WOLFSSL_CERT_GEN not enabled.\n");
    return 0;
}

#endif /* WOLFSSL_CERT_GEN */
