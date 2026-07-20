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

/* Native C unit test for the wolfcrypt Cert <- WOLFSSL_X509 helper
 * functions in src/x509/clu_cert_setup.c. These helpers are currently only
 * reachable from the (not-yet-wired) CSR->cert ML-DSA CA-signing path, so
 * there is no CLI entry point to exercise them from a Python test; this test
 * calls them directly. */

#include <stdio.h>
#include <string.h>
#ifdef _WIN32
    #include <process.h>
    #define GETPID _getpid
#else
    #include <unistd.h>
    #define GETPID getpid
#endif

#include <wolfclu/clu_header_main.h>
#include <wolfclu/clu_log.h>
#include <wolfclu/clu_error_codes.h>
#include <wolfclu/x509/clu_cert.h>

#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/ecc.h>

/* wolfCLU_X509FillCert and friends are only declared/defined under
 * WOLFSSL_CERT_GEN (see wolfclu/x509/clu_cert.h); skip this test entirely
 * on builds without it rather than failing to compile. */
#ifdef WOLFSSL_CERT_GEN

static int fail = 0;

#define CHECK(cond, msg)                                                    \
    do {                                                                    \
        if (!(cond)) {                                                      \
            printf("FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__);          \
            fail++;                                                         \
        }                                                                   \
    } while (0)

/* Build a self-signed RSA X.509 DER cert in memory using wolfCrypt directly,
 * mirroring the shape used in src/x509/clu_x509_sign.c (wc_InitCert /
 * wc_MakeCert / wc_SignCert) and src/genkey/clu_genkey.c
 * (wc_InitRsaKey / wc_MakeRsaKey), then parse it back into a WOLFSSL_X509*.
 * This exercises the same generic WOLFSSL_X509 getter APIs that
 * wolfCLU_X509FillCert relies on. */
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

    strncpy(cert.subject.country, "US", CTC_NAME_SIZE - 1);
    strncpy(cert.subject.state, "Washington", CTC_NAME_SIZE - 1);
    strncpy(cert.subject.locality, "Seattle", CTC_NAME_SIZE - 1);
    strncpy(cert.subject.org, "wolfSSL", CTC_NAME_SIZE - 1);
    strncpy(cert.subject.unit, "Testing", CTC_NAME_SIZE - 1);
    strncpy(cert.subject.commonName, "wolfCLU Cert Setup Test",
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

    memset(&name, 0, sizeof(name));

    /* valid nid/value populates the field and NUL-terminates */
    ret = wolfCLU_SetCertNameFieldByNid(&name, NID_commonName, "wolfSSL", 7);
    CHECK(ret == WOLFCLU_SUCCESS, "SetCertNameFieldByNid valid CN");
    CHECK(strcmp(name.commonName, "wolfSSL") == 0,
            "SetCertNameFieldByNid CN value");

    ret = wolfCLU_SetCertNameFieldByNid(&name, NID_countryName, "US", 2);
    CHECK(ret == WOLFCLU_SUCCESS, "SetCertNameFieldByNid valid C");
    CHECK(strcmp(name.country, "US") == 0, "SetCertNameFieldByNid C value");

    /* NULL dst */
    ret = wolfCLU_SetCertNameFieldByNid(NULL, NID_commonName, "wolfSSL", 7);
    CHECK(ret == BAD_FUNC_ARG, "SetCertNameFieldByNid NULL dst");

    /* NULL val */
    ret = wolfCLU_SetCertNameFieldByNid(&name, NID_commonName, NULL, 7);
    CHECK(ret == BAD_FUNC_ARG, "SetCertNameFieldByNid NULL val");

    /* valLen <= 0 */
    ret = wolfCLU_SetCertNameFieldByNid(&name, NID_commonName, "wolfSSL", 0);
    CHECK(ret == BAD_FUNC_ARG, "SetCertNameFieldByNid valLen 0");

    ret = wolfCLU_SetCertNameFieldByNid(&name, NID_commonName, "wolfSSL", -1);
    CHECK(ret == BAD_FUNC_ARG, "SetCertNameFieldByNid valLen -1");

    /* value too long */
    memset(longVal, 'A', sizeof(longVal));
    longVal[sizeof(longVal) - 1] = '\0';
    ret = wolfCLU_SetCertNameFieldByNid(&name, NID_organizationName, longVal,
            CTC_NAME_SIZE);
    CHECK(ret == WOLFCLU_FATAL_ERROR, "SetCertNameFieldByNid too long");
    CHECK(name.org[0] == '\0', "SetCertNameFieldByNid too-long org untouched");
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
    /* wolfCLU_CopyX509SanToCert uses wc_SetAltNamesBuffer() natively now, so
     * SAN handling no longer depends on OPENSSL_EXTRA/OPENSSL_ALL/WOLFSSL_QT
     * the way the rest of wolfCLU_ExtHandledNid's cases still do below. */
    CHECK(wolfCLU_ExtHandledNid(NID_subject_alt_name) == 1,
            "ExtHandledNid subject_alt_name");
#endif
    CHECK(wolfCLU_ExtHandledNid(NID_commonName) == 0,
            "ExtHandledNid commonName not handled");
}

/* wolfCLU_UnwrapX509Extensions() (declared in clu_cert.h, implemented in
 * src/x509/clu_cert_setup.c) is exercised directly here with synthetic
 * buffers -- see its header comment for why that unwrap logic exists.
 *
 * A single Extension { OID 2.5.29.19 (basicConstraints), OCTET STRING { SEQ
 * {} } }: 30 09 06 03 55 1D 13 04 02 30 00. Both fixtures below wrap this
 * same 11-byte entry differently; wolfCLU_UnwrapX509Extensions() must land
 * on it -- and specifically on its leading OID bytes, not reinterpret the
 * wrapper's own tag/length as if they were the first extension -- either
 * way. */
static const byte kOneExt[] = {
    0x30, 0x09, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x04, 0x02, 0x30, 0x00
};

static void checkUnwrapLandsOnExtension(const byte* buf, int bufSz,
        const char* label)
{
    const byte* extensions = buf;
    int extensionsSz = bufSz;
    char msg[128];

    wolfCLU_UnwrapX509Extensions(&extensions, &extensionsSz);

    XSNPRINTF(msg, sizeof(msg), "UnwrapX509Extensions %s: size", label);
    CHECK(extensionsSz == (int)sizeof(kOneExt), msg);

    XSNPRINTF(msg, sizeof(msg), "UnwrapX509Extensions %s: bytes match "
            "(first extension's OID, not the wrapper's tag bytes)", label);
    CHECK(extensionsSz == (int)sizeof(kOneExt) &&
            memcmp(extensions, kOneExt, sizeof(kOneExt)) == 0, msg);
}

static void testUnwrapX509Extensions(void)
{
    /* bare "SEQUENCE OF Extension" (no [3] wrapper): 30 0B <kOneExt> */
    byte bare[2 + sizeof(kOneExt)];
    /* "[3] EXPLICIT Extensions" wrapping the same bare form: A3 0D <bare> */
    byte wrapped[2 + sizeof(bare)];
    /* Neither a [3] tag nor a SEQUENCE at offset 0: extensions/extensionsSz
     * must come back untouched rather than misinterpreted. */
    static const byte garbage[] = { 0x02, 0x01, 0x00 }; /* INTEGER 0 */
    const byte* extensions;
    int extensionsSz;

    bare[0] = 0x30;
    bare[1] = (byte)sizeof(kOneExt);
    memcpy(bare + 2, kOneExt, sizeof(kOneExt));
    checkUnwrapLandsOnExtension(bare, (int)sizeof(bare), "bare SEQUENCE");

    wrapped[0] = 0xA3; /* ASN_EXTENSIONS, [3] EXPLICIT constructed */
    wrapped[1] = (byte)sizeof(bare);
    memcpy(wrapped + 2, bare, sizeof(bare));
    checkUnwrapLandsOnExtension(wrapped, (int)sizeof(wrapped),
            "[3]-wrapped");

    extensions = garbage;
    extensionsSz = (int)sizeof(garbage);
    wolfCLU_UnwrapX509Extensions(&extensions, &extensionsSz);
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

    memset(buf, 0, sizeof(buf));
    ret = wolfCLU_Asn1TimeToCertDate(buf, (int)sizeof(buf), t);
    CHECK(ret > 0, "Asn1TimeToCertDate round trip success");
    if (ret > 0) {
        int lenPrefixSz = ret - t->length;
        CHECK(lenPrefixSz >= 2, "Asn1TimeToCertDate sane length prefix");
        CHECK(buf[0] == (byte)t->type, "Asn1TimeToCertDate tag byte");
        CHECK(memcmp(buf + lenPrefixSz, t->data, (size_t)t->length) == 0,
                "Asn1TimeToCertDate value bytes");
    }

    /* bad tag */
    memset(&bad, 0, sizeof(bad));
    bad.type = 99; /* not UTCTime or GeneralizedTime */
    bad.length = 13;
    memset(bad.data, '0', 12);
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

    memset(&dst, 0, sizeof(dst));
    name = wolfSSL_X509_get_subject_name(x509);
    CHECK(name != NULL, "CopyX509NameToCert fixture subject present");
    if (name == NULL) {
        return;
    }

    ret = wolfCLU_CopyX509NameToCert(name, &dst);
    CHECK(ret == WOLFCLU_SUCCESS, "CopyX509NameToCert success");
    CHECK(strcmp(dst.commonName, "wolfCLU Cert Setup Test") == 0,
            "CopyX509NameToCert commonName matches");
    CHECK(strcmp(dst.country, "US") == 0, "CopyX509NameToCert country matches");
    CHECK(strcmp(dst.org, "wolfSSL") == 0, "CopyX509NameToCert org matches");

    /* NULL args */
    ret = wolfCLU_CopyX509NameToCert(NULL, &dst);
    CHECK(ret == BAD_FUNC_ARG, "CopyX509NameToCert NULL name");
    ret = wolfCLU_CopyX509NameToCert(name, NULL);
    CHECK(ret == BAD_FUNC_ARG, "CopyX509NameToCert NULL dst");
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
    CHECK(ret == BAD_FUNC_ARG, "CopyX509SanToCert NULL x509");
    ret = wolfCLU_CopyX509SanToCert(x509, NULL);
    CHECK(ret == BAD_FUNC_ARG, "CopyX509SanToCert NULL cert");

    ret = wolfCLU_CopyX509SanToCert(x509, &cert);
    CHECK(ret == WOLFCLU_SUCCESS, "CopyX509SanToCert no-SAN success");
    CHECK(cert.altNamesSz == 0, "CopyX509SanToCert no-SAN leaves altNamesSz 0");
}

/* Exercises the actual copy branch (a real subjectAltName present on the
 * x509), which the no-SAN fixture above never reaches. wolfCLU_CopyX509SanToCert
 * reads the SAN extension by re-parsing x509's DER (via
 * wolfSSL_X509_get_ext_by_NID/get_ext), so the SAN has to be baked into the
 * signed DER itself -- setting it post-hoc on the in-memory WOLFSSL_X509
 * (e.g. via wolfCLU_parseAddExt) does not reach that DER and is not visible
 * to this copy path. Cert.altNames/altNamesSz hold the raw DER content of the
 * SAN extension's OCTET STRING (a GeneralNames SEQUENCE), per
 * SetAltNames-adjacent encoding in wolfcrypt/src/asn.c. */
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
    /* DER: SEQUENCE { [2] IA5String "test.wolfssl.com" } -- a GeneralNames
     * SEQUENCE containing one dNSName entry. */
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
    strncpy(cert.subject.country, "US", CTC_NAME_SIZE - 1);
    strncpy(cert.subject.commonName, "wolfCLU Cert Setup Test SAN",
            CTC_NAME_SIZE - 1);
    cert.isCA = 0;
    cert.keyUsage = KU_DIGITAL_SIGNATURE;
    cert.sigType = CTC_SHA256wRSA;
    XMEMCPY(cert.altNames, sanDer, sizeof(sanDer));
    cert.altNamesSz = (int)sizeof(sanDer);

    if (wc_SetSubjectKeyIdFromPublicKey_ex(&cert, RSA_TYPE, &key) < 0) {
        CHECK(0, "CopyX509SanToCertWithSan: wc_SetSubjectKeyIdFromPublicKey_ex");
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
                    CHECK(memcmp(outCert.altNames, sanData->data,
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
    wolfCLU_FreeCertCustomExts(&cert);
}

#if defined(WOLFSSL_ASN_TEMPLATE) && defined(WOLFSSL_CUSTOM_OID) && \
    defined(HAVE_OID_ENCODING)
/* Non-standard OID extensions must fall back to generic custom-extension copy. */
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
        strncpy(fixture.subject.commonName, "wolfCLU Cert Setup Test",
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
                    strcmp((const char*)cert.customCertExt[i].oid,
                            customOid) == 0 &&
                    cert.customCertExt[i].valSz == sizeof(customVal) &&
                    memcmp(cert.customCertExt[i].val, customVal,
                            sizeof(customVal)) == 0) {
                found = 1;
                break;
            }
        }
        CHECK(found, "CopyX509ExtsToCert custom ext: OID and value match");
    }

    wolfCLU_FreeCertCustomExts(&cert);
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
        CHECK(strcmp(outCert.subject.commonName,
                    "wolfCLU Cert Setup Test") == 0,
                "X509FillCert subject commonName");
        CHECK(outCert.selfSigned == 1, "X509FillCert selfSigned (no caCert)");
#ifdef WOLFSSL_CERT_EXT
        wolfCLU_FreeCertCustomExts(&outCert);
#endif
    }

    /* Test with caCert != NULL */
    ret = wolfCLU_X509FillCert(x509, &outCert, CTC_SHA256wRSA, key, RSA_TYPE,
            key, RSA_TYPE, x509, 1, NULL);
    CHECK(ret == WOLFCLU_SUCCESS, "X509FillCert with caCert success");
    if (ret == WOLFCLU_SUCCESS) {
        CHECK(outCert.selfSigned == 0, "X509FillCert with caCert selfSigned == 0");
        CHECK(strcmp(outCert.issuer.commonName, "wolfCLU Cert Setup Test") == 0,
                "X509FillCert with caCert issuer commonName");
#ifdef WOLFSSL_CERT_EXT
        wolfCLU_FreeCertCustomExts(&outCert);
#endif
    }

    /* policySanitized == 0 must be refused */
    ret = wolfCLU_X509FillCert(x509, &outCert, CTC_SHA256wRSA, key, RSA_TYPE,
            NULL, 0, NULL, 0, NULL);
    CHECK(ret == WOLFCLU_FATAL_ERROR, "X509FillCert refuses unsanitized policy");

    /* NULL x509 */
    ret = wolfCLU_X509FillCert(NULL, &outCert, CTC_SHA256wRSA, key, RSA_TYPE,
            NULL, 0, NULL, 1, NULL);
    CHECK(ret == BAD_FUNC_ARG, "X509FillCert NULL x509");

    /* NULL subjWcKey must be rejected up front, even for a fixture whose
     * subjectKeyIdentifier extension would otherwise be requested. */
    ret = wolfCLU_X509FillCert(x509, &outCert, CTC_SHA256wRSA, NULL, RSA_TYPE,
            NULL, 0, NULL, 1, NULL);
    CHECK(ret == BAD_FUNC_ARG, "X509FillCert NULL subjWcKey");
}

/* Non-CA CSR with specific keyUsage must retain RSA defaults and extra bits. */
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
        wolfCLU_FreeCertCustomExts(&outCert);
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
    strncpy(fixture.subject.commonName, "wolfCLU Cert Setup Test",
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
        wolfCLU_FreeCertCustomExts(&outCert);
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
        wolfCLU_FreeCertCustomExts(&outCert);
#endif
    }

    wolfSSL_X509_free(x509);
    wc_FreeRsaKey(&key);
    XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    wc_FreeRng(&rng);
}

/* Non-RSA leaf keys must get plain digitalSignature, not RSA keyEncipherment default. */
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
    strncpy(cert.subject.country, "US", CTC_NAME_SIZE - 1);
    strncpy(cert.subject.commonName, "wolfCLU Cert Setup Test ECC",
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
    CHECK(ret == WOLFCLU_SUCCESS, "leaf keyUsage non-RSA: X509FillCert success");
    if (ret == WOLFCLU_SUCCESS) {
        CHECK(outCert.keyUsage == KU_DIGITAL_SIGNATURE,
                "leaf keyUsage non-RSA: plain digitalSignature, no "
                "RSA-only keyEncipherment");
#ifdef WOLFSSL_CERT_EXT
        wolfCLU_FreeCertCustomExts(&outCert);
#endif
    }

    wolfSSL_X509_free(x509);
    wc_ecc_free(&key);
    XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    wc_FreeRng(&rng);
}

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
    CHECK(ret == BAD_FUNC_ARG, "ReadFileToBuffer NULL path");
    ret = wolfCLU_ReadFileToBuffer(testFile, 100, NULL, &bufSz);
    CHECK(ret == BAD_FUNC_ARG, "ReadFileToBuffer NULL outBuf");
    ret = wolfCLU_ReadFileToBuffer(testFile, 100, &buf, NULL);
    CHECK(ret == BAD_FUNC_ARG, "ReadFileToBuffer NULL outSz");
    ret = wolfCLU_ReadFileToBuffer(testFile, 0, &buf, &bufSz);
    CHECK(ret == BAD_FUNC_ARG, "ReadFileToBuffer maxSz <= 0");

    /* Missing file */
    remove(testFile); /* Ensure it doesn't exist */
    ret = wolfCLU_ReadFileToBuffer(testFile, 100, &buf, &bufSz);
    CHECK(ret == BAD_FUNC_ARG, "ReadFileToBuffer missing file");

    /* Empty file */
    f = fopen(testFile, "wb");
    if (f) {
        fclose(f);
        ret = wolfCLU_ReadFileToBuffer(testFile, 100, &buf, &bufSz);
        CHECK(ret == WOLFCLU_FATAL_ERROR, "ReadFileToBuffer empty file");
        remove(testFile);
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
        }
        remove(testFile);
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
                CHECK(memcmp(buf, "12345", 5) == 0, "ReadFileToBuffer content");
                CHECK(buf[5] == '\0', "ReadFileToBuffer null terminated");
                XFREE(buf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            }
        } else {
            fclose(f);
        }
        remove(testFile);
    }
}

int main(void)
{
    WC_RNG rng;
    RsaKey key;
    WOLFSSL_X509* x509 = NULL;
    byte* derBuf = NULL;
    int derBufSz = 8192;
    int outDerSz = 0;

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
    testX509FillCertLeafKeyUsageMerge();
#ifdef WOLFSSL_CERT_EXT
    testX509FillCertExtKeyUsage();
#endif
    testX509FillCertCaKeyUsageMask();
    testX509FillCertLeafKeyUsageNonRsa();
    testReadFileToBuffer();

    wolfSSL_X509_free(x509);
    wc_FreeRsaKey(&key);
    XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    wc_FreeRng(&rng);

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
