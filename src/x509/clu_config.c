/* clu_config.c
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
#include <wolfclu/clu_log.h>
#include <wolfclu/clu_error_codes.h>
#include <wolfclu/x509/clu_parse.h>
#include <wolfclu/x509/clu_x509_sign.h>

#ifndef WOLFCLU_NO_FILESYSTEM

/* return WOLFCLU_SUCCESS on success */
static int wolfCLU_setAttributes(WOLFSSL_X509 *x509, WOLFSSL_CONF *conf,
                                 char *sect)
{
    const char *current;
    int currentSz;

    current = wolfSSL_NCONF_get_string(conf, sect, "challengePassword");
    if (current != NULL) {
        currentSz = (int)XSTRLEN(current);
        wolfSSL_X509_REQ_add1_attr_by_NID(
            x509, NID_pkcs9_challengePassword, MBSTRING_ASC,
            (const unsigned char *)current, currentSz);
    }

    current = wolfSSL_NCONF_get_string(conf, sect, "unstructuredName");
    if (current != NULL) {
        currentSz = (int)XSTRLEN(current);
        wolfSSL_X509_REQ_add1_attr_by_NID(
            x509, NID_pkcs9_unstructuredName, MBSTRING_ASC,
            (const unsigned char *)current, currentSz);
    }

    return WOLFCLU_SUCCESS;
}


#ifdef WOLFSSL_CERT_EXT
/* defined further down, forward declared for the parsers below. Both the
 * definition and every call site live inside this guard, so the declaration
 * has to as well or a !WOLFSSL_CERT_EXT build carries a static function that
 * is declared and never defined. */
static char *wolfCLU_trimToken(char *word);

#ifdef WOLFSSL_ALT_NAMES
/* defined further down, forward declared for wolfCLU_parseExtension */
static int wolfCLU_setInlineSubjectAltNames(WOLFSSL_X509 *x509, char *val);
#endif

WOLFSSL_ASN1_OBJECT *wolfCLU_extenstionGetObjectNID(WOLFSSL_X509_EXTENSION *ext,
                                                    int nid, int crit)
{
    WOLFSSL_ASN1_OBJECT *obj;
    if (ext == NULL)
        return NULL;

    wolfSSL_X509_EXTENSION_set_critical(ext, crit);
    obj = wolfSSL_OBJ_nid2obj(nid);
    if (wolfSSL_X509_EXTENSION_set_object(ext, obj) != WOLFSSL_SUCCESS) {
        wolfSSL_X509_EXTENSION_free(ext);
        wolfSSL_ASN1_OBJECT_free(obj);
        return NULL;
    }
    wolfSSL_ASN1_OBJECT_free(obj);

    obj = wolfSSL_X509_EXTENSION_get_object(ext);
    if (obj == NULL) {
        wolfSSL_X509_EXTENSION_free(ext);
        return NULL;
    }

    return obj;
}

static WOLFSSL_X509_EXTENSION *wolfCLU_parseBasicConstraint(char *in, int crit)
{
    char *word, *end, *str = in;
    WOLFSSL_X509_EXTENSION *ext;
    WOLFSSL_ASN1_OBJECT *obj;
    /* an empty value would otherwise tokenize to nothing and hand back a
     * CA:FALSE extension the user never asked for */
    int sawValue = 0;

    if (str == NULL) {
        return NULL;
    }

    ext = wolfSSL_X509_EXTENSION_new();
    if (ext == NULL) {
        return NULL;
    }

    /* on failure this takes 'ext' down with it, nothing to free here */
    obj = wolfCLU_extenstionGetObjectNID(ext, NID_basic_constraints, crit);
    if (obj == NULL) {
        return NULL;
    }


    /* Split the value on ',' first and only then split each token on ':'.
     * Tokenizing the whole string on ':' while the keyword branches consumed
     * their value with ',' let the two delimiters cross: for
     * "CA:TRUE,critical,pathlen:0" the pass after CA scanned past the comma
     * and yielded "critical,pathlen" as one token, which matched nothing and
     * rejected a valid value. Splitting on ',' first also makes "critical"
     * position independent, since it is then always a token of its own. */
    for (word = XSTRTOK(str, ",", &end); word != NULL;
         word = XSTRTOK(NULL, ",", &end)) {
        /* hold on to the keyword: 'val' is the part after the colon, and
         * testing that against the next keyword would let "CA:pathlen" style
         * nonsense through */
        char *tok = wolfCLU_trimToken(word);
        char *val = XSTRSTR(tok, ":");

        if (val != NULL) {
            *val = '\0';
            val = wolfCLU_trimToken(val + 1);
            tok = wolfCLU_trimToken(tok);
        }

        if (XSTRCMP(tok, "CA") == 0) {
            int z, valSz;

            if (val == NULL) {
                wolfCLU_LogError("basicConstraints CA is missing a value, "
                                 "expected \"CA:TRUE\" or \"CA:FALSE\"");
                wolfSSL_X509_EXTENSION_free(ext);
                return NULL;
            }

            valSz = (int)XSTRLEN(val);
            for (z = 0; z < valSz; z++)
                val[z] = XTOUPPER(val[z]);

            if (XSTRCMP(val, "TRUE") == 0) {
                obj->ca = 1;
                sawValue = 1;
                continue;
            }
            /* CA:FALSE is the default and the usual spelling for a leaf
             * certificate's conf file, not a bad token */
            if (XSTRCMP(val, "FALSE") == 0) {
                obj->ca = 0;
                sawValue = 1;
                continue;
            }

            wolfCLU_LogError("Unable to parse basic constraint CA value "
                             "%s, expected \"TRUE\" or \"FALSE\"",
                             valSz ? val : "\"\"");
            wolfSSL_X509_EXTENSION_free(ext);
            return NULL;
        }

        if (XSTRCMP(tok, "pathlen") == 0) {
            long pathLen = -1;

            /* 0 is a valid path length: the CA may issue end entity
             * certificates but no further CAs */
            if (val == NULL || wolfCLU_parseDecimalBounded(
                                   val, 0, 127, &pathLen) != WOLFCLU_SUCCESS) {
                wolfCLU_LogError("Unable to parse basic constraint "
                                 "pathlen value %s, it must be a number in the "
                                 "range [0, 127]",
                                 (val != NULL && XSTRLEN(val)) ? val : "\"\"");
                wolfSSL_X509_EXTENSION_free(ext);
                return NULL;
            }

            /* the [0, 127] bound above is WOLFSSL_MAX_PATH_LEN, which
             * CopyX509ToCert() rejects anything larger against */

            if (obj->pathlen != NULL)
                wolfSSL_ASN1_INTEGER_free(obj->pathlen);
            obj->pathlen = wolfSSL_ASN1_INTEGER_new();
            if (obj->pathlen == NULL) {
                wolfSSL_X509_EXTENSION_free(ext);
                return NULL;
            }

            obj->pathlen->length = (int)pathLen;
            sawValue = 1;
            continue;
        }

        /* the caller flagged 'critical' by searching the whole value, so
         * every occurrence of it is just a token to step over here */
        if (XSTRCMP(tok, "critical") == 0) {
            continue;
        }

        wolfCLU_LogError("Unknown token \"%s\" while parsing "
                         "basicConstraints",
                         tok);
        wolfSSL_X509_EXTENSION_free(ext);
        return NULL;
    }

    /* pathLenConstraint may only appear when cA is TRUE (RFC 5280 4.2.1.9) */
    if (obj->pathlen != NULL && !obj->ca) {
        wolfCLU_LogError("basicConstraints pathlen requires CA:TRUE "
                         "(RFC 5280 4.2.1.9)");
        wolfSSL_X509_EXTENSION_free(ext);
        return NULL;
    }

    /* an empty value tokenizes to nothing, so without this it would add a
     * CA:FALSE extension that was never asked for */
    if (!sawValue) {
        wolfCLU_LogError("no basicConstraints value found, expected "
                         "\"CA:TRUE\" or \"CA:FALSE\"");
        wolfSSL_X509_EXTENSION_free(ext);
        return NULL;
    }

    return ext;
}

/* Trim spaces and tabs from both ends of 'word', in place. Returns the new
 * start. Config values are commonly written "a, b" or even "a , b", so a
 * token has to survive whitespace on either side. */
static char *wolfCLU_trimToken(char *word)
{
    int sz;
    if (word == NULL) {
        return NULL;
    }

    while (*word == ' ' || *word == '\t' || *word == '\n' || *word == '\r') {
        word++;
    }
    sz = (int)XSTRLEN(word);
    while (sz > 0 && (word[sz - 1] == ' ' || word[sz - 1] == '\t' ||
                      word[sz - 1] == '\n' || word[sz - 1] == '\r')) {
        word[--sz] = '\0';
    }

    return word;
}

/* Is "critical" one of the comma separated tokens of 'str'?
 *
 * Matched per token rather than with a plain substring search, which reported
 * a critical extension for any value that merely contained the word -- i.e.
 * "subjectAltName=DNS:critical.example.com". 'str' is not modified, this runs
 * before the parsers tokenize it in place.
 * returns 1 when the key word is present, 0 otherwise */
static int wolfCLU_hasCriticalToken(const char *str)
{
    const char *tok = str;

    while (tok != NULL) {
        const char *end = XSTRSTR(tok, ",");
        int sz;

        while (*tok == ' ' || *tok == '\t' || *tok == '\n' || *tok == '\r') {
            tok++;
        }

        sz = (end != NULL) ? (int)(end - tok) : (int)XSTRLEN(tok);
        while (sz > 0 && (tok[sz - 1] == ' ' || tok[sz - 1] == '\t' ||
                          tok[sz - 1] == '\n' || tok[sz - 1] == '\r')) {
            sz--;
        }

        if (sz == 8 && XSTRNCMP(tok, "critical", 8) == 0) {
            return 1;
        }

        tok = (end != NULL) ? end + 1 : NULL;
    }

    return 0;
}

/* Does 'word' name the key word 'kw'? A ':' qualifier is allowed after it, so
 * that OpenSSL's "keyid:always" / "issuer:optional" spellings match, while a
 * typo such as "keyidalways" does not.
 * returns 1 on a match, 0 otherwise */
static int wolfCLU_tokenIs(const char *word, const char *kw)
{
    int kwSz = (int)XSTRLEN(kw);

    if (XSTRNCMP(word, kw, kwSz) != 0) {
        return 0;
    }

    return word[kwSz] == '\0' || word[kwSz] == ':';
}

/* Get the wolfCrypt key out of the certificate's public key and translate the
 * key type into the *_TYPE value the wc_Set*KeyIdFromPublicKey_ex() helpers
 * expect. On success the caller owns '*pkey' and must wolfSSL_EVP_PKEY_free()
 * it; '*key' points into it and must not outlive it.
 * return WOLFCLU_SUCCESS on success */
static int wolfCLU_getPubKeyForId(WOLFSSL_X509 *x509, WOLFSSL_EVP_PKEY **pkey,
                                  void **key, int *keyType)
{
    int type;

    *pkey = NULL;
    *key = NULL;

    type = wolfSSL_X509_get_pubkey_type(x509);

    *pkey = wolfSSL_X509_get_pubkey(x509);
    if (*pkey == NULL) {
        wolfCLU_LogError("no public key set to hash for key id");
        return WOLFCLU_FATAL_ERROR;
    }

    switch (type) {
        case RSAk:
            if ((*pkey)->rsa != NULL) {
                *key = (*pkey)->rsa->internal;
            }
            *keyType = RSA_TYPE;
            break;

        case ECDSAk:
            if ((*pkey)->ecc != NULL) {
                *key = (*pkey)->ecc->internal;
            }
            *keyType = ECC_TYPE;
            break;

        default:
            wolfCLU_LogError("key type not yet supported");
            wolfSSL_EVP_PKEY_free(*pkey);
            *pkey = NULL;
            return WOLFCLU_FATAL_ERROR;
    }

    if (*key == NULL) {
        wolfCLU_LogError("Could not get public key");
        wolfSSL_EVP_PKEY_free(*pkey);
        *pkey = NULL;
        return WOLFCLU_FATAL_ERROR;
    }

    return WOLFCLU_SUCCESS;
}

/* Only consulted when no issuing certificate is available, since this compares
 * names and so cannot tell a self signed certificate from an RFC 5280 4.2.1.1
 * key rollover one. An issuer with no entries is the self signed case too.
 * returns 1 when self issued, 0 otherwise */
static int wolfCLU_isSelfIssued(WOLFSSL_X509 *x509)
{
    WOLFSSL_X509_NAME *issuer = wolfSSL_X509_get_issuer_name(x509);

    if (issuer == NULL || wolfSSL_X509_NAME_entry_count(issuer) == 0) {
        return 1;
    }
    return wolfSSL_X509_NAME_cmp(wolfSSL_X509_get_subject_name(x509), issuer) ==
           0;
}

/* Create an authority key identifier extension from the config values
 * "keyid[:always]" (or "hash"). With 'issuer' the key id names that
 * certificate's key and wolfSSL applies it to 'x509' directly; without one it
 * is derived by hashing the key in 'x509', which is only the authority's key
 * for a self signed cert. The "issuer" DN/serial form is skipped, not an
 * error, since the keyid alone is still a valid AKID.
 *
 * On success '*out' holds the new extension, or NULL when it was applied
 * directly or every key word present was a skipped one.
 * return WOLFCLU_SUCCESS on success */
static int wolfCLU_parseAuthorityKeyId(char *str, int crit, WOLFSSL_X509 *x509,
                                       WOLFSSL_X509 *issuer,
                                       WOLFSSL_X509_EXTENSION **out)
{
    WOLFSSL_X509_EXTENSION *ext = NULL;
    WOLFSSL_EVP_PKEY *pkey = NULL;
    char *word, *end;
    char *deli = (char *)",";
    int ret = WOLFCLU_SUCCESS;
    /* A value naming only the skipped "issuer" is a success with no
     * extension; one naming nothing usable at all is an error. */
    int sawSkipped = 0;
    int sawKeyId = 0;

    if (x509 == NULL || str == NULL || out == NULL)
        return BAD_FUNC_ARG;

    *out = NULL;

    /* RFC 5280 4.2.1.1 says the AKID MUST be non-critical, so the key word is
     * accepted and reported rather than honoured. */
    if (crit) {
        WOLFCLU_LOG(WOLFCLU_L0,
                    "Ignoring \"critical\" on "
                    "authorityKeyIdentifier, RFC 5280 requires it be "
                    "non-critical");
    }

    for (word = XSTRTOK(str, deli, &end);
         word != NULL && ret == WOLFCLU_SUCCESS;
         word = XSTRTOK(NULL, deli, &end)) {
        word = wolfCLU_trimToken(word);

        /* the critical key word was already handled by the caller */
        if (XSTRCMP(word, "critical") == 0) {
            continue;
        }

        /* "keyid" may carry a ":always" or ":optional" qualifier, both are
         * treated the same here since the key id can always be derived */
        if (wolfCLU_tokenIs(word, "keyid") || wolfCLU_tokenIs(word, "hash")) {
            WOLFSSL_ASN1_STRING *data;
            void *key = NULL;
            int keyType;

            sawKeyId = 1;

            /* Take the key id from the issuing certificate rather than
             * hashing the key being certified; wolfSSL sets it on 'x509'
             * itself, so there is no extension to hand back. The API hashes
             * with SHA-1, so it is guarded the same way clu_request_setup.c
             * guards its own call. */
            if (issuer != NULL) {
#ifndef NO_SHA
                if (wolfSSL_X509_set_authority_key_id_ex(x509, issuer) !=
                    WOLFSSL_SUCCESS) {
                    wolfCLU_LogError("error setting the authority key id from "
                                     "the issuing certificate");
                    ret = WOLFCLU_FATAL_ERROR;
                }
#else
                wolfCLU_LogError(
                    "cannot derive an authority key id from the "
                    "issuing certificate, wolfSSL was built with NO_SHA");
                ret = NOT_COMPILED_IN;
#endif
                continue;
            }

            /* a value may name the key id more than once, i.e. "keyid,hash",
             * only the first one builds the extension */
            if (ext != NULL) {
                continue;
            }

            if (wolfCLU_getPubKeyForId(x509, &pkey, &key, &keyType) !=
                WOLFCLU_SUCCESS) {
                ret = WOLFCLU_FATAL_ERROR;
                break;
            }

            /* Cert is several kilobytes, so it is scoped to the one branch
             * that needs it rather than sitting on the frame throughout. */
            {
                Cert cert; /* temporary to use existing auth key id api */

                XMEMSET(&cert, 0, sizeof(Cert));
                if (wc_SetAuthKeyIdFromPublicKey_ex(&cert, keyType, key) < 0) {
                    wolfCLU_LogError("error hashing public key");
                    ret = WOLFCLU_FATAL_ERROR;
                }
                else {
                    data = wolfSSL_ASN1_STRING_new();
                    if (data == NULL) {
                        ret = MEMORY_E;
                    }
                    else {
                        if (wolfSSL_ASN1_STRING_set(data, cert.akid,
                                                    cert.akidSz) !=
                            WOLFSSL_SUCCESS) {
                            wolfCLU_LogError("error setting the akid");
                            ret = WOLFCLU_FATAL_ERROR;
                        }
                        else {
                            /* RFC 5280 4.2.1.1 requires a non-critical
                             * AKID, so the extension is built that way on
                             * both paths even when the config asked for
                             * critical. */
                            ext = wolfSSL_X509_EXTENSION_new();
                            if (ext != NULL &&
                                wolfCLU_extenstionGetObjectNID(
                                    ext, NID_authority_key_identifier, 0) ==
                                    NULL) {
                                /* extension was free'd on failure */
                                ext = NULL;
                            }
                            if (ext == NULL) {
                                ret = WOLFCLU_FATAL_ERROR;
                            }
                            else if (wolfSSL_X509_EXTENSION_set_data(
                                         ext, data) != WOLFSSL_SUCCESS) {
                                wolfCLU_LogError("error setting the akid data");
                                ret = WOLFCLU_FATAL_ERROR;
                            }
                        }
                        wolfSSL_ASN1_STRING_free(data);
                    }
                }
            }
            wolfSSL_EVP_PKEY_free(pkey);
            pkey = NULL;
        }
        else if (wolfCLU_tokenIs(word, "issuer")) {
            /* the issuer name / serial form can not be created without the
             * issuing certificate, the keyid alone is still a valid AKID */
            sawSkipped = 1;
            WOLFCLU_LOG(WOLFCLU_L0, "Skipping authority key identifier "
                                    "\"issuer\", only \"keyid\" is supported");
        }
        else {
            wolfCLU_LogError("unsupported authority key identifier \"%s\"",
                             word);
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret != WOLFCLU_SUCCESS) {
        if (ext != NULL) {
            wolfSSL_X509_EXTENSION_free(ext);
        }
        return ret;
    }

    /* The value was empty or held only "critical". Reported rather than
     * dropped, matching every sibling parser in this file. */
    if (ext == NULL && !sawKeyId && !sawSkipped) {
        wolfCLU_LogError("no authority key identifier value found, "
                         "expected \"keyid\" or \"issuer\"");
        return WOLFCLU_FATAL_ERROR;
    }

    *out = ext;

    return WOLFCLU_SUCCESS;
}

/* The extended key usages wolfSSL can express, by both the OpenSSL key word
 * and the dotted OID that conf files commonly use for the same purpose. */
typedef struct WOLFCLU_EKU_MAP {
    const char *name;
    const char *oid;
    byte flag;
} WOLFCLU_EKU_MAP;

static const WOLFCLU_EKU_MAP wolfCLU_ekuMap[] = {
    { "anyExtendedKeyUsage", "2.5.29.37.0", EXTKEYUSE_ANY },
    { "any", NULL, EXTKEYUSE_ANY },
    { "serverAuth", "1.3.6.1.5.5.7.3.1", EXTKEYUSE_SERVER_AUTH },
    { "clientAuth", "1.3.6.1.5.5.7.3.2", EXTKEYUSE_CLIENT_AUTH },
    { "codeSigning", "1.3.6.1.5.5.7.3.3", EXTKEYUSE_CODESIGN },
    { "emailProtection", "1.3.6.1.5.5.7.3.4", EXTKEYUSE_EMAILPROT },
    { "timeStamping", "1.3.6.1.5.5.7.3.8", EXTKEYUSE_TIMESTAMP },
    { "OCSPSigning", "1.3.6.1.5.5.7.3.9", EXTKEYUSE_OCSP_SIGN }
};

/* Create an extended key usage extension from a comma separated list of the
 * key words wolfSSL supports, i.e. "critical,serverAuth,clientAuth". The
 * dotted OID spelling of each of those purposes is accepted too, since conf
 * files written for OpenSSL commonly use it.
 *
 * returns the new extension on success, NULL on failure */
static WOLFSSL_X509_EXTENSION *wolfCLU_parseExtKeyUsage(char *str, int crit)
{
    WOLFSSL_ASN1_STRING *data;
    WOLFSSL_X509_EXTENSION *ext = NULL;
    char *word, *end;
    char *deli = (char *)",";
    byte extKeyUseFlag = 0;
    size_t i;

    if (str == NULL)
        return NULL;

    for (word = XSTRTOK(str, deli, &end); word != NULL;
         word = XSTRTOK(NULL, deli, &end)) {
        int found = 0;

        word = wolfCLU_trimToken(word);

        /* the critical key word was already handled by the caller */
        if (XSTRCMP(word, "critical") == 0) {
            continue;
        }

        for (i = 0; i < sizeof(wolfCLU_ekuMap) / sizeof(wolfCLU_ekuMap[0]);
             i++) {
            if (XSTRCMP(word, wolfCLU_ekuMap[i].name) == 0 ||
                (wolfCLU_ekuMap[i].oid != NULL &&
                 XSTRCMP(word, wolfCLU_ekuMap[i].oid) == 0)) {
                extKeyUseFlag |= wolfCLU_ekuMap[i].flag;
                found = 1;
                break;
            }
        }

        if (!found) {
            wolfCLU_LogError("unsupported extended key usage \"%s\"", word);
            wolfCLU_LogError(
                "supported: any, serverAuth, clientAuth, "
                "codeSigning, emailProtection, timeStamping, OCSPSigning");
            return NULL;
        }
    }

    if (extKeyUseFlag == 0) {
        wolfCLU_LogError("no extended key usage values found");
        return NULL;
    }

    /* wolfSSL's SetExtKeyUsage() short circuits on EXTKEYUSE_ANY and emits
     * anyExtendedKeyUsage alone, so every named purpose listed beside it
     * would be dropped from the certificate without a word. OpenSSL emits
     * them all, so refuse the combination rather than quietly diverging. */
    if ((extKeyUseFlag & EXTKEYUSE_ANY) && (extKeyUseFlag != EXTKEYUSE_ANY)) {
        wolfCLU_LogError("extended key usage \"any\" cannot be combined with "
                         "other purposes; it already covers all of them");
        return NULL;
    }

    ext = wolfSSL_X509_EXTENSION_new();
    if (ext == NULL) {
        return NULL;
    }

    if (wolfCLU_extenstionGetObjectNID(ext, NID_ext_key_usage, crit) == NULL) {
        /* extension was free'd on failure */
        wolfCLU_LogError("Could not add ExtKeyUsage extension");
        return NULL;
    }

    data = wolfSSL_ASN1_STRING_new();
    if (data == NULL) {
        wolfSSL_X509_EXTENSION_free(ext);
        return NULL;
    }

    /* a single byte of flags is what wolfSSL_X509_add_ext() expects */
    if (wolfSSL_ASN1_STRING_set(data, &extKeyUseFlag, (int)sizeof(byte)) !=
            WOLFSSL_SUCCESS ||
        wolfSSL_X509_EXTENSION_set_data(ext, data) != WOLFSSL_SUCCESS) {
        wolfCLU_LogError("error setting the extended key use");
        wolfSSL_X509_EXTENSION_free(ext);
        ext = NULL;
    }
    wolfSSL_ASN1_STRING_free(data);

    return ext;
}

/* Create a subject key identifier extension from the config value "hash",
 * derived by hashing the public key held in 'x509'.
 *
 * returns the new extension on success, NULL on failure */
static WOLFSSL_X509_EXTENSION *wolfCLU_parseSubjectKeyID(char *str, int crit,
                                                         WOLFSSL_X509 *x509)
{
    WOLFSSL_X509_EXTENSION *ext = NULL;
    WOLFSSL_EVP_PKEY *pkey = NULL;
    char *word, *end;
    char *deli = (char *)",";
    /* separates "the config named no key id" from "deriving one failed", which
     * both left ext NULL and reported the former */
    int sawHash = 0;

    if (x509 == NULL || str == NULL)
        return NULL;

    for (word = XSTRTOK(str, deli, &end); word != NULL;
         word = XSTRTOK(NULL, deli, &end)) {
        word = wolfCLU_trimToken(word);

        /* the critical key word was already handled by the caller */
        if (XSTRCMP(word, "critical") == 0) {
            continue;
        }

        if (XSTRCMP(word, "hash") == 0) {
            WOLFSSL_ASN1_STRING *data;
            int keyType;
            void *key = NULL;
            /* Cert is several kilobytes, so it is scoped to this branch */
            Cert cert; /* temporary to use existing subject key id api */

            sawHash = 1;

            /* only the first "hash" builds the extension */
            if (ext != NULL) {
                continue;
            }

            if (wolfCLU_getPubKeyForId(x509, &pkey, &key, &keyType) !=
                WOLFCLU_SUCCESS) {
                return NULL;
            }

            XMEMSET(&cert, 0, sizeof(Cert));
            if (wc_SetSubjectKeyIdFromPublicKey_ex(&cert, keyType, key) < 0) {
                wolfCLU_LogError("error hashing public key");
                /* this function owns pkey from here on, and returning skips
                 * the free below */
                wolfSSL_EVP_PKEY_free(pkey);
                return NULL;
            }
            else {
                data = wolfSSL_ASN1_STRING_new();
                if (data == NULL) {
                    wolfCLU_LogError("out of memory building the skid");
                }
                else {
                    if (wolfSSL_ASN1_STRING_set(data, cert.skid, cert.skidSz) !=
                        WOLFSSL_SUCCESS) {
                        wolfCLU_LogError("error setting the skid");
                    }
                    else {
                        ext = wolfSSL_X509V3_EXT_i2d(NID_subject_key_identifier,
                                                     crit, data);
                        if (ext == NULL) {
                            wolfCLU_LogError("error encoding the skid "
                                             "extension");
                        }
                    }
                    wolfSSL_ASN1_STRING_free(data);
                }
            }
            wolfSSL_EVP_PKEY_free(pkey);
            pkey = NULL;
        }
        else {
            wolfCLU_LogError("unsupported subject key identifier \"%s\"", word);
            if (ext != NULL) {
                wolfSSL_X509_EXTENSION_free(ext);
            }
            return NULL;
        }
    }

    /* only report a missing value when the config really named none; a failure
     * while deriving the key id has already logged its own cause */
    if (ext == NULL && !sawHash) {
        wolfCLU_LogError("no subject key identifier value found, "
                         "expected \"hash\"");
    }

    return ext;
}

/* Create a key usage extension from a comma separated list of the key words
 * wolfSSL supports, i.e. "critical,digitalSignature,keyEncipherment".
 * An unrecognized key word is an error rather than a silently dropped bit,
 * matching wolfCLU_parseExtKeyUsage().
 *
 * returns the new extension on success, NULL on failure */
static WOLFSSL_X509_EXTENSION *wolfCLU_parseKeyUsage(char *str, int crit)
{
    WOLFSSL_ASN1_STRING *data;
    WOLFSSL_X509_EXTENSION *ext = NULL;
    char *word, *end;
    char *deli = (char *)",";
    word16 keyUseFlag = 0;

    if (str == NULL)
        return NULL;

    for (word = XSTRTOK(str, deli, &end); word != NULL;
         word = XSTRTOK(NULL, deli, &end)) {
        word = wolfCLU_trimToken(word);

        /* the critical key word was already handled by the caller */
        if (XSTRCMP(word, "critical") == 0) {
            continue;
        }
        else if (XSTRCMP(word, "digitalSignature") == 0) {
            keyUseFlag |= KEYUSE_DIGITAL_SIG;
        }
        else if (XSTRCMP(word, "nonRepudiation") == 0 ||
                 XSTRCMP(word, "contentCommitment") == 0) {
            keyUseFlag |= KEYUSE_CONTENT_COMMIT;
        }
        else if (XSTRCMP(word, "keyEncipherment") == 0) {
            keyUseFlag |= KEYUSE_KEY_ENCIPHER;
        }
        else if (XSTRCMP(word, "dataEncipherment") == 0) {
            keyUseFlag |= KEYUSE_DATA_ENCIPHER;
        }
        else if (XSTRCMP(word, "keyAgreement") == 0) {
            keyUseFlag |= KEYUSE_KEY_AGREE;
        }
        else if (XSTRCMP(word, "keyCertSign") == 0) {
            keyUseFlag |= KEYUSE_KEY_CERT_SIGN;
        }
        else if (XSTRCMP(word, "cRLSign") == 0) {
            keyUseFlag |= KEYUSE_CRL_SIGN;
        }
        else if (XSTRCMP(word, "encipherOnly") == 0) {
            keyUseFlag |= KEYUSE_ENCIPHER_ONLY;
        }
        else if (XSTRCMP(word, "decipherOnly") == 0) {
            keyUseFlag |= KEYUSE_DECIPHER_ONLY;
        }
        else {
            wolfCLU_LogError("unsupported key usage \"%s\"",
                             XSTRLEN(word) ? word : "\"\"");
            return NULL;
        }
    }

    if (keyUseFlag == 0) {
        wolfCLU_LogError("no key usage values found");
        return NULL;
    }

    data = wolfSSL_ASN1_STRING_new();
    if (data != NULL) {
        if (wolfSSL_ASN1_STRING_set(data, (byte *)&keyUseFlag,
                                    sizeof(word16)) != WOLFSSL_SUCCESS) {
            wolfCLU_LogError("error setting the key use");
        }
        else {
            ext = wolfSSL_X509V3_EXT_i2d(NID_key_usage, crit, data);
        }
        wolfSSL_ASN1_STRING_free(data);
    }
    return ext;
}

/* Apply an inline "[critical,]TYPE:value[,TYPE:value...]" subject alt name
 * list. wolfSSL keeps alt names on the WOLFSSL_X509 struct rather than as a
 * generic extension, so nothing is handed back to the caller. 'str' is
 * tokenized in place, callers pass a writable copy.
 * return WOLFCLU_SUCCESS on success */
static int wolfCLU_parseSubjectAltNames(WOLFSSL_X509 *x509, char *str, int crit)
{
#ifndef WOLFSSL_ALT_NAMES
    (void)x509;
    (void)str;
    (void)crit;

    /* alt names were explicitly requested, so fail rather than silently
     * emitting a cert without them */
    wolfCLU_LogError(
        "wolfSSL not compiled with alt name support "
        "(WOLFSSL_ALT_NAMES); cannot apply requested subjectAltName");
    return NOT_COMPILED_IN;
#else
    /* wolfSSL has no way to mark alt names critical. Said out loud because
     * RFC 5280 4.2.1.6 requires a critical SAN when the subject is empty, so
     * dropping it silently can emit a non-conformant certificate. The token
     * itself is skipped wherever it appears, by the tokenizer below. */
    if (crit) {
        WOLFCLU_LOG(WOLFCLU_L0, "Warning: wolfSSL cannot mark subjectAltName "
                                "critical, emitting it as non-critical");
    }

    return wolfCLU_setInlineSubjectAltNames(x509, str);
#endif
}

/* Name an extension nid for a diagnostic, writing into 'buf' when it has to
 * build the text. For error messages only.
 *
 * The NID_* macros for certificate extensions do not expand to the small
 * OpenSSL nids: wolfSSL defines them as its internal OID sums, so
 * NID_issuer_alt_name is 0x7fed1daa rather than 86. Printing the raw value
 * hands the operator a ten digit number that matches nothing they can look
 * up, and it reads like memory corruption. Prefer the long name, fall back to
 * the dotted OID, and only use the number when neither is available. */
static const char *wolfCLU_extNidName(int nid, char *buf, int bufSz)
{
    const char *ln = wolfSSL_OBJ_nid2ln(nid);
    WOLFSSL_ASN1_OBJECT *obj;

    if (ln != NULL) {
        return ln;
    }

    /* nid2ln has no entry for several of the extensions handled here, but the
     * object table still knows the OID itself */
    obj = wolfSSL_OBJ_nid2obj(nid);
    if (obj != NULL) {
        int sz = wolfSSL_OBJ_obj2txt(buf, bufSz, obj, 1);

        wolfSSL_ASN1_OBJECT_free(obj);
        if (sz > 0) {
            return buf;
        }
    }

    XSNPRINTF(buf, bufSz, "%d", nid);
    return buf;
}

static int wolfCLU_extNotSupported(const char *name)
{
    wolfCLU_LogError("extension %s is not supported by wolfSSL when creating "
                     "a certificate",
                     name);
    return WOLFCLU_FATAL_ERROR;
}

/* Apply the extension 'nid' with value 'str' to 'x509'. 'issuer' is the
 * certificate that will sign it, or NULL when it signs itself or the signer is
 * not known here; only the authority key identifier uses it.
 * return WOLFCLU_SUCCESS on success */
static int wolfCLU_parseExtension(WOLFSSL_X509 *x509, char *str, int nid,
                                  WOLFSSL_X509 *issuer)
{
    char nameBuf[80];

    WOLFSSL_X509_EXTENSION *ext = NULL;
    int ret = WOLFCLU_SUCCESS;
    int crit = 0;

    if (x509 == NULL || str == NULL) {
        return BAD_FUNC_ARG;
    }

    if (wolfCLU_hasCriticalToken(str)) {
        crit = 1;
    }

    switch (nid) {
        case NID_basic_constraints:
            ext = wolfCLU_parseBasicConstraint(str, crit);
            break;
        case NID_subject_key_identifier:
            /* every failure path returns NULL, so it must fall through to the
             * error below rather than dropping the skid at exit 0 */
            ext = wolfCLU_parseSubjectKeyID(str, crit, x509);
            break;
        case NID_authority_key_identifier:
            /* With an issuing certificate the key id comes from it and is
             * right however the names compare; without one it can only be
             * derived from the subject's own key, which needs a self signed
             * cert. (The -CA path in clu_request_setup.c never lands here.) */
            if (issuer == NULL && !wolfCLU_isSelfIssued(x509)) {
                WOLFCLU_LOG(WOLFCLU_L0,
                            "Skipping authority key identifier, "
                            "deriving it for a certificate that is not self "
                            "issued needs the issuing certificate");
                return WOLFCLU_SUCCESS;
            }
            ret = wolfCLU_parseAuthorityKeyId(str, crit, x509, issuer, &ext);
            if (ret != WOLFCLU_SUCCESS) {
                return ret;
            }
            if (ext == NULL) {
                /* either wolfSSL applied the key id to 'x509' directly from
                 * the issuing certificate, or every key word present was one
                 * that is deliberately skipped, i.e. "issuer" on its own */
                return WOLFCLU_SUCCESS;
            }
            break;
        case NID_key_usage:
            /* EncodeExtensions() sets the criticality flag unconditionally
             * whenever a key usage is present, and CopyX509ToCert() never
             * carries keyUsageCrit across, so the emitted extension is
             * critical either way. Say so when the config asked for the
             * opposite rather than letting the two silently disagree. */
            if (!crit) {
                WOLFCLU_LOG(WOLFCLU_L0, "Note: wolfSSL always emits keyUsage "
                        "as critical when creating a certificate");
            }
            ext = wolfCLU_parseKeyUsage(str, crit);
            break;
        case NID_ext_key_usage:
            if (crit) {
                WOLFCLU_LOG(WOLFCLU_L0,
                            "Warning: wolfSSL cannot mark "
                            "extendedKeyUsage critical, emitting it as "
                            "non-critical");
            }
            ext = wolfCLU_parseExtKeyUsage(str, crit);
            break;
        /* alt names are stored on the x509 struct instead of being added as
         * an extension, so this case is done once it returns */
        case NID_subject_alt_name:
            return wolfCLU_parseSubjectAltNames(x509, str, crit);

        /* wolfSSL_X509_add_ext() has nowhere to keep these on the x509 struct,
         * so report them rather than silently dropping what was asked for.
         * Named literally with the spelling -addext and the conf files use:
         * three of the five are absent from wolfSSL's object table, so neither
         * nid2ln nor nid2obj can name them and the message would otherwise
         * degrade to a bare OID sum. */
        case NID_issuer_alt_name:
            return wolfCLU_extNotSupported("issuerAltName");
        case NID_name_constraints:
            return wolfCLU_extNotSupported("nameConstraints");
        case NID_policy_constraints:
            return wolfCLU_extNotSupported("policyConstraints");
        case NID_policy_mappings:
            return wolfCLU_extNotSupported("policyMappings");
        case NID_inhibit_any_policy:
            return wolfCLU_extNotSupported("inhibitAnyPolicy");

        default:
            wolfCLU_LogError(
                "unknown / unsupported extension %s",
                wolfCLU_extNidName(nid, nameBuf, (int)sizeof(nameBuf)));
            return WOLFCLU_FATAL_ERROR;
    }

    /* note that 'str' has been tokenized in place by now, so it is not worth
     * echoing back in the error */
    if (ext == NULL) {
        wolfCLU_LogError(
            "unable to create extension %s",
            wolfCLU_extNidName(nid, nameBuf, (int)sizeof(nameBuf)));
        return WOLFCLU_FATAL_ERROR;
    }

    /* wolfSSL only supports appending, loc must be negative */
    if (wolfSSL_X509_add_ext(x509, ext, -1) != WOLFSSL_SUCCESS) {
        wolfCLU_LogError(
            "error adding extension %s",
            wolfCLU_extNidName(nid, nameBuf, (int)sizeof(nameBuf)));
        ret = WOLFCLU_FATAL_ERROR;
    }
    wolfSSL_X509_EXTENSION_free(ext);

    return ret;
}

/* add a single alt name of type 'name' ("IP", "DNS", "URI", "RID" or "email")
 * with value 'value' to x509, shared by the config and -addext paths.
 * return WOLFCLU_SUCCESS on success */
#ifdef WOLFSSL_ALT_NAMES
static int wolfCLU_addAltName(WOLFSSL_X509 *x509, const char *name,
                              const char *value)
{
    int ret = WOLFCLU_SUCCESS;
    WOLFSSL_ASN1_STRING *ipStr = NULL;
    WOLFSSL_ASN1_OBJECT *ridObj = NULL;
    char *token, *ptr, *s = NULL;
    int sSz = 0;
    int type = 0;
    byte oid[ASN1_OID_DOTTED_MAX_SZ];
    word32 oidSz = ASN1_OID_DOTTED_MAX_SZ;
    word32 decodedCount = 0;
    word16 decoded[ASN1_OID_DOTTED_MAX_SZ];

    if (XSTRNCMP(name, "IP", 2) == 0) {
        ipStr = wolfSSL_a2i_IPADDRESS(value);

        if (ipStr != NULL) {
            s = (char *)wolfSSL_ASN1_STRING_data(ipStr);
            sSz = wolfSSL_ASN1_STRING_length(ipStr);
            type = ASN_IP_TYPE;
        }
        else {
            wolfCLU_LogError("bad IP found %s", value);
            return WOLFCLU_FATAL_ERROR;
        }
    }

    else if (XSTRNCMP(name, "DNS", 3) == 0) {
        type = ASN_DNS_TYPE;
        s = (char *)value;
        sSz = (int)XSTRLEN(value);
    }

    else if (XSTRNCMP(name, "URI", 3) == 0) {
        type = ASN_URI_TYPE;
        s = (char *)value;
        sSz = (int)XSTRLEN(value);
    }

    else if (XSTRNCMP(name, "RID", 3) == 0) {
        if ((ridObj = wolfSSL_OBJ_txt2obj(value, 0)) == NULL) {
#if defined(HAVE_OID_ENCODING) && !defined(NO_WC_ENCODE_OBJECT_ID)
            /* If RID value is not named OID, manually encode
             * dotted OID into byte array. Tokenize a copy so the
             * original value stays intact for error messages. */
            int ridLen = (int)XSTRLEN(value);
            char *ridDup =
                (char *)XMALLOC(ridLen + 1, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (ridDup == NULL) {
                wolfCLU_LogError("Failed to allocate memory for RID");
                return MEMORY_E;
            }
            XMEMCPY(ridDup, value, ridLen + 1);

            token = XSTRTOK(ridDup, ".", &ptr);

            while (token != NULL) {
                char *digit;
                int n;

                if (decodedCount >= ASN1_OID_DOTTED_MAX_SZ) {
                    wolfCLU_LogError("RID has too many components "
                                     "(max %d): %s",
                                     ASN1_OID_DOTTED_MAX_SZ, value);
                    ret = WOLFCLU_FATAL_ERROR;
                    break;
                }
                /* require decimal-digits-only token so that things
                 * like "1a" or "abc" are rejected instead of being
                 * silently coerced by XATOI */
                for (digit = token; *digit != '\0'; digit++) {
                    if (*digit < '0' || *digit > '9') {
                        wolfCLU_LogError("Non-numeric RID "
                                         "component '%s' in: %s",
                                         token, value);
                        ret = WOLFCLU_FATAL_ERROR;
                        break;
                    }
                }
                if (ret != WOLFCLU_SUCCESS) {
                    break;
                }
                n = XATOI(token);
                if (n < 0 || n > 0xFFFF) {
                    wolfCLU_LogError("RID component out of range "
                                     "[0, 65535]: %s",
                                     token);
                    ret = WOLFCLU_FATAL_ERROR;
                    break;
                }
                decoded[decodedCount] = (word16)n;
                decodedCount++;
                token = XSTRTOK(NULL, ".", &ptr);
            }

            XFREE(ridDup, NULL, DYNAMIC_TYPE_TMP_BUFFER);

            if (ret != WOLFCLU_SUCCESS) {
                return ret;
            }

            if (wc_EncodeObjectId(decoded, decodedCount, oid, &oidSz) == 0) {
                s = (char *)oid;
                sSz = (int)oidSz;
            }
            else {
                wolfCLU_LogError("bad RID found %s", value);
                return WOLFCLU_FATAL_ERROR;
            }
#else
            (void)token;
            (void)ptr;
            (void)decoded;
            (void)decodedCount;
            (void)oid;
            (void)oidSz;

            wolfCLU_LogError("Couldn't encode RID. OID encoding is not"
                             " compiled in");
            return WOLFCLU_FATAL_ERROR;

#endif
        }
        else {
            s = (char *)wolfSSL_OBJ_get0_data(ridObj);
            sSz = (int)wolfSSL_OBJ_length(ridObj);
        }


        type = ASN_RID_TYPE;
    }

    else if (XSTRNCMP(name, "email", 5) == 0) {
        type = ASN_RFC822_TYPE;
        s = (char *)value;
        sSz = (int)XSTRLEN(value);
    }

    else {
        wolfCLU_LogError("unsupported alt name type %s", name);
        return WOLFCLU_FATAL_ERROR;
    }

    if (wolfSSL_X509_add_altname_ex(x509, s, sSz, type) != WOLFSSL_SUCCESS) {
        wolfCLU_LogError("error adding alt name %s", value);
        ret = WOLFCLU_FATAL_ERROR;
    }

    if (ipStr != NULL)
        wolfSSL_ASN1_STRING_free(ipStr);

    if (ridObj != NULL)
        wolfSSL_ASN1_OBJECT_free(ridObj);

    return ret;
}
#endif /* WOLFSSL_ALT_NAMES */

/* return WOLFCLU_SUCCESS on success, searches for IP's and DNS's */
static int wolfCLU_setAltNames(WOLFSSL_X509 *x509, WOLFSSL_CONF *conf,
                               char *sect)
{
    WOLFSSL_STACK *altNames;
    int i, ret = WOLFCLU_SUCCESS;

    if (sect == NULL) {
        return WOLFCLU_SUCCESS; /* none set */
    }

#ifndef WOLFSSL_ALT_NAMES
    (void)x509;
    (void)conf;
    (void)altNames;
    (void)i;

    /* the config named an alt name section, so fail rather than silently
     * emitting a cert without those names */
    wolfCLU_LogError(
        "wolfSSL not compiled with alt name support "
        "(WOLFSSL_ALT_NAMES); cannot apply requested subjectAltName "
        "section \"%s\"",
        sect);
    ret = NOT_COMPILED_IN;
#else
    altNames = wolfSSL_NCONF_get_section(conf, sect);
    if (altNames != NULL) {
        int total;

        total = wolfSSL_sk_CONF_VALUE_num(altNames);
        for (i = 0; i < total; i++) {
            WOLFSSL_CONF_VALUE *c;

            c = wolfSSL_sk_CONF_VALUE_value(altNames, i);
            if (c == NULL) {
                WOLFCLU_LOG(WOLFCLU_L0, "Unexpected null value found in alt "
                                        "names stack");
                ret = WOLFCLU_FATAL_ERROR;
                break;
            }

            ret = wolfCLU_addAltName(x509, c->name, c->value);
            if (ret != WOLFCLU_SUCCESS) {
                break;
            }
        }
    }
    else {
        wolfCLU_LogError("Section %s was not found", sect);
        ret = WOLFCLU_FATAL_ERROR;
    }
#endif

    return ret;
}

#ifdef WOLFSSL_ALT_NAMES
/* Apply an inline subjectAltName list to x509, e.g.
 * "DNS:example.com,IP:10.0.0.1". Leading whitespace per entry is skipped.
 * Buffer is tokenized in place, so callers pass a writable string. Returns
 * WOLFCLU_SUCCESS, or WOLFCLU_FATAL_ERROR on a malformed entry so a bad SAN is
 * never silently ignored. */
static int wolfCLU_setInlineSubjectAltNames(WOLFSSL_X509 *x509, char *val)
{
    int ret = WOLFCLU_SUCCESS;
    int sawName = 0;
    char *token;
    char *ptr = NULL;

    if (x509 == NULL || val == NULL) {
        return WOLFCLU_FATAL_ERROR;
    }

    token = XSTRTOK(val, ",", &ptr);
    while (token != NULL) {
        char *colon;
        char *value;
        size_t len;

        /* trim whitespace around entries and trailing whitespace */
        while (*token == ' ' || *token == '\t' || *token == '\r' ||
               *token == '\n') {
            token++;
        }
        len = XSTRLEN(token);
        while (len > 0 && (token[len - 1] == ' ' || token[len - 1] == '\t' ||
                           token[len - 1] == '\r' || token[len - 1] == '\n')) {
            token[--len] = '\0';
        }
        /* "critical" is a flag, not a name, and the caller has already acted
         * on it. Skipped here so it is position independent, matching the
         * other extension parsers. */
        if (XSTRCMP(token, "critical") == 0) {
            token = XSTRTOK(NULL, ",", &ptr);
            continue;
        }

        colon = XSTRSTR(token, ":");
        if (colon == NULL) {
            wolfCLU_LogError("bad subjectAltName entry \"%s\", expected "
                             "TYPE:value",
                             token);
            ret = WOLFCLU_FATAL_ERROR;
            break;
        }
        *colon = '\0';
        /* The trailing-whitespace trim above already NUL-terminated the token
         * at the correct boundary, so value needs no second trailing trim. */
        /* drop whitespace between the colon and the value */
        value = colon + 1;
        while (*value == ' ' || *value == '\t' || *value == '\r' ||
               *value == '\n') {
            value++;
        }

        /* Check for empty type or value after trimming */
        if (XSTRLEN(token) == 0) {
            wolfCLU_LogError("bad subjectAltName entry: empty type prefix");
            ret = WOLFCLU_FATAL_ERROR;
            break;
        }
        if (XSTRLEN(value) == 0) {
            wolfCLU_LogError(
                "bad subjectAltName entry: empty value for type \"%s\"", token);
            ret = WOLFCLU_FATAL_ERROR;
            break;
        }

        ret = wolfCLU_addAltName(x509, token, value);
        if (ret != WOLFCLU_SUCCESS) {
            break;
        }
        sawName = 1;
        token = XSTRTOK(NULL, ",", &ptr);
    }

    /* The value was empty or held only "critical". Reported rather than
     * dropped, matching every sibling parser in this file. */
    if (ret == WOLFCLU_SUCCESS && !sawName) {
        wolfCLU_LogError("no subjectAltName value found, expected TYPE:value");
        ret = WOLFCLU_FATAL_ERROR;
    }

    return ret;
}
#endif /* WOLFSSL_ALT_NAMES */

/* Hand 'val' to wolfCLU_parseExtension() as the extension 'nid'. The value is
 * copied first: the extension parsers tokenize (and upper case) in place, and
 * the string returned by wolfSSL_NCONF_get_string() belongs to the
 * WOLFSSL_CONF. 'key' only names the value in the out of memory message.
 * return WOLFCLU_SUCCESS on success */
static int wolfCLU_setExtensionFromValue(WOLFSSL_X509 *x509, const char *val,
                                         const char *key, int nid,
                                         WOLFSSL_X509 *issuer)
{
    char *dup;
    int len;
    int ret;

    len = (int)XSTRLEN(val);
    dup = (char *)XMALLOC(len + 1, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (dup == NULL) {
        wolfCLU_LogError("out of memory duplicating %s value", key);
        return MEMORY_E;
    }
    XMEMCPY(dup, val, len + 1);

    ret = wolfCLU_parseExtension(x509, dup, nid, issuer);
    XFREE(dup, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}

/* Look 'key' up in the config section and apply its value as extension 'nid'.
 * A key that is not present in the section is not an error.
 * return WOLFCLU_SUCCESS on success */
static int wolfCLU_setExtensionFromConf(WOLFSSL_X509 *x509, WOLFSSL_CONF *conf,
                                        char *sect, const char *key, int nid,
                                        WOLFSSL_X509 *issuer)
{
    char *current;

    current = wolfSSL_NCONF_get_string(conf, sect, key);
    if (current == NULL) {
        return WOLFCLU_SUCCESS; /* not set in this section */
    }

    return wolfCLU_setExtensionFromValue(x509, current, key, nid, issuer);
}

/* return WOLFCLU_SUCCESS on success */
int wolfCLU_setExtensions(WOLFSSL_X509 *x509, WOLFSSL_CONF *conf, char *sect,
                          WOLFSSL_X509 *issuer)
{
    char *current;
    int ret = WOLFCLU_SUCCESS;

    if (sect == NULL) {
        return WOLFCLU_SUCCESS; /* none set */
    }

    ret = wolfCLU_setExtensionFromConf(x509, conf, sect, "basicConstraints",
                                       NID_basic_constraints, issuer);

    if (ret == WOLFCLU_SUCCESS) {
        ret = wolfCLU_setExtensionFromConf(x509, conf, sect,
                                           "subjectKeyIdentifier",
                                           NID_subject_key_identifier, issuer);
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = wolfCLU_setExtensionFromConf(
            x509, conf, sect, "authorityKeyIdentifier",
            NID_authority_key_identifier, issuer);
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = wolfCLU_setExtensionFromConf(x509, conf, sect, "keyUsage",
                                           NID_key_usage, issuer);
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = wolfCLU_setExtensionFromConf(x509, conf, sect, "extendedKeyUsage",
                                           NID_ext_key_usage, issuer);
    }

    if (ret == WOLFCLU_SUCCESS) {
        /* looked up here rather than through wolfCLU_setExtensionFromConf()
         * because the "@section" form needs the conf handle to resolve the
         * section, which wolfCLU_parseExtension() does not have */
        current = wolfSSL_NCONF_get_string(conf, sect, "subjectAltName");
        if (current != NULL && current[0] == '@') {
            ret = wolfCLU_setAltNames(x509, conf, current + 1);
        }
        else if (current != NULL) {
            ret = wolfCLU_setExtensionFromValue(x509, current,
                    "subjectAltName", NID_subject_alt_name, issuer);
        }
    }

    return ret;
}

/* the extension names -addext accepts, and the nid each one routes to */
typedef struct WOLFCLU_ADDEXT_MAP {
    const char *name;
    int nid;
} WOLFCLU_ADDEXT_MAP;

static const WOLFCLU_ADDEXT_MAP wolfCLU_addExtMap[] = {
    { "basicConstraints", NID_basic_constraints },
    { "subjectKeyIdentifier", NID_subject_key_identifier },
    { "authorityKeyIdentifier", NID_authority_key_identifier },
    { "subjectAltName", NID_subject_alt_name },
    { "issuerAltName", NID_issuer_alt_name },
    { "keyUsage", NID_key_usage },
    { "extendedKeyUsage", NID_ext_key_usage },
    { "nameConstraints", NID_name_constraints },
    { "policyConstraints", NID_policy_constraints },
    { "policyMappings", NID_policy_mappings },
    { "inhibitAnyPolicy", NID_inhibit_any_policy }
};

/* parse a command line "-addext name=value" and apply it to x509, i.e.
 * "subjectAltName=DNS:example.com,IP:10.0.0.1".
 * return WOLFCLU_SUCCESS on success */
int wolfCLU_parseAddExt(WOLFSSL_X509 *x509, char *addExt)
{
    int ret;
    int len;
    int nameSz;
    int nid = 0;
    size_t i;
    char *dup;
    char *name;
    char *value;

    if (x509 == NULL || addExt == NULL) {
        return BAD_FUNC_ARG;
    }

    value = XSTRSTR(addExt, "="); /* find value */
    if (value == NULL) {
        wolfCLU_LogError("-addext expects \"name=value\", got %s", addExt);
        return WOLFCLU_FATAL_ERROR;
    }

    /* work on a writable copy, the extension parsers tokenize in place and
     * the original argv string should be left alone */
    len = (int)XSTRLEN(addExt);
    dup = (char *)XMALLOC(len + 1, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (dup == NULL) {
        return MEMORY_E;
    }
    XMEMCPY(dup, addExt, len + 1);

    /* Split the copy at the '=' and trim the name, so that the spacing
     * OpenSSL's conf parser tolerates -- "keyUsage = digitalSignature" -- is
     * accepted here too. Comparing whole names also keeps a longer name that
     * starts with a shorter one, i.e. "keyUsagePeriod", from matching. */
    nameSz = (int)(value - addExt);
    dup[nameSz] = '\0';
    name = wolfCLU_trimToken(dup);
    value = dup + nameSz + 1;

    for (i = 0; i < sizeof(wolfCLU_addExtMap) / sizeof(wolfCLU_addExtMap[0]);
         i++) {
        if (XSTRCMP(name, wolfCLU_addExtMap[i].name) == 0) {
            nid = wolfCLU_addExtMap[i].nid;
            break;
        }
    }

    if (nid == 0) {
        wolfCLU_LogError("unsupported -addext extension \"%s\"", name);
        ret = WOLFCLU_FATAL_ERROR;
    }
    else {
        ret = wolfCLU_parseExtension(x509, value, nid, NULL);
    }

    XFREE(dup, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}

#else
int wolfCLU_setExtensions(WOLFSSL_X509 *x509, WOLFSSL_CONF *conf, char *sect,
                          WOLFSSL_X509 *issuer)
{
    (void)x509;
    (void)conf;
    (void)issuer;

    /* No extension section requested, so not having WOLFSSL_CERT_EXT
     * can be ignored. (Coupled with `ret = ` in wolfCLU_readConfig) */
    if (sect == NULL) {
        return WOLFCLU_SUCCESS;
    }

    /* If not compiled with WOLFSSL_CERT_EXT, fail so certs can be built as
     * intended by user. */
    wolfCLU_LogError(
        "wolfSSL not compiled with cert extensions "
        "(WOLFSSL_CERT_EXT); cannot apply requested x509_extensions "
        "section \"%s\"",
        sect);
    return NOT_COMPILED_IN;
}

int wolfCLU_parseAddExt(WOLFSSL_X509 *x509, char *addExt)
{
    (void)x509;
    (void)addExt;

    wolfCLU_LogError("wolfSSL not compiled with cert extensions");
    return NOT_COMPILED_IN;
}
#endif /* WOLFSSL_CERT_EXT */

#define MAX_DIST_NAME 80
#define DEFAULT_STR_SZ 9
#define MIN_MAX_STR_SZ 5

static int CheckDisName(WOLFSSL_CONF *conf, char *sect, WOLFSSL_X509_NAME *name,
                        const char *str, int nid, int strType, int noPrompt)
{
    int ret = WOLFCLU_SUCCESS;
    long mn = 0;
    long mx = 0;
    FILE *fout = stdout;
    FILE *fin = stdin; /* defaulting to stdin but using a fd variable to make it
                        * easy for expanding to other inputs */
    char *curnt = NULL;
    char *deflt = NULL;
    char *in = NULL;
    size_t inSz;
    int lineRet;

    char *deflt_str = NULL;
    char *mn_str = NULL;
    char *mx_str = NULL;

    if (noPrompt) {
        curnt = wolfSSL_NCONF_get_string(conf, sect, str);
        if (curnt != NULL) {
            wolfCLU_AddNameEntry(name, strType, nid, curnt);
        }
        return ret;
    }

    inSz = (int)XSTRLEN(str);
    deflt_str =
        (char *)XMALLOC(inSz + DEFAULT_STR_SZ, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (deflt_str == NULL) {
        ret = WOLFCLU_FATAL_ERROR;
    }
    else {
        XMEMSET(deflt_str, 0, inSz + DEFAULT_STR_SZ);
        XSTRNCPY(deflt_str, str, inSz);
        XSTRNCAT(deflt_str, "_default", inSz + DEFAULT_STR_SZ);
    }

    mn_str =
        (char *)XMALLOC(inSz + MIN_MAX_STR_SZ, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (mn_str == NULL) {
        ret = WOLFCLU_FATAL_ERROR;
    }
    else {
        XMEMSET(mn_str, 0, inSz + MIN_MAX_STR_SZ);
        XSTRNCPY(mn_str, str, inSz);
        XSTRNCAT(mn_str, "_min", inSz + MIN_MAX_STR_SZ);
    }

    mx_str =
        (char *)XMALLOC(inSz + MIN_MAX_STR_SZ, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (mx_str == NULL) {
        ret = WOLFCLU_FATAL_ERROR;
    }
    else {
        XMEMSET(mx_str, 0, inSz + MIN_MAX_STR_SZ);
        XSTRNCPY(mx_str, str, inSz);
        XSTRNCAT(mx_str, "_max", inSz + MIN_MAX_STR_SZ);
    }

    if (ret == WOLFCLU_SUCCESS) {
        curnt = wolfSSL_NCONF_get_string(conf, sect, str);
        if (curnt != NULL) {
            deflt = wolfSSL_NCONF_get_string(conf, sect, deflt_str);
            fprintf(fout, "%s [%s] : ", curnt, (deflt) ? deflt : "");

            lineRet = wolfCLU_getline(&in, &inSz, fin);
            if (lineRet == WOLFCLU_FATAL_ERROR) {
                ret = WOLFCLU_FATAL_ERROR;
            }
            else {
                if (lineRet > 0) {
                    deflt = in;
                }

                if (deflt && XSTRCMP(deflt, ".") != 0) {
                    if (wolfSSL_NCONF_get_number(conf, sect, mx_str, &mx) ==
                            WOLFSSL_SUCCESS &&
                        (long)XSTRLEN(deflt) > mx) {
                        WOLFCLU_LOG(WOLFCLU_E0,
                                    "Name %s is larger than max %ld", deflt,
                                    mx);
                        ret = WOLFCLU_FATAL_ERROR;
                    }

                    if (wolfSSL_NCONF_get_number(conf, sect, mn_str, &mn) ==
                            WOLFSSL_SUCCESS &&
                        (long)XSTRLEN(deflt) < mn) {
                        WOLFCLU_LOG(WOLFCLU_E0,
                                    "Name %s is smaller than min %ld", deflt,
                                    mn);
                        ret = WOLFCLU_FATAL_ERROR;
                    }

                    if (ret == WOLFCLU_SUCCESS) {
                        wolfCLU_AddNameEntry(name, strType, nid, deflt);
                    }
                }
            }
            XFREE(in, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            in = NULL;
        }
    }

    XFREE(deflt_str, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(mn_str, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(mx_str, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

/* extracts the distinguished names from the conf file and puts them into
 * the x509
 * returns WOLFCLU_SUCCESS on success */
static int wolfCLU_setDisNames(WOLFSSL_X509 *x509, WOLFSSL_CONF *conf,
                               char *sect, int noPrompt)
{
    int i;
    int ret = WOLFCLU_SUCCESS;
    char buf[MAX_DIST_NAME];
    WOLFSSL_X509_NAME *name;
    FILE *fout = stdout;

    if (sect == NULL) {
        return WOLFCLU_SUCCESS; /* none set */
    }

    name = wolfSSL_X509_NAME_new();
    if (name == NULL) {
        return WOLFCLU_FATAL_ERROR;
    }

    fprintf(fout, "Enter '.' will result in the field being "
                  "skipped.\nExamples of inputs are provided as [*]\n");

    ret = CheckDisName(conf, sect, name, "countryName", NID_countryName,
                       CTC_PRINTABLE, noPrompt);
    if (ret == WOLFCLU_SUCCESS) {
        ret = CheckDisName(conf, sect, name, "stateOrProvinceName",
                           NID_stateOrProvinceName, CTC_UTF8, noPrompt);
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = CheckDisName(conf, sect, name, "localityName", NID_localityName,
                           CTC_UTF8, noPrompt);
    }


    /* check for additional organization names, keep going while successfully
     * finding an entry */
    if (ret == WOLFCLU_SUCCESS) {
        ret = CheckDisName(conf, sect, name, "organizationName",
                           NID_organizationName, CTC_UTF8, noPrompt);
    }

    if (ret == WOLFCLU_SUCCESS) {
        for (i = 0; i < 10; i++) {
            XSNPRINTF(buf, sizeof(buf), "%d.organizationName", i);
            ret = CheckDisName(conf, sect, name, buf, NID_organizationName,
                               CTC_UTF8, noPrompt);
            if (ret != WOLFCLU_SUCCESS) {
                break;
            }
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = CheckDisName(conf, sect, name, "organizationalUnitName",
                           NID_organizationalUnitName, CTC_UTF8, noPrompt);
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = CheckDisName(conf, sect, name, "commonName", NID_commonName,
                           CTC_UTF8, noPrompt);
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = CheckDisName(conf, sect, name, "CN", NID_commonName, CTC_UTF8,
                           noPrompt);
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = CheckDisName(conf, sect, name, "emailAddress", NID_emailAddress,
                           CTC_UTF8, noPrompt);
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = CheckDisName(conf, sect, name, "name", NID_name, CTC_UTF8,
                           noPrompt);
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = CheckDisName(conf, sect, name, "surname", NID_surname, CTC_UTF8,
                           noPrompt);
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = CheckDisName(conf, sect, name, "initials", NID_initials, CTC_UTF8,
                           noPrompt);
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = CheckDisName(conf, sect, name, "givenName", NID_givenName,
                           CTC_UTF8, noPrompt);
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = CheckDisName(conf, sect, name, "dnQualifier", NID_dnQualifier,
                           CTC_UTF8, noPrompt);
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = wolfSSL_X509_REQ_set_subject_name(x509, name);
    }

    wolfSSL_X509_NAME_free(name);
    return ret;
}

/* Make a new WOLFSSL_X509 based off of the config file read */
int wolfCLU_readConfig(WOLFSSL_X509 *x509, char *config, char *sect, char *ext)
{
    int ret = WOLFCLU_SUCCESS;
    WOLFSSL_CONF *conf = NULL;
    long line = 0;
    long defaultBits = 0;
    char *defaultKey = NULL;
    int noPrompt = 0;
    char *curnt;

    conf = wolfSSL_NCONF_new(NULL);
    wolfSSL_NCONF_load(conf, config, &line);

    /* check if no prompting */
    curnt = wolfSSL_NCONF_get_string(conf, sect, "prompt");
    if (curnt != NULL && XSTRSTR(curnt, "no")) {
        noPrompt = 1;
    }

    wolfSSL_NCONF_get_number(conf, sect, "default_bits", &defaultBits);
    defaultKey = wolfSSL_NCONF_get_string(conf, sect, "default_keyfile");

    wolfCLU_setAttributes(x509, conf,
                          wolfSSL_NCONF_get_string(conf, sect, "attributes"));
    if (ext == NULL) {
        /* Note: we capture this return code because the !WOLFSSL_CERT_EXT stub
         * of wolfCLU_setExtensions gracefully returns SUCCESS when the string
         * is NULL, but fails loudly if an extension section IS requested and
         * WOLFSSL_CERT_EXT is disabled. These two behaviors are coupled. */
        ret = wolfCLU_setExtensions(
            x509, conf, wolfSSL_NCONF_get_string(conf, sect, "x509_extensions"),
            NULL);
    }
    else {
        /* extension was specifically set, error out if not found */
        if (wolfSSL_NCONF_get_section(conf, ext) == NULL) {
            wolfCLU_LogError("Unable to find certificate extension "
                             "section %s",
                             ext);
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            ret = wolfCLU_setExtensions(x509, conf, ext, NULL);
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = wolfCLU_setDisNames(
            x509, conf,
            wolfSSL_NCONF_get_string(conf, sect, "distinguished_name"),
            noPrompt);
    }

    (void)defaultKey;
    wolfSSL_NCONF_free(conf);
    return ret;
}

int wolfCLU_GetTypeFromPKEY(WOLFSSL_EVP_PKEY *key)
{
    int keyType = 0;

    switch (wolfSSL_EVP_PKEY_base_id(key)) {
        case EVP_PKEY_RSA:
            keyType = RSAk;
            break;

        case EVP_PKEY_DSA:
            keyType = DSAk;
            break;

        case EVP_PKEY_EC:
            keyType = ECDSAk;
            break;

        case EVP_PKEY_DH:
            keyType = DHk;
            break;
    }
    return keyType;
}

#endif /* !WOLFCLU_NO_FILESYSTEM */
