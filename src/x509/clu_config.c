/* clu_config.c
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


/* return WOLFCLU_SUCCESS on success */
static int wolfCLU_setAttributes(WOLFSSL_X509* x509, WOLFSSL_CONF* conf,
            char* sect)
{

    (void)x509;
    (void)conf;
    (void)sect;
#if 0
    /*
     * @TODO
     * [ req_attributes ]
     * challengePassword               = A challenge password
     * challengePassword_min           = 4
     * challengePassword_max           = 20
     * unstructuredName                = An optional company name
     */
#endif
    return WOLFCLU_FAILURE;
}


#ifdef WOLFSSL_CERT_EXT
static WOLFSSL_X509_EXTENSION* wolfCLU_parseBasicConstraint(char* str, int crit)
{
    char* word, *end;
    char* deli = (char*)":";
    WOLFSSL_X509_EXTENSION *ext;
    WOLFSSL_ASN1_OBJECT *obj;

    ext = wolfSSL_X509_EXTENSION_new();
    if (ext == NULL || str == NULL)
        return NULL;

    wolfSSL_X509_EXTENSION_set_critical(ext, crit);
    obj = wolfSSL_OBJ_nid2obj(NID_basic_constraints);
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

    for (word = strtok_r(str, deli, &end); word != NULL;
            word = strtok_r(NULL, deli, &end)) {
        if (word != NULL && strncmp(word, "CA", strlen(word)) == 0) {
            word = strtok_r(NULL, deli, &end);
            if (word != NULL && strncmp(word, "TRUE", strlen(word)) == 0) {
                obj->ca = 1;
            }
        }

        if (word != NULL && strncmp(word, "pathlen", strlen(word)) == 0) {
            word = strtok_r(NULL, deli, &end);
            if (word != NULL) {
                if (obj->pathlen != NULL)
                    wolfSSL_ASN1_INTEGER_free(obj->pathlen);
                obj->pathlen = wolfSSL_ASN1_INTEGER_new();
                wolfSSL_ASN1_INTEGER_set(obj->pathlen, XATOI(word));
            }
        }
    }

    return ext;
}


static WOLFSSL_X509_EXTENSION* wolfCLU_parseSubjectKeyID(char* str, int crit,
        WOLFSSL_X509* x509)
{
    Cert cert; /* temporary to use existing subject key id api */
    WOLFSSL_X509_EXTENSION *ext = NULL;
    WOLFSSL_EVP_PKEY *pkey = NULL;
    char* word, *end;
    char* deli = (char*)",";

    if (x509 == NULL || str == NULL)
        return NULL;

    for (word = strtok_r(str, deli, &end); word != NULL;
            word = strtok_r(NULL, deli, &end)) {

        if (strncmp(word, "hash", strlen(word)) == 0) {
            WOLFSSL_ASN1_STRING *data;
            int  keyType;
            void *key = NULL;

            XMEMSET(&cert, 0, sizeof(Cert));
            keyType = wolfSSL_X509_get_pubkey_type(x509);

            pkey = wolfSSL_X509_get_pubkey(x509);
            if (pkey == NULL) {
                WOLFCLU_LOG(WOLFCLU_E0, "no public key set to hash for subject key id");
                return NULL;
            }

            switch (keyType) {
                case RSAk:
                    key = pkey->rsa->internal;
                    keyType = RSA_TYPE;
                    break;

                case ECDSAk:
                    key = pkey->ecc->internal;
                    keyType = ECC_TYPE;
                    break;

                default:
                    WOLFCLU_LOG(WOLFCLU_E0, "key type not yet supported");
            }

            if (wc_SetSubjectKeyIdFromPublicKey_ex(&cert, keyType, key) < 0) {
                WOLFCLU_LOG(WOLFCLU_E0, "error hashing public key");
            }
            else {
                data = wolfSSL_ASN1_STRING_new();
                if (data != NULL) {
                    if (wolfSSL_ASN1_STRING_set(data, cert.skid, cert.skidSz)
                            != WOLFSSL_SUCCESS) {
                        WOLFCLU_LOG(WOLFCLU_E0, "error setting the skid");
                    }
                    else {
                        ext = wolfSSL_X509V3_EXT_i2d(NID_subject_key_identifier,
                                crit, data);
                    }
                    wolfSSL_ASN1_STRING_free(data);
                }
            }
	    wolfSSL_EVP_PKEY_free(pkey);
        }
    }

    return ext;
}


static WOLFSSL_X509_EXTENSION* wolfCLU_parseKeyUsage(char* str, int crit,
        WOLFSSL_X509* x509)
{
    WOLFSSL_ASN1_STRING *data;
    WOLFSSL_X509_EXTENSION *ext = NULL;
    char* word, *end;
    char* deli = (char*)",";
    word16 keyUseFlag = 0;

    if (x509 == NULL || str == NULL)
        return NULL;

    for (word = strtok_r(str, deli, &end); word != NULL;
            word = strtok_r(NULL, deli, &end)) {

        /* remove empty spaces at beginning of word */
        int mxSz = (int)XSTRLEN(word);
        while (word[0] == ' ' && mxSz > 0) {
            word++;
            mxSz--;
        }

        if (strncmp(word, "digitalSignature", XSTRLEN(word)) == 0) {
            keyUseFlag |= KEYUSE_DIGITAL_SIG;
        }

        if (strncmp(word, "nonRepudiation", XSTRLEN(word)) == 0 ||
                strncmp(word, "contentCommitment", XSTRLEN(word)) == 0) {
            keyUseFlag |= KEYUSE_CONTENT_COMMIT;
        }

        if (strncmp(word, "keyEncipherment", XSTRLEN(word)) == 0) {
            keyUseFlag |= KEYUSE_KEY_ENCIPHER;
        }

        if (strncmp(word, "dataEncipherment", XSTRLEN(word)) == 0) {
            keyUseFlag |= KEYUSE_DATA_ENCIPHER;
        }

        if (strncmp(word, "keyAgreement", XSTRLEN(word)) == 0) {
            keyUseFlag |= KEYUSE_KEY_AGREE;
        }

        if (strncmp(word, "keyCertSign", XSTRLEN(word)) == 0) {
            keyUseFlag |= KEYUSE_KEY_CERT_SIGN;
        }

        if (strncmp(word, "cRLSign", XSTRLEN(word)) == 0) {
            keyUseFlag |= KEYUSE_CRL_SIGN;
        }

        if (strncmp(word, "encipherOnly", XSTRLEN(word)) == 0) {
            keyUseFlag |= KEYUSE_ENCIPHER_ONLY;
        }

        if (strncmp(word, "decipherOnly", XSTRLEN(word)) == 0) {
            keyUseFlag |= KEYUSE_DECIPHER_ONLY;
        }
    }

    data = wolfSSL_ASN1_STRING_new();
    if (data != NULL) {
        if (wolfSSL_ASN1_STRING_set(data, (byte*)&keyUseFlag, sizeof(word16))
                        != WOLFSSL_SUCCESS) {
            WOLFCLU_LOG(WOLFCLU_E0, "error setting the key use");
        }
        else {
            ext = wolfSSL_X509V3_EXT_i2d(NID_key_usage, crit, data);
        }
        wolfSSL_ASN1_STRING_free(data);
    }
    return ext;
}


/* return WOLFCLU_SUCCESS on success */
static int wolfCLU_parseExtension(WOLFSSL_X509* x509, char* str, int nid,
        int* idx)
{
    WOLFSSL_X509_EXTENSION *ext = NULL;
    int   ret, crit = 0;

    if (strstr("critical", str) != NULL) {
        crit = 1;
    }
    switch (nid) {
        case NID_basic_constraints:
            ext = wolfCLU_parseBasicConstraint(str, crit);
            break;
        case NID_subject_key_identifier:
            ext = wolfCLU_parseSubjectKeyID(str, crit, x509);
            break;
        case NID_authority_key_identifier:
            /* @TODO */
            break;
        case NID_key_usage:
            ext = wolfCLU_parseKeyUsage(str, crit, x509);
            break;

        default:
            WOLFCLU_LOG(WOLFCLU_L0, "unknown / supported nid %d value for extension",
                    nid);
    }

    if (ext != NULL) {
        ret = wolfSSL_X509_add_ext(x509, ext, -1);
        if (ret != WOLFSSL_SUCCESS) {
            WOLFCLU_LOG(WOLFCLU_E0, "error %d adding extesion", ret);
        }
        *idx = *idx + 1;
        wolfSSL_X509_EXTENSION_free(ext);
    }
    return WOLFCLU_SUCCESS;
}


/* return WOLFCLU_SUCCESS on success, searches for IP's and DNS's */
static int wolfCLU_setAltNames(WOLFSSL_X509* x509, WOLFSSL_CONF* conf,
            char* sect)
{
    char *current;
    int  i;

    if (sect == NULL) {
        return WOLFCLU_SUCCESS; /* none set */
    }

#ifndef WOLFSSL_ALT_NAMES
    WOLFCLU_LOG(WOLFCLU_L0, "Skipping alt names, recompile wolfSSL with WOLFSSL_ALT_NAMES...");
#else

    /* get DNS names */
    i = 1;
    do {
        char name[7];
        snprintf(name, 6, "DNS.%d", i);
        current = wolfSSL_NCONF_get_string(conf, sect, name);
        if (current != NULL) {
            if (wolfSSL_X509_add_altname(x509, current, ASN_DNS_TYPE)
                    != WOLFSSL_SUCCESS) {
                WOLFCLU_LOG(WOLFCLU_E0, "error adding alt name %s", current);
            }
        }
        i++;
    } while(current != NULL);

    /* get IP names */
    i = 1;
    do {
        char name[7];
        snprintf(name, 6, "IP.%d", i);
        current = wolfSSL_NCONF_get_string(conf, sect, name);
        if (current != NULL) {
            /* convert to hex value */
            WOLFSSL_ASN1_STRING *str = wolfSSL_a2i_IPADDRESS(current);

            if (str != NULL) {
                unsigned char *data;
                int dataSz;

                data   = wolfSSL_ASN1_STRING_data(str);
                dataSz = wolfSSL_ASN1_STRING_length(str);

                if (wolfSSL_X509_add_altname_ex(x509, (const char*)data, dataSz,
                            ASN_IP_TYPE) != WOLFSSL_SUCCESS) {
                    WOLFCLU_LOG(WOLFCLU_E0, "error adding ip alt name %s", data);
                }
                wolfSSL_ASN1_STRING_free(str);
            }
            else {
                WOLFCLU_LOG(WOLFCLU_E0, "bad IP found %s", current);
                return WOLFCLU_FATAL_ERROR;
            }
        }
        i++;
    } while(current != NULL);
#endif

    return WOLFCLU_SUCCESS;
}


/* return WOLFCLU_SUCCESS on success */
int wolfCLU_setExtensions(WOLFSSL_X509* x509, WOLFSSL_CONF* conf, char* sect)
{
    char *current;
    int  idx = 1;

    if (sect == NULL) {
        return WOLFCLU_SUCCESS; /* none set */
    }

    current = wolfSSL_NCONF_get_string(conf, sect, "basicConstraints");
    if (current != NULL) {
        wolfCLU_parseExtension(x509, current, NID_basic_constraints, &idx);
    }

    current = wolfSSL_NCONF_get_string(conf, sect, "subjectKeyIdentifier");
    if (current != NULL) {
        wolfCLU_parseExtension(x509, current, NID_subject_key_identifier, &idx);
    }

    current = wolfSSL_NCONF_get_string(conf, sect, "authorityKeyIdentifier");
    if (current != NULL) {
        wolfCLU_parseExtension(x509, current, NID_authority_key_identifier,
                &idx);
    }

    current = wolfSSL_NCONF_get_string(conf, sect, "keyUsage");
    if (current != NULL) {
        wolfCLU_parseExtension(x509, current, NID_key_usage, &idx);
    }

    current = wolfSSL_NCONF_get_string(conf, sect, "subjectAltName");
    if (current != NULL && current[0] == '@') {
        current = current+1;
        wolfCLU_setAltNames(x509, conf, current);
    }
    return WOLFCLU_SUCCESS;
}
#else
static int wolfCLU_setExtensions(WOLFSSL_X509* x509, WOLFSSL_CONF* conf,
            char* sect)
{
    (void)x509;
    (void)conf;
    (void)sect;

    WOLFCLU_LOG(WOLFCLU_E0, "wolfSSL not compiled with cert extensions");
    return NOT_COMPILED_IN;
}
#endif /* WOLFSSL_CERT_EXT */


/* return WOLFCLU_SUCCESS on success, WOLFCLU_FAILURE if unable to find or add
 * the entry */
static int wolfCLU_X509addEntry(WOLFSSL_X509_NAME* name, WOLFSSL_CONF* conf,
        int nid, int type, const char* sect, const char* str)
{
    const unsigned char *current;
    WOLFSSL_X509_NAME_ENTRY *entry;

    current = (const unsigned char*)wolfSSL_NCONF_get_string(conf, sect, str);
    if (current != NULL) {
        entry = wolfSSL_X509_NAME_ENTRY_create_by_NID(NULL, nid,
                type, current, (int)XSTRLEN((const char*)current));
        wolfSSL_X509_NAME_add_entry(name, entry, -1, 0);
        wolfSSL_X509_NAME_ENTRY_free(entry);
        return WOLFCLU_SUCCESS;
    }
    return WOLFCLU_FAILURE;
}

#define MAX_DIST_NAME 80
/* extracts the distinguished names from the conf file and puts them into
 * the x509
 * returns WOLFCLU_SUCCESS on success */
static int wolfCLU_setDisNames(WOLFSSL_X509* x509, WOLFSSL_CONF* conf,
        char* sect)
{
    int  i, ret;
    char buf[MAX_DIST_NAME];
    WOLFSSL_X509_NAME *name;
    long countryName_min = 0;
    long countryName_max = 0;

    if (sect == NULL) {
        return WOLFCLU_SUCCESS; /* none set */
    }

    name = wolfSSL_X509_NAME_new();
    if (name == NULL) {
        return WOLFCLU_FATAL_ERROR;
    }

    wolfCLU_X509addEntry(name, conf, NID_countryName, CTC_PRINTABLE, sect,
            "countryName_default");
    wolfCLU_X509addEntry(name, conf, NID_countryName, CTC_PRINTABLE, sect,
            "countryName");

    wolfSSL_NCONF_get_number(conf, sect, "countryName_min", &countryName_min);
    wolfSSL_NCONF_get_number(conf, sect, "countryName_max", &countryName_max);

    wolfCLU_X509addEntry(name, conf, NID_stateOrProvinceName, CTC_UTF8, sect,
            "stateOrProvinceName_default");
    wolfCLU_X509addEntry(name, conf, NID_stateOrProvinceName, CTC_UTF8, sect,
            "stateOrProvinceName");
    wolfCLU_X509addEntry(name, conf, NID_localityName, CTC_UTF8, sect,
            "localityName_default");
    wolfCLU_X509addEntry(name, conf, NID_localityName, CTC_UTF8, sect,
            "localityName");


    /* check for additional organization names, keep going while successfully
     * finding an entry */
    wolfCLU_X509addEntry(name, conf, NID_organizationName, CTC_UTF8, sect,
            "organizationName_default");
    wolfCLU_X509addEntry(name, conf, NID_organizationName, CTC_UTF8, sect,
            "organizationName");
    i = 0;
    do {
        XSNPRINTF(buf, sizeof(buf), "%d.organizationName", i++);
        ret = wolfCLU_X509addEntry(name, conf, NID_organizationName, CTC_UTF8,
                sect, buf);
    } while (ret == WOLFCLU_SUCCESS);


    wolfCLU_X509addEntry(name, conf, NID_organizationalUnitName, CTC_UTF8, sect,
            "organizationalUnitName_default");
    wolfCLU_X509addEntry(name, conf, NID_organizationalUnitName, CTC_UTF8, sect,
            "organizationalUnitName");
    wolfCLU_X509addEntry(name, conf, NID_commonName, CTC_UTF8, sect,
            "commonName_default");
    wolfCLU_X509addEntry(name, conf, NID_commonName, CTC_UTF8, sect,
            "commonName");
    wolfCLU_X509addEntry(name, conf, NID_commonName, CTC_UTF8, sect,
            "CN");
    wolfCLU_X509addEntry(name, conf, NID_emailAddress, CTC_UTF8, sect,
            "emailAddress_default");
    wolfCLU_X509addEntry(name, conf, NID_emailAddress, CTC_UTF8, sect,
            "emailAddress");

    wolfSSL_X509_REQ_set_subject_name(x509, name);
    wolfSSL_X509_NAME_free(name);
    return WOLFCLU_SUCCESS;
}

/* Make a new WOLFSSL_X509 based off of the config file read */
int wolfCLU_readConfig(WOLFSSL_X509* x509, char* config, char* sect, char* ext)
{
    WOLFSSL_CONF *conf = NULL;
    long line = 0;
    long defaultBits = 0;
    char *defaultKey = NULL;

    conf = wolfSSL_NCONF_new(NULL);
    wolfSSL_NCONF_load(conf, config, &line);

    wolfSSL_NCONF_get_number(conf, sect, "default_bits", &defaultBits);
    defaultKey = wolfSSL_NCONF_get_string(conf, sect, "default_keyfile");

    wolfCLU_setAttributes(x509, conf,
            wolfSSL_NCONF_get_string(conf, sect, "attributes"));
    if (ext == NULL) {
        wolfCLU_setExtensions(x509, conf,
            wolfSSL_NCONF_get_string(conf, sect, "x509_extensions"));
    }
    else {
        wolfCLU_setExtensions(x509, conf, ext);
    }
    wolfCLU_setDisNames(x509, conf,
            wolfSSL_NCONF_get_string(conf, sect, "distinguished_name"));

    (void)defaultKey;
    wolfSSL_NCONF_free(conf);
    return WOLFCLU_SUCCESS;
}


int wolfCLU_GetTypeFromPKEY(WOLFSSL_EVP_PKEY* key)
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

