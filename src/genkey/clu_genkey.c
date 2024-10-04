/* clu_genkey.c
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

#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/asn_public.h> /* wc_DerToPem */

#if defined(WOLFSSL_KEY_GEN) && !defined(NO_ASN)

#include <wolfclu/clu_header_main.h>
#include <wolfclu/clu_log.h>
#include <wolfclu/genkey/clu_genkey.h>
#include <wolfclu/x509/clu_parse.h>
#include <wolfclu/x509/clu_cert.h>    /* PER_FORM/DER_FORM */

#ifdef HAVE_ED25519
/* return WOLFCLU_SUCCESS on success */
int wolfCLU_genKey_ED25519(WC_RNG* rng, char* fOutNm, int directive, int format)
{
    int ret;                             /* return value */
    int fOutNmSz;                        /* file name without append */
    int fOutNmAppendSz = 6;              /* # of bytes to append to file name */
    int flagOutputPub = 0;               /* set if outputting both priv/pub */
    char privAppend[6] = ".priv\0";      /* last part of the priv file name */
    char pubAppend[6] = ".pub\0\0";      /* last part of the pub file name*/
    byte privKeyBuf[ED25519_KEY_SIZE*2]; /* will hold public & private parts */
    byte pubKeyBuf[ED25519_KEY_SIZE];    /* holds just the public key part */
    word32 privKeySz;                    /* size of private key */
    word32 pubKeySz;                     /* size of public key */
    ed25519_key edKeyOut;                /* the ed25519 key structure */
    char* finalOutFNm = NULL;            /* file name + append */
    XFILE file = NULL;                   /* file stream */
    byte* derBuf = NULL;                 /* buffer for DER format */
    byte* pemBuf = NULL;                 /* buffer for PEM format */
    int derSz;                           /* size of DER buffer */
    int pemSz;                           /* size of PEM buffer */

    /* initialize ed25519 key */
    ret = wc_ed25519_init(&edKeyOut);
    if (ret != 0) {
        wolfCLU_LogError("Failed to initialize ed25519 key.\nRET: %d", ret);
    }

    /* make ed25519 key */
    if (ret == 0) {
        ret = wc_ed25519_make_key(rng, ED25519_KEY_SIZE, &edKeyOut);
        if (ret != 0) {
            wolfCLU_LogError("Failed to make ed25519 key.\nRET: %d", ret);
        }
    }

    if (ret == 0) {
        if (fOutNm == NULL) {
            ret = BAD_FUNC_ARG;
        }
        else {
            WOLFCLU_LOG(WOLFCLU_L0, "fOutNm = %s", fOutNm);
            fOutNmSz = (int)XSTRLEN(fOutNm);
        }
    }

    if (format == RAW_FORM && ret == 0) {
        /* get key size */
        privKeySz = wc_ed25519_priv_size(&edKeyOut);
        if (privKeySz <= 0)
            ret = WC_KEY_SIZE_E;

        pubKeySz = wc_ed25519_pub_size(&edKeyOut);
        if (pubKeySz <= 0)
            ret = WC_KEY_SIZE_E;

        /* export keys to buffers */
        ret = wc_ed25519_export_key(&edKeyOut, privKeyBuf, &privKeySz,
                                    pubKeyBuf, &pubKeySz);
    }

    /* set up the file name output buffer */
    if (ret == 0) {
        finalOutFNm = (char*) XMALLOC( (fOutNmSz + fOutNmAppendSz), HEAP_HINT,
                                                DYNAMIC_TYPE_TMP_BUFFER);
        if (finalOutFNm == NULL) {
            ret = MEMORY_E;
        } else {
            /* get the first part of the file name setup */
            XMEMSET(finalOutFNm, 0, fOutNmSz + fOutNmAppendSz);
            XMEMCPY(finalOutFNm, fOutNm, fOutNmSz);
        }
    }

    if (ret == 0) {
        switch(directive) {
        case PRIV_AND_PUB_FILES:
            flagOutputPub = 1;

            /* fall through to PRIV_ONLY_FILE */
            FALL_THROUGH;
        case PRIV_ONLY_FILE:
            /* add on the final part of the file name ".priv" */
            XMEMCPY(finalOutFNm + fOutNmSz, privAppend, fOutNmAppendSz);
            WOLFCLU_LOG(WOLFCLU_L0, "finalOutFNm = %s", finalOutFNm);

            /* open the file for writing the private key */
            if (ret == 0) {
                file = XFOPEN(finalOutFNm, "wb");
                if (!file) {
                    ret = OUTPUT_FILE_ERROR;
                }
            }

            /* write RAW format to the file */
            if (format == RAW_FORM && ret == 0) {
                if (XFWRITE(privKeyBuf, 1, privKeySz, file) != privKeySz) {
                    ret = OUTPUT_FILE_ERROR;
                }
            }
            else { /* DER and PEM */
                /* determine size for buffer */
                if (ret == 0) {
                    derSz = wc_Ed25519PrivateKeyToDer(&edKeyOut, NULL, 0);
                    if (derSz <= 0) {
                        ret = MEMORY_E;
                    }
                }

                /* allocate DER buffer */
                if (ret == 0) {
                    derBuf = (byte*)XMALLOC(derSz, HEAP_HINT,
                            DYNAMIC_TYPE_TMP_BUFFER);
                    if (derBuf == NULL) {
                        ret = MEMORY_E;
                    }
                }

                /* convert Key to DER */
                if (ret == 0) {
                    derSz = wc_Ed25519PrivateKeyToDer(&edKeyOut, derBuf, derSz);
                    if (derSz < 0) {
                        ret = derSz;
                    }
                }
                if (ret != 0)
                    break;

                /* convert DER to PEM if necessary */
                if (format == PEM_FORM) {
                    if (ret == 0) {
                        pemSz = wolfCLU_KeyDerToPem(derBuf, derSz, &pemBuf,
                                PRIVATEKEY_TYPE, DYNAMIC_TYPE_TMP_BUFFER);
                        if (pemSz < 0) {
                            ret = pemSz;
                        }
                    }
                    /* write PEM format to the file */
                    if (ret == 0) {
                        ret = (int)XFWRITE(pemBuf, 1, pemSz, file);
                        if (ret != pemSz) {
                            ret = OUTPUT_FILE_ERROR;
                        }
                        else {
                            ret = 0;
                        }
                    }
                }
                else {
                    /* write DER format to the file */
                    if (ret == 0) {
                        ret = (int)XFWRITE(derBuf, 1, derSz, file);
                        if (ret != derSz) {
                            ret = OUTPUT_FILE_ERROR;
                        }
                        else {
                            ret = 0;
                        }
                    }
                }
            }
            if (ret != 0) {
                break;
            }
            if (flagOutputPub == 0) {
                break;
            } /* else fall through to PUB_ONLY_FILE if flagOutputPub == 1 */

            XFCLOSE(file);
            file = NULL;
            XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            derBuf = NULL;
            XFREE(pemBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            pemBuf = NULL;

            FALL_THROUGH;
        case PUB_ONLY_FILE:
            /* add on the final part of the file name ".pub" */
            XMEMCPY(finalOutFNm + fOutNmSz, pubAppend, fOutNmAppendSz);
            WOLFCLU_LOG(WOLFCLU_L0, "finalOutFNm = %s", finalOutFNm);

            /* open the file for writing the public key */
            if (ret == 0) {
                file = XFOPEN(finalOutFNm, "wb");
                if (!file) {
                    ret = OUTPUT_FILE_ERROR;
                }
            }

            /* write RAW format to the file */
            if (format == RAW_FORM && ret == 0) {
                if (XFWRITE(pubKeyBuf, 1, pubKeySz, file) != pubKeySz) {
                    ret = OUTPUT_FILE_ERROR;
                }
            }
            else { /* DER and PEM */
                /* determine size for buffer */
                if (ret == 0) {
                    derSz = wc_Ed25519PublicKeyToDer(&edKeyOut, NULL, 0, 1);
                    if (derSz <= 0) {
                        ret = MEMORY_E;
                    }
                }

                /* allocate DER buffer */
                if (ret == 0) {
                    derBuf = (byte*)XMALLOC(derSz, HEAP_HINT,
                            DYNAMIC_TYPE_TMP_BUFFER);
                    if (derBuf == NULL) {
                        ret = MEMORY_E;
                    }
                }

                /* convert Key to DER */
                if (ret == 0) {
                    derSz = wc_Ed25519PublicKeyToDer(&edKeyOut, derBuf, derSz, 1);
                    if (derSz < 0) {
                        ret = derSz;
                    }
                }

                if (ret != 0)
                    break;

                /* convert DER to PEM if necessary */
                if (format == PEM_FORM) {
                    if (ret == 0) {
                        pemSz = wolfCLU_KeyDerToPem(derBuf, derSz, &pemBuf,
                                PUBLICKEY_TYPE, DYNAMIC_TYPE_TMP_BUFFER);
                        if (pemSz < 0) {
                            ret = pemSz;
                        }
                    }
                    /* write PEM format to the file */
                    if (ret == 0) {
                        ret = (int)XFWRITE(pemBuf, 1, pemSz, file);
                        if (ret != pemSz) {
                            ret = OUTPUT_FILE_ERROR;
                        } else {
                            ret = 0;
                        }
                    }
                }
                else {
                    /* write DER format to the file */
                    if (ret == 0) {
                        ret = (int)XFWRITE(derBuf, 1, derSz, file);
                        if (ret != derSz) {
                            ret = OUTPUT_FILE_ERROR;
                        }
                        else {
                            ret = 0;
                        }
                    }
                }
            }

            if (ret != 0) {
                ret = OUTPUT_FILE_ERROR;
            }
            break;
        default:
            wolfCLU_LogError("Invalid directive");
            ret = BAD_FUNC_ARG;
        } /* switch */
    }

    /* cleanup allocated resources */
    if (finalOutFNm != NULL) {
        XFREE(finalOutFNm, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        finalOutFNm = NULL;
    }
    if (derBuf != NULL) {
        XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (pemBuf != NULL) {
        XFREE(pemBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (file != NULL) {
        XFCLOSE(file);
        file = NULL;
    }

    /* expected ret == WOLFCLU_SUCCESS */
    return (ret >= 0) ? WOLFCLU_SUCCESS : ret;
}
#endif /* HAVE_ED25519 */

#ifdef HAVE_ECC
/* returns WOLFCLU_SUCCESS on successfully writing out public DER key */
static int wolfCLU_ECC_write_pub_der(WOLFSSL_BIO* out, WOLFSSL_EC_KEY* key)
{
    int derSz, ret = WOLFCLU_SUCCESS;
    unsigned char *der = NULL;

    if (out == NULL || key == NULL)
        return BAD_FUNC_ARG;

    derSz = wc_EccPublicKeyDerSize(key->internal, 1);
    if (derSz <= 0) {
        wolfCLU_LogError("error getting der size");
        ret = derSz;
    }

    if (ret == WOLFCLU_SUCCESS) {
        der = (byte*)XMALLOC(derSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (der == NULL) {
            ret = MEMORY_E;
        }
        else {
            derSz = wc_EccPublicKeyToDer(key->internal, der, derSz, 1);
            if (derSz < 0) {
                ret = derSz;
            }
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = wolfSSL_BIO_write(out, der, derSz);
        if (ret != derSz) {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (der != NULL)
        XFREE(der, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}


/* returns WOLFCLU_SUCCESS on successfully writing out private DER key */
static int wolfCLU_ECC_write_priv_der(WOLFSSL_BIO* out, WOLFSSL_EC_KEY* key)
{
    int derSz = 0, ret;
    unsigned char *der = NULL;

    if (out == NULL || key == NULL)
        return BAD_FUNC_ARG;

    ret = wc_EccKeyDerSize(key->internal, 0);
    if (ret > 0) {
        derSz = ret;
        der   = (byte*)XMALLOC(derSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (der == NULL) {
            ret = MEMORY_E;
        }
        else {
            ret = wc_EccPrivateKeyToDer(key->internal, der, derSz);
        }
    }

    if (ret > 0) {
        WOLFCLU_LOG(WOLFCLU_L0, "writing out %d bytes for private key", derSz);
        ret = wolfSSL_BIO_write(out, der, derSz);
        if (ret != derSz) {
            ret = WOLFCLU_FATAL_ERROR;
        }
        WOLFCLU_LOG(WOLFCLU_L0, "ret of write = %d", ret);
    }

    if (der != NULL)
        XFREE(der, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

    if (ret > 0)
        ret = WOLFCLU_SUCCESS; /* successfully wrote out key */

    return ret;
}

void wolfCLU_EcparamPrintOID(WOLFSSL_BIO* out, WOLFSSL_EC_KEY* key,
        int fmt)
{
    int ret = WOLFCLU_SUCCESS;
    const WOLFSSL_EC_GROUP* group = NULL;
    char header[] = "-----BEGIN EC PARAMETERS-----\n";
    char footer[] = "-----END EC PARAMETERS-----\n";
    const byte* oid = NULL;
    byte* objOID = NULL;
    word32 objOIDSz = 0;
    word32 oidSz = 0;

    group = wolfSSL_EC_KEY_get0_group(key);
    if (group == NULL) {
        ret = WOLFCLU_FATAL_ERROR;
    }

    if (ret == WOLFCLU_SUCCESS) {
        if (wc_ecc_get_oid(group->curve_oid, &oid, &oidSz) == NOT_COMPILED_IN) {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        objOIDSz = oidSz + 2;
        objOID = (byte*)XMALLOC(oidSz + 2, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (objOID == NULL) {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* set object ID tag and internal oid section */
    if (ret == WOLFCLU_SUCCESS) {
        objOID[0] = ASN_OBJECT_ID;
        objOID[1] = oidSz;
        XMEMCPY(objOID + 2, oid, oidSz);
    }

    if (ret == WOLFCLU_SUCCESS) {
        if (fmt == PEM_FORM) {
            byte*  base64 = NULL;
            word32 base64Sz;

            if (wolfSSL_BIO_write(out, header, (int)XSTRLEN(header)) <= 0) {
                ret = WOLFCLU_FATAL_ERROR;
            }

            if (ret == WOLFCLU_SUCCESS) {
                if (Base64_Encode(objOID, objOIDSz, NULL, &base64Sz) !=
                        LENGTH_ONLY_E) {
                    ret = WOLFCLU_FATAL_ERROR;
                }
            }

            if (ret == WOLFCLU_SUCCESS) {
                base64 = (byte*)XMALLOC(base64Sz, HEAP_HINT,
                        DYNAMIC_TYPE_TMP_BUFFER);
                if (base64 == NULL) {
                    ret = WOLFCLU_FATAL_ERROR;
                }
            }

            if (ret == WOLFCLU_SUCCESS &&
                    Base64_Encode(objOID, objOIDSz, base64, &base64Sz) != 0) {
                ret = WOLFCLU_FATAL_ERROR;
            }

            if (ret == WOLFCLU_SUCCESS &&
                    wolfSSL_BIO_write(out, base64, base64Sz) <= 0) {

                ret = WOLFCLU_FATAL_ERROR;
            }
            XFREE(base64, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

            if (ret == WOLFCLU_SUCCESS &&
                    wolfSSL_BIO_write(out, footer, (int)XSTRLEN(footer)) <= 0) {

                ret = WOLFCLU_FATAL_ERROR;
            }
        }
        else {
            if (wolfSSL_BIO_write(out, objOID, objOIDSz) <= 0) {
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
    }

    if (objOID != NULL) {
        XFREE(objOID, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }
    (void)ret;
}

WOLFSSL_EC_KEY* wolfCLU_GenKeyECC(char* name)
{
    char* lower = NULL;
    int ret = WOLFCLU_SUCCESS;
    int nameSz;
    WOLFSSL_EC_KEY* key = NULL;


    if (name != NULL) {
        nameSz = (int)XSTRLEN(name) + 1;
        lower  = (char*)XMALLOC(nameSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (lower == NULL) {
            ret = MEMORY_E;
        }

    }

    if (name != NULL && ret == WOLFCLU_SUCCESS) {
        XSTRNCPY(lower, name, nameSz);
        wolfCLU_convertToLower(lower, nameSz - 1);
    }

    /* use prime256v1 instead of secp256r1 so that txt2nid can handle it */
    if (name != NULL && ret == WOLFCLU_SUCCESS &&
            XSTRNCMP(lower, "secp256r1", nameSz) == 0) {
        nameSz = (int)XSTRLEN("prime256v1") + 1;
        XFREE(lower, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        lower  = (char*)XMALLOC(nameSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (lower == NULL) {
            ret = MEMORY_E;
        }
        else {
            XSTRNCPY(lower, "prime256v1", nameSz);
        }
    }

    /* use prime192v1 instead of secp192r1 so that txt2nid can handle it */
    if (name != NULL && ret == WOLFCLU_SUCCESS &&
            XSTRNCMP(lower, "secp192r1", nameSz) == 0) {
        nameSz = (int)XSTRLEN("prime192v1") + 1;
        XFREE(lower, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        lower  = (char*)XMALLOC(nameSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (lower == NULL) {
            ret = MEMORY_E;
        }
        else {
            XSTRNCPY(lower, "prime192v1", nameSz);
        }
    }

    /* brainpool needs a capital p before value */
    if (name != NULL && ret == WOLFCLU_SUCCESS &&
            XSTRNCMP(lower, "brainpool", 9) == 0) {
        lower[9] = 'P';
    }

    if (ret == WOLFCLU_SUCCESS) {
        key = wolfSSL_EC_KEY_new();
        if (key != NULL && name != NULL) {
            WOLFSSL_EC_GROUP *group = NULL;
            int nid;

            WOLFCLU_LOG(WOLFCLU_L0, "Setting ECC group with curve %s", lower);
            nid = wolfSSL_OBJ_txt2nid(lower);
            if (nid <= 0) {
                wolfCLU_LogError("Error getting NID value for curve %s",
                        lower);
                ret = WOLFCLU_FATAL_ERROR;
            }

            if (ret == WOLFCLU_SUCCESS) {
                group = wolfSSL_EC_GROUP_new_by_curve_name(
                        wolfSSL_OBJ_txt2nid(lower));
                if (group == NULL) {
                    wolfCLU_LogError("unable to set curve");
                    ret = WOLFCLU_FATAL_ERROR;
                }
            }

            if (ret == WOLFCLU_SUCCESS) {
                if (wolfSSL_EC_KEY_set_group(key, group) != WOLFSSL_SUCCESS) {
                    wolfCLU_LogError("unable to set ec group");
                    ret = WOLFCLU_FATAL_ERROR;
                }
            }
            wolfSSL_EC_GROUP_free(group);
        }
    }

    if (key != NULL && ret == WOLFCLU_SUCCESS) {
        if (wolfSSL_EC_KEY_generate_key(key) != WOLFSSL_SUCCESS) {
            wolfCLU_LogError("error generating EC key");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret != WOLFCLU_SUCCESS) {
        wolfSSL_EC_KEY_free(key);
        key = NULL;
    }

    if (lower != NULL) {
        XFREE(lower, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }

    return key;
}
#endif /* HAVE_ECC */

/* return WOLFCLU_SUCCESS on success */
int wolfCLU_GenAndOutput_ECC(WC_RNG* rng, char* fName, int directive,
        int fmt, char* name)
{
#ifdef HAVE_ECC
    int   fNameSz;
    int   fExtSz      = 6;
    char  fExtPriv[6] = ".priv\0";
    char  fExtPub[6]  = ".pub\0\0";
    char* fOutNameBuf = NULL;

    WOLFSSL_BIO *bioPub = NULL;
    WOLFSSL_BIO *bioPri = NULL;
    WOLFSSL_EC_KEY   *key;
    int ret = WOLFCLU_SUCCESS;

    if (rng == NULL || fName == NULL)
        return BAD_FUNC_ARG;
    fNameSz = (int)XSTRLEN(fName);

    if (name != NULL) {
        if (wc_ecc_get_curve_idx_from_name(name) < 0) {
            wolfCLU_LogError("Bad curve name %s (could be not compiled in)",
                    name);
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    key = wolfCLU_GenKeyECC(name);
    if (key == NULL) {
        ret = WOLFCLU_FATAL_ERROR;
    }

    /* create buffer for alternate file name use */
    if (ret == WOLFCLU_SUCCESS) {
        fOutNameBuf = (char*)XMALLOC(fNameSz + fExtSz + 1, NULL,
                DYNAMIC_TYPE_TMP_BUFFER);
        if (fOutNameBuf == NULL) {
            ret = MEMORY_E;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        switch(directive) {
            case PRIV_AND_PUB_FILES:
                /* Fall through to PRIV_ONLY_FILE */
                FALL_THROUGH;
            case PRIV_ONLY_FILE: /* adding .priv to file name */
                if (ret == WOLFCLU_SUCCESS) {
                    XMEMCPY(fOutNameBuf, fName, fNameSz);
                    XMEMCPY(fOutNameBuf + fNameSz, fExtPriv, fExtSz);
                    fOutNameBuf[fNameSz + fExtSz] = '\0';
                    WOLFCLU_LOG(WOLFCLU_L0, "Private key file = %s", fOutNameBuf);

                    bioPri = wolfSSL_BIO_new_file(fOutNameBuf, "wb");
                    if (bioPri == NULL) {
                        wolfCLU_LogError("unable to read outfile %s",
                                fOutNameBuf);
                        ret = MEMORY_E;
                    }
                }

                if (ret == WOLFCLU_SUCCESS) {
                    if (fmt == PEM_FORM) {
                        if (wolfSSL_PEM_write_bio_ECPrivateKey(bioPri, key,
                                NULL, NULL, 0, NULL, NULL) != WOLFSSL_SUCCESS) {
                            ret = WOLFCLU_FATAL_ERROR;
                        }
                    }
                    else {
                        ret = wolfCLU_ECC_write_priv_der(bioPri, key);
                    }
                }

                if (ret < 0) {
                    break;
                }
                if (directive != PRIV_AND_PUB_FILES) {
                    break;
                }
                FALL_THROUGH;
            case PUB_ONLY_FILE: /* appending .pub to file name */
                if (ret == WOLFCLU_SUCCESS) {
                    XMEMCPY(fOutNameBuf, fName, fNameSz);
                    XMEMCPY(fOutNameBuf + fNameSz, fExtPub, fExtSz);
                    fOutNameBuf[fNameSz + fExtSz] = '\0';
                    WOLFCLU_LOG(WOLFCLU_L0, "Public key file = %s", fOutNameBuf);

                    bioPub = wolfSSL_BIO_new_file(fOutNameBuf, "wb");
                    if (bioPub == NULL) {
                        wolfCLU_LogError("unable to read outfile %s",
                                fOutNameBuf);
                        ret = MEMORY_E;
                    }
                }

                if (ret == WOLFCLU_SUCCESS) {
                    if (fmt == PEM_FORM) {
                        if (wolfSSL_PEM_write_bio_EC_PUBKEY(bioPub, key)
                            != WOLFSSL_SUCCESS) {
                            ret = WOLFCLU_FATAL_ERROR;
                        }
                    }
                    else {
                        ret = wolfCLU_ECC_write_pub_der(bioPub, key);
                    }
                }
                break;
            default:
                wolfCLU_LogError("Invalid directive");
                ret = BAD_FUNC_ARG;
        }
    }

    wolfSSL_EC_KEY_free(key);
    wolfSSL_BIO_free(bioPri);
    wolfSSL_BIO_free(bioPub);

    if (fOutNameBuf != NULL) {
        XFREE(fOutNameBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    if (ret > 0) {
        /* ret > 0 indicates a successful file write, set to zero for return */
        ret = WOLFCLU_SUCCESS;
    }

    return ret;
#else
    (void)rng;
    (void)fName;
    (void)directive;
    (void)fmt;

    return NOT_COMPILED_IN;
#endif /* HAVE_ECC */
}


#if !defined(NO_RSA) || defined(HAVE_ED25519)
/* helper function to convert a key to PEM format. Creates new 'out' buffer on
 * success.
 * returns size of PEM buffer created on success
 * returns 0 or negative value on failure */
int wolfCLU_KeyDerToPem(const byte* der, int derSz, byte** out, int pemType,
        int heapType)
{
    int pemBufSz;
    byte* pemBuf = NULL;

    if (out == NULL || der == NULL || derSz <= 0) {
        return 0;
    }

    pemBufSz = wc_DerToPemEx(der, derSz, NULL, 0, NULL, pemType);
    if (pemBufSz > 0) {
        pemBuf = (byte*)XMALLOC(pemBufSz, HEAP_HINT, heapType);
        if (pemBuf == NULL) {
            pemBufSz = 0;
        }
        else {
            pemBufSz = wc_DerToPemEx(der, derSz, pemBuf, pemBufSz, NULL,
                    pemType);
        }
    }

    if (pemBufSz <= 0 && pemBuf != NULL) {
        XFREE(pemBuf, HEAP_HINT, heapType);
        pemBuf = NULL;
    }
    *out = pemBuf;
    return pemBufSz;
}
#endif /* !NO_RSA || HAVE_ED25519*/


/* return WOLFCLU_SUCCESS on success */
int wolfCLU_genKey_RSA(WC_RNG* rng, char* fName, int directive, int fmt, int
                       keySz, long exp)
{
#ifndef NO_RSA
    RsaKey key;                        /* the RSA key structure */
    XFILE file = NULL;                 /* file stream */
    int   ret = WOLFCLU_SUCCESS;       /* return value */
    int   fNameSz;                     /* file name without append */
    int   fExtSz       = 6;            /* number of bytes to append to file name */
    char  fExtPriv[6]  = ".priv\0";    /* last part of the priv file name */
    char  fExtPub[6]   = ".pub\0\0";   /* last part of the pub file name*/
    char* fOutNameBuf  = NULL;         /* file name + fExt */
    int   flagOutputPub = 0;           /* set if outputting both priv/pub */
    byte* derBuf       = NULL;         /* buffer for DER format */
    byte* pemBuf       = NULL;         /* buffer for PEM format */
    int   derBufSz     = -1;           /* size of DER buffer */
    int   pemBufSz     = 0;            /* size of PEM buffer */

    if (rng == NULL || fName == NULL)
        return BAD_FUNC_ARG;

    WOLFCLU_LOG(WOLFCLU_L0, "fOutNm = %s", fName);
    fNameSz = (int)XSTRLEN(fName);

    /* init RSA key */
    if (wc_InitRsaKey(&key, HEAP_HINT) != 0) {
        return WOLFCLU_FAILURE;
    }

    /* make RSA key */
    if (wc_MakeRsaKey(&key, keySz, exp, rng) != 0) {
        wc_FreeRsaKey(&key);
        return WOLFCLU_FAILURE;
    }

    /* set up the file name output buffer */
    fOutNameBuf = (char*) XMALLOC( (fNameSz + fExtSz), HEAP_HINT,
                                    DYNAMIC_TYPE_TMP_BUFFER);
    if (fOutNameBuf == NULL) {
        wc_FreeRsaKey(&key);
        return MEMORY_E;
    }
    else {
        /* get the first part of the file name setup */
        XMEMSET(fOutNameBuf, 0, fNameSz + fExtSz);
        XMEMCPY(fOutNameBuf, fName, fNameSz);

    }

    if (ret == WOLFCLU_SUCCESS) {
        switch (directive) {
        case PRIV_AND_PUB_FILES:
            flagOutputPub = 1;

            /* Fall through to PRIV_ONLY_FILE */
            FALL_THROUGH;
        case PRIV_ONLY_FILE:
            /* add on the final part of the file name ".priv" */
            XMEMCPY(fOutNameBuf + fNameSz, fExtPriv, fExtSz);
            WOLFCLU_LOG(WOLFCLU_L0, "fOutNameBuf = %s", fOutNameBuf);

            /* open the file for writing the private key */
            if (ret == WOLFCLU_SUCCESS) {
                file = XFOPEN(fOutNameBuf, "wb");
                if (!file) {
                    ret = OUTPUT_FILE_ERROR;
                }
            }

            /* determine size for buffer */
            if (ret == WOLFCLU_SUCCESS) {
                derBufSz = wc_RsaKeyToDer(&key, NULL, 0);
                if (derBufSz < 0) {
                    ret = MEMORY_E;
                }
            }

            /* allocate DER buffer */
            if (ret == WOLFCLU_SUCCESS) {
                derBuf = (byte*)XMALLOC(derBufSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
                if (derBuf == NULL) {
                    ret = MEMORY_E;
                }
            }

            /* convert Key to DER */
            if (ret == WOLFCLU_SUCCESS) {
                derBufSz = wc_RsaKeyToDer(&key, derBuf, derBufSz);
                if (derBufSz < 0) {
                    ret = derBufSz;
                }
            }
            if (ret != WOLFCLU_SUCCESS)
                break;

            /* convert DER to PEM if necessary */
            if (fmt == PEM_FORM) {
                if (ret == WOLFCLU_SUCCESS) {
                    pemBufSz = wolfCLU_KeyDerToPem(derBuf, derBufSz, &pemBuf,
                            PRIVATEKEY_TYPE, DYNAMIC_TYPE_TMP_BUFFER);
                    if (pemBufSz < 0) {
                        ret = pemBufSz;
                    }
                }
                if (ret == WOLFCLU_SUCCESS) {
                    ret = (int)XFWRITE(pemBuf, 1, pemBufSz, file);
                    if (ret != pemBufSz) {
                        ret = OUTPUT_FILE_ERROR;
                    }
                    else {
                        ret = WOLFCLU_SUCCESS;
                    }
                }
            }
            else {
                /* write DER format to the file */
                if (ret == WOLFCLU_SUCCESS) {
                    ret = (int)XFWRITE(derBuf, 1, derBufSz, file);
                    if (ret != derBufSz) {
                        ret = OUTPUT_FILE_ERROR;
                    }
                    else {
                        ret = WOLFCLU_SUCCESS;
                    }
                }
            }
            if (ret != WOLFCLU_SUCCESS) {
                break;
            }
            if (flagOutputPub == 0) {
                break;
            } /* else fall through to PUB_ONLY_FILE if flagOutputPub == 1 */

            XFCLOSE(file);
            file = NULL;
            XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            derBuf = NULL;
            XFREE(pemBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            pemBuf = NULL;

            FALL_THROUGH;
        case PUB_ONLY_FILE:
            /* add on the final part of the file name ".pub" */
            XMEMCPY(fOutNameBuf + fNameSz, fExtPub, fExtSz);
            WOLFCLU_LOG(WOLFCLU_L0, "fOutNameBuf = %s", fOutNameBuf);

            /* open the file for writing the public key */
            if (ret == WOLFCLU_SUCCESS) {
                file = XFOPEN(fOutNameBuf, "wb");
                if (!file) {
                    ret = OUTPUT_FILE_ERROR;
                }
            }

            /* determine size for buffer */
            if (ret == WOLFCLU_SUCCESS) {
                derBufSz = wc_RsaKeyToPublicDer(&key, NULL, 0);
                if (derBufSz < 0) {
                    ret = MEMORY_E;
                }
            }

            /* allocate DER buffer */
            if (ret == WOLFCLU_SUCCESS) {
                derBuf = (byte*)XMALLOC(derBufSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
                if (derBuf == NULL) {
                    ret = MEMORY_E;
                }
            }

            /* convert Key to DER */
            if (ret == WOLFCLU_SUCCESS) {
                derBufSz = wc_RsaKeyToPublicDer(&key, derBuf, derBufSz);
                if (derBufSz < 0) {
                    ret = derBufSz;
                }
            }
            if (ret != WOLFCLU_SUCCESS)
                break;

            /* convert DER to PEM if necessary */
            if (fmt == PEM_FORM) {
                if (ret == WOLFCLU_SUCCESS) {
                    pemBufSz = wolfCLU_KeyDerToPem(derBuf, derBufSz, &pemBuf,
                            PUBLICKEY_TYPE, DYNAMIC_TYPE_TMP_BUFFER);
                    if (pemBufSz < 0) {
                        ret = pemBufSz;
                    }
                }
                if (ret == WOLFCLU_SUCCESS) {
                    ret = (int)XFWRITE(pemBuf, 1, pemBufSz, file);
                    if (ret != pemBufSz) {
                        ret = OUTPUT_FILE_ERROR;
                    }
                    else {
                        ret = WOLFCLU_SUCCESS;
                    }
                }
            }
            else {
                /* write DER format to the file */
                if (ret == WOLFCLU_SUCCESS) {
                    ret = (int)XFWRITE(derBuf, 1, derBufSz, file);
                    if (ret != derBufSz) {
                        ret = OUTPUT_FILE_ERROR;
                    }
                    else {
                        ret = WOLFCLU_SUCCESS;
                    }
                }
            }

            if (ret != WOLFCLU_SUCCESS) {
                ret = OUTPUT_FILE_ERROR;
            }
            break;
        default:
            wolfCLU_LogError("Invalid directive");
            ret = BAD_FUNC_ARG;
        } /* switch */
    }

    /* cleanup allocated resources */
    if (fOutNameBuf != NULL) {
        XFREE(fOutNameBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        fOutNameBuf = NULL;
    }
    if (derBuf != NULL) {
        XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (pemBuf != NULL) {
        XFREE(pemBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }
     if (file != NULL) {
        XFCLOSE(file);
        file = NULL;
    }

    wc_FreeRsaKey(&key);

    return ret;
#else
    (void)rng;
    (void)fName;
    (void)directive;
    (void)fmt;
    (void)keySz;
    (void)exp;

    return NOT_COMPILED_IN;
#endif
}


int wolfCLU_genKey_Dilithium(WC_RNG* rng, char* fName, int directive, int fmt,
                            int keySz, int level, int withAlg, int keyType)
{
#ifdef HAVE_DILITHIUM    
    int    ret = WOLFCLU_SUCCESS;

    XFILE  file;
    int   fNameSz     = 0;
    int   fExtSz      = 6;  // size of ".priv\0" or ".pub\0\0"
    char  fExtPriv[6] = ".priv\0";
    char  fExtPub[6]  = ".pub\0\0";
    char* fOutNameBuf = NULL;

// #ifdef WOLFSSL_SMALL_STACK
//     dilithium_key* key;
// #else
//     dilithium_key key[1];
// #endif

    dilithium_key key;

    #ifdef NO_AES
    /* use 16 bytes for AES block size */
    size_t maxDerBufSz = 4 * keySz * 16;
    #else
    size_t maxDerBufSz = 4 * keySz * AES_BLOCK_SIZE;
    #endif  /* NO_AES */
    byte*  derBuf      = NULL;
    byte*  pemBuf      = NULL;
    byte*  outBuf      = NULL;
    int    derBufSz    = -1;
    int    pemBufSz    = 0;
    int    outBufSz    = 0;

    if (rng == NULL || fName == NULL) {
        return BAD_FUNC_ARG;
    }

    /* initialize the dilithium key */
    if (wc_dilithium_init(&key) != 0) {
        return WOLFCLU_FAILURE;
    }

    /* set the level of the dilithium key */
    if (wc_dilithium_set_level(&key, level) != 0) {
        return WOLFCLU_FAILURE;
    }

    /* make the dilithium key */
    if (wc_dilithium_make_key(&key, rng) != 0) {
        return WOLFCLU_FAILURE;
    }

    /* set up the file name output buffer */
    if (ret == WOLFCLU_SUCCESS) {
        fNameSz     = (int)XSTRLEN(fName);
        fOutNameBuf = (char*)XMALLOC(fNameSz + fExtSz + 1, HEAP_HINT,
                                 DYNAMIC_TYPE_TMP_BUFFER);
        if (fOutNameBuf == NULL)
            ret = MEMORY_E;
    }

    if (ret == WOLFCLU_SUCCESS) {
        XMEMSET(fOutNameBuf, 0, fNameSz + fExtSz);
        XMEMCPY(fOutNameBuf, fName, fNameSz);

        derBuf = (byte*) XMALLOC(maxDerBufSz, HEAP_HINT,
                DYNAMIC_TYPE_TMP_BUFFER);
        if (derBuf == NULL) {
            ret = MEMORY_E;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        switch (directive) {
            case PRIV_AND_PUB_FILES:
                /* Fall through to PRIV_ONLY_FILE */
                FALL_THROUGH;
            case PRIV_ONLY_FILE:
                /* add on the final part of the file name ".priv" */
                XMEMCPY(fOutNameBuf + fNameSz, fExtPriv, fExtSz);
                WOLFCLU_LOG(WOLFCLU_L0, "Private key file = %s", fOutNameBuf);

                /* Private key to der */
                derBufSz = wc_Dilithium_PrivateKeyToDer(&key,
                                        derBuf, (word32)maxDerBufSz);
                if (derBufSz < 0) {
                    ret = derBufSz;
                }
                outBuf   = derBuf;
                outBufSz = derBufSz;

                /* check if should convert to PEM format */
                if (ret == WOLFCLU_SUCCESS && fmt == PEM_FORM) {
                    pemBufSz = wolfCLU_KeyDerToPem(derBuf, derBufSz, &pemBuf,
                            keyType, DYNAMIC_TYPE_PRIVATE_KEY);
                    if (pemBufSz <= 0 || pemBuf == NULL) {
                        ret =  WOLFCLU_FAILURE;
                    }
                    outBuf   = pemBuf;
                    outBufSz = pemBufSz;
                }

                /* open file and write Private key */
                if (ret == WOLFCLU_SUCCESS) {
                    file = XFOPEN(fOutNameBuf, "wb");
                    if (file == XBADFILE) {
                        wolfCLU_LogError("unable to open file %s",
                                        fOutNameBuf);
                        ret = OUTPUT_FILE_ERROR;
                    }
                }
                
                if (ret == WOLFCLU_SUCCESS) {
                    if ((int)XFWRITE(outBuf, 1, outBufSz, file) <= 0) {
                        ret = OUTPUT_FILE_ERROR;
                    }
                }

                XFCLOSE(file);

                if (pemBuf != NULL) {
                    wolfCLU_ForceZero(pemBuf, pemBufSz);
                    XFREE(pemBuf, HEAP_HINT, DYNAMIC_TYPE_PRIVATE_KEY);
                }         

                if (directive != PRIV_AND_PUB_FILES) {
                    break;
                }

                FALL_THROUGH;
            case PUB_ONLY_FILE:
                /* add on the final part of the file name ".priv" */
                XMEMCPY(fOutNameBuf + fNameSz, fExtPub, fExtSz);
                WOLFCLU_LOG(WOLFCLU_L0, "Public key file = %s", fOutNameBuf);

                derBufSz = wc_Dilithium_PublicKeyToDer(&key, derBuf,
                                                (word32)maxDerBufSz, withAlg);
                if (derBufSz < 0) {
                    ret = derBufSz;
                }
                else {
                    outBuf   = derBuf;
                    outBufSz = derBufSz;
                }

                /* check if should convert to PEM format */
                if (ret == WOLFCLU_SUCCESS && fmt == PEM_FORM) {
                    pemBufSz = wolfCLU_KeyDerToPem(derBuf, derBufSz, &pemBuf,
                            PUBLICKEY_TYPE, DYNAMIC_TYPE_PRIVATE_KEY);
                    if (pemBufSz <= 0 || pemBuf == NULL) {
                        ret =  WOLFCLU_FAILURE;
                    }
                    outBuf   = pemBuf;
                    outBufSz = pemBufSz;
                }

                /* open file and write Public key */
                if (ret == WOLFCLU_SUCCESS) {
                    file = XFOPEN(fOutNameBuf, "wb");
                    if (file == XBADFILE) {
                        wolfCLU_LogError("unable to open file %s",
                                        fOutNameBuf);
                        ret = OUTPUT_FILE_ERROR;
                    }
                }
                
                if (ret == WOLFCLU_SUCCESS) {
                    if ((int)XFWRITE(outBuf, 1, outBufSz, file) <= 0) {
                        ret = OUTPUT_FILE_ERROR;
                    }
                }

                XFCLOSE(file);

                if (pemBuf != NULL) {
                    wolfCLU_ForceZero(pemBuf, pemBufSz);
                    XFREE(pemBuf, HEAP_HINT, DYNAMIC_TYPE_PRIVATE_KEY);
                }

                break;
            default:
                wolfCLU_LogError("Invalid directive");
                ret = BAD_FUNC_ARG;
        }
    }

    if (derBuf != NULL) {
        wolfCLU_ForceZero(derBuf, (unsigned int)maxDerBufSz);
        XFREE(derBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }

    if (fOutNameBuf != NULL) {
        XFREE(fOutNameBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }

    wc_dilithium_free(&key);

    return ret;
#else
    (void)rng;
    (void)fName;
    (void)directive;
    (void)fmt;
    (void)level; 
    return NOT_COMPILED_IN;
#endif /* HAVE_DILITHIUM */
}

#endif /* WOLFSSL_KEY_GEN && !NO_ASN*/


/*
 * makes a cyptographically secure key by stretching a user entered pwdKey
 * return WOLFCLU_SUCCESS on success
 */
int wolfCLU_genKey_PWDBASED(WC_RNG* rng, byte* pwdKey, int size, byte* salt,
                            int pad)
{
    int ret;        /* return variable */

    /* randomly generates salt */

    ret = wc_RNG_GenerateBlock(rng, salt, SALT_SIZE-1);
    if (ret != 0)
        return ret;

    /* set first value of salt to let us know
     * if message has padding or not
     */
    if (pad == 0)
        salt[0] = 0;

    /* stretches pwdKey */
    ret = (int) wc_PBKDF2(pwdKey, pwdKey, (int) XSTRLEN((const char*)pwdKey),
                          salt, SALT_SIZE, CLU_4K_TYPE, size, CLU_SHA256);
    if (ret != 0)
        return ret;

    return WOLFCLU_SUCCESS;
}

