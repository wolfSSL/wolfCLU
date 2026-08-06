/* clu_ca_setup.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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
#include <wolfclu/x509/clu_x509_sign.h>
#include <wolfclu/x509/clu_mldsa.h>
#include <wolfclu/certgen/clu_certgen.h>
#include <wolfssl/openssl/evp.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#ifdef WOLFCLU_HAVE_MLDSA
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfclu/sign-verify/clu_sign.h>
#endif /* WOLFCLU_HAVE_MLDSA */

#ifndef WOLFCLU_NO_FILESYSTEM

/*Transfer the ML-DSA or EVP_PKEY CA key into signer. */
static int wolfCLU_CASetupCertSignSetCA(WOLFCLU_CERT_SIGN* signer,
        WOLFSSL_X509* issuer, CLU_KEY_CTX* keyCtx)
{
#if defined(WOLFCLU_HAVE_MLDSA)
    if (keyCtx->key != NULL) {
        int ret = wolfCLU_CertSignSetCA(signer, issuer, (MlDsaKey*)keyCtx->key,
                wolfCLU_MLDSALevelToKeyOid(keyCtx->level));
        if (ret == WOLFCLU_SUCCESS) {
            keyCtx->key = NULL;
        }
        return ret;
    }
#endif

    if (keyCtx->evp != NULL) {
        return wolfCLU_CertSignSetCA(signer, issuer, keyCtx->evp,
                wolfCLU_GetTypeFromPKEY(keyCtx->evp));
    }

    /* -cert without -keyfile: update issuer only */
    return wolfCLU_CertSignSetCA(signer, issuer, NULL, 0);
}

static const struct option ca_options[] = {
    {"-in",        required_argument, 0, WOLFCLU_INFILE    },
    {"-out",       required_argument, 0, WOLFCLU_OUTFILE   },
    {"-keyfile",   required_argument, 0, WOLFCLU_KEY       },
    {"-subjkey",   required_argument, 0, WOLFCLU_SUBJKEY   },
    {"-altkey",    required_argument, 0, WOLFCLU_ALTKEY    },
    {"-altpub",    required_argument, 0, WOLFCLU_ALTPUB    },
    {"-cert",      required_argument, 0, WOLFCLU_CAFILE    },
    {"-extensions",required_argument, 0, WOLFCLU_EXTENSIONS},
    {"-md",        required_argument, 0, WOLFCLU_MD        },
    {"-inform",    required_argument, 0, WOLFCLU_INFORM    },
    {"-outform",   required_argument, 0, WOLFCLU_OUTFORM   },
    {"-config",    required_argument, 0, WOLFCLU_CONFIG },
    {"-days",      required_argument, 0, WOLFCLU_DAYS },
    {"-selfsign",  no_argument, 0, WOLFCLU_SELFSIGN  },
    {"-altextend", no_argument, 0, WOLFCLU_ALTEXTEND },
    {"-h",         no_argument, 0, WOLFCLU_HELP },
    {"-help",      no_argument, 0, WOLFCLU_HELP },

    {0, 0, 0, 0} /* terminal element */
};

static void wolfCLU_CAHelp(void)
{
    WOLFCLU_LOG(WOLFCLU_L0, "./wolfssl ca");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-in CSR file input");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-out file to output to");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-keyfile file to read private key from");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-cert file to read CA from");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-extensions section in config file to parse extensions from");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-md type of hash i.e sha256");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-inform type PEM/DER of CSR input");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-outform type PEM/DER of output");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-config file to read configuration from");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-days number of days for certificate to be valid");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-selfsign sign with key associated with cert");
#if defined(WOLFCLU_HAVE_MLDSA) && defined(WOLFSSL_CERT_GEN) && \
    !defined(WOLFCLU_NO_FILESYSTEM)
    WOLFCLU_LOG(WOLFCLU_L0, "  ML-DSA CA signing (parameter set 2, 3, or 5 is "
            "read");
    WOLFCLU_LOG(WOLFCLU_L0, "  from the key file; there is no -level option on "
            "ca):");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-keyfile ML-DSA private key (<name>.priv) with");
    WOLFCLU_LOG(WOLFCLU_L0,
            "\t        companion <name>.pub (or <stem>Pub.pem);");
    WOLFCLU_LOG(WOLFCLU_L0, "\t        or set [CA_default] private_key in "
            "-config.");
    WOLFCLU_LOG(WOLFCLU_L0, "\t        Signs RSA/ECDSA CSRs; ML-DSA subject "
            "keys");
    WOLFCLU_LOG(WOLFCLU_L0, "\t        are supported when present on the CSR.");
    WOLFCLU_LOG(WOLFCLU_L0, "\t        Verify issued certs with:");
    WOLFCLU_LOG(WOLFCLU_L0, "\t        wolfssl verify -CAfile <ca-cert> "
            "<issued-cert>");
#endif /* WOLFCLU_HAVE_MLDSA && WOLFSSL_CERT_GEN && !WOLFCLU_NO_FILESYSTEM */
#if defined(WOLFSSL_DUAL_ALG_CERTS) && defined(WOLFCLU_HAVE_MLDSA)
    WOLFCLU_LOG(WOLFCLU_L0, "  Chimera (dual-algorithm) options for adding a "
            "post-quantum");
    WOLFCLU_LOG(WOLFCLU_L0, "  ML-DSA/dilithium alternate signature to a "
            "conventional cert:");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-altextend add an alternate (ML-DSA) signature "
            "to the cert");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-altkey file to read the alternate (ML-DSA) "
            "private key from");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-altpub file to read the alternate (ML-DSA) "
            "public key from");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-subjkey file to read subject key from");
#endif /* WOLFSSL_DUAL_ALG_CERTS && WOLFCLU_HAVE_MLDSA */
}
#endif /* !WOLFCLU_NO_FILESYSTEM */

/* return WOLFCLU_SUCCESS on success */
int wolfCLU_CASetup(int argc, char** argv)
{
#ifndef WOLFCLU_NO_FILESYSTEM
    WOLFCLU_CERT_SIGN* signer = NULL;
    WOLFSSL_BIO *subjKey   = NULL;
    WOLFSSL_BIO *altKey    = NULL;
    WOLFSSL_BIO *altKeyPub = NULL;
    WOLFSSL_BIO *reqIn     = NULL;
    WOLFSSL_X509 *x509     = NULL;
    WOLFSSL_X509 *ca       = NULL;
    CLU_KEY_CTX keyCtx;
    int pkeyOwned = 0;   /* set once keyCtx ownership transfers to signer */
    int issuerOwned = 0; /* set once ca/x509 ownership transfers to signer */
    enum wc_HashType hashType = WC_HASH_TYPE_NONE;

    char* keyPath = NULL;

    int   ret = WOLFCLU_SUCCESS;
    char* out = NULL;
    char* config = NULL;
    char* ext = NULL;
    int inForm  = PEM_FORM;
    int outForm = PEM_FORM;
    int option;
    int longIndex = 1;
    int days = 0;
    int selfSigned = 0;
    int altSign = 0;

    opterr = 0; /* do not display unrecognized options */
    optind = 0; /* start at indent 0 */
    XMEMSET(&keyCtx, 0, sizeof(keyCtx));
    while (ret == WOLFCLU_SUCCESS &&
            (option = wolfCLU_GetOpt(argc, argv, "", ca_options,
                    &longIndex)) != END_OF_ARGS) {

        switch (option) {
            case WOLFCLU_INFILE:
                reqIn = wolfSSL_BIO_new_file(optarg, "rb");
                if (reqIn == NULL) {
                    wolfCLU_LogError("Unable to open CSR file %s",
                            optarg);
                    ret = WOLFCLU_FATAL_ERROR;
                }
                break;

            case WOLFCLU_SELFSIGN:
                selfSigned = 1;
                break;

            case WOLFCLU_KEY:
                keyPath = optarg;
                break;
#if defined(WOLFSSL_DUAL_ALG_CERTS) && defined(WOLFCLU_HAVE_MLDSA)
            case WOLFCLU_SUBJKEY:
                subjKey = wolfSSL_BIO_new_file(optarg, "rb");
                if (subjKey == NULL) {
                    wolfCLU_LogError("Unable to open subject key file %s",
                            optarg);
                    ret = WOLFCLU_FATAL_ERROR;
                }
                break;

            case WOLFCLU_ALTKEY:
                altKey = wolfSSL_BIO_new_file(optarg, "rb");
                if (altKey == NULL) {
                    wolfCLU_LogError("Unable to open alternate key file %s",
                            optarg);
                    ret = WOLFCLU_FATAL_ERROR;
                }
                break;

            case WOLFCLU_ALTPUB:
                altKeyPub = wolfSSL_BIO_new_file(optarg, "rb");
                if (altKeyPub == NULL) {
                    wolfCLU_LogError("Unable to open \
                                    alternate public key file %s", optarg);
                    ret = WOLFCLU_FATAL_ERROR;
                }
                break;
#endif /* WOLFSSL_DUAL_ALG_CERTS && WOLFCLU_HAVE_MLDSA */

            case WOLFCLU_ALTEXTEND:
                altSign = 1;
                break;

            case WOLFCLU_CAFILE:
                ca = wolfSSL_X509_load_certificate_file(optarg,
                        WOLFSSL_FILETYPE_PEM);
                if (ca == NULL) {
                    ca = wolfSSL_X509_load_certificate_file(optarg,
                        WOLFSSL_FILETYPE_ASN1);
                }

                if (ca == NULL) {
                    wolfCLU_LogError("Unable to open CA file %s", optarg);
                    ret = WOLFCLU_FATAL_ERROR;
                }
                break;

            case WOLFCLU_MD:
                hashType = wolfCLU_StringToHashType(optarg);
                if (hashType == WC_HASH_TYPE_NONE) {
                    wolfCLU_LogError("Invalid digest name");
                    ret = WOLFCLU_FATAL_ERROR;
                }
                break;

            case WOLFCLU_OUTFILE:
                out = optarg;
                break;

            case WOLFCLU_INFORM:
                inForm = wolfCLU_checkInform(optarg);
                if (inForm < 0) {
                    /*wolfCLU_checkInform signals invalid input with                      USER_INPUT_ERROR (negative), never 0. */
                    wolfCLU_LogError("Invalid input format: %s", optarg);
                    ret = USER_INPUT_ERROR;
                }
                break;

            case WOLFCLU_OUTFORM:
                outForm = wolfCLU_checkOutform(optarg);
                if (outForm < 0) {
                    /*wolfCLU_checkOutform signals an invalid format with                      USER_INPUT_ERROR (negative), never 0. */
                    wolfCLU_LogError("Invalid output format: %s", optarg);
                    ret = USER_INPUT_ERROR;
                }
                break;

            case WOLFCLU_CONFIG:
                config = optarg;
                break;

            case WOLFCLU_DAYS:
                /* #5879: validate -days to prevent RFC 5280 notAfter
                 * overflow. */
                if (wolfCLU_ParseDaysArg(optarg, &days) != WOLFCLU_SUCCESS) {
                    wolfCLU_LogError("-days must be a positive integer "
                            "in [1, %d], got: %s", WOLFCLU_MAX_CERT_DAYS,
                            optarg);
                    ret = USER_INPUT_ERROR;
                }
                break;

            case WOLFCLU_EXTENSIONS:
                ext = optarg;
                break;

            case WOLFCLU_HELP:
                wolfCLU_CAHelp();
                ret = WOLFCLU_SUCCESS;
                goto cleanup;

            case ARG_FOUND_TWICE:
                wolfCLU_LogError("Found duplicate argument");
                ret = WOLFCLU_FATAL_ERROR;
                break;

            case ':':
            case '?':
                wolfCLU_LogError("Unexpected argument");
                ret = WOLFCLU_FATAL_ERROR;
                wolfCLU_CAHelp();
                break;

            default:
                /* do nothing. */
                (void)ret;
        }
    }

    if (ret == WOLFCLU_SUCCESS && reqIn == NULL && !altSign) {
        wolfCLU_LogError("Expecting CSR input");
        ret = WOLFCLU_FATAL_ERROR;
    }

    if (ret == WOLFCLU_SUCCESS && selfSigned && altSign) {
        wolfCLU_LogError("-selfsign and -altextend are mutually exclusive");
        ret = WOLFCLU_FATAL_ERROR;
    }

    if (ret == WOLFCLU_SUCCESS && config != NULL) {
        signer = wolfCLU_readSignConfig(config, (char*)"ca");
    }
    else if (ret == WOLFCLU_SUCCESS) {
        signer = wolfCLU_CertSignNew();
    }
    if (ret == WOLFCLU_SUCCESS && signer == NULL) {
        wolfCLU_LogError("Unable to create a signer struct");
        ret = WOLFCLU_FATAL_ERROR;
    }

    /* override hash type if -md was passed in */
    if (ret == WOLFCLU_SUCCESS && hashType != WC_HASH_TYPE_NONE) {
        wolfCLU_CertSignSetHash(signer, hashType);
    }

    if (ret == WOLFCLU_SUCCESS && keyPath != NULL && altSign == 0) {
        ret = wolfCLU_LoadKey(keyPath, &keyCtx);
        if (ret != WOLFCLU_SUCCESS) {
            ret = USER_INPUT_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS && out != NULL) {
        ret = wolfCLU_CertSignAppendOut(signer, out);
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = wolfCLU_CertSignSetOutForm(signer, outForm);
    }

    if (ret == WOLFCLU_SUCCESS && days > 0) {
        wolfCLU_CertSignSetDate(signer, days);
    }

    if (ret == WOLFCLU_SUCCESS) {
        if (altSign) {
           wolfSSL_PEM_read_bio_X509(reqIn, &x509, NULL, NULL);
        }
        else if (inForm == PEM_FORM) {
            wolfSSL_PEM_read_bio_X509_REQ(reqIn, &x509, NULL, NULL);
        }
        else {
            wolfSSL_d2i_X509_REQ_bio(reqIn, &x509);
        }
        if (x509 == NULL) {
            wolfCLU_LogError("Issue creating structure to use");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

#if defined(WOLFCLU_HAVE_MLDSA)
    if (ret == WOLFCLU_SUCCESS && keyCtx.key != NULL) {
        if (wolfCLU_MLDSALevelToKeyOid(keyCtx.level) == 0) {
            wolfCLU_LogError("Unsupported ML-DSA level %d "
                    "(supported: 2, 3, 5)", keyCtx.level);
            ret = WOLFCLU_FATAL_ERROR;
        }
    }
#endif /* WOLFCLU_HAVE_MLDSA */

    if (ret == WOLFCLU_SUCCESS && (keyCtx.evp != NULL || ca != NULL ||
            altKey != NULL || altKeyPub != NULL
#if defined(WOLFCLU_HAVE_MLDSA)
            || keyCtx.key != NULL
#endif /* WOLFCLU_HAVE_MLDSA */
            )) {
        if (selfSigned) {
            if (keyCtx.evp == NULL &&
#if defined(WOLFCLU_HAVE_MLDSA)
                keyCtx.key == NULL &&
#endif
                    !wolfCLU_CertSignHasKey(signer)) {
                wolfCLU_LogError("No signing key provided");
                ret = WOLFCLU_FATAL_ERROR;
            }
            else {
                ret = wolfCLU_CASetupCertSignSetCA(signer, x509, &keyCtx);
            }
        }
        else if (altSign) {
            char* subjName = wolfSSL_X509_NAME_oneline(
                wolfSSL_X509_get_subject_name(x509), 0, 0);
            if (subjName != NULL) {
                WOLFSSL_BIO* chimeraKey = NULL;
                if (keyPath != NULL) {
                    chimeraKey = wolfSSL_BIO_new_file(keyPath, "rb");
                }
                if (keyPath != NULL && chimeraKey == NULL) {
                    wolfCLU_LogError("Unable to open private key file %s",
                            keyPath);
                    ret = WOLFCLU_FATAL_ERROR;
                }
                else {
                    ret = wolfCLU_GenChimeraCertSign(chimeraKey, altKey,
                        altKeyPub, subjKey, ca, subjName, out, outForm);
                }
                if (chimeraKey != NULL) {
                    wolfSSL_BIO_free(chimeraKey);
                }
                XFREE(subjName, 0, DYNAMIC_TYPE_OPENSSL);
            }
            else {
                ret = MEMORY_E;
            }
        }
        else {
            if (keyCtx.evp == NULL &&
#if defined(WOLFCLU_HAVE_MLDSA)
                keyCtx.key == NULL &&
#endif
                    !wolfCLU_CertSignHasKey(signer)) {
                wolfCLU_LogError("No signing key provided");
                ret = WOLFCLU_FATAL_ERROR;
            }
            else {
                ret = wolfCLU_CASetupCertSignSetCA(signer, ca, &keyCtx);
            }
        }

        /* On success, signer now owns ca and (if set) pkey. */
        if (ret == WOLFCLU_SUCCESS && !altSign) {
            issuerOwned = 1;
            if (keyCtx.evp != NULL) {
                pkeyOwned = 1;
            }
        }
    }

    /* No CLI key/cert flags were given above (the guard on the block just
     * above only fires when at least one of pkey/ca/altKey/altKeyPub/
     * mldsaKey is set), so re-check here whether -config supplied a usable
     * signing key. */
    if (ret == WOLFCLU_SUCCESS && !altSign && !wolfCLU_CertSignHasKey(signer)) {
        wolfCLU_LogError("No signing key provided");
        ret = WOLFCLU_FATAL_ERROR;
    }

    /* default to version 3 which supports extensions */
    if (ret == WOLFCLU_SUCCESS &&
           wolfSSL_X509_set_version(x509, WOLFSSL_X509_V3) != WOLFSSL_SUCCESS &&
           !altSign) {
        wolfCLU_LogError("Unable to set version 3 for cert");
        ret = WOLFCLU_FATAL_ERROR;
    }

    if (ret == WOLFCLU_SUCCESS && ext != NULL && !altSign) {
        wolfCLU_CertSignSetExt(signer, ext);
    }

    if (ret == WOLFCLU_SUCCESS && !altSign) {
        ret = wolfCLU_CertSign(signer, x509);
    }

cleanup:
    wolfSSL_BIO_free(reqIn);
    if (altKey != NULL) {
        wolfSSL_BIO_free(altKey);
    }
    if (altKeyPub != NULL) {
        wolfSSL_BIO_free(altKeyPub);
    }
    if (subjKey != NULL) {
        wolfSSL_BIO_free(subjKey);
    }
    if (selfSigned) {
        /* x509 was the issuer handed to CertSignSetCA; the signer owns it
         * only when that call succeeded, otherwise free it here. */
        if (!issuerOwned) {
            wolfSSL_X509_free(x509);
        }
    }
    else {
        /* x509 is the CSR here, always ours to free */
        wolfSSL_X509_free(x509);
    }

    /*Free ca unless ownership transferred to the signer. */
    if (ca != NULL && (selfSigned || !issuerOwned)) {
        wolfSSL_X509_free(ca);
    }
    /* free keyCtx only when it was not handed off to the signer */
    if (!pkeyOwned) {
        wolfCLU_FreeKeyCtx(&keyCtx);
    }

    /* check for success on signer free since random data is output */
    if (wolfCLU_CertSignFree(signer) != WOLFCLU_SUCCESS) {
        ret = WOLFCLU_FATAL_ERROR;
    }
    return ret;
#else
    (void)argc;
    (void)argv;
    WOLFCLU_LOG(WOLFCLU_E0, "No filesystem support");
    return WOLFCLU_FATAL_ERROR;
#endif /* !WOLFCLU_NO_FILESYSTEM */
}
