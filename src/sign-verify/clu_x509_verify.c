/* clu_x509_verify.c
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
#include <wolfclu/sign-verify/clu_verify.h>
#include <wolfclu/x509/clu_cert.h>
#include <wolfssl/wolfcrypt/types.h>

#ifndef WOLFCLU_NO_FILESYSTEM

#define CA_BUNDLE_MAX_SZ   (10L * 1024 * 1024) /* 10 MB limit for CA bundle */
#define PEM_FOOTER_PREFIX  "-----END "

static const struct option verify_options[] = {
    {"-CAfile",        required_argument, 0, WOLFCLU_CAFILE        },
    {"-untrusted",     required_argument, 0, WOLFCLU_INTERMEDIATE  },
    {"-crl_check",     no_argument,       0, WOLFCLU_CHECK_CRL     },
    {"-partial_chain", no_argument,       0, WOLFCLU_PARTIAL_CHAIN },
    {"-legacy_ca",     no_argument,       0, WOLFCLU_LEGACY_CA     },
    {"-inform",        required_argument, 0, WOLFCLU_INFORM        },
    {"-help",          no_argument,       0, WOLFCLU_HELP          },
    {"-h",             no_argument,       0, WOLFCLU_HELP          },

    {0, 0, 0, 0} /* terminal element */
};


static void wolfCLU_x509VerifyHelp(void)
{
    WOLFCLU_LOG(WOLFCLU_L0, "./wolfssl verify -CAfile <ca file name> "
            "[-untrusted <intermidate file>] [-crl_check] "
            "[-partial_chain] [-legacy_ca] [-inform pem|der] "
            "<cert to verify>");

    WOLFCLU_LOG(WOLFCLU_L0, "Note: Current support only allows for loading "
            "1 cert as -untrusted");
    WOLFCLU_LOG(WOLFCLU_L0, "Note: -inform is accepted for compatibility "
            "and ignored; input format is auto-detected");
    WOLFCLU_LOG(WOLFCLU_L0, "Note: -legacy_ca trusts a self-signed CA "
            "bundle cert with no basicConstraints extension as a root "
            "(pre-RFC 5280 certs); -partial_chain implies this too");
}

/* Returns 1 if cert is a self-signed root, 0 otherwise (or on hard error,
 * with *hardErr set to a non-WOLFCLU_SUCCESS code). */
static int cert_is_self_signed_root(WOLFSSL_X509* cert, int* hardErr)
{
    WOLFSSL_X509_NAME* subj = wolfSSL_X509_get_subject_name(cert);
    WOLFSSL_X509_NAME* issu = wolfSSL_X509_get_issuer_name(cert);

    *hardErr = WOLFCLU_SUCCESS;

    if (subj == NULL || issu == NULL ||
            wolfSSL_X509_NAME_cmp(subj, issu) != 0) {
        return 0;
    }

    {
        WOLFSSL_EVP_PKEY* pubKey = wolfSSL_X509_get_pubkey(cert);
        int isRoot;
        if (pubKey == NULL) {
            *hardErr = WOLFCLU_FATAL_ERROR;
            return 0;
        }
        isRoot = (wolfSSL_X509_verify(cert, pubKey) == 1);
        wolfSSL_EVP_PKEY_free(pubKey);
        return isRoot;
    }
}

/* Returns 1 if cert should be skipped as a non-CA trust anchor/issuer, 0 if
 * it's acceptable to add to the CA bundle's trust store. allowLegacy opts
 * into trusting a self-signed cert with no basicConstraints extension at
 * all (pre-RFC 5280). outHardErr is updated on hard error. */
static int should_skip_non_ca_cert(WOLFSSL_X509* cert, int allowLegacy,
                                   int* outHardErr)
{
    if (wolfSSL_X509_get_isCA(cert) == 1) {
        return 0;
    }
    if (wolfSSL_X509_ext_isSet_by_NID(cert, NID_basic_constraints)) {
        wolfCLU_Log(WOLFCLU_L0, "Skipping CA bundle cert that explicitly "
                "asserts basicConstraints CA:FALSE");
        return 1;
    }
    if (allowLegacy) {
        int hardErr = WOLFCLU_SUCCESS;
        int isRoot = cert_is_self_signed_root(cert, &hardErr);
        if (outHardErr != NULL && hardErr != WOLFCLU_SUCCESS) {
            *outHardErr = hardErr;
        }
        if (isRoot) {
            wolfCLU_Log(WOLFCLU_L0, "Warning: CA bundle cert has no "
                    "basicConstraints extension (pre-dates RFC 5280); "
                    "treating self-signed legacy root as a CA");
            return 0;
        }
        wolfCLU_Log(WOLFCLU_L0, "Skipping CA bundle cert with no "
                "basicConstraints extension that is not a self-signed "
                "root");
        return 1;
    }
    wolfCLU_Log(WOLFCLU_L0, "Skipping CA bundle cert with no basicConstraints "
            "extension; pass -legacy_ca (or -partial_chain) to trust a "
            "legacy (pre-RFC 5280) CA cert without it");
    return 1;
}

enum pem_block_type {
    PEM_BLOCK_NONE = 0,
    PEM_BLOCK_CERT,
    PEM_BLOCK_TRUSTED_CERT,
    PEM_BLOCK_CRL
};

#define PEM_HEADER_PREFIX "-----BEGIN "

/* Finds the earliest recognized PEM block header at or after curr.
 * Returns PEM_BLOCK_NONE (with *start untouched) if none remain.
 *
 * Searches once per header for the generic "-----BEGIN " prefix and
 * classifies the fixed-length text that follows, rather than running an
 * independent XSTRSTR for each of the 3 recognized block types: on a
 * bundle containing only one block type, the other 2 searches would
 * otherwise scan from curr to the buffer's end on every iteration,
 * making the whole scan O(n^2) for a bundle of many small blocks. */
static enum pem_block_type find_next_pem_block(char* curr, char** start)
{
    while (curr != NULL) {
        char* hdr = XSTRSTR(curr, PEM_HEADER_PREFIX);
        char* tail;

        if (hdr == NULL) {
            return PEM_BLOCK_NONE;
        }
        tail = hdr + (sizeof(PEM_HEADER_PREFIX) - 1);

        if (XSTRNCMP(tail, "CERTIFICATE-----",
                sizeof("CERTIFICATE-----") - 1) == 0) {
            *start = hdr;
            return PEM_BLOCK_CERT;
        }
        if (XSTRNCMP(tail, "TRUSTED CERTIFICATE-----",
                sizeof("TRUSTED CERTIFICATE-----") - 1) == 0) {
            *start = hdr;
            return PEM_BLOCK_TRUSTED_CERT;
        }
        if (XSTRNCMP(tail, "X509 CRL-----",
                sizeof("X509 CRL-----") - 1) == 0) {
            *start = hdr;
            return PEM_BLOCK_CRL;
        }

        /* Unrecognized header (e.g. a private key block); keep scanning
         * past it so the next call doesn't re-match the same "-----BEGIN ". */
        curr = tail;
    }
    return PEM_BLOCK_NONE;
}

static WOLFSSL_X509* load_cert_from_file(const char* filename) {
    WOLFSSL_BIO*  bio = NULL;
    WOLFSSL_X509* cert = NULL;

    /* Try PEM format first */
    bio = wolfSSL_BIO_new_file(filename, "r");
    if (bio) {
        cert = wolfSSL_PEM_read_bio_X509(bio, NULL, NULL, NULL);
        wolfSSL_BIO_free(bio);
    }

    /* Try DER if PEM was unsuccessful */
    if (!cert) {
        bio = wolfSSL_BIO_new_file(filename, "rb");
        if (bio) {
            cert = wolfSSL_d2i_X509_bio(bio, NULL);
            wolfSSL_BIO_free(bio);
        }
    }

    return cert;
}
#endif /* !WOLFCLU_NO_FILESYSTEM */

int wolfCLU_x509Verify(int argc, char** argv)
{
#ifndef WOLFCLU_NO_FILESYSTEM
    int ret    = WOLFCLU_SUCCESS;
    int crlCheck     = 0;
    int partialChain = 0;
    int legacyCa     = 0;
    int longIndex    = 1;
    int option;
    char* caCert     = NULL;
    char* verifyCert = NULL;
    char* intermCert = NULL;
    WOLFSSL_X509_STORE*  store = NULL;
    WOLFSSL_X509_STORE_CTX* ctx = NULL;
    WOLFSSL_X509* cert = NULL;
    WOLFSSL_X509* intermediate = NULL;
    STACK_OF(WOLFSSL_X509)* intermStack = NULL;
    int loaded = 0;
    int anyBlock = 0;
    int foundRoot = 0;
    int hardErr = WOLFCLU_SUCCESS;
    int rootErr = WOLFCLU_SUCCESS;
    WOLFSSL_X509* caX509 = NULL;

    /* last parameter is the certificate to verify */
    if (XSTRNCMP("-h", argv[argc-1], 2) == 0) {
        wolfCLU_x509VerifyHelp();
        return WOLFCLU_SUCCESS;
    }
    else {
        verifyCert = argv[argc-1];
        if (verifyCert == NULL) {
            wolfCLU_LogError("Unable to open certificate file %s",
                             argv[argc-1]);
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        WOLFCLU_LOG(WOLFCLU_L0, "verifying certificate file %s", verifyCert);

        opterr = 0; /* do not display unrecognized options */
        optind = 0; /* start at indent 0 */
        while ((option = wolfCLU_GetOpt(argc, argv,
                        "", verify_options, &longIndex )) != END_OF_ARGS) {
            switch (option) {
                case ARG_FOUND_TWICE:
                    wolfCLU_LogError("Found duplicate argument");
                    ret = WOLFCLU_FATAL_ERROR;
                    break;

                case WOLFCLU_CHECK_CRL:
                #ifndef HAVE_CRL
                    wolfCLU_LogError("recompile wolfSSL with CRL");
                    ret = WOLFCLU_FATAL_ERROR;
                #endif
                    crlCheck = 1;
                    break;

                case WOLFCLU_CAFILE:
                    WOLFCLU_LOG(WOLFCLU_L0, "using CA file %s", optarg);
                    caCert = optarg;
                    if (caCert == verifyCert) {
                        wolfCLU_LogError("Malformed argument: last argument "
                                "\"%s\" must not be a flag arg", verifyCert);
                        ret = WOLFCLU_FATAL_ERROR;
                    }
                    break;

                case WOLFCLU_INTERMEDIATE:
                    intermCert = optarg;
                    if (intermCert == verifyCert) {
                        wolfCLU_LogError("Malformed argument: last argument "
                                "\"%s\" must not be a flag arg", verifyCert);
                        ret = WOLFCLU_FATAL_ERROR;
                    }
                    break;

                case WOLFCLU_PARTIAL_CHAIN:
                    partialChain = 1;
                    break;

                case WOLFCLU_LEGACY_CA:
                    legacyCa = 1;
                    break;

                case WOLFCLU_INFORM:
                    /* Format is auto-detected; -inform is a compat no-op. */
                    if (optarg != NULL) {
                        wolfCLU_convertToLower(optarg, (int)XSTRLEN(optarg));
                        if (XSTRNCMP(optarg, "pem", 4) != 0) {
                            WOLFCLU_LOG(WOLFCLU_L0,
                                    "Warning: -inform %s is ignored; "
                                    "verify auto-detects PEM then DER", optarg);
                        }
                    }
                    break;

                case WOLFCLU_HELP:
                    wolfCLU_x509VerifyHelp();
                    return WOLFCLU_SUCCESS;

                case ':':
                case '?':
                    break;

                default:
                    /* do nothing. */
                    (void)ret;
            }
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        cert = load_cert_from_file(verifyCert);
        if (cert == NULL) {
            wolfCLU_LogError("Failed to load cert: %s\n", verifyCert);
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS && intermCert != NULL) {
        intermediate = load_cert_from_file(intermCert);
        if (intermediate == NULL) {
            wolfCLU_LogError("Failed to load cert: %s\n", intermCert);
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        store = wolfSSL_X509_STORE_new();
        if (store == NULL) {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* Require -CAfile to contain a self-signed root CA unless -partial_chain. */
    if (ret == WOLFCLU_SUCCESS && caCert != NULL) {
        if (!partialChain && wolfCLU_PathsRefEqual(caCert, verifyCert)) {
            wolfCLU_LogError("Cannot verify a certificate against itself "
                    "as a CA without -partial_chain");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS && caCert != NULL) {
        byte* pemBuf = NULL;
        int pemSz = 0;
        long maxSz = CA_BUNDLE_MAX_SZ;
        loaded = 0;

        wolfSSL_ERR_clear_error();
        if (wolfCLU_ReadFileToBuffer(caCert, maxSz, &pemBuf, &pemSz) != WOLFCLU_SUCCESS) {
            wolfCLU_LogError("Failed to open or read CA file %s", caCert);
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            char* pem = (char*)pemBuf;
            long sz = (long)pemSz;

            if (ret == WOLFCLU_SUCCESS && pem != NULL) {
                char* curr = pem;

                while (curr != NULL && curr < pem + sz &&
                        ret == WOLFCLU_SUCCESS) {
                    char* best = NULL;
                    char* footer;
                    enum pem_block_type type = find_next_pem_block(curr,
                            &best);

                    if (type == PEM_BLOCK_NONE) {
                        break;
                    }
                    anyBlock = 1;

                    if (type == PEM_BLOCK_CERT || type == PEM_BLOCK_TRUSTED_CERT) {
                        long remain = pem + sz - best;
                        WOLFSSL_BIO* memBio = wolfSSL_BIO_new_mem_buf(best,
                                (remain > (long)INT_MAX) ? INT_MAX : (int)remain);
                        if (memBio) {
                            /* TRUSTED CERTIFICATE blocks carry trailing
                             * trust attributes after the DER; only the
                             * _AUX reader understands that footer format. */
                            caX509 = (type == PEM_BLOCK_TRUSTED_CERT) ?
                                wolfSSL_PEM_read_bio_X509_AUX(memBio, NULL, NULL, NULL) :
                                wolfSSL_PEM_read_bio_X509(memBio, NULL, NULL, NULL);
                            if (caX509 != NULL) {
                                int skipCert = 0;
                                /* Counts certs found in the file (to decide
                                 * whether to fall back to a DER parse
                                 * below), not certs added to the trust
                                 * store. */
                                loaded++;
                                if (!partialChain) {
                                    hardErr = WOLFCLU_SUCCESS;
                                    if (should_skip_non_ca_cert(caX509,
                                                legacyCa, &hardErr)) {
                                        skipCert = 1;
                                    }
                                    if (hardErr != WOLFCLU_SUCCESS && rootErr == WOLFCLU_SUCCESS) {
                                        rootErr = hardErr;
                                    }
                                }
                                if (!skipCert && !partialChain && !foundRoot) {
                                    if (cert_is_self_signed_root(caX509, &hardErr)) {
                                        foundRoot = 1;
                                    }
                                    if (hardErr != WOLFCLU_SUCCESS && rootErr == WOLFCLU_SUCCESS) {
                                        rootErr = hardErr;
                                    }
                                }
                                if (!skipCert && wolfSSL_X509_STORE_add_cert(store, caX509) != WOLFSSL_SUCCESS) {
                                    wolfCLU_LogError("Failed to add CA cert to trust store");
                                    ret = WOLFCLU_FATAL_ERROR;
                                }
                                wolfSSL_X509_free(caX509);
                            } else {
                                wolfCLU_LogError("CA bundle contains corrupt or truncated certificate; aborting verification");
                                ret = WOLFCLU_FATAL_ERROR;
                            }
                            wolfSSL_BIO_free(memBio);
                        } else {
                            wolfCLU_LogError("Failed to allocate memory BIO for CA certificate");
                            ret = WOLFCLU_FATAL_ERROR;
                        }
                    }
                    else { /* PEM_BLOCK_CRL */
#ifdef HAVE_CRL
                        if (crlCheck) {
                            long remain = pem + sz - best;
                            WOLFSSL_BIO* memBio = wolfSSL_BIO_new_mem_buf(best,
                                    (remain > (long)INT_MAX) ? INT_MAX : (int)remain);
                            if (memBio) {
                                WOLFSSL_X509_CRL* crl = wolfSSL_PEM_read_bio_X509_CRL(memBio, NULL, NULL, NULL);
                                if (crl != NULL) {
                                    if (wolfSSL_X509_STORE_add_crl(store, crl) != WOLFSSL_SUCCESS) {
                                        wolfCLU_LogError("Failed to add CRL to trust store");
                                        ret = WOLFCLU_FATAL_ERROR;
                                    }
                                    wolfSSL_X509_CRL_free(crl);
                                } else {
                                    wolfCLU_LogError("CRL data in CA file is corrupt or truncated; aborting verification");
                                    ret = WOLFCLU_FATAL_ERROR;
                                }
                                wolfSSL_BIO_free(memBio);
                            } else {
                                wolfCLU_LogError("Failed to allocate memory BIO for CRL");
                                ret = WOLFCLU_FATAL_ERROR;
                            }
                        }
#endif /* HAVE_CRL */
                    }

                    footer = XSTRSTR(best, PEM_FOOTER_PREFIX);
                    curr = footer ? footer + (sizeof(PEM_FOOTER_PREFIX) - 1)
                                  : pem + sz;
                }
            }
            /* Fall back to a raw DER parse only if the file had no
             * recognized PEM blocks at all (cert or CRL). A bundle that
             * has CRL blocks but no certificate is a distinct, reportable
             * error below rather than a DER file. Reuse the already
             * size-capped pemBuf instead of re-reading caCert from disk,
             * which would bypass the CA_BUNDLE_MAX_SZ limit enforced by
             * wolfCLU_ReadFileToBuffer above. */
            if (ret == WOLFCLU_SUCCESS && !anyBlock) {
                const byte* derBuf = pemBuf;
                caX509 = wolfSSL_d2i_X509(NULL, &derBuf, pemSz);
                if (caX509 == NULL) {
                    wolfCLU_LogError("Failed to load CA file %s", caCert);
                    ret = WOLFCLU_FATAL_ERROR;
                }
                /* Same CA:TRUE requirement as the PEM bundle path above. */
                if (ret == WOLFCLU_SUCCESS && !partialChain) {
                    hardErr = WOLFCLU_SUCCESS;
                    if (should_skip_non_ca_cert(caX509, legacyCa, &hardErr)) {
                        wolfCLU_LogError("CA file does not assert "
                                         "basicConstraints CA:TRUE");
                        ret = WOLFCLU_FATAL_ERROR;
                    }
                    if (hardErr != WOLFCLU_SUCCESS && rootErr == WOLFCLU_SUCCESS) {
                        rootErr = hardErr;
                    }
                }
                if (ret == WOLFCLU_SUCCESS && !partialChain && !foundRoot) {
                    if (cert_is_self_signed_root(caX509, &hardErr)) {
                        foundRoot = 1;
                    }
                    /* Single DER cert: latch the first hard error seen. */
                    if (hardErr != WOLFCLU_SUCCESS &&
                            rootErr == WOLFCLU_SUCCESS) {
                        rootErr = hardErr;
                    }
                }
                if (ret == WOLFCLU_SUCCESS &&
                        wolfSSL_X509_STORE_add_cert(store, caX509)
                            != WOLFSSL_SUCCESS) {
                    wolfCLU_LogError("Failed to add CA cert to trust store");
                    ret = WOLFCLU_FATAL_ERROR;
                }
                wolfSSL_X509_free(caX509);
            }
            else if (ret == WOLFCLU_SUCCESS && loaded == 0) {
                wolfCLU_LogError("CA file %s contains no CA certificate "
                                 "(only CRL data found)", caCert);
                ret = WOLFCLU_FATAL_ERROR;
            }

            if (pem) {
                XFREE(pem, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            }
        }
    }



    if (ret == WOLFCLU_SUCCESS && !partialChain && caCert != NULL &&
            !foundRoot) {
        if (rootErr != WOLFCLU_SUCCESS) {
            wolfCLU_LogError("Error while checking CA bundle for a "
                             "self-signed root CA");
            ret = rootErr;
        }
        else {
            wolfCLU_LogError("CA file does not contain a self-signed root CA "
                             "(use -partial_chain to trust an intermediate)");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS && crlCheck) {
        wolfSSL_X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
    }

    if (ret == WOLFCLU_SUCCESS && partialChain) {
        wolfSSL_X509_STORE_set_flags(store, X509_V_FLAG_PARTIAL_CHAIN);
    }

    if (ret == WOLFCLU_SUCCESS && intermCert) {
        intermStack = wolfSSL_sk_X509_new_null();
        if (!intermStack) {
            wolfCLU_LogError("Failed to create untrusted chain stack");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            wolfSSL_sk_X509_push(intermStack, intermediate);
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        ctx = X509_STORE_CTX_new();
        if (!ctx || X509_STORE_CTX_init(ctx, store, cert, intermStack) != 1) {
            wolfCLU_LogError("Failed to initialize verification context");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        if (X509_verify_cert(ctx) == 1) {
            WOLFCLU_LOG(WOLFCLU_L0, "OK");
        } else {
            int err = X509_STORE_CTX_get_error(ctx);
            wolfCLU_LogError("Verification Failed\nErr (%d): %s",
                             err, wolfSSL_ERR_reason_error_string(err));
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    wolfSSL_X509_STORE_CTX_free(ctx);
    wolfSSL_X509_free(cert);
    wolfSSL_X509_free(intermediate);
    wolfSSL_X509_STORE_free(store);
    wolfSSL_sk_X509_free(intermStack);
    return ret;
#else
    (void)argc;
    (void)argv;
    WOLFCLU_LOG(WOLFCLU_E0, "No filesystem support");
    return WOLFCLU_FATAL_ERROR;
#endif /* !WOLFCLU_NO_FILESYSTEM */
}
