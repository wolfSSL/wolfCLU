/* clu_x509_verify.c
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
#include <wolfclu/clu_optargs.h>
#include <wolfclu/sign-verify/clu_verify.h>
#include <wolfclu/x509/clu_cert.h>
#ifdef WOLFCLU_HAVE_MLDSA
#include <wolfclu/x509/clu_mldsa.h>
#endif

#ifndef WOLFCLU_NO_FILESYSTEM

static const struct option verify_options[] = {
    {"-CAfile",        required_argument, 0, WOLFCLU_CAFILE        },
    {"-untrusted",     required_argument, 0, WOLFCLU_INTERMEDIATE  },
    {"-crl_check",     no_argument,       0, WOLFCLU_CHECK_CRL     },
    {"-partial_chain", no_argument,       0, WOLFCLU_PARTIAL_CHAIN },
    {"-inform",        required_argument, 0, WOLFCLU_INFORM        },
    {"-help",          no_argument,       0, WOLFCLU_HELP          },
    {"-h",             no_argument,       0, WOLFCLU_HELP          },

    {0, 0, 0, 0} /* terminal element */
};


static void wolfCLU_x509VerifyHelp(void)
{
    WOLFCLU_LOG(WOLFCLU_L0, "./wolfssl verify -CAfile <ca file name> "
            "[-untrusted <intermidate file>] [-crl_check] "
            "[-partial_chain] <cert to verify>");

    WOLFCLU_LOG(WOLFCLU_L0, "Note: Current support only allows for loading "
            "1 cert as -untrusted");
}
#endif

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

int wolfCLU_x509Verify(int argc, char** argv)
{
#ifndef WOLFCLU_NO_FILESYSTEM
    int ret    = WOLFCLU_SUCCESS;
    int crlCheck     = 0;
    int partialChain = 0;
    int longIndex    = 1;
    int option;
    char* caCert     = NULL;
    char* verifyCert = NULL;
    char* intermCert = NULL;
    WOLFSSL_X509_STORE*  store = NULL;
    WOLFSSL_X509_LOOKUP* lookup = NULL;
    WOLFSSL_X509_STORE_CTX* ctx = NULL;
    WOLFSSL_X509* cert = NULL;
    WOLFSSL_X509* intermediate = NULL;
    STACK_OF(WOLFSSL_X509)* intermStack = NULL;
    int loaded = 0;
    unsigned long queueErr = 0;
    WOLFSSL_BIO* caBio = NULL;
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
        while ((option = wolfCLU_GetOpt(argc - 1, argv, "",
                       verify_options, &longIndex )) != -1) {
            switch (option) {
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
                    break;

                case WOLFCLU_INTERMEDIATE:
                    intermCert = optarg;
                    break;

                case WOLFCLU_PARTIAL_CHAIN:
                    partialChain = 1;
                    break;

                case WOLFCLU_INFORM:
                    /* Format is auto-detected (PEM then DER); -inform is a
                     * compatibility no-op.  Warn when a non-PEM value is
                     * given so the user is not silently surprised. */
                    if (optarg != NULL &&
                            XSTRNCMP(optarg, "pem", 4) != 0 &&
                            XSTRNCMP(optarg, "PEM", 4) != 0) {
                        WOLFCLU_LOG(WOLFCLU_L0,
                                "Warning: -inform %s is ignored; "
                                "verify auto-detects PEM then DER", optarg);
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

    if (ret == WOLFCLU_SUCCESS) {
        lookup = wolfSSL_X509_STORE_add_lookup(store,
                wolfSSL_X509_LOOKUP_file());
        if (lookup == NULL) {
            wolfCLU_LogError("Failed to setup lookup");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* Confirm CA file is root CA unless partialChain enabled.
     * load_cert_from_file reads only the first PEM/DER cert; -CAfile must
     * have the root as its first (or only) cert. Bundles with an intermediate
     * before the root will fail here; use -partial_chain or reorder the file. */
    if (ret == WOLFCLU_SUCCESS && !partialChain && caCert != NULL) {
        WOLFSSL_X509* caTmp = load_cert_from_file(caCert);
        if (caTmp == NULL) {
            wolfCLU_LogError("CA file is not root CA");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            WOLFSSL_X509_NAME* subj = wolfSSL_X509_get_subject_name(caTmp);
            WOLFSSL_X509_NAME* issu = wolfSSL_X509_get_issuer_name(caTmp);
            if (wolfSSL_X509_NAME_cmp(subj, issu) != 0) {
                wolfCLU_LogError("CA file is not root CA");
                ret = WOLFCLU_FATAL_ERROR;
            }
            else {
#ifdef WOLFCLU_HAVE_MLDSA
                int keyType = wolfSSL_X509_get_pubkey_type(caTmp);
                if (wolfCLU_IsMLDSAKeyType(keyType)) {
#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_SMALL_CERT_VERIFY)
                    /* EVP_PKEY has no ML-DSA support yet; use the wolfcrypt
                     * path: parse TBS + sig from cert DER and verify against
                     * the embedded public key. */
                    {
                        const byte* certDer  = NULL;
                        byte*       pubDer   = NULL;
                        int         certDerSz = 0;
                        int         pubDerSz  = 0;

                        certDer = wolfSSL_X509_get_der(caTmp, &certDerSz);
                        if (certDer == NULL || certDerSz <= 0) {
                            wolfCLU_LogError("Failed to get CA cert DER");
                            ret = WOLFCLU_FATAL_ERROR;
                        }
                        if (ret == WOLFCLU_SUCCESS &&
                                wolfSSL_X509_get_pubkey_buffer(caTmp, NULL,
                                    &pubDerSz) != WOLFSSL_SUCCESS) {
                            wolfCLU_LogError("Failed to get CA public key size");
                            ret = WOLFCLU_FATAL_ERROR;
                        }
                        if (ret == WOLFCLU_SUCCESS &&
                                pubDerSz > WOLFCLU_MLDSA_MAX_SPKI_DER_SZ) {
                            wolfCLU_LogError("CA public key size %d exceeds "
                                             "expected maximum", pubDerSz);
                            ret = WOLFCLU_FATAL_ERROR;
                        }
                        if (ret == WOLFCLU_SUCCESS && pubDerSz > 0) {
                            pubDer = (byte*)XMALLOC((size_t)pubDerSz,
                                    HEAP_HINT, DYNAMIC_TYPE_PUBLIC_KEY);
                            if (pubDer == NULL) {
                                ret = MEMORY_E;
                            }
                            else if (wolfSSL_X509_get_pubkey_buffer(caTmp,
                                    pubDer, &pubDerSz) != WOLFSSL_SUCCESS) {
                                wolfCLU_LogError("Failed to get CA public key");
                                ret = WOLFCLU_FATAL_ERROR;
                            }
                        }
                        else if (ret == WOLFCLU_SUCCESS) {
                            wolfCLU_LogError("CA public key buffer has zero size");
                            ret = WOLFCLU_FATAL_ERROR;
                        }
                        if (ret == WOLFCLU_SUCCESS) {
                            int checkRet = wc_CheckCertSigPubKey(certDer,
                                    (word32)certDerSz, HEAP_HINT,
                                    pubDer, (word32)pubDerSz, keyType);
                            if (checkRet != 0) {
                                wolfCLU_LogError("CA file is not root CA "
                                        "(err %d)", checkRet);
                                ret = WOLFCLU_FATAL_ERROR;
                            }
                        }
                        XFREE(pubDer, HEAP_HINT, DYNAMIC_TYPE_PUBLIC_KEY);
                    }
#else
                    wolfCLU_LogError("ML-DSA CA cert self-signature check "
                                     "requires OPENSSL_EXTRA or "
                                     "WOLFSSL_SMALL_CERT_VERIFY");
                    ret = WOLFCLU_FATAL_ERROR;
#endif /* OPENSSL_EXTRA || WOLFSSL_SMALL_CERT_VERIFY */
                }
                else
#endif
                {
                    WOLFSSL_EVP_PKEY* pubKey = wolfSSL_X509_get_pubkey(caTmp);
                    if (pubKey == NULL ||
                            wolfSSL_X509_verify(caTmp, pubKey) != 1) {
                        wolfCLU_LogError("CA file is not root CA");
                        ret = WOLFCLU_FATAL_ERROR;
                    }
                    if (pubKey != NULL) {
                        wolfSSL_EVP_PKEY_free(pubKey);
                    }
                }
            }
            wolfSSL_X509_free(caTmp);
        }
    }

    if (ret == WOLFCLU_SUCCESS && caCert != NULL) {
        caBio = wolfSSL_BIO_new_file(caCert, "r");
        loaded = 0;

        if (caBio == NULL) {
            wolfCLU_LogError("Failed to open CA file %s", caCert);
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            /* wolfSSL_PEM_read_bio_X509 reads only CERTIFICATE blocks.
             * Bundles that begin with a CRL or other non-CERTIFICATE block
             * fall through to the DER fallback and fail. */
            while (ret == WOLFCLU_SUCCESS &&
                   (caX509 = wolfSSL_PEM_read_bio_X509(caBio, NULL,
                                                       NULL, NULL)) != NULL) {
                loaded++;
                /* Intentional: require CA:TRUE for all key types (RSA,
                 * ECDSA, ML-DSA).  Roots without basicConstraints CA:TRUE
                 * are rejected; use -partial_chain to override. */
                if (!partialChain && wolfSSL_X509_get_isCA(caX509) != 1) {
                    wolfCLU_LogError("CA cert does not assert "
                                     "basicConstraints CA:TRUE");
                    ret = WOLFCLU_FATAL_ERROR;
                }
                if (ret == WOLFCLU_SUCCESS &&
                        wolfSSL_X509_STORE_add_cert(store, caX509)
                            != WOLFSSL_SUCCESS) {
                    wolfCLU_LogError("Failed to add CA cert to trust store");
                    ret = WOLFCLU_FATAL_ERROR;
                }
                wolfSSL_X509_free(caX509);
                caX509 = NULL;
            }

            /* Drain the error queue. PEM_R_NO_START_LINE is the normal EOF
             * marker; anything else is genuine bundle corruption. Assumes
             * wolfSSL queues no other reasons on a clean successful read —
             * re-validate if upgrading wolfSSL. When the constant is absent
             * skip discrimination entirely (lenient). */
            {
                int errLimit = 1000;
                while (errLimit-- > 0 && (queueErr = wolfSSL_ERR_get_error()) != 0) {
#ifdef PEM_R_NO_START_LINE
                    if (ret == WOLFCLU_SUCCESS &&
                            wolfSSL_ERR_GET_REASON(queueErr) !=
                                PEM_R_NO_START_LINE) {
                        wolfCLU_LogError("CA bundle is corrupt or truncated "
                                         "after cert %d; aborting verification",
                                         loaded);
                        ret = WOLFCLU_FATAL_ERROR;
                    }
#else
                    /* PEM_R_NO_START_LINE unavailable: cannot distinguish
                     * normal EOF from genuine corruption.  Drain leniently
                     * to avoid false-failing valid bundles on builds without
                     * OpenSSL compatibility layer. */
                    (void)queueErr;
#endif
                }
            }

#ifdef HAVE_CRL
            if (ret == WOLFCLU_SUCCESS && crlCheck) {
                WOLFSSL_X509_CRL* crl = NULL;
                wolfSSL_BIO_free(caBio);
                caBio = wolfSSL_BIO_new_file(caCert, "r");
                if (caBio == NULL) {
                    wolfCLU_LogError(
                        "Failed to reopen CA file for CRL loading");
                    ret = WOLFCLU_FATAL_ERROR;
                }
                else {
                    while (ret == WOLFCLU_SUCCESS &&
                           (crl = wolfSSL_PEM_read_bio_X509_CRL(caBio,
                                    NULL, NULL, NULL)) != NULL) {
                        if (wolfSSL_X509_STORE_add_crl(store, crl)
                                != WOLFSSL_SUCCESS) {
                            wolfCLU_LogError(
                                "Failed to add CRL to trust store");
                            ret = WOLFCLU_FATAL_ERROR;
                        }
                        wolfSSL_X509_CRL_free(crl);
                        crl = NULL;
                    }
                    {
                        int errLimit = 1000;
                        while (errLimit-- > 0 && wolfSSL_ERR_get_error() != 0);
                    }
                }
            }
#endif /* HAVE_CRL */

            wolfSSL_BIO_free(caBio);

            /* fall back to DER if file opened but had no PEM certs. */
            if (ret == WOLFCLU_SUCCESS && loaded == 0) {
                caX509 = load_cert_from_file(caCert);
                if (caX509 == NULL) {
                    wolfCLU_LogError("Failed to load CA file %s", caCert);
                    ret = WOLFCLU_FATAL_ERROR;
                }
                /* Same CA:TRUE requirement as the PEM bundle path above. */
                if (ret == WOLFCLU_SUCCESS && !partialChain &&
                        wolfSSL_X509_get_isCA(caX509) != 1) {
                    wolfCLU_LogError("CA file does not assert "
                                     "basicConstraints CA:TRUE");
                    ret = WOLFCLU_FATAL_ERROR;
                }
                if (ret == WOLFCLU_SUCCESS &&
                        wolfSSL_X509_STORE_add_cert(store, caX509)
                            != WOLFSSL_SUCCESS) {
                    wolfCLU_LogError("Failed to add CA cert to trust store");
                    ret = WOLFCLU_FATAL_ERROR;
                }
                wolfSSL_X509_free(caX509);
            }
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
#endif
}
