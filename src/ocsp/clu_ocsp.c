/* clu_ocsp.c
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
#include <wolfclu/clu_error_codes.h>

#if defined(HAVE_OCSP) && defined(HAVE_OCSP_RESPONDER)

#include <wolfssl/ocsp.h>

enum {
    WOLFCLU_OCSP_HELP = 2100,
    WOLFCLU_OCSP_IGNORE_ERR,
    WOLFCLU_OCSP_CAFILE,
    WOLFCLU_OCSP_CAPATH,
    WOLFCLU_OCSP_CASTORE,
    WOLFCLU_OCSP_NO_CAFILE,
    WOLFCLU_OCSP_NO_CAPATH,
    WOLFCLU_OCSP_NO_CASTORE,
    WOLFCLU_OCSP_TIMEOUT,
    WOLFCLU_OCSP_RESP_NO_CERTS,
    WOLFCLU_OCSP_MULTI,
    WOLFCLU_OCSP_NO_CERTS,
    WOLFCLU_OCSP_BADSIG,
    WOLFCLU_OCSP_CA,
    WOLFCLU_OCSP_NMIN,
    WOLFCLU_OCSP_NREQUEST,
    WOLFCLU_OCSP_REQIN,
    WOLFCLU_OCSP_SIGNER,
    WOLFCLU_OCSP_SIGN_OTHER,
    WOLFCLU_OCSP_INDEX,
    WOLFCLU_OCSP_NDAYS,
    WOLFCLU_OCSP_RSIGNER,
    WOLFCLU_OCSP_RKEY,
    WOLFCLU_OCSP_PASSIN,
    WOLFCLU_OCSP_ROTHER,
    WOLFCLU_OCSP_RMD,
    WOLFCLU_OCSP_RSIGOPT,
    WOLFCLU_OCSP_HEADER,
    WOLFCLU_OCSP_RCID,
    WOLFCLU_OCSP_URL,
    WOLFCLU_OCSP_HOST,
    WOLFCLU_OCSP_PORT,
    WOLFCLU_OCSP_PATH,
    WOLFCLU_OCSP_PROXY,
    WOLFCLU_OCSP_NO_PROXY,
    WOLFCLU_OCSP_OUT,
    WOLFCLU_OCSP_NOVERIFY,
    WOLFCLU_OCSP_NONCE,
    WOLFCLU_OCSP_NO_NONCE,
    WOLFCLU_OCSP_NO_SIGNATURE_VERIFY,
    WOLFCLU_OCSP_RESP_KEY_ID,
    WOLFCLU_OCSP_NO_CERT_VERIFY,
    WOLFCLU_OCSP_TEXT,
    WOLFCLU_OCSP_REQ_TEXT,
    WOLFCLU_OCSP_RESP_TEXT,
    WOLFCLU_OCSP_NO_CHAIN,
    WOLFCLU_OCSP_NO_CERT_CHECKS,
    WOLFCLU_OCSP_NO_EXPLICIT,
    WOLFCLU_OCSP_TRUST_OTHER,
    WOLFCLU_OCSP_NO_INTERN,
    WOLFCLU_OCSP_RESPIN,
    WOLFCLU_OCSP_VAFILE,
    WOLFCLU_OCSP_VERIFY_OTHER,
    WOLFCLU_OCSP_CERT,
    WOLFCLU_OCSP_SERIAL,
    WOLFCLU_OCSP_VALIDITY_PERIOD,
    WOLFCLU_OCSP_SIGNKEY,
    WOLFCLU_OCSP_REQOUT,
    WOLFCLU_OCSP_RESPOUT,
    WOLFCLU_OCSP_ISSUER,
    WOLFCLU_OCSP_STATUS_AGE,
    WOLFCLU_OCSP_POLICY,
    WOLFCLU_OCSP_PURPOSE,
    WOLFCLU_OCSP_VERIFY_NAME,
    WOLFCLU_OCSP_VERIFY_DEPTH,
    WOLFCLU_OCSP_AUTH_LEVEL,
    WOLFCLU_OCSP_ATTIME,
    WOLFCLU_OCSP_VERIFY_HOSTNAME,
    WOLFCLU_OCSP_VERIFY_EMAIL,
    WOLFCLU_OCSP_VERIFY_IP,
    WOLFCLU_OCSP_IGNORE_CRITICAL,
    WOLFCLU_OCSP_ISSUER_CHECKS,
    WOLFCLU_OCSP_CRL_CHECK,
    WOLFCLU_OCSP_CRL_CHECK_ALL,
    WOLFCLU_OCSP_POLICY_CHECK,
    WOLFCLU_OCSP_EXPLICIT_POLICY,
    WOLFCLU_OCSP_INHIBIT_ANY,
    WOLFCLU_OCSP_INHIBIT_MAP,
    WOLFCLU_OCSP_X509_STRICT,
    WOLFCLU_OCSP_EXTENDED_CRL,
    WOLFCLU_OCSP_USE_DELTAS,
    WOLFCLU_OCSP_POLICY_PRINT,
    WOLFCLU_OCSP_CHECK_SS_SIG,
    WOLFCLU_OCSP_TRUSTED_FIRST,
    WOLFCLU_OCSP_SUITEB_128_ONLY,
    WOLFCLU_OCSP_SUITEB_128,
    WOLFCLU_OCSP_SUITEB_192,
    WOLFCLU_OCSP_PARTIAL_CHAIN,
    WOLFCLU_OCSP_NO_ALT_CHAINS,
    WOLFCLU_OCSP_NO_CHECK_TIME,
    WOLFCLU_OCSP_ALLOW_PROXY_CERTS,
    WOLFCLU_OCSP_PROVIDER_PATH,
    WOLFCLU_OCSP_PROVIDER,
    WOLFCLU_OCSP_PROPQUERY,
    WOLFCLU_OCSP_SCGI,
};

typedef struct OcspClientConfig {
    const char* caFile;
    const char* issuer;
    const char* url;
    const char* cert;
    int         noNonce;
} OcspClientConfig;

typedef struct OcspResponderConfig {
    word16      port;
    const char* indexFile;
    const char* caFile;
    const char* rsignerFile;
    const char* rkeyFile;
    int         nrequest;
    int         scgiMode;
} OcspResponderConfig;

static const struct option ocsp_options[] = {
    /* General options */
    {"-help",                 no_argument,       0, WOLFCLU_OCSP_HELP              },
    {"-ignore_err",           no_argument,       0, WOLFCLU_OCSP_IGNORE_ERR        },
    {"-CAfile",               required_argument, 0, WOLFCLU_OCSP_CAFILE            },
    {"-CApath",               required_argument, 0, WOLFCLU_OCSP_CAPATH            },
    {"-CAstore",              required_argument, 0, WOLFCLU_OCSP_CASTORE           },
    {"-no-CAfile",            no_argument,       0, WOLFCLU_OCSP_NO_CAFILE         },
    {"-no-CApath",            no_argument,       0, WOLFCLU_OCSP_NO_CAPATH         },
    {"-no-CAstore",           no_argument,       0, WOLFCLU_OCSP_NO_CASTORE        },

    /* Responder options */
    {"-timeout",              required_argument, 0, WOLFCLU_OCSP_TIMEOUT           },
    {"-resp_no_certs",        no_argument,       0, WOLFCLU_OCSP_RESP_NO_CERTS     },
    {"-multi",                required_argument, 0, WOLFCLU_OCSP_MULTI             },
    {"-no_certs",             no_argument,       0, WOLFCLU_OCSP_NO_CERTS          },
    {"-badsig",               no_argument,       0, WOLFCLU_OCSP_BADSIG            },
    {"-CA",                   required_argument, 0, WOLFCLU_OCSP_CA                },
    {"-nmin",                 required_argument, 0, WOLFCLU_OCSP_NMIN              },
    {"-nrequest",             required_argument, 0, WOLFCLU_OCSP_NREQUEST          },
    {"-reqin",                required_argument, 0, WOLFCLU_OCSP_REQIN             },
    {"-signer",               required_argument, 0, WOLFCLU_OCSP_SIGNER            },
    {"-sign_other",           required_argument, 0, WOLFCLU_OCSP_SIGN_OTHER        },
    {"-index",                required_argument, 0, WOLFCLU_OCSP_INDEX             },
    {"-ndays",                required_argument, 0, WOLFCLU_OCSP_NDAYS             },
    {"-rsigner",              required_argument, 0, WOLFCLU_OCSP_RSIGNER           },
    {"-rkey",                 required_argument, 0, WOLFCLU_OCSP_RKEY              },
    {"-passin",               required_argument, 0, WOLFCLU_OCSP_PASSIN            },
    {"-rother",               required_argument, 0, WOLFCLU_OCSP_ROTHER            },
    {"-rmd",                  required_argument, 0, WOLFCLU_OCSP_RMD               },
    {"-rsigopt",              required_argument, 0, WOLFCLU_OCSP_RSIGOPT           },
    {"-header",               required_argument, 0, WOLFCLU_OCSP_HEADER            },
    {"-rcid",                 required_argument, 0, WOLFCLU_OCSP_RCID              },

    /* Client options */
    {"-url",                  required_argument, 0, WOLFCLU_OCSP_URL               },
    {"-host",                 required_argument, 0, WOLFCLU_OCSP_HOST              },
    {"-port",                 required_argument, 0, WOLFCLU_OCSP_PORT              },
    {"-path",                 required_argument, 0, WOLFCLU_OCSP_PATH              },
    {"-proxy",                required_argument, 0, WOLFCLU_OCSP_PROXY             },
    {"-no_proxy",             required_argument, 0, WOLFCLU_OCSP_NO_PROXY          },
    {"-out",                  required_argument, 0, WOLFCLU_OCSP_OUT               },
    {"-noverify",             no_argument,       0, WOLFCLU_OCSP_NOVERIFY          },
    {"-nonce",                no_argument,       0, WOLFCLU_OCSP_NONCE             },
    {"-no_nonce",             no_argument,       0, WOLFCLU_OCSP_NO_NONCE          },
    {"-no_signature_verify",  no_argument,       0, WOLFCLU_OCSP_NO_SIGNATURE_VERIFY},
    {"-resp_key_id",          no_argument,       0, WOLFCLU_OCSP_RESP_KEY_ID       },
    {"-no_cert_verify",       no_argument,       0, WOLFCLU_OCSP_NO_CERT_VERIFY    },
    {"-text",                 no_argument,       0, WOLFCLU_OCSP_TEXT              },
    {"-req_text",             no_argument,       0, WOLFCLU_OCSP_REQ_TEXT          },
    {"-resp_text",            no_argument,       0, WOLFCLU_OCSP_RESP_TEXT         },
    {"-no_chain",             no_argument,       0, WOLFCLU_OCSP_NO_CHAIN          },
    {"-no_cert_checks",       no_argument,       0, WOLFCLU_OCSP_NO_CERT_CHECKS    },
    {"-no_explicit",          no_argument,       0, WOLFCLU_OCSP_NO_EXPLICIT       },
    {"-trust_other",          no_argument,       0, WOLFCLU_OCSP_TRUST_OTHER       },
    {"-no_intern",            no_argument,       0, WOLFCLU_OCSP_NO_INTERN         },
    {"-respin",               required_argument, 0, WOLFCLU_OCSP_RESPIN            },
    {"-VAfile",               required_argument, 0, WOLFCLU_OCSP_VAFILE            },
    {"-verify_other",         required_argument, 0, WOLFCLU_OCSP_VERIFY_OTHER      },
    {"-cert",                 required_argument, 0, WOLFCLU_OCSP_CERT              },
    {"-serial",               required_argument, 0, WOLFCLU_OCSP_SERIAL            },
    {"-validity_period",      required_argument, 0, WOLFCLU_OCSP_VALIDITY_PERIOD   },
    {"-signkey",              required_argument, 0, WOLFCLU_OCSP_SIGNKEY           },
    {"-reqout",               required_argument, 0, WOLFCLU_OCSP_REQOUT            },
    {"-respout",              required_argument, 0, WOLFCLU_OCSP_RESPOUT           },
    {"-issuer",               required_argument, 0, WOLFCLU_OCSP_ISSUER            },
    {"-status_age",           required_argument, 0, WOLFCLU_OCSP_STATUS_AGE        },

    /* Validation options */
    {"-policy",               required_argument, 0, WOLFCLU_OCSP_POLICY            },
    {"-purpose",              required_argument, 0, WOLFCLU_OCSP_PURPOSE           },
    {"-verify_name",          required_argument, 0, WOLFCLU_OCSP_VERIFY_NAME       },
    {"-verify_depth",         required_argument, 0, WOLFCLU_OCSP_VERIFY_DEPTH      },
    {"-auth_level",           required_argument, 0, WOLFCLU_OCSP_AUTH_LEVEL        },
    {"-attime",               required_argument, 0, WOLFCLU_OCSP_ATTIME            },
    {"-verify_hostname",      required_argument, 0, WOLFCLU_OCSP_VERIFY_HOSTNAME   },
    {"-verify_email",         required_argument, 0, WOLFCLU_OCSP_VERIFY_EMAIL      },
    {"-verify_ip",            required_argument, 0, WOLFCLU_OCSP_VERIFY_IP         },
    {"-ignore_critical",      no_argument,       0, WOLFCLU_OCSP_IGNORE_CRITICAL   },
    {"-issuer_checks",        no_argument,       0, WOLFCLU_OCSP_ISSUER_CHECKS     },
    {"-crl_check",            no_argument,       0, WOLFCLU_OCSP_CRL_CHECK         },
    {"-crl_check_all",        no_argument,       0, WOLFCLU_OCSP_CRL_CHECK_ALL     },
    {"-policy_check",         no_argument,       0, WOLFCLU_OCSP_POLICY_CHECK      },
    {"-explicit_policy",      no_argument,       0, WOLFCLU_OCSP_EXPLICIT_POLICY   },
    {"-inhibit_any",          no_argument,       0, WOLFCLU_OCSP_INHIBIT_ANY       },
    {"-inhibit_map",          no_argument,       0, WOLFCLU_OCSP_INHIBIT_MAP       },
    {"-x509_strict",          no_argument,       0, WOLFCLU_OCSP_X509_STRICT       },
    {"-extended_crl",         no_argument,       0, WOLFCLU_OCSP_EXTENDED_CRL      },
    {"-use_deltas",           no_argument,       0, WOLFCLU_OCSP_USE_DELTAS        },
    {"-policy_print",         no_argument,       0, WOLFCLU_OCSP_POLICY_PRINT      },
    {"-check_ss_sig",         no_argument,       0, WOLFCLU_OCSP_CHECK_SS_SIG      },
    {"-trusted_first",        no_argument,       0, WOLFCLU_OCSP_TRUSTED_FIRST     },
    {"-suiteB_128_only",      no_argument,       0, WOLFCLU_OCSP_SUITEB_128_ONLY   },
    {"-suiteB_128",           no_argument,       0, WOLFCLU_OCSP_SUITEB_128        },
    {"-suiteB_192",           no_argument,       0, WOLFCLU_OCSP_SUITEB_192        },
    {"-partial_chain",        no_argument,       0, WOLFCLU_OCSP_PARTIAL_CHAIN     },
    {"-no_alt_chains",        no_argument,       0, WOLFCLU_OCSP_NO_ALT_CHAINS     },
    {"-no_check_time",        no_argument,       0, WOLFCLU_OCSP_NO_CHECK_TIME     },
    {"-allow_proxy_certs",    no_argument,       0, WOLFCLU_OCSP_ALLOW_PROXY_CERTS },

    /* Provider options */
    {"-provider-path",        required_argument, 0, WOLFCLU_OCSP_PROVIDER_PATH     },
    {"-provider",             required_argument, 0, WOLFCLU_OCSP_PROVIDER          },
    {"-propquery",            required_argument, 0, WOLFCLU_OCSP_PROPQUERY         },

    /* SCGI mode */
    {"-scgi",                 no_argument,       0, WOLFCLU_OCSP_SCGI              },

    {0, 0, 0, 0} /* terminal element */
};

static void wolfCLU_OcspHelp(void)
{
    WOLFCLU_LOG(WOLFCLU_L0, "wolfssl ocsp [options]");
    WOLFCLU_LOG(WOLFCLU_L0, "OCSP utility - client and responder");
    WOLFCLU_LOG(WOLFCLU_L0, " ");
    WOLFCLU_LOG(WOLFCLU_L0, "General options:");
    WOLFCLU_LOG(WOLFCLU_L0, "  -help                   Display this summary");
    WOLFCLU_LOG(WOLFCLU_L0, "  -ignore_err             Ignore error on OCSP request or response");
    WOLFCLU_LOG(WOLFCLU_L0, "  -CAfile file            Trusted certificates file");
    WOLFCLU_LOG(WOLFCLU_L0, "  -CApath dir             Trusted certificates directory");
    WOLFCLU_LOG(WOLFCLU_L0, " ");
    WOLFCLU_LOG(WOLFCLU_L0, "Client mode (specify -cert to use):");
    WOLFCLU_LOG(WOLFCLU_L0, "  -url val                Responder URL (overrides AIA in cert)");
    WOLFCLU_LOG(WOLFCLU_L0, "  -host val               TCP/IP hostname:port to connect to");
    WOLFCLU_LOG(WOLFCLU_L0, "  -path val               Path to use in OCSP request");
    WOLFCLU_LOG(WOLFCLU_L0, "  -cert file              Certificate to check");
    WOLFCLU_LOG(WOLFCLU_L0, "  -issuer file            Issuer certificate");
    WOLFCLU_LOG(WOLFCLU_L0, "  -serial val             Serial number to check");
    WOLFCLU_LOG(WOLFCLU_L0, "  -nonce                  Add OCSP nonce to request");
    WOLFCLU_LOG(WOLFCLU_L0, "  -no_nonce               Don't add OCSP nonce to request");
    WOLFCLU_LOG(WOLFCLU_L0, "  -out file               Output filename");
    WOLFCLU_LOG(WOLFCLU_L0, "  -text                   Print text form of request and response");
    WOLFCLU_LOG(WOLFCLU_L0, " ");
    WOLFCLU_LOG(WOLFCLU_L0, "Responder mode (specify -port to use):");
    WOLFCLU_LOG(WOLFCLU_L0, "  -port num               Port to run responder on");
    WOLFCLU_LOG(WOLFCLU_L0, "  -index file             Certificate status index file");
    WOLFCLU_LOG(WOLFCLU_L0, "  -rsigner file           Responder certificate to sign responses");
    WOLFCLU_LOG(WOLFCLU_L0, "  -rkey file              Responder key to sign responses");
    WOLFCLU_LOG(WOLFCLU_L0, "  -CA file                CA certificate");
    WOLFCLU_LOG(WOLFCLU_L0, "  -scgi                   Use SCGI protocol (for web server reverse proxy)");
    WOLFCLU_LOG(WOLFCLU_L0, " ");
}

static int ocspClient(OcspClientConfig* config)
{
    WOLFSSL_CERT_MANAGER* cm  = NULL;
    byte*                 der = NULL;
    int                   derSz;
    int                   ocspFlags = 0;
    int                   ret = WOLFCLU_SUCCESS;

    if (config->cert == NULL) {
        wolfCLU_LogError("Client mode requires -cert");
        return WOLFCLU_FATAL_ERROR;
    }

    if (config->issuer == NULL) {
        wolfCLU_LogError("Client mode requires -issuer");
        return WOLFCLU_FATAL_ERROR;
    }

    /* Read the certificate to check into a DER buffer */
    derSz = wolfCLU_ReadCertDer(config->cert, &der);
    if (derSz <= 0) {
        wolfCLU_LogError("Failed to read certificate %s", config->cert);
        return WOLFCLU_FATAL_ERROR;
    }

    cm = wolfSSL_CertManagerNew();
    if (cm == NULL) {
        wolfCLU_LogError("Failed to create CertManager");
        XFREE(der, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        return WOLFCLU_FATAL_ERROR;
    }

    /* Load trusted CA certificates and issuer */
    if (ret == WOLFCLU_SUCCESS && config->issuer != NULL) {
        if (wolfSSL_CertManagerLoadCA(cm, config->issuer, NULL)
                != WOLFSSL_SUCCESS) {
            wolfCLU_LogError("Unable to load issuer file %s", config->issuer);
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS && config->caFile != NULL) {
        if (wolfSSL_CertManagerLoadCA(cm, config->caFile, NULL)
                != WOLFSSL_SUCCESS) {
            wolfCLU_LogError("Unable to load CA file %s", config->caFile);
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* Build OCSP flags */
    if (config->noNonce)
        ocspFlags |= WOLFSSL_OCSP_NO_NONCE;
    if (config->url != NULL)
        ocspFlags |= WOLFSSL_OCSP_URL_OVERRIDE;

    /* Enable OCSP in the CertManager */
    if (ret == WOLFCLU_SUCCESS) {
        if (wolfSSL_CertManagerEnableOCSP(cm, ocspFlags)
                != WOLFSSL_SUCCESS) {
            wolfCLU_LogError("Failed to enable OCSP");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* Set override URL if provided */
    if (ret == WOLFCLU_SUCCESS && config->url != NULL) {
        if (wolfSSL_CertManagerSetOCSPOverrideURL(cm, config->url)
                != WOLFSSL_SUCCESS) {
            wolfCLU_LogError("Failed to set OCSP override URL");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* Perform the OCSP check – wolfSSL handles networking and HTTP */
    if (ret == WOLFCLU_SUCCESS) {
        int ocspRet = wolfSSL_CertManagerCheckOCSP(cm, der, derSz);
        if (ocspRet == WOLFSSL_SUCCESS) {
            WOLFCLU_LOG(WOLFCLU_L0, "%s: good", config->cert);
        }
        else if (ocspRet == OCSP_CERT_REVOKED) {
            /* Certificate is revoked - report it but return success.
             * OpenSSL returns exit code 0 for revoked certs because the OCSP
             * transaction itself succeeded. The revocation status is in output. */
            WOLFCLU_LOG(WOLFCLU_L0, "%s: revoked", config->cert);
            /* ret remains WOLFCLU_SUCCESS */
        }
        else {
            /* Other OCSP errors (network, malformed response, etc.) */
            wolfCLU_LogError("OCSP check failed for %s (err %d: %s)",
                config->cert, ocspRet,
                wolfSSL_ERR_reason_error_string(ocspRet));
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    wolfSSL_CertManagerFree(cm);
    XFREE(der, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

/* Index file entry structure */
typedef struct IndexEntry {
    char status;
    time_t revocationTime;
    char serial[64];
    struct IndexEntry* next;
} IndexEntry;

/* Free index entries linked list */
static void freeIndexEntries(IndexEntry* head)
{
    while (head) {
        IndexEntry* next = head->next;
        XFREE(head, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        head = next;
    }
}

/* Parse OpenSSL index.txt file */
static IndexEntry* parseIndexFile(const char* filename)
{
    XFILE f = XBADFILE;
    char line[1024];
    IndexEntry* head = NULL;
    IndexEntry* tail = NULL;
    IndexEntry* entry = NULL;

    if (filename == NULL) {
        return NULL;
    }

    f = XFOPEN(filename, "r");
    if (f == XBADFILE) {
        wolfCLU_LogError("Error opening index file: %s", filename);
        return NULL;
    }

    while (XFGETS(line, sizeof(line), f) != NULL) {
        char* p = line;
        char* field;
        int fieldNum = 0;

        /* Skip empty lines */
        if (line[0] == '\n' || line[0] == '\r' || line[0] == '\0')
            continue;

        entry = (IndexEntry*)XMALLOC(sizeof(IndexEntry), HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (entry == NULL) {
            goto cleanup;
        }
        XMEMSET(entry, 0, sizeof(IndexEntry));

        /* Parse tab-separated fields */
        while ((field = XSTRSEP(&p, "\t")) != NULL && fieldNum < 6) {
            switch (fieldNum) {
                case 0: /* Status */
                    entry->status = field[0];
                    break;
                case 2: /* Revocation time */
                    if (field[0] != '\0') {
                        struct tm tm;
                        XMEMSET(&tm, 0, sizeof(tm));
                        if (XSTRLEN(field) >= 12) {
                            int year = (field[0] - '0') * 10 + (field[1] - '0');
                            tm.tm_year = (year < 50) ? (100 + year) : year;
                            tm.tm_mon = (field[2] - '0') * 10 + (field[3] - '0') - 1;
                            tm.tm_mday = (field[4] - '0') * 10 + (field[5] - '0');
                            tm.tm_hour = (field[6] - '0') * 10 + (field[7] - '0');
                            tm.tm_min = (field[8] - '0') * 10 + (field[9] - '0');
                            tm.tm_sec = (field[10] - '0') * 10 + (field[11] - '0');
                            entry->revocationTime = XMKTIME(&tm);
                        }
                    }
                    break;
                case 3: /* Serial (hex) */
                    XSTRNCPY(entry->serial, field, sizeof(entry->serial) - 1);
                    break;
            }
            fieldNum++;
        }

        /* Validate entry */
        if (fieldNum < 4 || entry->serial[0] == '\0') {
            XFREE(entry, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            entry = NULL;
            continue;
        }
        
        /* For revoked certificates, revocationTime must be valid */
        if (entry->status == 'R' && entry->revocationTime == (time_t)-1) {
            wolfCLU_LogError("Invalid revocation time for serial %s", entry->serial);
            XFREE(entry, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            entry = NULL;
            continue;
        }

        /* Add to list */
        entry->next = NULL;
        if (tail) {
            tail->next = entry;
            tail = entry;
        }
        else {
            head = tail = entry;
        }
        entry = NULL;
    }

cleanup:
    if (f != XBADFILE)
        XFCLOSE(f);
    if (entry != NULL)
        XFREE(entry, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    return head;
}

static byte reqBuffer[16384];
static byte respBuffer[16384];

/* Signal handling for graceful shutdown */
#ifndef _WIN32
    #include <signal.h>
    #include <errno.h>
#endif

static volatile sig_atomic_t shutdownRequested = 0;

#ifndef _WIN32
/* Signal handler for SIGINT and SIGTERM - sets shutdown flag */
static void ocspSignalHandler(int sig)
{
    int saved_errno = errno;
    (void)sig;
    shutdownRequested = 1;
    errno = saved_errno;
}

/* Setup signal handlers without SA_RESTART to allow accept() interruption */
static void setupSignalHandlers(void)
{
    struct sigaction sa;
    XMEMSET(&sa, 0, sizeof(sa));
    sa.sa_handler = ocspSignalHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;  /* NO SA_RESTART - allow accept() to be interrupted */
    
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}
#endif

enum TRANSPORT_TYPE {
    TRANSPORT_NONE = 0,
    TRANSPORT_HTTP,
    TRANSPORT_SCGI
};

/* Read OCSP request from transport layer */
static int transportReadRequest(SOCKET_T clientfd, enum TRANSPORT_TYPE transportType, const byte** ocspReq, int* ocspReqSz)
{
    if (transportType == TRANSPORT_HTTP) {
        int recvLen;
        
        recvLen = wolfCLU_HttpServerRecv(clientfd, reqBuffer, sizeof(reqBuffer));
        if (recvLen <= 0) {
            return WOLFCLU_FATAL_ERROR;
        }
        
        if (wolfCLU_HttpServerParseRequest(reqBuffer, recvLen, ocspReq, ocspReqSz) != 0 ||
            *ocspReq == NULL || *ocspReqSz <= 0) {
            wolfCLU_HttpServerSendError(clientfd, 400, "Bad Request");
            return WOLFCLU_FATAL_ERROR;
        }

        return WOLFCLU_SUCCESS;
    }
    else if (transportType == TRANSPORT_SCGI) {
        ScgiRequest scgiReq;
        int ret = wolfCLU_ScgiReadRequest(clientfd, reqBuffer, sizeof(reqBuffer), &scgiReq);
        if (ret != 0) {
            return WOLFCLU_FATAL_ERROR;
        }
        
        /* Validate request method */
        if (scgiReq.requestMethod == NULL ||
            XSTRCMP(scgiReq.requestMethod, "POST") != 0) {
            wolfCLU_ScgiSendError(clientfd, 405, "Method Not Allowed");
            return WOLFCLU_FATAL_ERROR;
        }
        
        /* Validate we have a body */
        if (scgiReq.body == NULL || scgiReq.bodyLen <= 0) {
            wolfCLU_ScgiSendError(clientfd, 400, "Bad Request");
            return WOLFCLU_FATAL_ERROR;
        }
        
        *ocspReq = scgiReq.body;
        *ocspReqSz = scgiReq.bodyLen;

        return WOLFCLU_SUCCESS;
    }
    else {
        return WOLFCLU_FATAL_ERROR;
    }
}

/* Send OCSP response via transport layer */
static int transportSendResponse(SOCKET_T clientfd, enum TRANSPORT_TYPE transportType, const byte* respBuf, int respSz)
{
    if (transportType == TRANSPORT_HTTP) {
        return wolfCLU_HttpServerSendOcspResponse(clientfd, respBuf, respSz);
    }
    else if (transportType == TRANSPORT_SCGI) {
        return wolfCLU_ScgiSendResponse(clientfd, 200, "OK",
                                        "application/ocsp-response",
                                        respBuf, respSz);
    }
    else {
        return WOLFCLU_FATAL_ERROR;
    }
}

/* Send error response via transport layer */
static int transportSendError(SOCKET_T clientfd, enum TRANSPORT_TYPE transportType, int statusCode, const char* statusMsg)
{
    if (transportType == TRANSPORT_HTTP) {
        wolfCLU_HttpServerSendError(clientfd, statusCode, statusMsg);
        return WOLFCLU_SUCCESS;
    }
    else if (transportType == TRANSPORT_SCGI) {
        return wolfCLU_ScgiSendError(clientfd, statusCode, statusMsg);
    }
    else {
        return WOLFCLU_FATAL_ERROR;
    }
}

static int ocspResponder(OcspResponderConfig* config)
{
    OcspResponder* responder = NULL;
    IndexEntry* indexEntries = NULL;
    DecodedCert caCert;
    SOCKET_T sockfd = INVALID_SOCKET;
    SOCKET_T clientfd = INVALID_SOCKET;
    int requestsProcessed = 0;
    int ret = WOLFCLU_SUCCESS;
    char* caSubject = NULL;
    word32 caSubjectSz = 0;
    byte* caCertDer = NULL;
    word32 caCertDerSz = 0;
    byte* signerCertDer = NULL;
    word32 signerCertDerSz = 0;
    byte* signerKeyDer = NULL;
    word32 signerKeyDerSz = 0;
    enum TRANSPORT_TYPE transportType = config->scgiMode ? TRANSPORT_SCGI : TRANSPORT_HTTP;

    XMEMSET(&caCert, 0, sizeof(caCert));

    /* Validate required options */
    if (config->caFile == NULL) {
        wolfCLU_LogError("Error: CA certificate required (-CA)");
        return WOLFCLU_FATAL_ERROR;
    }
    if (config->rsignerFile == NULL) {
        wolfCLU_LogError("Error: Responder signer certificate required (-rsigner)");
        return WOLFCLU_FATAL_ERROR;
    }
    if (config->rkeyFile == NULL) {
        wolfCLU_LogError("Error: Responder key required (-rkey)");
        return WOLFCLU_FATAL_ERROR;
    }
    if (config->port == 0) {
        wolfCLU_LogError("Error: Port required (-port)");
        return WOLFCLU_FATAL_ERROR;
    }

    /* Load CA certificate */
    if (wolfCLU_LoadCertDer(config->caFile, &caCertDer, &caCertDerSz) != 0) {
        wolfCLU_LogError("Error loading CA certificate: %s", config->caFile);
        ret = WOLFCLU_FATAL_ERROR;
        goto cleanup;
    }

    /* Load responder signer certificate */
    if (wolfCLU_LoadCertDer(config->rsignerFile, &signerCertDer, &signerCertDerSz) != 0) {
        wolfCLU_LogError("Error loading signer certificate: %s", config->rsignerFile);
        ret = WOLFCLU_FATAL_ERROR;
        goto cleanup;
    }

    /* Load responder signer key */
    if (wolfCLU_LoadKeyDer(config->rkeyFile, &signerKeyDer, &signerKeyDerSz) != 0) {
        wolfCLU_LogError("Error loading signer key: %s", config->rkeyFile);
        ret = WOLFCLU_FATAL_ERROR;
        goto cleanup;
    }

    /* Parse CA certificate */
    wc_InitDecodedCert(&caCert, caCertDer, caCertDerSz, NULL);
    if (wc_ParseCert(&caCert, CERT_TYPE, 0, NULL) != 0) {
        wolfCLU_LogError("Error parsing CA certificate");
        ret = WOLFCLU_FATAL_ERROR;
        goto cleanup;
    }

    /* First call: get required buffer size */
    if (wc_GetDecodedCertSubject(&caCert, NULL, &caSubjectSz) != LENGTH_ONLY_E ||
            caSubjectSz == 0) {
        wolfCLU_LogError("Could not get CA subject size");
        ret = WOLFCLU_FATAL_ERROR;
        goto cleanup;
    }
    caSubject = (char*)XMALLOC(caSubjectSz + 1, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (caSubject == NULL) {
        wolfCLU_LogError("Memory allocation failed for CA subject");
        ret = WOLFCLU_FATAL_ERROR;
        goto cleanup;
    }
    if (wc_GetDecodedCertSubject(&caCert, caSubject, &caSubjectSz) != 0) {
        wolfCLU_LogError("Could not get CA subject");
        ret = WOLFCLU_FATAL_ERROR;
        goto cleanup;
    }
    caSubject[caSubjectSz] = '\0';

    /* Load index file if provided */
    if (config->indexFile) {
        indexEntries = parseIndexFile(config->indexFile);
        if (indexEntries == NULL) {
            wolfCLU_LogError("Warning: Could not parse index file: %s", config->indexFile);
        }
    }

    /* Create OCSP responder */
    responder = wc_OcspResponder_new(NULL, 1);
    if (responder == NULL) {
        wolfCLU_LogError("Error creating OCSP responder");
        ret = WOLFCLU_FATAL_ERROR;
        goto cleanup;
    }

    /* Add signer to responder. When the signer cert is the CA itself, pass
     * NULL for the issuer cert (direct CA signing). Only pass the CA cert as
     * issuer when using an authorized responder (delegated signing). */
    {
        const byte* issuerDer = NULL;
        word32 issuerDerSz = 0;
        if (signerCertDerSz != caCertDerSz ||
                XMEMCMP(signerCertDer, caCertDer, signerCertDerSz) != 0) {
            issuerDer = caCertDer;
            issuerDerSz = caCertDerSz;
        }
        if (wc_OcspResponder_AddSigner(responder, signerCertDer, signerCertDerSz,
                signerKeyDer, signerKeyDerSz, issuerDer, issuerDerSz) != 0) {
            wolfCLU_LogError("Error adding signer to responder");
            ret = WOLFCLU_FATAL_ERROR;
            goto cleanup;
        }
    }

    /* Populate responder with certificate statuses from index */
    if (indexEntries != NULL) {
        IndexEntry* entry;
        for (entry = indexEntries; entry != NULL; entry = entry->next) {
            byte serial[64];
            word32 serialLen = 0;
            enum Ocsp_Cert_Status status;
            time_t revTime = 0;
            word32 i;
            char* p = entry->serial;

            /* Convert hex string to bytes */
            serialLen = (word32)XSTRLEN(entry->serial) / 2;
            if (serialLen == 0 || serialLen > sizeof(serial)) {
                continue;
            }

            for (i = 0; i < serialLen; i++) {
                int high = (p[i*2] >= 'A') ? (p[i*2] - 'A' + 10) :
                          (p[i*2] >= 'a') ? (p[i*2] - 'a' + 10) : (p[i*2] - '0');
                int low = (p[i*2+1] >= 'A') ? (p[i*2+1] - 'A' + 10) :
                         (p[i*2+1] >= 'a') ? (p[i*2+1] - 'a' + 10) : (p[i*2+1] - '0');
                serial[i] = (byte)((high << 4) | low);
            }

            /* Determine status */
            if (entry->status == 'V') {
                status = CERT_GOOD;
            }
            else if (entry->status == 'R') {
                status = CERT_REVOKED;
                revTime = entry->revocationTime;
            }
            else {
                status = CERT_UNKNOWN;
            }

            /* Set validity period: only for CERT_GOOD, must be 0 for others */
            wc_OcspResponder_SetCertStatus(responder, caSubject, caSubjectSz,
                                          serial, serialLen, status, revTime,
                                          CRL_REASON_UNSPECIFIED,
                                          (status == CERT_GOOD) ? 86400 : 0);
        }
    }

    /* Create and listen on server socket */
    sockfd = wolfCLU_HttpServerListen(&config->port);
    if (sockfd == INVALID_SOCKET) {
        wolfCLU_LogError("Failed to create server socket on port %d", config->port);
        ret = WOLFCLU_FATAL_ERROR;
        goto cleanup;
    }

#ifndef _WIN32
    /* Setup signal handlers for graceful shutdown */
    setupSignalHandlers();
#endif

    WOLFCLU_LOG(WOLFCLU_L0, "OCSP responder%s listening on port %d", 
                (transportType == TRANSPORT_SCGI) ? " (SCGI mode)" : "", config->port);

    /* Main loop - exit on shutdown signal */
    while (!shutdownRequested && 
           (config->nrequest == 0 || requestsProcessed < config->nrequest)) {
        const byte* ocspReq;
        int ocspReqSz;
        word32 respSz;

        /* Accept connection */
        clientfd = wolfCLU_ServerAccept(sockfd);
        if (clientfd == INVALID_SOCKET) {
            continue;
        }

        /* Read request from transport layer */
        ret = transportReadRequest(clientfd, transportType, &ocspReq, &ocspReqSz);
        if (ret != WOLFCLU_SUCCESS) {
            break;
        }

        /* Process OCSP request and generate response */
        respSz = sizeof(respBuffer);
        ret = wc_OcspResponder_WriteResponse(responder, ocspReq, (word32)ocspReqSz,
                respBuffer, &respSz);

        if (ret != 0) {
            enum Ocsp_Response_Status errStatus;

            /* Map error to OCSP response status */
            switch (ret) {
                case ASN_PARSE_E:
                    errStatus = OCSP_MALFORMED_REQUEST;
                    break;
                case ASN_SIG_HASH_E:
                    errStatus = OCSP_INTERNAL_ERROR;
                    break;
                case ASN_NO_SIGNER_E:
                    errStatus = OCSP_UNAUTHORIZED;
                    break;
                case OCSP_CERT_UNKNOWN:
                    errStatus = OCSP_UNAUTHORIZED;
                    break;
                default:
                    errStatus = OCSP_INTERNAL_ERROR;
                    break;
            }

            /* Generate OCSP error response */
            respSz = sizeof(respBuffer);
            ret = wc_OcspResponder_WriteErrorResponse(errStatus, respBuffer, &respSz);

            if (ret != 0) {
                /* If we can't encode an error response, send HTTP/SCGI error */
                transportSendError(clientfd, transportType, 500, "Internal Server Error");
                break;
            }
        }

        /* Send response via transport layer */
        if (transportSendResponse(clientfd, transportType, respBuffer, (int)respSz) != 0) {
            break;
        }

        requestsProcessed++;

        /* Check if we've hit the request limit */
        if (config->nrequest > 0 && requestsProcessed >= config->nrequest) {
            break;
        }

        wolfCLU_ServerClose(clientfd);
        clientfd = INVALID_SOCKET;
    }

    ret = WOLFCLU_SUCCESS;

cleanup:
    if (clientfd != INVALID_SOCKET)
        wolfCLU_ServerClose(clientfd);
    if (sockfd != INVALID_SOCKET)
        wolfCLU_ServerClose(sockfd);

    wc_FreeDecodedCert(&caCert);
    wc_OcspResponder_free(responder);
    freeIndexEntries(indexEntries);
    XFREE(caCertDer, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(signerCertDer, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(signerKeyDer, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(caSubject, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}

int wolfCLU_OcspSetup(int argc, char** argv)
{
    int ret = WOLFCLU_SUCCESS;
    int option;
    int longIndex = 1;
    int isClientMode = 0;
    int isResponderMode = 0;
    OcspClientConfig clientConfig;
    OcspResponderConfig responderConfig;

    XMEMSET(&clientConfig, 0, sizeof(clientConfig));
    XMEMSET(&responderConfig, 0, sizeof(responderConfig));

    opterr = 0;
    optind = 0;

    while ((option = wolfCLU_GetOpt(argc, argv, "", ocsp_options, &longIndex)) != -1) {
        switch (option) {
            case WOLFCLU_OCSP_HELP:
                wolfCLU_OcspHelp();
                return WOLFCLU_SUCCESS;

            case WOLFCLU_OCSP_URL:
                isClientMode = 1;
                clientConfig.url = optarg;
                break;

            case WOLFCLU_OCSP_CERT:
                isClientMode = 1;
                clientConfig.cert = optarg;
                break;

            case WOLFCLU_OCSP_CAFILE:
                clientConfig.caFile = optarg;
                break;

            case WOLFCLU_OCSP_NO_NONCE:
                clientConfig.noNonce = 1;
                break;

            case WOLFCLU_OCSP_PORT:
                isResponderMode = 1;
                responderConfig.port = (word16)XATOI(optarg);
                break;

            case WOLFCLU_OCSP_IGNORE_ERR:
                wolfCLU_LogError("Option -ignore_err is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_CAPATH:
                wolfCLU_LogError("Option -CApath is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_CASTORE:
                wolfCLU_LogError("Option -CAstore is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_NO_CAFILE:
                wolfCLU_LogError("Option -no-CAfile is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_NO_CAPATH:
                wolfCLU_LogError("Option -no-CApath is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_NO_CASTORE:
                wolfCLU_LogError("Option -no-CAstore is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_TIMEOUT:
                wolfCLU_LogError("Option -timeout is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_RESP_NO_CERTS:
                wolfCLU_LogError("Option -resp_no_certs is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_MULTI:
                wolfCLU_LogError("Option -multi is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_NO_CERTS:
                wolfCLU_LogError("Option -no_certs is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_BADSIG:
                wolfCLU_LogError("Option -badsig is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_CA:
                responderConfig.caFile = optarg;
                break;

            case WOLFCLU_OCSP_NMIN:
                wolfCLU_LogError("Option -nmin is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_NREQUEST:
                responderConfig.nrequest = XATOI(optarg);
                break;

            case WOLFCLU_OCSP_REQIN:
                wolfCLU_LogError("Option -reqin is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_SIGNER:
                wolfCLU_LogError("Option -signer is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_SIGN_OTHER:
                wolfCLU_LogError("Option -sign_other is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_INDEX:
                responderConfig.indexFile = optarg;
                break;

            case WOLFCLU_OCSP_NDAYS:
                wolfCLU_LogError("Option -ndays is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_RSIGNER:
                responderConfig.rsignerFile = optarg;
                break;

            case WOLFCLU_OCSP_RKEY:
                responderConfig.rkeyFile = optarg;
                break;

            case WOLFCLU_OCSP_SCGI:
                responderConfig.scgiMode = 1;
                break;

            case WOLFCLU_OCSP_PASSIN:
                wolfCLU_LogError("Option -passin is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_ROTHER:
                wolfCLU_LogError("Option -rother is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_RMD:
                wolfCLU_LogError("Option -rmd is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_RSIGOPT:
                wolfCLU_LogError("Option -rsigopt is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_HEADER:
                wolfCLU_LogError("Option -header is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_RCID:
                wolfCLU_LogError("Option -rcid is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_HOST:
                wolfCLU_LogError("Option -host is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_PATH:
                wolfCLU_LogError("Option -path is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_PROXY:
                wolfCLU_LogError("Option -proxy is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_NO_PROXY:
                wolfCLU_LogError("Option -no_proxy is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_OUT:
                wolfCLU_LogError("Option -out is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_NOVERIFY:
                wolfCLU_LogError("Option -noverify is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_NONCE:
                wolfCLU_LogError("Option -nonce is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_NO_SIGNATURE_VERIFY:
                wolfCLU_LogError("Option -no_signature_verify is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_RESP_KEY_ID:
                wolfCLU_LogError("Option -resp_key_id is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_NO_CERT_VERIFY:
                wolfCLU_LogError("Option -no_cert_verify is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_TEXT:
                wolfCLU_LogError("Option -text is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_REQ_TEXT:
                wolfCLU_LogError("Option -req_text is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_RESP_TEXT:
                wolfCLU_LogError("Option -resp_text is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_NO_CHAIN:
                wolfCLU_LogError("Option -no_chain is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_NO_CERT_CHECKS:
                wolfCLU_LogError("Option -no_cert_checks is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_NO_EXPLICIT:
                wolfCLU_LogError("Option -no_explicit is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_TRUST_OTHER:
                wolfCLU_LogError("Option -trust_other is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_NO_INTERN:
                wolfCLU_LogError("Option -no_intern is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_RESPIN:
                wolfCLU_LogError("Option -respin is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_VAFILE:
                wolfCLU_LogError("Option -VAfile is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_VERIFY_OTHER:
                wolfCLU_LogError("Option -verify_other is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_SERIAL:
                wolfCLU_LogError("Option -serial is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_VALIDITY_PERIOD:
                wolfCLU_LogError("Option -validity_period is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_SIGNKEY:
                wolfCLU_LogError("Option -signkey is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_REQOUT:
                wolfCLU_LogError("Option -reqout is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_RESPOUT:
                wolfCLU_LogError("Option -respout is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_ISSUER:
                isClientMode = 1;
                clientConfig.issuer = optarg;
                break;

            case WOLFCLU_OCSP_STATUS_AGE:
                wolfCLU_LogError("Option -status_age is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_POLICY:
                wolfCLU_LogError("Option -policy is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_PURPOSE:
                wolfCLU_LogError("Option -purpose is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_VERIFY_NAME:
                wolfCLU_LogError("Option -verify_name is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_VERIFY_DEPTH:
                wolfCLU_LogError("Option -verify_depth is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_AUTH_LEVEL:
                wolfCLU_LogError("Option -auth_level is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_ATTIME:
                wolfCLU_LogError("Option -attime is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_VERIFY_HOSTNAME:
                wolfCLU_LogError("Option -verify_hostname is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_VERIFY_EMAIL:
                wolfCLU_LogError("Option -verify_email is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_VERIFY_IP:
                wolfCLU_LogError("Option -verify_ip is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_IGNORE_CRITICAL:
                wolfCLU_LogError("Option -ignore_critical is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_ISSUER_CHECKS:
                wolfCLU_LogError("Option -issuer_checks is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_CRL_CHECK:
                wolfCLU_LogError("Option -crl_check is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_CRL_CHECK_ALL:
                wolfCLU_LogError("Option -crl_check_all is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_POLICY_CHECK:
                wolfCLU_LogError("Option -policy_check is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_EXPLICIT_POLICY:
                wolfCLU_LogError("Option -explicit_policy is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_INHIBIT_ANY:
                wolfCLU_LogError("Option -inhibit_any is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_INHIBIT_MAP:
                wolfCLU_LogError("Option -inhibit_map is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_X509_STRICT:
                wolfCLU_LogError("Option -x509_strict is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_EXTENDED_CRL:
                wolfCLU_LogError("Option -extended_crl is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_USE_DELTAS:
                wolfCLU_LogError("Option -use_deltas is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_POLICY_PRINT:
                wolfCLU_LogError("Option -policy_print is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_CHECK_SS_SIG:
                wolfCLU_LogError("Option -check_ss_sig is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_TRUSTED_FIRST:
                wolfCLU_LogError("Option -trusted_first is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_SUITEB_128_ONLY:
                wolfCLU_LogError("Option -suiteB_128_only is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_SUITEB_128:
                wolfCLU_LogError("Option -suiteB_128 is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_SUITEB_192:
                wolfCLU_LogError("Option -suiteB_192 is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_PARTIAL_CHAIN:
                wolfCLU_LogError("Option -partial_chain is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_NO_ALT_CHAINS:
                wolfCLU_LogError("Option -no_alt_chains is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_NO_CHECK_TIME:
                wolfCLU_LogError("Option -no_check_time is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_ALLOW_PROXY_CERTS:
                wolfCLU_LogError("Option -allow_proxy_certs is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_PROVIDER_PATH:
                wolfCLU_LogError("Option -provider-path is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_PROVIDER:
                wolfCLU_LogError("Option -provider is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case WOLFCLU_OCSP_PROPQUERY:
                wolfCLU_LogError("Option -propquery is not yet supported");
                return WOLFCLU_FATAL_ERROR;

            case ':':
            case '?':
                wolfCLU_LogError("Bad argument found");
                wolfCLU_OcspHelp();
                return WOLFCLU_FATAL_ERROR;

            default:
                break;
        }
    }

    if (ret != WOLFCLU_SUCCESS) {
        return ret;
    }

    if (!(isClientMode ^ isResponderMode)) {
        wolfCLU_LogError("Can't detect side (client vs responder) or multiple sides specified");
        wolfCLU_OcspHelp();
        ret = WOLFCLU_FATAL_ERROR;
    }
    else if (isClientMode) {
        ret = ocspClient(&clientConfig);
    }
    else if (isResponderMode) {
        ret = ocspResponder(&responderConfig);
    }
    else {
        wolfCLU_LogError("Unexpected error");
        ret = WOLFCLU_FATAL_ERROR;
    }

    WOLFCLU_LOG(WOLFCLU_L0, "wolfssl exiting gracefully");

    return ret;
}

#endif /* HAVE_OCSP && HAVE_OCSP_RESPONDER */
