/* clu_asn1_setup.c
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#include <wolfclu/clu_header_main.h>
#include <wolfclu/clu_error_codes.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfclu/clu_log.h>
#include <wolfclu/asn1/clu_asn1.h>


#if defined(WOLFSSL_ASN_PRINT) && !defined(NO_FILESYSTEM)

static const struct option asn1_options[] = {
    { "-oid", required_argument, 0, WOLFCLU_OID },
    { "-inform", required_argument, 0, WOLFCLU_INFORM },
    { "-in", required_argument, 0, WOLFCLU_INFILE },
    { "-out", required_argument, 0, WOLFCLU_OUTFILE },
    { "-offset", required_argument, 0, WOLFCLU_OFFSET },
    { "-length", required_argument, 0, WOLFCLU_LENGTH },
    { "-strparse", required_argument, 0, WOLFCLU_STRPARSE },
    { "-noout", no_argument, 0, WOLFCLU_NOOUT },
    { "-i", no_argument, 0, WOLFCLU_INDENT },
    { "-dump", no_argument, 0, WOLFCLU_DUMP },
    { "-help", no_argument, 0, WOLFCLU_HELP },
    { 0, 0, 0, 0 } /* terminal element */
};

static void wolfCLU_Asn1Help(void)
{
    WOLFCLU_LOG(WOLFCLU_L0, "./wolfssl asn1parse");
    WOLFCLU_LOG(WOLFCLU_L0, "General Options:");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-help                Display this text");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-oid <infile>        File of extra oid "
                            "definitions");
    wolfCLU_Log(WOLFCLU_L0, "\t                     To use built in Oid Table "
                            "configure with:");
    wolfCLU_Log(WOLFCLU_L0, "\t                     --enable-oid-table");

    WOLFCLU_LOG(WOLFCLU_L0, "\nI/O Options:");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-inform <file type>  Input file format "
                            "- [DER, PEM, B64]");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-in <input file>     Input file");
    WOLFCLU_LOG(
        WOLFCLU_L0,
        "\t-out <output file>   Output file for the Asn1 Der data "
        "after processing");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-noout               Do not print output");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-offset <int>        Offset in to the file "
                            "to begin parsing");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-length <int>        Number of bytes to parse");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-strparse <int>      Offset to OCTET/BIT STRING "
                            "to parse\n "
                            "\t\t             can be used with a list. "
                            "Ex:-strparse 702,64");
    WOLFCLU_LOG(WOLFCLU_L0, "\nFormatting Options:");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-i                   Indents the output");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-dump                Unknown data in hex form");
    WOLFCLU_LOG(WOLFCLU_L0, "\nOutput:");
    WOLFCLU_LOG(WOLFCLU_L0, "              Offset v      v Data Length");
    WOLFCLU_LOG(WOLFCLU_L0, "                     0: 4 [1187]  (0) ┌SEQUENCE");
    WOLFCLU_LOG(WOLFCLU_L0, "          Header Length ^    Depth ^");
    WOLFCLU_LOG(WOLFCLU_L0, "\n           Brackets indicate constructed "
                            "types");
    WOLFCLU_LOG(WOLFCLU_L0, "                     0: 4 [1187] (0) ┌SEQUENCE");
    WOLFCLU_LOG(WOLFCLU_L0, "\n               Pluses indicate primitive types");
    WOLFCLU_LOG(WOLFCLU_L0, "                     0: 4 +   7  (0) ┌INTEGER");
    WOLFCLU_LOG(WOLFCLU_L0, "\nOid File:\n");
    WOLFCLU_LOG(WOLFCLU_L0, "       Pass in a file to -oid in this format:")
    WOLFCLU_LOG(WOLFCLU_L0, "           1.2.3.4 shortName Long name with "
                            "spaces");
    WOLFCLU_LOG(WOLFCLU_L0, "           5.6.7.8 shortName2 spaces with "
                            "name long\n");
    WOLFCLU_LOG(WOLFCLU_L0, "       Entry Fields:");
    WOLFCLU_LOG(WOLFCLU_L0, "           <oid> <shortname> <longName>");
}

/* close all files opened during setup returns WOLFCLU_SUCCESS */
static int Asn1ParseOptions_clean_up(WOLFCLU_ASN1_PARSE_OPTIONS *opt)
{
    if (opt->oidFile != NULL) {
        XFCLOSE(opt->oidFile);
    }

    if (opt->inputFile != NULL) {
        XFCLOSE(opt->inputFile);
    }

    if (opt->outputFile != NULL) {
        XFCLOSE(opt->outputFile);
    }

    *opt = (WOLFCLU_ASN1_PARSE_OPTIONS){ 0 };

    return WOLFCLU_SUCCESS;
}


static int checkFileArg(const char *file, const char *flag, const char *mode,
                        XFILE *file_out)
{
    int ret = WOLFCLU_FATAL_ERROR;

    if (file != NULL) {
        XFILE f = XFOPEN(file, mode);
        if (f != NULL) {
            if (*file_out != NULL) {
                wolfCLU_LogError("File for %s was already opened", flag);
                XFCLOSE(f);
                return WOLFCLU_FATAL_ERROR;
            }
            *file_out = f;
            ret = WOLFCLU_SUCCESS;
        }
    }

    if (ret != WOLFCLU_SUCCESS) {
        file = file && (file[0] != '-') ? file : "*missing*";
        wolfCLU_LogError("%s argument either missing argument or "
                         "file does not exist : %s",
                         flag, file);
    }

    return ret;
}

/* check, parse, and set comma separated list for -strparse
 * return WOLFCLU_SUCCESS if successful */
static int checkStrParse(const char *arg, word32 *outSz, const word32 cap,
                         word32 *out)
{
    int ret = WOLFCLU_SUCCESS;
    char *end;
    char *token;
    unsigned long len;
    char* tmp;

    if (out == NULL || arg == NULL || outSz == NULL) {
        return WOLFCLU_FATAL_ERROR;
    }

    len = XSTRLEN(arg) + 1;
    tmp = (char *)XMALLOC(len, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

    if (tmp == NULL) {
        return MEMORY_E;
    }

    XMEMCPY(tmp, arg, len);

    token = XSTRTOK(tmp, ",", &end);
    while (token != NULL && ret == WOLFCLU_SUCCESS) {
        word32 val = 0;
        if (wolfCLU_StrToWord32(token, XSTRLEN(token), &val) !=
                                                        WOLFCLU_SUCCESS) {
            ret = WOLFCLU_FATAL_ERROR;
            wolfCLU_LogError(
                "Not a valid integer value passed to -strparse. %s", arg);
        }
        else if (*outSz >= cap) {
            ret = WOLFCLU_FATAL_ERROR;
            wolfCLU_LogError("Too many values passed to -strparse. "
                             "Max is %u : %s", cap, arg);
        }
        else {
            out[(*outSz)++] = val;
        }
        token = XSTRTOK(NULL, ",", &end);
    }

    XFREE(tmp, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

/* check and set the arg currently in optarg to the out
 * return WOLFCLU_SUCCESS if successful */
static int checkWord32Arg(const char *arg, const char *flagName, word32 *out)
{
    int ret = WOLFCLU_FATAL_ERROR;

    if (arg != NULL) {
        ret = wolfCLU_StrToWord32(arg, XSTRLEN(arg), out);
    }

    if (ret != WOLFCLU_SUCCESS) {
        arg = arg && (arg[0] != '-') ? arg : "*missing*";
        wolfCLU_LogError("%s argument either missing argument or "
                         "is not a non negative integer : %s",
                         flagName, arg);
    }

    return ret;
}

/* takes optarg as inform and places inform id in inform_id returns
 * WOLFCLU_SUCCESS if successful and a fatal error if not successful */
static int checkInForm(char *inform, word8 *inform_id_out)
{
    int ret = WOLFCLU_FATAL_ERROR;
    if (inform != NULL && XSTRLEN(inform) == 3) {
        wolfCLU_convertToLower(inform, (int)XSTRLEN(inform));
        if (XSTRCMP(inform, "pem") == 0) {
            *inform_id_out = WOLFCLU_ASN1_PEM;
            ret = WOLFCLU_SUCCESS;
        }
        else if (XSTRCMP(inform, "der") == 0) {
            *inform_id_out = WOLFCLU_ASN1_DER;
            ret = WOLFCLU_SUCCESS;
        }
        else if (XSTRCMP(inform, "b64") == 0) {
            *inform_id_out = WOLFCLU_ASN1_B64;
            ret = WOLFCLU_SUCCESS;
        }
    }

    if (ret != WOLFCLU_SUCCESS) {
        inform = inform && (inform[0] != '-') ? inform : (char*)"*missing*";
        wolfCLU_LogError("-inform argument either missing or is not valid "
                         "value : %s", inform);
    }
    return ret;
}
#endif /* defined(WOLFSSL_ASN_PRINT) && !defined(NO_FILESYSTEM) */

/* return WOLFCLU_SUCCESS on success */
int wolfCLU_Asn1Setup(int argc, char *argv[])
{
#if defined(WOLFSSL_ASN_PRINT) && !defined(NO_FILESYSTEM)
    int ret = WOLFCLU_SUCCESS;
    int option;
    int longIndex = 1;
    static WOLFCLU_ASN1_PARSE_OPTIONS asn1Config = { 0 };

    opterr = 0;
    optind = 0;
    while ((option = wolfCLU_GetOpt(argc, argv, "", asn1_options,
                                    &longIndex)) != END_OF_ARGS &&
           ret == WOLFCLU_SUCCESS) {
        switch (option) {
            case WOLFCLU_INFORM:
                ret = checkInForm(optarg, &asn1Config.inForm);
                break;

            case WOLFCLU_OUTFILE:
                ret =
                    checkFileArg(optarg, "-out", "wb", &asn1Config.outputFile);
                break;

            case WOLFCLU_INFILE:
                ret = checkFileArg(optarg, "-in", "rb", &asn1Config.inputFile);
                break;

            case WOLFCLU_OID:
#ifndef NO_WC_ENCODE_OBJECT_ID
                ret = checkFileArg(optarg, "-oid", "rb", &asn1Config.oidFile);
#else
                wolfCLU_LogError("wolfSSL is not configured to "
                                 "handle encoding oids");
                ret = WOLFCLU_FATAL_ERROR;
#endif /* NO_WC_ENCODE_OBJECT_ID */
                break;

            case WOLFCLU_OFFSET:
                ret = checkWord32Arg(optarg, "-offset", &asn1Config.offset);
                break;

            case WOLFCLU_LENGTH:
                ret = checkWord32Arg(optarg, "-length", &asn1Config.length);
                if (ret == WOLFCLU_SUCCESS && asn1Config.length == 0) {
                    wolfCLU_LogError("-length arg must be greater than 0");
                    ret = WOLFCLU_FATAL_ERROR;
                }
                break;

            case WOLFCLU_STRPARSE:
                ret = checkStrParse(optarg, &asn1Config.strParseSz,
                                    WOLFCLU_ASN1_STR_PARSE_CAP,
                                    asn1Config.strParse);
                break;

            case WOLFCLU_NOOUT:
                asn1Config.noOut = 1;
                break;

            case WOLFCLU_DUMP:
                asn1Config.dump = 1;
                break;

            case WOLFCLU_INDENT:
                asn1Config.indent = 1;
                break;

            case WOLFCLU_HELP:
                wolfCLU_Asn1Help();
                Asn1ParseOptions_clean_up(&asn1Config);
                return WOLFCLU_SUCCESS;

            case ARG_FOUND_TWICE:
                ret = WOLFCLU_FATAL_ERROR;
                break;

            case '?':
            default:
                /* Unreachable */
                wolfCLU_LogError("Error getting arguments");
                ret = WOLFCLU_FATAL_ERROR;
                break;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = wolfCLU_Asn1Parse(&asn1Config);
    }

    Asn1ParseOptions_clean_up(&asn1Config);
    return ret;
#else
#if !defined(WOLFSSL_ASN_PRINT)
    wolfCLU_LogError("WOLFSSL_ASN_PRINT option not set. Cannot parse Asn1.");
#endif /* !defined(WOLFSSL_ASN_PRINT) */
#if defined(NO_FILESYSTEM)
    wolfCLU_LogError("NO_FILESYSTEM option is set. Cannot parse Asn1.");
#endif /* defined(NO_FILESYSTEM) */
    return WOLFCLU_FATAL_ERROR;
#endif /* defined(WOLFSSL_ASN_PRINT) && !defined(NO_FILESYSTEM) */
}
