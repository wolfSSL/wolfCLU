/* clu_asn1.h
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

#ifndef CLU_ASN1_H
#define CLU_ASN1_H

#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#include <wolfclu/clu_error_codes.h>
#include <wolfclu/clu_header_main.h>
#include <wolfclu/clu_log.h>
#include <wolfclu/clu_optargs.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/wc_port.h>

/* number of str parse "digs" allowed */
#ifndef WOLFCLU_ASN1_STR_PARSE_CAP
    #define WOLFCLU_ASN1_STR_PARSE_CAP 10
#endif

typedef struct WOLFCLU_ASN1_PARSE_OPTIONS
#if !defined(NO_FILESYSTEM) && defined(WOLFSSL_ASN_PRINT)
{
    XFILE  inputFile;
    XFILE  outputFile;
    XFILE  oidFile;
    Asn1OidToNameCb  nameCb;
    word32 strParse[WOLFCLU_ASN1_STR_PARSE_CAP];
    word32 strParseSz;
    word32 length;
    word32 offset;
    word8  inForm;
    word8  dump;
    word8  indent;
    word8  noOut;
}
#endif
WOLFCLU_ASN1_PARSE_OPTIONS;

enum {
WOLFCLU_ASN1_DER = 0,
WOLFCLU_ASN1_B64,
WOLFCLU_ASN1_PEM,
};

/* Entry point for the asn1parse command. Parses argc/argv into a
 * WOLFCLU_ASN1_PARSE_OPTIONS struct and hands off to wolfCLU_Asn1Parse().
 * Returns WOLFCLU_SUCCESS on success. */
int wolfCLU_Asn1Setup(int argc, char* argv[]);

/* Performs the ASN.1 operation described by parseOptions: decodes the input
 * (DER, base64 or PEM), applies the offset/length/string-parse selections, and
 * writes the formatted structure to the configured output target(s).
 * Returns WOLFCLU_SUCCESS on success. */
int wolfCLU_Asn1Parse(WOLFCLU_ASN1_PARSE_OPTIONS* parseOptions);

#endif
