/* clu_asn1_parse.c
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

#include <wolfclu/clu_log.h>
#include <wolfclu/clu_error_codes.h>
#include <wolfclu/clu_header_main.h>
#include <wolfclu/asn1/clu_asn1.h>
#include <wolfclu/asn1/clu_oid_name_table.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/wc_port.h>

#if defined(WOLFSSL_ASN_PRINT) && !defined(WOLFCLU_NO_FILESYSTEM)

static int Asn1Print(Asn1 *asn1, const WOLFCLU_ASN1_PARSE_OPTIONS *opts)
{
    int ret = WOLFCLU_SUCCESS;
    Asn1PrintOptions PrintOpts = { 0 };

    /* wc_Asn1_Init (called once in wolfCLU_Asn1Parse) leaves the output
     * file as XBADFILE; point it at stdout and wire up the OID-to-name
     * callback before printing the tree. */
    if (wc_Asn1_SetFile(asn1, stdout) != 0)
        return WOLFCLU_FATAL_ERROR;

    if (wc_Asn1_SetOidToNameCb(asn1, opts->nameCb) != 0)
        return WOLFCLU_FATAL_ERROR;

    if (wc_Asn1PrintOptions_Init(&PrintOpts) != 0)
        return WOLFCLU_FATAL_ERROR;
    /* wolfSSL only honours the indent when branch drawing is off, so -i
     * swaps the default branch drawing for an indent of one space per
     * depth. */
    if (wc_Asn1PrintOptions_Set(&PrintOpts, ASN1_PRINT_OPT_INDENT,
                                opts->indent) != 0)
        return WOLFCLU_FATAL_ERROR;
    if (wc_Asn1PrintOptions_Set(&PrintOpts, ASN1_PRINT_OPT_DRAW_BRANCH,
                                !opts->indent) != 0)
        return WOLFCLU_FATAL_ERROR;

    /* this shows the hex in a readable print out and hides only the text
     * form of INTEGER, BIT STRING and OCTET STRING data so it is not reported
     * twice; OID names and string values are still printed */
    if (wc_Asn1PrintOptions_Set(&PrintOpts, ASN1_PRINT_OPT_SHOW_DATA,
                                opts->dump) != 0)
        return WOLFCLU_FATAL_ERROR;
    if (wc_Asn1PrintOptions_Set(&PrintOpts, ASN1_PRINT_OPT_SHOW_NO_DUMP_TEXT,
                                opts->dump) != 0)
        return WOLFCLU_FATAL_ERROR;

    ret = wc_Asn1_PrintAll(asn1, &PrintOpts, asn1->data, asn1->max);

    if (ret == 0) {
        ret = WOLFCLU_SUCCESS;
    }
    else {
        wolfCLU_LogError("%s", wc_GetErrorString(ret));
        ret = WOLFCLU_FATAL_ERROR;
    }
    return ret;
}

/* Apply the -strparse offsets in po->strParse in order. Each entry is an
 * absolute byte offset from the current position to an OCTET STRING or BIT
 * STRING whose contents are themselves ASN.1; the parser descends into that
 * content so the next offset (and the final print) operate on the nested
 * structure. Only asn1->data and asn1->max are updated, as they are all
 * Asn1Print reads. Returns WOLFCLU_SUCCESS on success or a negative error
 * code.
 */
static int StrParse(Asn1 *asn1, const WOLFCLU_ASN1_PARSE_OPTIONS *po)
{
    int ret = WOLFCLU_SUCCESS;
    word32 i;

    for (i = 0; i < po->strParseSz; i++) {
        const byte *data;
        word32 max;
        word32 idx = 0;
        byte tag;
        int len;

        /* Need at least one byte (the tag) available at the jump target. */
        if (po->strParse[i] >= asn1->max) {
            ret = WOLFCLU_FATAL_ERROR;
            wolfCLU_LogError("-strparse entry %u (offset %u) "
                             "tried to jump to invalid location. "
                             "Unable to parse",
                             i + 1, po->strParse[i]);
            break;
        }

        /* Advance into the buffer and shrink the remaining length to match so
         * later bounds checks stay accurate. */
        data = asn1->data + po->strParse[i];
        max = asn1->max - po->strParse[i];

        /* Only primitive strings are accepted: a constructed (BER) string
         * holds segments, not the nested DER directly. */
        tag = data[idx++];
        if (tag != ASN_OCTET_STRING && tag != ASN_BIT_STRING) {
            ret = WOLFCLU_FATAL_ERROR;
            wolfCLU_LogError("-strparse entry %u (offset %u) did not find an "
                             "OCTET STRING or BIT STRING. Unable to parse",
                             i + 1, po->strParse[i]);
            break;
        }

        /* Decode length and step over it. GetLength also fails when the
         * length runs past max. */
        if (GetLength(data, &idx, &len, max) < 0) {
            ret = WOLFCLU_FATAL_ERROR;
            wolfCLU_LogError("-strparse entry %u (offset %u) has an invalid "
                             "length encoding or its length runs past the "
                             "end of the buffer",
                             i + 1, po->strParse[i]);
            break;
        }

        if (len <= 0) {
            ret = WOLFCLU_FATAL_ERROR;
            wolfCLU_LogError("-strparse entry %u (offset %u) has a length "
                             "of 0", i + 1, po->strParse[i]);
            break;
        }

        /* Defence in depth: GetLength already rejects a length that does
         * not fit within the bytes remaining after the tag and length
         * octets. */
        if ((word32)len > max - idx) {
            ret = WOLFCLU_FATAL_ERROR;
            wolfCLU_LogError("-strparse entry %u (offset %u) decoded length "
                             "runs past the end of the buffer. Unable to "
                             "parse", i + 1, po->strParse[i]);
            break;
        }

        /* A BIT STRING only holds nested DER when its leading unused-bits
         * octet is 0 and something follows it. */
        if (tag == ASN_BIT_STRING) {
            if (len < 2 || data[idx] != 0) {
                ret = WOLFCLU_FATAL_ERROR;
                wolfCLU_LogError("-strparse entry %u (offset %u) BIT STRING "
                                 "has no nested DER (empty or non-zero unused "
                                 "bits)", i + 1, po->strParse[i]);
                break;
            }
            idx++;
            len--;
        }

        /* treat the string contents as a fresh object */
        asn1->data = (byte *)data + idx;
        asn1->max = (word32)len;
    }

    return ret;
}

/* Apply data altering options to raw input before printing
 *
 * return WOLFCLU_SUCCESS on success,
 * WOLFCLU_FATAL_ERROR otherwise */
static int Asn1Fmt(Asn1 *asn1, const WOLFCLU_ASN1_PARSE_OPTIONS *opts,
                   byte *data, word32 dataSz)
{
    int ret = WOLFCLU_SUCCESS;

    /* e.g. a PEM header and footer with no body between them */
    if (dataSz == 0) {
        wolfCLU_LogError("No data to parse");
        return WOLFCLU_FATAL_ERROR;
    }

    /* -strparse descends from the start of the whole input and
     * -offset/-length then select bytes within the result. */
    asn1->data = data;
    asn1->max = dataSz;

    if (opts->strParseSz != 0) {
        ret = StrParse(asn1, opts);
    }

    /* Reject an offset that points past the end of the buffer. Both values
     * are word32, so an out-of-range offset would make the length below
     * underflow and produce a near-4GB out-of-bounds read. */
    if (ret == WOLFCLU_SUCCESS && opts->offset >= asn1->max) {
        wolfCLU_LogError("-offset %u is past the end of the data to parse "
                         "(%u bytes)", opts->offset, asn1->max);
        ret = WOLFCLU_FATAL_ERROR;
    }

    if (ret == WOLFCLU_SUCCESS) {
        asn1->data += opts->offset;
        asn1->max -= opts->offset;
        /* A user supplied length that runs past the end is clamped to the
         * bytes remaining. */
        if (opts->length > 0 && opts->length < asn1->max) {
            asn1->max = opts->length;
        }
    }

    return ret;
}

/* Writes the ASN.1 DER encoding to the output file in po->outputPath,
 * applying -strparse and then the offset/length bounds from po to
 * data/dataSz. Prints the
 * tree output to stdout
 *
 * Returns WOLFCLU_SUCCESS on success.
 * */
static int wolfCLU_Asn1Write(Asn1 *asn1, const WOLFCLU_ASN1_PARSE_OPTIONS *opts,
                             byte *data, word32 dataSz)
{
    int ret = WOLFCLU_SUCCESS;

    if (asn1 == NULL || opts == NULL || data == NULL) {
        wolfCLU_LogError("Illegal null argument. Could not write asn1 data");
        return WOLFCLU_FATAL_ERROR;
    }

    /* Handle offsets, strparse, etc... */
    ret = Asn1Fmt(asn1, opts, data, dataSz);

    if (ret == WOLFCLU_SUCCESS && opts->outputPath != NULL) {
        /* opened here, after the input is in memory, so -out may be the
         * same file as -in */
        XFILE out = XFOPEN(opts->outputPath, "wb");
        if (out == XBADFILE) {
            wolfCLU_LogError("Unable to open file passed by -out : %s",
                             opts->outputPath);
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            if (XFWRITE(asn1->data, 1, asn1->max, out) != asn1->max) {
                wolfCLU_LogError("Unable to write to file passed by -out");
                ret = WOLFCLU_FATAL_ERROR;
            }
            XFCLOSE(out);
        }
    }

    if (!opts->noOut && ret == WOLFCLU_SUCCESS) {
        ret = Asn1Print(asn1, opts);
    }

    return ret;
}

/* Find the next PEM block.
 *
 * @param [in]  data    PEM data.
 * @param [in]  offset  Offset into data to start looking.
 * @param [in]  len     Length of PEM data.
 * @param [out] start   Start of Base64 encoding.
 * @param [out] end     End of Base64 encoding.
 */
static int FindPem(unsigned char *data, word32 offset, word32 len,
                   word32 *start, word32 *end)
{
    int ret = WOLFCLU_SUCCESS;
    word32 i = 0;
    word32 j = 0;

    /* Find header. */
    for (i = offset; i < len; i++) {
        if ((data[i] == '-') &&
            (XSTRNCMP((char *)data + i, "-----BEGIN", 10) == 0)) {
            i += (sizeof("-----BEGIN") - 1); /* Skip -----BEGIN text */
            break;
        }
    }
    if (i == len) {
        /* Got to end without finding PEM header. */
        wolfCLU_LogError("No PEM header found");
        ret = WOLFCLU_FATAL_ERROR;
    }
    if (ret == WOLFCLU_SUCCESS) {
        /* Confirm header. */
        for (; i < len; i++) {
            if ((data[i] == '-') &&
                (XSTRNCMP((char *)data + i, "-----", 5) == 0)) {
                break;
            }
        }
        if (i == len) {
            /* Got to end without finding rest of PEM header. */
            wolfCLU_LogError("Invalid PEM header");
            ret = WOLFCLU_FATAL_ERROR;
        }
        i += sizeof("-----") - 1;
    }
    if (ret == WOLFCLU_SUCCESS) {
        /* Find footer. */
        for (j = i + 1; j < len; j++) {
            if ((data[j] == '-') &&
                (XSTRNCMP((char *)data + j, "-----END", 8) == 0)) {
                break;
            }
        }
        if (j >= len) {
            /* Got to end without finding PEM footer. */
            wolfCLU_LogError("No PEM footer found");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        /* Return start and end indices. */
        *start = i;
        *end = j;
    }
    return ret;
}

/* Allocate buffer to read returns length of file read if success.
 * and returns negative code on failure. An empty file succeeds with a
 * length of 0; the caller decides whether that is an error. */
static long asn1_ReadFile(XFILE fp, byte **buffer, word32 *bufLen)
{
    long fileLen;

    if (fp == NULL) {
        return WOLFCLU_FATAL_ERROR;
    }

    if (XFSEEK(fp, 0, SEEK_END) != 0) {
        return WOLFCLU_FATAL_ERROR;
    }

    /* XFTELL returns a signed long; check it before narrowing to word32 so an
     * error (-1) is not mistaken for a ~4GB length. */
    fileLen = XFTELL(fp);
    if (fileLen < 0) {
        return WOLFCLU_FATAL_ERROR;
    }

    /* A file at or below 0x7FFFFFFEU still lets the +1 for the null terminator
     * fit in a int (windows); anything larger would overflow the length below, so
     * reject it here rather than allocate and read a near-2GB buffer. */
    if (fileLen > (0x7FFFFFFEU)) {
        wolfCLU_LogError("File is longer than 0x7FFFFFFEU byte max");
        return WOLFCLU_FATAL_ERROR;
    }

    if (XFSEEK(fp, 0, SEEK_SET) != 0) {
        return WOLFCLU_FATAL_ERROR;
    }
    /* add 1 for null terminator */
    *buffer = (byte *)XMALLOC(fileLen + 1, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (*buffer == NULL) {
        return MEMORY_E;
    }

    if (fileLen > 0 &&
        XFREAD(*buffer, sizeof(char), fileLen, fp) != (word32)fileLen) {
        XFREE(*buffer, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        *buffer = NULL;
        return WOLFCLU_FATAL_ERROR;
    }
    (*buffer)[fileLen] = '\0'; /* add null terminator */

    if (bufLen != NULL) {
        *bufLen = (word32)fileLen;
    }
    return fileLen;
}

static int WOLFCLU_OID_TO_NAME_free(WOLFCLU_OID_TO_NAME *p)
{
    if (p->dataBuffer != NULL) {
        XFREE(p->dataBuffer, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }

    if (p->entries != NULL) {
        XFREE(p->entries, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }

    XMEMSET(p, 0, sizeof(*p));

    return WOLFCLU_SUCCESS;
}

#define OID_FILE_IS_SPACE(c) ((c) == ' ' || (c) == '\t' || (c) == '\r')

/* return WOLFCLU_SUCCESS if successful
 * if this function returns success you must call
 * WOLFCLU_OID_TO_NAME_free. */
static int WOLFCLU_OID_TO_NAME_initWFile(WOLFCLU_OID_TO_NAME *newOids, XFILE fp)
{
#ifdef WOLFCLU_OID_ENCODE
    int ret = WOLFCLU_SUCCESS;
    byte *fileBuffer;
    char *line;
    char *nextLine;
    word32 lineNum = 0;

    if (newOids == NULL) {
        wolfCLU_LogError("WOLFCLU_OID_TO_NAME was null");
        return WOLFCLU_FATAL_ERROR;
    }

    XMEMSET(newOids, 0, sizeof(*newOids));

    if (asn1_ReadFile(fp, &fileBuffer, NULL) < 0) {
        wolfCLU_LogError("Error reading -oid file");
        return WOLFCLU_FATAL_ERROR;
    }

    /* file format is <byte string> <shortname> <longName>\n
     * we load the first token and go until error or all lines are hit
     * and loaded */
    /* walk lines by hand rather than XSTRTOK so blank lines are counted */
    for (line = (char *)fileBuffer; ret == WOLFCLU_SUCCESS && line != NULL;
         line = nextLine) {
        OidName *currentName;
        char *lineCursor = NULL;
        char *oid;
        char *shortName;
        char *longName;
        char *lineEnd;
        word32 oidSz;

        lineNum++;
        nextLine = XSTRSTR(line, "\n");
        if (nextLine != NULL) {
            *nextLine++ = '\0';
        }

        /* trim surrounding whitespace, including the '\r' of CRLF files */
        while (OID_FILE_IS_SPACE(*line)) {
            line++;
        }
        lineEnd = line + XSTRLEN(line);
        while (lineEnd > line && OID_FILE_IS_SPACE(lineEnd[-1])) {
            *--lineEnd = '\0';
        }
        if (*line == '\0') {
            continue; /* blank line */
        }

        oid = XSTRTOK(line, " \t", &lineCursor);
        shortName = XSTRTOK(NULL, " \t", &lineCursor);
        /* long name is the rest of the line and may contain spaces */
        longName = XSTRTOK(NULL, "\n", &lineCursor);
        while (longName != NULL && OID_FILE_IS_SPACE(*longName)) {
            longName++;
        }
        if (shortName == NULL || longName == NULL || *longName == '\0') {
            wolfCLU_LogError("malformed tokens, check line %u for bad "
                             "formatting; wanted <oid> <short name> "
                             "<long name>", lineNum);
            ret = WOLFCLU_FATAL_ERROR;
            break;
        }

        /* DER is never longer than the dotted form, so encode in place */
        oidSz = (word32)XSTRLEN(oid);
        if (wolfCLU_OidStrToDer(oid, (byte *)oid, &oidSz) != WOLFCLU_SUCCESS) {
            wolfCLU_LogError("Could not convert Oid to der check line %u",
                             lineNum);
            ret = WOLFCLU_FATAL_ERROR;
            break;
        }

        if (newOids->cap <= newOids->len) {
            OidName *tmp;
            tmp = (OidName *)XREALLOC(newOids->entries,
                    sizeof(*newOids->entries) * (newOids->cap + 10), HEAP_HINT,
                    DYNAMIC_TYPE_TMP_BUFFER);
            if (tmp == NULL) {
                ret = MEMORY_E;
                break;
            }
            newOids->entries = tmp;
            newOids->cap += 10;
        }
        currentName = &newOids->entries[newOids->len++];
        currentName->name = longName;
        currentName->oid = (byte *)oid;
        currentName->len = oidSz;
    }

    newOids->dataBuffer = fileBuffer;

    if (ret != WOLFCLU_SUCCESS) {
        wolfCLU_LogError("Error parsing file passed to -oid flag");
        WOLFCLU_OID_TO_NAME_free(newOids);
    }

    return ret;
#else
    (void)newOids;
    (void)fp;
    wolfCLU_LogError("wolfSSL is not configured to handle encoding oids");
    return WOLFCLU_FATAL_ERROR;
#endif /* WOLFCLU_OID_ENCODE */
}

/* Callback that wolfSSL uses to assign byte oids to names */
static WOLFCLU_OID_TO_NAME asn1parse_AdditionalOidNames = { 0 };
static const char *OidToNameCallback(unsigned char *oid, word32 len)
{
    word32 i;
    for (i = 0; i < asn1parse_AdditionalOidNames.len; i++) {
        if ((len == asn1parse_AdditionalOidNames.entries[i].len) &&
            (XMEMCMP(oid, asn1parse_AdditionalOidNames.entries[i].oid, len) ==
             0)) {
            return asn1parse_AdditionalOidNames.entries[i].name;
        }
    }

    for (i = 0; i < oid_names_len; i++) {
        if ((len == oid_name_table[i].len) &&
            (XMEMCMP(oid, oid_name_table[i].oid, len) == 0)) {
            return oid_name_table[i].name;
        }
    }

    return NULL;
}

/* Decode the input data from base64 based on file type */
static int HandleProcessing(const WOLFCLU_ASN1_PARSE_OPTIONS *po,
                            byte **inputFileBuffer, word32 *inputFileLen)
{
    int ret = WOLFCLU_SUCCESS;
    word32 i = 0;
    word32 j = 0;

    if (po == NULL)
        return WOLFCLU_FATAL_ERROR;

    switch (po->inForm) {
        case WOLFCLU_ASN1_PEM:
            /* Find start and end of PEM Base64 data. */
            ret = FindPem(*inputFileBuffer, j, *inputFileLen, &i, &j);
            /* Decode data between header and footer. */
            if ((ret == WOLFCLU_SUCCESS) &&
                (Base64_Decode((*inputFileBuffer) + i, j - i, *inputFileBuffer,
                               inputFileLen) != 0)) {
                wolfCLU_LogError("PEM input is not base64 encoded");
                ret = WOLFCLU_FATAL_ERROR;
            }
            break;

        case WOLFCLU_ASN1_B64:
            if (Base64_Decode(*inputFileBuffer, *inputFileLen, *inputFileBuffer,
                              inputFileLen) != 0) {
                wolfCLU_LogError("input is not base64 encoded");
                ret = WOLFCLU_FATAL_ERROR;
            }
            break;

        case WOLFCLU_ASN1_DER:
            /* DER is parsed as-is; this is also the default when -inform is
             * not supplied (asn1Config.inForm is initialized to DER). */
            break;

        default:
            wolfCLU_LogError("Unsupported input format");
            ret = WOLFCLU_FATAL_ERROR;
            break;
    }

    return ret;
}
#endif /* defined(WOLFSSL_ASN_PRINT) && !defined(WOLFCLU_NO_FILESYSTEM) */

/* Performs the ASN.1 operation described by parseOptions: decodes the input
 * (DER, base64 or PEM), applies the offset/length/string-parse selections, and
 * writes the formatted structure to the configured output target(s).
 * Returns WOLFCLU_SUCCESS on success. */
int wolfCLU_Asn1Parse(WOLFCLU_ASN1_PARSE_OPTIONS *po)
{
#if defined(WOLFSSL_ASN_PRINT) && !defined(WOLFCLU_NO_FILESYSTEM)
    int ret = WOLFCLU_SUCCESS;
    byte *inputFileBuffer = NULL;
    word32 inputFileLen = 0;
    Asn1 asn1Master = { 0 };

    if (po == NULL)
        return USER_INPUT_ERROR;

    if (po->oidFile != NULL) {
        ret = WOLFCLU_OID_TO_NAME_initWFile(&asn1parse_AdditionalOidNames,
                                            po->oidFile);
    }

    if (po->nameCb == NULL) {
        po->nameCb = OidToNameCallback;
    }

    if (ret == WOLFCLU_SUCCESS && po->noOut && po->outputPath == NULL) {
        ret = WOLFCLU_FATAL_ERROR;
        wolfCLU_LogError("No output file given and -noout set");
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = wc_Asn1_Init(&asn1Master) == 0 ? WOLFCLU_SUCCESS
                                             : WOLFCLU_FATAL_ERROR;
    }

    if (ret == WOLFCLU_SUCCESS) {
        if (po->inputFile == NULL) {
            ret = WOLFCLU_FATAL_ERROR;
            wolfCLU_LogError("Must have input via file passed to -in");
        }

        if (ret == WOLFCLU_SUCCESS) {
            if (asn1_ReadFile(po->inputFile, &inputFileBuffer, &inputFileLen) <
                0) {
                ret = WOLFCLU_FATAL_ERROR;
                wolfCLU_LogError("Could not read input file");
            }
            else if (inputFileLen == 0) {
                ret = WOLFCLU_FATAL_ERROR;
                wolfCLU_LogError("Input file is empty");
            }
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = HandleProcessing(po, &inputFileBuffer, &inputFileLen);
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = wolfCLU_Asn1Write(&asn1Master, po, inputFileBuffer, inputFileLen);
        /* DER is the default, so a PEM file passed without -inform lands
         * here; the buffer is untouched (and null terminated) for DER */
        if (ret != WOLFCLU_SUCCESS && po->inForm == WOLFCLU_ASN1_DER &&
            XSTRSTR((char *)inputFileBuffer, "-----BEGIN") != NULL) {
            wolfCLU_LogError("Input looks like PEM, try -inform PEM");
        }
    }

    if (inputFileBuffer != NULL) {
        XFREE(inputFileBuffer, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }
    WOLFCLU_OID_TO_NAME_free(&asn1parse_AdditionalOidNames);
    return ret;
#else
#if !defined(WOLFSSL_ASN_PRINT)
    wolfCLU_LogError("WOLFSSL_ASN_PRINT option not set. Cannot parse Asn1.");
#endif
#if defined(WOLFCLU_NO_FILESYSTEM)
    wolfCLU_LogError("WOLFCLU_NO_FILESYSTEM option is set. Cannot parse Asn1.");
#endif
    return WOLFCLU_FATAL_ERROR;
#endif /* defined(WOLFSSL_ASN_PRINT) && !defined(WOLFCLU_NO_FILESYSTEM) */
}
