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

#if defined(WOLFSSL_ASN_PRINT) && !defined(NO_FILESYSTEM)


static int Asn1Print(Asn1* asn1, const WOLFCLU_ASN1_PARSE_OPTIONS* opts)
{
    int ret = WOLFCLU_SUCCESS;
    Asn1PrintOptions PrintOpts = {0};

    /* wc_Asn1_Init (called once in wolfCLU_Asn1Parse) leaves the output
     * file as XBADFILE; point it at stdout and wire up the OID-to-name
     * callback before printing the tree. */
    if (wc_Asn1_SetFile(asn1, stdout) != 0)
        return WOLFCLU_FATAL_ERROR;

    if (wc_Asn1_SetOidToNameCb(asn1, opts->nameCb) != 0)
        return WOLFCLU_FATAL_ERROR;

    if (wc_Asn1PrintOptions_Init(&PrintOpts) != 0)
        return WOLFCLU_FATAL_ERROR;
    if (wc_Asn1PrintOptions_Set(&PrintOpts, ASN1_PRINT_OPT_INDENT,
            opts->indent) != 0)
        return WOLFCLU_FATAL_ERROR;
    if (wc_Asn1PrintOptions_Set(&PrintOpts, ASN1_PRINT_OPT_DRAW_BRANCH,
            1) != 0)
        return WOLFCLU_FATAL_ERROR;

    /* this shows the hex in a readable print out and hides text data
     * so there is no double reporting on BIT STRING and OCTET STRINGS */
    if (wc_Asn1PrintOptions_Set(&PrintOpts, ASN1_PRINT_OPT_SHOW_DATA,
            opts->dump) != 0)
        return WOLFCLU_FATAL_ERROR;
    if (wc_Asn1PrintOptions_Set(&PrintOpts, ASN1_PRINT_OPT_SHOW_OID,
            opts->dump) != 0)
        return WOLFCLU_FATAL_ERROR;
    if (wc_Asn1PrintOptions_Set(&PrintOpts, ASN1_PRINT_OPT_SHOW_NO_TEXT,
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

enum {
    /* Expecting tag part of ASN.1 item. */
    ASN_PART_TAG = 0,
    /* Expecting length part of ASN.1 item. */
    ASN_PART_LENGTH,
    /* Expecting data part of ASN.1 item. */
    ASN_PART_DATA,
};


/* Apply the -strparse offsets in po->strParse in order. Each entry is an
 * absolute byte offset from the current position to an OCTET STRING or BIT
 * STRING whose contents are themselves ASN.1; the parser descends into that
 * content so the next offset (and the final print) operate on the nested
 * structure. Returns WOLFCLU_SUCCESS on success or a negative error code.
 */
static int StrParse(Asn1* asn1, const WOLFCLU_ASN1_PARSE_OPTIONS* po)
{
    int ret = WOLFCLU_SUCCESS;
    word32 idx = 0;

    for (; idx < po->strParseSz; idx++) {
        int len;

        /* Need at least one byte (the tag) available at the jump target. */
        if (po->strParse[idx] >= asn1->max) {
            ret = WOLFCLU_FATAL_ERROR;
            wolfCLU_LogError("-strparse %u with value %u "
                    "tried to jump to invalid location. "
                    "Unable to parse", idx, po->strParse[idx]);
            break;
        }

        /* Advance into the buffer and shrink the remaining length to match so
         * later bounds checks stay accurate. */
        asn1->data = asn1->data + po->strParse[idx];
        asn1->max  = asn1->max - po->strParse[idx];

        /* Mask off the constructed bit to compare the base tag. */
        asn1->item.tag = asn1->data[asn1->curr] & (byte)~ASN_CONSTRUCTED;

        if (asn1->item.tag != ASN_OCTET_STRING &&
                asn1->item.tag != ASN_BIT_STRING) {
            ret = WOLFCLU_FATAL_ERROR;
            wolfCLU_LogError("-strparse %u with value %u "
                    "did not find an octet string "
                    "unable to parse", idx, po->strParse[idx]);
            break;
        }

        asn1->curr++;

        asn1->part = ASN_PART_LENGTH;

        /* Decode length and step over it. */
        if (GetLength(asn1->data, &asn1->curr, &len, asn1->max) < 0) {
            ret = WOLFCLU_FATAL_ERROR;
            break;
        }

        /* The decoded length must fit within the bytes remaining after the
         * tag and length octets. */
        if (len < 0 || (word32)len > asn1->max - asn1->curr) {
            ret = WOLFCLU_FATAL_ERROR;
            wolfCLU_LogError("-strparse %u decoded length runs past the end "
                    "of the buffer. Unable to parse", idx);
            break;
        }

        if (asn1->item.tag == ASN_BIT_STRING) {
            if (len < 1) {
                ret = WOLFCLU_FATAL_ERROR;
                wolfCLU_LogError("-strparse %u BIT STRING has no content", idx);
                break;
            }
            asn1->curr++;
            len--;
        }

        /* reset data structure to treat the new data as a fresh object */
        asn1->data = asn1->data + (asn1->curr);
        asn1->curr = 0;
        asn1->depth = 0;
        asn1->max = len;
        asn1->part = ASN_PART_TAG;
    }

    return ret;
}

/* Apply data altering options to raw input before printing
 *
 * return WOLFCLU_SUCCESS on success,
 * WOLFLCU_FATAL_ERROR otherwise */
static int Asn1Fmt(Asn1* asn1, const WOLFCLU_ASN1_PARSE_OPTIONS* opts,
                      byte* data, word32 dataSz)
{
    int ret = WOLFCLU_SUCCESS;
    /* Reject an offset that points past the end of the buffer. Both values
     * are word32, so an out-of-range offset would make the length below
     * underflow and produce a near-4GB out-of-bounds read. */
    if (opts->offset > dataSz) {
        wolfCLU_LogError("-offset %u is past the end of the input (%u bytes)",
                opts->offset, dataSz);
        return WOLFCLU_FATAL_ERROR;
    }

    /* A user supplied length must fit within the bytes remaining after the
     * offset. */
    if (opts->length > 0 && opts->length > dataSz - opts->offset) {
        wolfCLU_LogError("-length %u runs past the end of the input "
                "(%u bytes remaining after offset)",
                opts->length, dataSz - opts->offset);
        return WOLFCLU_FATAL_ERROR;
    }

    /* Store the starting point of the data to parse. */
    asn1->data = data + opts->offset;
    if (opts->length > 0) {
        /* Use user specified maximum length. */
        asn1->max = opts->length;
    }
    else {
        /* Maximum length is up to end from offset. */
        asn1->max = dataSz - opts->offset;
    }

    if (ret == WOLFCLU_SUCCESS && opts->strParseSz != 0) {
        ret = StrParse(asn1, opts);
    }

    return ret;
}

/* Writes the ASN.1 DER encoding to the output file in po->outputfile,
 * applying the offset/length bounds from po to data/dataSz. Prints the
 * tree output to stdout
 *
 * Returns WOLFCLU_SUCCESS on success.
 * */
static int wolfCLU_Asn1Write(Asn1* asn1,
        const WOLFCLU_ASN1_PARSE_OPTIONS* opts, byte* data, word32 dataSz)
{
    int ret = WOLFCLU_SUCCESS;

    if (asn1 == NULL || opts == NULL || data == NULL) {
        wolfCLU_LogError("Illegal null argument. Could not write asn1 data");
        return WOLFCLU_FATAL_ERROR;
    }

    /* Handle offsets, strparse, etc... */
    ret = Asn1Fmt(asn1, opts, data, dataSz);

    if (ret == WOLFCLU_SUCCESS && opts->outputFile != NULL) {
        if (XFWRITE(asn1->data, 1, asn1->max, opts->outputFile) != asn1->max) {
            wolfCLU_LogError("Unable to write to file passed by -out");
            ret = WOLFCLU_FATAL_ERROR;
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
static int FindPem(unsigned char* data, word32 offset, word32 len,
    word32* start, word32* end)
{
    int ret = WOLFCLU_SUCCESS;
    word32 i = 0;
    word32 j = 0;

    /* Find header. */
    for (i = offset; i < len; i++) {
        if ((data[i] == '-') &&
                (XSTRNCMP((char*)data + i, "-----BEGIN", 10) == 0)) {
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
                    (XSTRNCMP((char*)data + i, "-----", 5) == 0)) {
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
                    (XSTRNCMP((char*)data + j, "-----END", 8) == 0)) {
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
 * and returns negative code on failure. */
static long asn1_ReadFile(XFILE fp, byte** buffer, word32* bufLen)
{
    long fileLen;

    if (fp == NULL) {
        return WOLFCLU_FATAL_ERROR;
    }

    if (XFSEEK(fp, 0,SEEK_END) != 0) {
        return WOLFCLU_FATAL_ERROR;
    }

    /* XFTELL returns a signed long; check it before narrowing to word32 so an
     * error (-1) or empty file is not mistaken for a ~4GB length. */
    fileLen = XFTELL(fp);
    if (fileLen <= 0) {
        return WOLFCLU_FATAL_ERROR;
    }

    /* A file at or below 0xFFFFFFEU still lets the +1 for the null terminator
     * fit in a int (windows); anything larger would overflow the length below, so
     * reject it here rather than allocate and read a near-2GB buffer. */
    if (fileLen > (0xFFFFFFEU)) {
        wolfCLU_LogError("File is longer than 0xFFFFFFEU byte max");
        return WOLFCLU_FATAL_ERROR;
    }

    if (XFSEEK(fp, 0,SEEK_SET) != 0) {
        return WOLFCLU_FATAL_ERROR;
    }
    /* add 1 for null terminator */
    *buffer = (byte*)XMALLOC(fileLen + 1, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if(*buffer == NULL) {
        return MEMORY_E;
    }

    if (XFREAD(*buffer, sizeof(char), fileLen, fp) != (word32)fileLen) {
        XFREE(*buffer, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        *buffer = NULL;
        return WOLFCLU_FATAL_ERROR;
    }
    (*buffer)[fileLen] = '\0';/* add null terminator */

    if (bufLen != NULL) {
        *bufLen = (word32)fileLen;
    }
    return fileLen;
}

static int WOLFCLU_OID_TO_NAME_free(WOLFCLU_OID_TO_NAME* p)
{
    if (p->dataBuffer != NULL) {
        XFREE(p->dataBuffer, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }

    if (p->entries != NULL) {
        XFREE(p->entries , HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }

    wc_ForceZero(p, sizeof(*p));

    return WOLFCLU_SUCCESS;
}

/* take in dot separated oid string and fill it with Der encoding *
*  return wolfCLU_SUCCESS on success */
static int OidToDer(char* oid, word32* oidSz)
{
#ifndef NO_WC_ENCODE_OBJECT_ID
    int ret = WOLFCLU_SUCCESS;
    int err;
    int idx = 0;
    char* token;
    char* end;
    word32* arc = (word32*)XMALLOC(sizeof(*arc) * *oidSz,
            HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (arc == NULL) {
        return MEMORY_E;
    }

    token = XSTRTOK(oid, ".", &end);
    while (token != NULL && ret == WOLFCLU_SUCCESS) {
        word32 tmp = 0;
        if (wolfCLU_StrToWord32(token, XSTRLEN(token), &tmp)
                == WOLFCLU_SUCCESS) {
            arc[idx++] = tmp;
        }
        else{
            wolfCLU_LogError("Could not parse oid dot form");
            ret = WOLFCLU_FATAL_ERROR;
            break;
        }
        token = XSTRTOK(NULL, ".", &end);
    }

    if (ret == WOLFCLU_SUCCESS) {
        /* oid is overwritten by and replaces with DER encoding */
        XMEMSET(oid, '\0', *oidSz);
        if ((err = wc_EncodeObjectId(arc, idx, (byte*)oid, oidSz)) != 0) {
            wolfCLU_LogError("%s", wc_GetErrorString(err));
            ret = WOLFCLU_FATAL_ERROR;
        }
    }


    XFREE(arc, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
#else
    wolfCLU_LogError("Old Version of wolfSSL %s must be greater than 5.9.2 to "
            "use custom oids", WOLFSSL_VERSION);
    (void)oid;
    (void)oidSz;
    return WOLFCLU_FATAL_ERROR;
#endif

}

/* return WOLFCLU_SUCCESS if successful
 * if this function returns success you must call
 * WOLFCLU_OID_TO_NAME_free. */
static int WOLFCLU_OID_TO_NAME_initWFile(WOLFCLU_OID_TO_NAME* newOids, XFILE fp)
{
#ifndef NO_WC_ENCODE_OBJECT_ID
    int ret = WOLFCLU_SUCCESS;
    OidName* tmpPtr;
    byte* fileBuffer;
    char* tracker;
    char* token;
    char* oid;

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
    token = XSTRTOK((char*)fileBuffer, " ", &tracker);
    while (ret == WOLFCLU_SUCCESS && token != NULL) {
        word32 len;
        oid = token;
        len = XSTRLEN(oid);

        ret = OidToDer(oid, &len);
        if (ret != WOLFCLU_SUCCESS) {
            wolfCLU_LogError("Could not convert Oid : %s to der check line %u",
                    token, newOids->len + 1);
            break;
        }

        /* skip short name */
        token = XSTRTOK(NULL, " ", &tracker);
        if (token == NULL) {
            wolfCLU_LogError("malformed tokens, check line %u for bad "
                    "formatting; wanted short name", newOids->len + 1);
            ret = WOLFCLU_FATAL_ERROR;
            break;
        }

        token = XSTRTOK(NULL, "\n", &tracker);
        if (token == NULL) {
            wolfCLU_LogError("malformed tokens, check line %u for bad "
                    "formatting; wanted long name", newOids->len + 1);
            ret = WOLFCLU_FATAL_ERROR;
            break;
        }

        /* realloc array if need more slots */
        if (newOids->len >= newOids->cap) {

            tmpPtr = XREALLOC(newOids->entries,
                    sizeof(OidName) * (newOids->cap + 10),
                    HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

            if (tmpPtr == NULL) {
                ret = MEMORY_E;
                break;
            }
            else {
                newOids->entries = tmpPtr;
                newOids->cap    += 10;
            }
        }

        newOids->entries[newOids->len].name = token;
        newOids->entries[newOids->len].oid = (byte*)oid;
        newOids->entries[newOids->len].len = len;
        newOids->len++;

        token = XSTRTOK(NULL, " ", &tracker);
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
    return OidToDer(NULL, NULL);
#endif
}

/* Callback that wolfSSL uses to assign byte oids to names */
static WOLFCLU_OID_TO_NAME AdditionalOidNames = {0};
static const char* OidToNameCallback (unsigned char* oid, word32 len)
{
    word32 i;
    for (i = 0; i < AdditionalOidNames.len; i++){
        if ((len == AdditionalOidNames.entries[i].len) &&
                (XMEMCMP(oid, AdditionalOidNames.entries[i].oid, len) == 0)) {
            return AdditionalOidNames.entries[i].name;
        }
    }

    for (i = 0; i < oid_names_len; i++){
        if ((len == oid_name_table[i].len) &&
                (XMEMCMP(oid, oid_name_table[i].oid, len) == 0)) {
            return oid_name_table[i].name;
        }
    }

    return NULL;
}

/* Decode the input data from base64 based on file type */
static int HandleProcessing(const WOLFCLU_ASN1_PARSE_OPTIONS* po,
        byte** inputFileBuffer, word32* inputFileLen)
{
    int ret = WOLFCLU_SUCCESS;
    word32 i = 0;
    word32 j = 0;

    if (po == NULL)
        return WOLFCLU_FATAL_ERROR;

    switch (po->inForm){
        case WOLFCLU_ASN1_PEM:
            /* Find start and end of PEM Base64 data. */
            ret = FindPem(*inputFileBuffer, j, *inputFileLen, &i, &j);
            /* Decode data between header and footer. */
            if ((ret == WOLFCLU_SUCCESS) &&
                    (Base64_Decode((*inputFileBuffer) + i, j - i,
                            *inputFileBuffer, inputFileLen) != 0)) {
                wolfCLU_LogError("PEM input is not base64 encoded");
                ret = WOLFCLU_FATAL_ERROR;
            }
            break;

        case WOLFCLU_ASN1_B64:
            if (Base64_Decode(*inputFileBuffer, *inputFileLen,
                *inputFileBuffer, inputFileLen) != 0) {
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

#endif


/* Performs the ASN.1 operation described by parseOptions: decodes the input
 * (DER, base64 or PEM), applies the offset/length/string-parse selections, and
 * writes the formatted structure to the configured output target(s).
 * Returns WOLFCLU_SUCCESS on success. */
int wolfCLU_Asn1Parse(WOLFCLU_ASN1_PARSE_OPTIONS* po)
{
#if defined(WOLFSSL_ASN_PRINT) && !defined(NO_FILESYSTEM)
    int ret = WOLFCLU_SUCCESS;
    byte* inputFileBuffer = NULL;
    word32 inputFileLen = 0;
    po->nameCb = OidToNameCallback;
    Asn1 asn1Master = {0};

    if (po->oidFile != NULL) {
        ret = WOLFCLU_OID_TO_NAME_initWFile(&AdditionalOidNames, po->oidFile);
    }

    if (ret == WOLFCLU_SUCCESS && po->noOut && po->outputFile == NULL) {
        ret = WOLFCLU_FATAL_ERROR;
        wolfCLU_LogError("No output file given and -noout set");
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = wc_Asn1_Init(&asn1Master) == 0 ?
            WOLFCLU_SUCCESS : WOLFCLU_FATAL_ERROR;
    }

    if (ret == WOLFCLU_SUCCESS) {
        if (po->inputFile == NULL) {
            ret = WOLFCLU_FATAL_ERROR;
            wolfCLU_LogError("Must have input via file passed to -in");
        }

        if (ret == WOLFCLU_SUCCESS) {
            if (asn1_ReadFile(po->inputFile, &inputFileBuffer,
                &inputFileLen) < 0){
                ret = WOLFCLU_FATAL_ERROR;
                wolfCLU_LogError("Could not open input file");
            }
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = HandleProcessing(po, &inputFileBuffer, &inputFileLen);
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = wolfCLU_Asn1Write(&asn1Master, po, inputFileBuffer, inputFileLen);
    }

    if (inputFileBuffer != NULL) {
        XFREE(inputFileBuffer, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }
    WOLFCLU_OID_TO_NAME_free(&AdditionalOidNames);
    return ret;
#else
#if !defined(WOLFSSL_ASN_PRINT)
    wolfCLU_LogError("WOLFSSL_ASN_PRINT option not set. Cannot Parse Asn1.");
#endif
#if defined(NO_FILESYSTEM)
    wolfCLU_LogError("NO_FILESYSTEM option is set. Cannot Parse Asn1.");
#endif
    return WOLFCLU_FATAL_ERROR;
#endif
}

