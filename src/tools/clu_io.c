/* clu_io.c
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
#include <limits.h>

/* Windows opens stdout and stdin in text mode, translating 0x0A <-> 0x0D 0x0A.
 * We don't want that */
#if defined(_WIN32)
    #include <io.h>
    #include <fcntl.h>
#endif

typedef struct WOLFCLU_IO_BUFFER {
    byte* outBuf;
    int len;
    int cap;
} WOLFCLU_IO_BUFFER;

/* move the data to a new allocation of newCap bytes, wiping the old one so no
 * stale copies are left on the heap */
static int ResizeBuffer(WOLFCLU_IO_BUFFER* buffer, int newCap)
{
    byte* tmp = (byte*)XMALLOC(newCap, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (tmp == NULL) {
        wolfCLU_LogError("Could not allocate space for io read.");
        return WOLFCLU_FATAL_ERROR;
    }
    if (buffer->outBuf != NULL) {
        XMEMCPY(tmp, buffer->outBuf, buffer->len);
        wolfCLU_ForceZero(buffer->outBuf, buffer->len);
        XFREE(buffer->outBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }
    buffer->outBuf = tmp;
    buffer->cap = newCap;
    return WOLFCLU_SUCCESS;
}

/* read a stream of unknown length, growing the buffer as we go */
static int StreamRead(XFILE fp, WOLFCLU_IO_BUFFER* buffer)
{
    sword32 bytesRead = 0;
    int newCap;
    int ret = WOLFCLU_SUCCESS;
    while (1) {
        if (buffer->cap == buffer->len) {
            if (buffer->cap == INT_MAX) {
                /* try to read one more byte to make sure that if the
                 * one more byte is EOF we break out with a full buffer */
                char lookOneMore;
                if (XFREAD(&lookOneMore, 1, 1, fp) == 0 && !XFERROR(fp))
                    break;

                wolfCLU_LogError("input too big needs to be %d "
                        "bytes or less", INT_MAX);
                ret = WOLFCLU_FATAL_ERROR;
                break;
            }
            if (buffer->cap > ((INT_MAX - 1024) / 2)) {
                newCap = INT_MAX;
            }
            else {
                newCap = buffer->cap * 2 + 1024;
            }
            ret = ResizeBuffer(buffer, newCap);
            if (ret != WOLFCLU_SUCCESS) {
                break;
            }
        }
        bytesRead = (sword32)XFREAD(buffer->outBuf + buffer->len,
                sizeof(*buffer->outBuf), buffer->cap - buffer->len, fp);
        /* check for errors first, ports without ferror define XFERROR as 0 */
        if (bytesRead < 0 || XFERROR(fp)) {
            wolfCLU_LogError("Error while reading input stream.");
            ret = WOLFCLU_FATAL_ERROR;
            break;
        }
        if (bytesRead == 0) {
            break; /* EOF */
        }

        buffer->len += bytesRead;
    }

    return ret;
}

/* seek to get the length, then read it in one allocation. Inputs that can't
 * be sized this way, like pipes and devices, are read as a stream */
static int FileRead(XFILE fp, WOLFCLU_IO_BUFFER* buffer)
{
    sword32 bytesRead = 0;
    long fileSize = 0;
    if (XFSEEK(fp, 0, XSEEK_END) != 0) {
        /* not seekable, e.g. a pipe */
        return StreamRead(fp, buffer);
    }
    if ((fileSize = XFTELL(fp)) < 0) {
        wolfCLU_LogError("Could not get length of file");
        return WOLFCLU_FATAL_ERROR;
    }
    else if (fileSize > INT_MAX) {
        wolfCLU_LogError("File is too large max is %d bytes", INT_MAX);
        return WOLFCLU_FATAL_ERROR;
    }
    if (XFSEEK(fp, 0, XSEEK_SET) != 0) {
        wolfCLU_LogError("Could not seek input file");
        return WOLFCLU_FATAL_ERROR;
    }
    if (fileSize == 0) {
        /* devices report a size of 0, an empty file just reads nothing */
        return StreamRead(fp, buffer);
    }
    buffer->len = (int)fileSize;
    buffer->outBuf = (byte*)XMALLOC(buffer->len, HEAP_HINT,
            DYNAMIC_TYPE_TMP_BUFFER);
    if (buffer->outBuf == NULL) {
        wolfCLU_LogError("Could not allocate space for io "
                "read.");
        return WOLFCLU_FATAL_ERROR;
    }
    buffer->cap = buffer->len;
    bytesRead = (sword32)XFREAD(buffer->outBuf, sizeof(*buffer->outBuf),
            buffer->len, fp);
    if (bytesRead != buffer->len) {
        wolfCLU_LogError("Could not read all of the file data");
        return WOLFCLU_FATAL_ERROR;
    }
    return WOLFCLU_SUCCESS;
}

int wolfCLU_ReadIo(enum WOLFCLU_IO_TYPE ioType, XFILE fp, byte** buf,
        word32* len)
{
    int ret = WOLFCLU_SUCCESS;
    WOLFCLU_IO_BUFFER buffer = {0};

    if (fp == XBADFILE || buf == NULL || len == NULL) {
        wolfCLU_LogError("Bad arg passed to wolfCLU_ReadIo");
        return BAD_FUNC_ARG;
    }

    *buf = NULL;
    *len = 0;
    if (!(ioType & WOLFCLU_IO_READABLE)) {
        wolfCLU_LogError("Invalid ioType passed to wolfCLU_ReadIo");
        return BAD_FUNC_ARG;
    }
#ifdef WOLFCLU_NO_FILESYSTEM
    if (ioType & WOLFCLU_IO_RW_FILE) {
        wolfCLU_LogError("Cannot read files when compiled with "
                "WOLFCLU_NO_FILESYSTEM");
        return NOT_COMPILED_IN;
    }
#endif
#ifdef _WIN32
    /* binary mode, see note at top of file */
    (void)_setmode(_fileno(fp), _O_BINARY);
#endif

    if (ioType & WOLFCLU_IO_READABLE_FILE) {
        ret = FileRead(fp, &buffer);
    }
    else {
        ret = StreamRead(fp, &buffer);
    }

    if (ret != WOLFCLU_SUCCESS) {
        if (buffer.outBuf != NULL) {
            wolfCLU_ForceZero(buffer.outBuf, buffer.len);
            XFREE(buffer.outBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        }
        return ret;
    }
    else {
        if (buffer.len == 0 && buffer.outBuf != NULL) {
            XFREE(buffer.outBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            buffer.outBuf = NULL;
        }
        *len = buffer.len;
        *buf = buffer.outBuf;
        return ret;
    }
}

int wolfCLU_WriteIo(enum WOLFCLU_IO_TYPE ioType, XFILE fp,
        const byte* buf, word32 len)
{
    int ret = WOLFCLU_SUCCESS;
    if (fp == XBADFILE || (buf == NULL && len > 0) || len > INT_MAX) {
        wolfCLU_LogError("Bad arg passed to wolfCLU_WriteIo");
        return BAD_FUNC_ARG;
    }

    if (!(ioType & WOLFCLU_IO_WRITABLE)) {
        wolfCLU_LogError("Invalid ioType passed to wolfCLU_WriteIo");
        return BAD_FUNC_ARG;
    }
#ifdef WOLFCLU_NO_FILESYSTEM
    if (ioType & WOLFCLU_IO_RW_FILE) {
        wolfCLU_LogError("Cannot write out to a file when compiled with "
                "WOLFCLU_NO_FILESYSTEM");
        return NOT_COMPILED_IN;
    }
#endif
#ifdef _WIN32
    /* binary mode, see note at top of file */
    (void)_setmode(_fileno(fp), _O_BINARY);
#endif

    if (len > 0 && XFWRITE(buf, sizeof(*buf), (int)len, fp) != len) {
        wolfCLU_LogError("Could not write buffer out to target");
        ret = WOLFCLU_FATAL_ERROR;
    }
#ifdef XFFLUSH
    /* the write may only be buffered, flush so errors like a full disk are
     * caught here */
    if (ret == WOLFCLU_SUCCESS && XFFLUSH(fp) != 0) {
        wolfCLU_LogError("Could not flush buffer out to target");
        ret = WOLFCLU_FATAL_ERROR;
    }
#endif
    return ret;
}

