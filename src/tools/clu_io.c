/* clu_io.c
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
#include <wolfclu/clu_log.h>
#include <wolfclu/clu_io.h>
#include <limits.h>

/* Windows opens stdout and stdin in text mode, translating 0x0A <-> 0x0D 0x0A.
 * We don't want that */
#if defined(_WIN32)
    #include <io.h>
    #include <fcntl.h>
#endif


enum WOLFCLU_IO_TYPE_SETS {
    WOLFCLU_IO_READABLE =
        WOLFCLU_IO_READABLE_STREAM |
        WOLFCLU_IO_READABLE_FILE,

    WOLFCLU_IO_WRITABLE =
        WOLFCLU_IO_WRITABLE_STREAM |
        WOLFCLU_IO_WRITABLE_FILE,

    WOLFCLU_IO_RW =
        WOLFCLU_IO_READABLE_STREAM |
        WOLFCLU_IO_READABLE_FILE   |
        WOLFCLU_IO_WRITABLE_STREAM |
        WOLFCLU_IO_WRITABLE_FILE,
};

typedef struct WOLFCLU_IO_BUFFER {
    byte* outBuf;
    word32 len;
    word32 cap;
} WOLFCLU_IO_BUFFER;

#ifndef WOLFCLU_NO_FILESYSTEM
/* move the data to a new allocation of newCap bytes, wiping the old one so no
 * stale copies are left on the heap */
static int ResizeBuffer(WOLFCLU_IO_BUFFER* buffer, word32 newCap)
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

/* read a stream of unknown length, growing the buffer as we go. A stream with
 * no end, like /dev/urandom, is read until WOLFCLU_IO_MAX_READ_SZ is passed */
static int StreamRead(XFILE fp, WOLFCLU_IO_BUFFER* buffer, word32 limit)
{
    word32 bytesRead = 0;
    int newCap;
    int ret = WOLFCLU_SUCCESS;
    while (1) {
        if (buffer->cap == buffer->len) {
            if (buffer->cap == limit) {
                /* try to read one more byte to make sure that if the
                 * one more byte is EOF we break out with a full buffer */
                char lookOneMore;
                if (XFREAD(&lookOneMore, 1, 1, fp) != 0) {
                    wolfCLU_LogError("input too big needs to be %u "
                            "bytes or less", limit);
                    ret = WOLFCLU_FATAL_ERROR;
                    break;
                }
                else if (XFERROR(fp) != 0) {
                    wolfCLU_LogError("Error occured while reading the file");
                    ret = WOLFCLU_FATAL_ERROR;
                    break;
                }
                else {
                    /* we have read exactly to our limit! */
                    break;
                }
            }

            if (buffer->cap == 0) {
                newCap = limit > 1024 ? 1024 : limit;
            }
            else if (buffer->cap > (limit / 3)) {
                newCap = limit;
            }
            else {
                newCap = buffer->cap * 2;
            }
            ret = ResizeBuffer(buffer, newCap);
            if (ret != WOLFCLU_SUCCESS) {
                break;
            }
        }
        bytesRead = (word32)XFREAD(buffer->outBuf + buffer->len,
                sizeof(*buffer->outBuf), buffer->cap - buffer->len, fp);
        /* check for errors first, ports without ferror define XFERROR as 0 */
        if (XFERROR(fp)) {
            wolfCLU_LogError("Error while reading input stream.");
            ret = WOLFCLU_FATAL_ERROR;
            break;
        }
        if (bytesRead == 0) {
            break; /* EOF */
        }

        buffer->len += (word32)bytesRead;
    }

    return ret;
}

/* seek to get the length, then read it in one allocation. Inputs that can't
 * be sized this way, like pipes and devices, are read as a stream */
static int FileRead(XFILE fp, WOLFCLU_IO_BUFFER* buffer, word32 limit)
{
    word32 bytesRead = 0;
    long fileSize = 0;
    if (XFSEEK(fp, 0, XSEEK_END) != 0) {
        /* not seekable, e.g. a pipe */
        return StreamRead(fp, buffer, limit);
    }
    if ((fileSize = XFTELL(fp)) < 0) {
        wolfCLU_LogError("Could not get length of file");
        return WOLFCLU_FATAL_ERROR;
    }
    else if (fileSize > limit) {
        wolfCLU_LogError("File is too large max is %d bytes",
                limit);
        return WOLFCLU_FATAL_ERROR;
    }
    if (XFSEEK(fp, 0, XSEEK_SET) != 0) {
        wolfCLU_LogError("Could not seek input file");
        return WOLFCLU_FATAL_ERROR;
    }
    if (fileSize == 0) {
        /* devices report a size of 0, an empty file just reads nothing. An
         * endless device, like /dev/zero, reads until the max read size */
        return StreamRead(fp, buffer, limit);
    }
    buffer->len = (word32)fileSize;
    buffer->outBuf = (byte*)XMALLOC(buffer->len, HEAP_HINT,
            DYNAMIC_TYPE_TMP_BUFFER);
    if (buffer->outBuf == NULL) {
        wolfCLU_LogError("Could not allocate space for io read.");
        return WOLFCLU_FATAL_ERROR;
    }
    buffer->cap = buffer->len;
    bytesRead = (word32)XFREAD(buffer->outBuf, sizeof(*buffer->outBuf),
            buffer->len, fp);
    /* check for errors first, ports without ferror define XFERROR as 0 */
    if (XFERROR(fp)) {
        wolfCLU_LogError("Could not read all of the file data");
        return WOLFCLU_FATAL_ERROR;
    }
    /* a short read is EOF, e.g. sysfs files report a size larger than their
     * data */
    buffer->len = (int)bytesRead;
    return WOLFCLU_SUCCESS;
}
#endif

int wolfCLU_ReadIo(WOLFCLU_IO* io, byte** buf, word32* len, word32 limit)
{
    int ret = WOLFCLU_SUCCESS;
#ifndef WOLFCLU_NO_FILESYSTEM
    WOLFCLU_IO_BUFFER buffer = {0};

    if (io == NULL || io->type <= 0 || buf == NULL || len == NULL) {
        wolfCLU_LogError("Bad arg passed to wolfCLU_ReadIo");
        return BAD_FUNC_ARG;
    }

    if (limit == 0) {
        limit = UINT_MAX;
    }

    *buf = NULL;
    *len = 0;
    if (!(io->type & WOLFCLU_IO_READABLE)) {
        wolfCLU_LogError("Invalid ioType passed to wolfCLU_ReadIo");
        return BAD_FUNC_ARG;
    }

    if (io->type & WOLFCLU_IO_READABLE_FILE) {
        ret = FileRead(io->fp, &buffer, limit);
    }
    else {
        ret = StreamRead(io->fp, &buffer, limit);
    }

    if (ret != WOLFCLU_SUCCESS) {
        if (buffer.outBuf != NULL) {
            wolfCLU_ForceZero(buffer.outBuf, buffer.cap);
            XFREE(buffer.outBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            buffer.outBuf = NULL;
        }
    }
    else {
        if (buffer.len == 0 && buffer.outBuf != NULL) {
            wolfCLU_ForceZero(buffer.outBuf, buffer.cap);
            XFREE(buffer.outBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            buffer.outBuf = NULL;
        }
        *len = buffer.len;
        *buf = buffer.outBuf;
    }
    return ret;
#else
    (void)io;
    (void)buf;
    (void)len;
    ret = NOT_COMPILED_IN;
    return ret;
#endif
}

int wolfCLU_WriteIo(WOLFCLU_IO* io, const byte* buf, word32 len)
{
    int ret = WOLFCLU_SUCCESS;
#ifndef WOLFCLU_NO_FILESYSTEM
    if (io == NULL || io->type <= 0 || (buf == NULL && len > 0)) {
        wolfCLU_LogError("Bad arg passed to wolfCLU_WriteIo");
        return BAD_FUNC_ARG;
    }

    if (!(io->type & WOLFCLU_IO_WRITABLE)) {
        wolfCLU_LogError("Invalid ioType passed to wolfCLU_WriteIo");
        return BAD_FUNC_ARG;
    }

    if (len > 0 && XFWRITE(buf, sizeof(*buf), len, io->fp) != len) {
        wolfCLU_LogError("Could not write buffer out to target");
        ret = WOLFCLU_FATAL_ERROR;
    }
#ifdef XFFLUSH
    /* the write may only be buffered, flush so errors like a full disk are
     * caught here */
    if (ret == WOLFCLU_SUCCESS && XFFLUSH(io->fp) != 0) {
        wolfCLU_LogError("Could not flush buffer out to target");
        ret = WOLFCLU_FATAL_ERROR;
    }
#endif
    return ret;

#else
    (void)io;
    (void)buf;
    (void)len;
    wolfCLU_LogError("There is no filesystem in this config: "
            "cannot do file operations");
    ret = NOT_COMPILED_IN;
    return ret;
#endif
}

WOLFCLU_IO wolfCLU_OpenIo_fd(int fd, enum WOLFCLU_IO_TYPE type)
{
    WOLFCLU_IO io = {WOLFCLU_IO_NOT_OPEN, XBADFILE};
#if !defined(WOLFCLU_NO_FILESYSTEM) && defined(XFDOPEN)
    XFILE fp = XBADFILE;
    if (fd < 0 || type <= 0) {
        wolfCLU_LogError("Bad arg passed to wolfCLU_OpenIo_fd");
        io.type = WOLFCLU_IO_ERROR;
        return io;
    }

    if ((type & WOLFCLU_IO_READABLE) && (type & WOLFCLU_IO_WRITABLE)) {
        fp = XFDOPEN(fd, "rb+");
    }
    else if (type & WOLFCLU_IO_READABLE) {
        fp = XFDOPEN(fd, "rb");
    }
    else if (type & WOLFCLU_IO_WRITABLE) {
        fp = XFDOPEN(fd, "wb");
    }
    else {
        wolfCLU_LogError("Bad type passed to wolfCLU_OpenIo_fd");
        io.type = WOLFCLU_IO_ERROR;
    }
    if (fp == XBADFILE) {
        wolfCLU_LogError("Could not open file pointer from file descriptor");
        io.type = WOLFCLU_IO_ERROR;
    }

    if (io.type == WOLFCLU_IO_NOT_OPEN) {
        io.fp = fp;
        io.type = type;
#ifdef _WIN32
        /* binary mode */
        (void)_setmode(_fileno(io.fp), _O_BINARY);
#endif
    }
    return io;
#else
    (void)type;
    (void)fd;
#if defined(WOLFCLU_NO_FILESYSTEM)
    wolfCLU_LogError("There is no filesystem in this config: "
            "cannot do file operations");
#endif
#if !defined(XFDOPEN)
    wolfCLU_LogError("Cannot open file pointer from file descriptor");
#endif
    io.type = WOLFCLU_IO_NOT_COMPILED_IN;
    return io;
#endif
}

WOLFCLU_IO wolfCLU_OpenIo_fp(XFILE fp, enum WOLFCLU_IO_TYPE type)
{
    WOLFCLU_IO io = {WOLFCLU_IO_NOT_OPEN, XBADFILE};
#ifndef WOLFCLU_NO_FILESYSTEM
    if (fp == XBADFILE) {
        wolfCLU_LogError("Bad file pointer passed to wolfCLU_OpenIo_fp");
        io.type = WOLFCLU_IO_ERROR;
    }

    /* check that at least one valid type bit is set */
    if (!(type & WOLFCLU_IO_RW) || type <= 0) {
        wolfCLU_LogError("Bad type passed to wolfCLU_OpenIo_fp");
        io.type = WOLFCLU_IO_ERROR;
    }

    if (io.type == WOLFCLU_IO_NOT_OPEN) {
        io.fp = fp;
        io.type = type;
#ifdef _WIN32
        /* binary mode */
        (void)_setmode(_fileno(io.fp), _O_BINARY);
#endif
    }
    return io;
#else
    (void)fp;
    (void)type;
    wolfCLU_LogError("There is no filesystem in this config: "
            "cannot do file operations");
    io.type = WOLFCLU_IO_NOT_COMPILED_IN;
    return io;
#endif
}

WOLFCLU_IO wolfCLU_OpenIo_file(const char* fileName, enum WOLFCLU_IO_TYPE type)
{
    WOLFCLU_IO io = {WOLFCLU_IO_NOT_OPEN, XBADFILE};
#ifndef WOLFCLU_NO_FILESYSTEM
    XFILE fp = XBADFILE;
    if (fileName == NULL || type <= 0) {
        wolfCLU_LogError("Bad arg passed to wolfCLU_OpenIo_file");
        io.type = WOLFCLU_IO_ERROR;
        return io;
    }

    if ((type & WOLFCLU_IO_READABLE) && (type & WOLFCLU_IO_WRITABLE)) {
        fp = XFOPEN(fileName, "rb+");
    }
    else if (type & WOLFCLU_IO_READABLE) {
        fp = XFOPEN(fileName, "rb");
    }
    else if (type & WOLFCLU_IO_WRITABLE) {
        fp = XFOPEN(fileName, "wb");
    }
    else {
        wolfCLU_LogError("Bad type passed to wolfCLU_OpenIo_file");
        io.type = WOLFCLU_IO_ERROR;
    }
    if (fp == XBADFILE) {
        wolfCLU_LogError("Could not open file pointer from file name: %s",
                fileName);
        io.type = WOLFCLU_IO_ERROR;
    }

    if (io.type == WOLFCLU_IO_NOT_OPEN) {
        io.fp = fp;
        io.type = type;
#ifdef _WIN32
        /* binary mode */
        (void)_setmode(_fileno(io.fp), _O_BINARY);
#endif
    }
    return io;
#else
    (void)type;
    (void)fileName;
    wolfCLU_LogError("There is no filesystem in this config: "
            "cannot do file operations");
    io.type = WOLFCLU_IO_NOT_COMPILED_IN;
    return io;
#endif
}

int wolfCLU_CloseIo(WOLFCLU_IO* io)
{
#ifndef WOLFCLU_NO_FILESYSTEM
    int ret = WOLFCLU_SUCCESS;
    if (io == NULL || io->type <= 0)
        return BAD_FUNC_ARG;

    /* the stream is gone even when fclose fails */
    if (!(io->type & WOLFCLU_IO_NOCLOSE) && XFCLOSE(io->fp) != 0) {
        ret = WOLFCLU_FATAL_ERROR;
    }

    io->fp = XBADFILE;
    io->type = WOLFCLU_IO_NOT_OPEN;

    return ret;
#else
    (void)io;
    wolfCLU_LogError("There is no filesystem in this config: "
            "cannot do file operations");
    return NOT_COMPILED_IN;
#endif
}
