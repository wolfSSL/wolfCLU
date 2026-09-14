/* clu_io.h
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

#ifndef _WOLFSSL_CLU_IO_HEADER_
#define _WOLFSSL_CLU_IO_HEADER_

#ifdef __cplusplus
extern "C" {
#endif

#include <wolfclu/clu_header_main.h>
#include <wolfclu/clu_log.h>
#include <limits.h>

/**
 * @brief IO types passed to the IO functions below
 */
enum WOLFCLU_IO_TYPE {
    /*error codes*/
    WOLFCLU_IO_NOT_COMPILED_IN = NOT_COMPILED_IN,
    WOLFCLU_IO_ERROR = WOLFCLU_FATAL_ERROR,

    /* base types */
    WOLFCLU_IO_NOT_OPEN        = 0,
    WOLFCLU_IO_READABLE_STREAM = 1 << 0,
    WOLFCLU_IO_WRITABLE_STREAM = 1 << 1,
    WOLFCLU_IO_READABLE_FILE   = 1 << 2,
    WOLFCLU_IO_WRITABLE_FILE   = 1 << 3,

    /*behaviors*/
    WOLFCLU_IO_NOCLOSE = 1 << 10,

    /* type groups */
    WOLFCLU_IO_RW_STREAM =
        WOLFCLU_IO_READABLE_STREAM |
        WOLFCLU_IO_WRITABLE_STREAM,

    WOLFCLU_IO_RW_FILE =
        WOLFCLU_IO_READABLE_FILE |
        WOLFCLU_IO_WRITABLE_FILE,
};

#ifndef XFILE
#define XFILE void*
#endif

#ifndef XBADFILE
#define XBADFILE NULL
#endif


typedef struct WOLFCLU_IO {
    enum WOLFCLU_IO_TYPE type;
    XFILE fp;
}WOLFCLU_IO;

/**
 * @brief Open a WOLFCLU_IO from a file descriptor, file pointer or file name.
 *        type sets the read/write mode and can include WOLFCLU_IO_NOCLOSE to
 *        leave the underlying file open on wolfCLU_CloseIo, e.g. for stdin
 * @param fd file descriptor to open a file pointer on. After a successful open
 *        the fd is owned by the IO and closed by wolfCLU_CloseIo, on failure
 *        the caller still owns it
 * @param fp file pointer to wrap, closed by wolfCLU_CloseIo unless
 *        WOLFCLU_IO_NOCLOSE is set
 * @param fileName path of the file to open, writable files are truncated,
 *                 read/write files are not truncated.
 * @param type WOLFCLU_IO_TYPE flags for the IO
 * @return an IO with type > 0 on success. On failure type is <= 0
 *         (WOLFCLU_IO_ERROR or WOLFCLU_IO_NOT_COMPILED_IN) and the IO must not
 *         be passed to wolfCLU_CloseIo
 */
WOLFCLU_IO wolfCLU_OpenIo_fd(int fd, enum WOLFCLU_IO_TYPE type);
WOLFCLU_IO wolfCLU_OpenIo_fp(XFILE fp, enum WOLFCLU_IO_TYPE type);
WOLFCLU_IO wolfCLU_OpenIo_file(const char* fileName, enum WOLFCLU_IO_TYPE type);

/**
 * @brief close an open IO. The file is closed unless WOLFCLU_IO_NOCLOSE is
 *        set. The IO is reset to WOLFCLU_IO_NOT_OPEN even if the close fails
 * @param io IO from a successful wolfCLU_OpenIo_* call
 * @return WOLFCLU_SUCCESS on success, BAD_FUNC_ARG if io is not open,
 *         WOLFCLU_FATAL_ERROR if closing the file failed
 */
int wolfCLU_CloseIo(WOLFCLU_IO* io);

/**
 * @brief read file/stream data in to an allocated buffer. If limit is
 *        0 it will default to UINT_MAX otherwise it will be the max number of
 *        bytes read from the file/stream.
 * @param io open IO with a readable type
 * @param buf pointer to store the buffer, NULL if empty. The caller frees it,
 *        wiping it first with wolfCLU_ForceZero if it holds secrets
 * @param len pointer to store the number of bytes read
 * @param limit maximum number of bytes that we want to read from a
 * file or stream; 0 defaults to UINT_MAX bound
 * @return WOLFCLU_SUCCESS on success, negative on error
 */
int wolfCLU_ReadIo(WOLFCLU_IO* io, byte** buf, word32* len, word32 limit);

/**
 * @brief write len bytes of buf to io and flush it
 * @param io open IO with a writable type
 * @param buf buffer to write, may be NULL when len is 0
 * @param len number of bytes to write
 * @return WOLFCLU_SUCCESS on success, negative on error
 */
int wolfCLU_WriteIo(WOLFCLU_IO* io, const byte* buf, word32 len);

#ifdef __cplusplus
}
#endif

#endif /*_WOLFSSL_CLU_IO_HEADER_*/
