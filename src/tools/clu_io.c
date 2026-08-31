#include <wolfclu/clu_header_main.h>
#include <wolfclu/clu_log.h>
#include <limits.h>

/* Windows opens stdout and stdin in text mode, translating 0x0A <-> 0x0D 0x0A.
 * We don't want that */
#if defined(_WIN32)
    #include <io.h>
    #include <fcntl.h>
#endif

int wolfCLU_readInIo(enum WOLFCLU_IO_TYPE ioType, XFILE fp, char** buf,
        word32* len)
{
    WOLFSSL_BIO* bio = NULL;
    int ret = WOLFCLU_SUCCESS;

    struct {
        char* outBuf;
        sword32 len;
        sword32 cap;
    } buffer = {0};

    switch (ioType) {
        case WOLFCLU_IO_STDIN:
            bio = wolfSSL_BIO_new_fp(fp, BIO_NOCLOSE);
            if (bio == NULL) {
                wolfCLU_LogError("Could not create BIO with stdin");
                return WOLFCLU_FATAL_ERROR;
            }
#ifdef _WIN32
            /* Put stdin in binary mode so raw bytes pass through
             * untranslated on windows. */
            (void)_setmode(_fileno(fp), _O_BINARY);
#endif
            break;

        case WOLFCLU_IO_FILE:
            bio = wolfSSL_BIO_new_fp(fp, BIO_NOCLOSE);
            if (bio == NULL) {
                wolfCLU_LogError("Could not create BIO");
                return WOLFCLU_FATAL_ERROR;
            }
            break;

        case WOLFCLU_IO_STDOUT:
        default:
            wolfCLU_LogError("Could not open file: unknown file type");
            return WOLFCLU_FATAL_ERROR;
    }

    switch (ioType) {
        case WOLFCLU_IO_STDIN:
            {
                char* tmp = NULL;
                sword32 read = 0;
                char cannotBump = 0;
                while (1) {
                    if (buffer.cap == buffer.len) {
                        if (cannotBump == 1) {
                            wolfCLU_LogError("input too big needs to be %d "
                                    "bytes or less", INT_MAX);
                            ret = WOLFCLU_FATAL_ERROR;
                            break;
                        }
                        if (buffer.cap > (INT_MAX - 1024 / 2)) {
                            buffer.cap = INT_MAX;
                            cannotBump = 1;
                        }
                        else {
                            buffer.cap *= 2;
                            buffer.cap += 1024;
                        }
                        tmp = XREALLOC(buffer.outBuf, buffer.cap,
                                HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
                        if (tmp == NULL) {
                            wolfCLU_LogError("Could not allocate space for io "
                                    "read.");
                            ret = WOLFCLU_FATAL_ERROR;
                            break;
                        }
                    }
                    buffer.outBuf = tmp;
                    read = wolfSSL_BIO_read(bio, buffer.outBuf + buffer.len,
                            buffer.cap - buffer.len);
                    if (read < 0) {
                        wolfCLU_LogError("Error while reading from stdin.");
                        ret = WOLFCLU_FATAL_ERROR;
                        break;
                    }

                    if (read == 0) {
                        break;
                    }

                    buffer.len += read;
                }

                tmp = XREALLOC(buffer.outBuf, buffer.cap,
                        HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
                if (tmp == NULL) {
                    wolfCLU_LogError("Could not allocate space for io "
                            "read.");
                    ret = WOLFCLU_FATAL_ERROR;
                    break;
                }
                buffer.outBuf = tmp;
            }
            break;

        case WOLFCLU_IO_FILE: {
            sword32 read = 0;
            long fileSize = 0;
            XFILE innerFp = NULL;
            if (wolfSSL_BIO_get_fp(bio, &innerFp) != WOLFSSL_SUCCESS) {
                wolfCLU_LogError("Could not get file pointer from BIO");
                ret = WOLFCLU_FATAL_ERROR;
                break;
            }
            if (XFSEEK(innerFp, 0, SEEK_END) != 0) {
                wolfCLU_LogError("Could not seek input file");
                ret = WOLFCLU_FATAL_ERROR;
                break;
            }
            if ((fileSize = XFTELL(innerFp)) < 0) {
                wolfCLU_LogError("Could not get length of file");
                ret = WOLFCLU_FATAL_ERROR;
                break;
            }
            if (wolfSSL_BIO_reset(bio) != WOLFSSL_SUCCESS) {
                wolfCLU_LogError("Could not reset Bio");
                ret = WOLFCLU_FATAL_ERROR;
                break;
            }
            buffer.len = (sword32)fileSize;
            if (buffer.len < 0) {
                wolfCLU_LogError("Could not get length of file data");
                ret = WOLFCLU_FATAL_ERROR;
                break;
            }

            buffer.outBuf = XMALLOC(buffer.len, HEAP_HINT,
                    DYNAMIC_TYPE_TMP_BUFFER);
            if (buffer.outBuf == NULL) {
                wolfCLU_LogError("Could not allocate space for io "
                        "read.");
                ret = WOLFCLU_FATAL_ERROR;
                break;
            }
            buffer.cap = buffer.len;
            read = wolfSSL_BIO_read(bio, buffer.outBuf, buffer.len);
            if (read != buffer.len) {
                wolfCLU_LogError("Could not create BIO");
                ret = WOLFCLU_FATAL_ERROR;
                break;
            }
            break;
        }

        case WOLFCLU_IO_STDOUT:
        default:
            ret = WOLFCLU_FATAL_ERROR;
    }

    if (bio != NULL) {
        wolfSSL_BIO_free(bio);
    }
    if (ret != WOLFCLU_SUCCESS) {
        if (buffer.outBuf != NULL) {
            XFREE(buffer.outBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            XMEMSET(&buffer, 0, sizeof(buffer));
        }
        return ret;
    }
    else {
        *len = buffer.len;
        *buf = buffer.outBuf;
        return ret;
    }
}

int wolfCLU_writeOutIo(enum WOLFCLU_IO_TYPE ioType, XFILE fp,
        char* buf, word32 len)
{
    WOLFSSL_BIO* bio = NULL;
    int ret = WOLFCLU_SUCCESS;
    switch (ioType) {

        case WOLFCLU_IO_STDOUT: {
            bio = wolfSSL_BIO_new_fp(fp, BIO_NOCLOSE);
            if (bio == NULL) {
                wolfCLU_LogError("Could not get BIO from stdout");
                return WOLFCLU_FATAL_ERROR;
            }
#ifdef _WIN32
            /* Put stdout in binary mode so raw bytes pass through
             * untranslated. */
            (void)_setmode(_fileno(stdout), _O_BINARY);
#endif
            break;
        }

        case WOLFCLU_IO_FILE: {
            bio = wolfSSL_BIO_new_fp(fp, BIO_NOCLOSE);
            if (bio == NULL) {
                wolfCLU_LogError("Could not create BIO");
                return WOLFCLU_FATAL_ERROR;
            }
            break;
        }

        case WOLFCLU_IO_STDIN:
        default:
            wolfCLU_LogError("Could not open BIO: Wrong Io type.");
            return WOLFCLU_FATAL_ERROR;
    }

    if (wolfSSL_BIO_write(bio, buf, len) != (int)len) {
        wolfCLU_LogError("Could not write buffer out to target");
        ret = WOLFCLU_FATAL_ERROR;
    }

    if (bio != NULL) {
        wolfSSL_BIO_free(bio);
    }

    return ret;
}

