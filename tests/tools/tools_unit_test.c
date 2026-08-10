/* tools_unit_test.c */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
/* struct stat/stat() are used on both platforms; MSVC and MinGW supply them
 * from <sys/stat.h> too, so this cannot live in the POSIX arm below. */
#include <sys/types.h>
#include <sys/stat.h>
#ifdef _WIN32
    #include <process.h>
    #define GETPID _getpid
#else
    #include <unistd.h>
    #define GETPID getpid
#endif

#include <wolfclu/clu_header_main.h>
#include <wolfclu/clu_log.h>
#include <wolfclu/clu_error_codes.h>

/* Everything under test is compiled out without a stdio filesystem, so the
 * whole suite reports the automake "skipped" status in that configuration. */
#ifndef WOLFCLU_NO_FILESYSTEM

static int fail = 0;

/* Total assertions actually executed, pass or fail. Distinguishes "every
 * fixture in this environment was unbuildable, nothing ran" (automake SKIP)
 * from "some fixtures were unbuildable, but everything that did run passed"
 * (automake PASS) - the latter must not be reported as skipped. */
static int checked = 0;

#define CHECK(cond, msg)                                                    \
    do {                                                                    \
        checked++;                                                          \
        if (!(cond)) {                                                      \
            printf("FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__);          \
            fail++;                                                         \
        }                                                                   \
    } while (0)

/* An environment that cannot build a fixture (no symlinks, no hard links, no
 * FIFOs) must be distinguishable from a run that genuinely asserted. */
static int skipped = 0;
#define SKIP(msg) do { \
    printf("SKIP: %s (%s:%d)\n", msg, __FILE__, __LINE__); \
    skipped++; \
} while(0)

static void testReadFileToBuffer(void)
{
    byte* buf = NULL;
    int bufSz = 0;
    int ret;
    char testFile[64];
    FILE* f;

    XSNPRINTF(testFile, sizeof(testFile), "test_read_file_%d.tmp",
            (int)GETPID());

    /* NULL args */
    ret = wolfCLU_ReadFileToBuffer(NULL, 100, &buf, &bufSz);
    CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "ReadFileToBuffer NULL path");
    ret = wolfCLU_ReadFileToBuffer(testFile, 100, NULL, &bufSz);
    CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "ReadFileToBuffer NULL outBuf");
    ret = wolfCLU_ReadFileToBuffer(testFile, 100, &buf, NULL);
    CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "ReadFileToBuffer NULL outSz");
    ret = wolfCLU_ReadFileToBuffer(testFile, 0, &buf, &bufSz);
    CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "ReadFileToBuffer maxSz <= 0");

    /* Missing file */
    remove(testFile); /* Ensure it doesn't exist */
    ret = wolfCLU_ReadFileToBuffer(testFile, 100, &buf, &bufSz);
    CHECK(ret == WOLFCLU_FATAL_ERROR, "ReadFileToBuffer missing file");

    /* Empty file */
    f = fopen(testFile, "wb");
    if (f) {
        fclose(f);
        ret = wolfCLU_ReadFileToBuffer(testFile, 100, &buf, &bufSz);
        CHECK(ret == WOLFCLU_FATAL_ERROR, "ReadFileToBuffer empty file");

        /* Unlike ReadFileToBuffer(), the message-file variant must accept
         * an empty file: some algorithms (e.g. Ed25519, RFC 8032 test
         * vector 1) sign/verify a 0-byte message. */
        ret = wolfCLU_ReadMessageFileToBuffer(testFile, 100, &buf, &bufSz);
        CHECK(ret == WOLFCLU_SUCCESS,
                "ReadMessageFileToBuffer empty file succeeds");
        CHECK(bufSz == 0, "ReadMessageFileToBuffer empty file size");
        if (buf) {
            CHECK(buf[0] == '\0',
                    "ReadMessageFileToBuffer empty file null terminated");
            XFREE(buf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        }
        remove(testFile);
    } else {
        CHECK(0, "ReadFileToBuffer empty file: fopen failed");
    }

    /* File exceeds maxSz */
    f = fopen(testFile, "wb");
    if (f) {
        if (fwrite("12345", 1, 5, f) == 5) {
            fclose(f);
            ret = wolfCLU_ReadFileToBuffer(testFile, 4, &buf, &bufSz);
            CHECK(ret == WOLFCLU_FATAL_ERROR, "ReadFileToBuffer exceeds maxSz");
        } else {
            fclose(f);
            CHECK(0, "ReadFileToBuffer exceeds maxSz: fwrite failed");
        }
        remove(testFile);
    } else {
        CHECK(0, "ReadFileToBuffer exceeds maxSz: fopen failed");
    }

    /* Valid read */
    f = fopen(testFile, "wb");
    if (f) {
        if (fwrite("12345", 1, 5, f) == 5) {
            fclose(f);
            ret = wolfCLU_ReadFileToBuffer(testFile, 10, &buf, &bufSz);
            CHECK(ret == WOLFCLU_SUCCESS, "ReadFileToBuffer valid read");
            CHECK(bufSz == 5, "ReadFileToBuffer size");
            if (buf) {
                CHECK(XMEMCMP(buf, "12345", 5) == 0,
                        "ReadFileToBuffer content");
                CHECK(buf[5] == '\0', "ReadFileToBuffer null terminated");
                XFREE(buf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            }
        } else {
            fclose(f);
            CHECK(0, "ReadFileToBuffer valid read: fwrite failed");
        }
        remove(testFile);
    } else {
        CHECK(0, "ReadFileToBuffer valid read: fopen failed");
    }
}

static void testPathsRefEqual(void)
{
    FILE* f;
    char relPath[64];
    char dotRelPath[80];

    CHECK(wolfCLU_PathsRefEqual(NULL, NULL) == 0, "PathsRefEqual NULLs");
    CHECK(wolfCLU_PathsRefEqual("a", NULL) == 0, "PathsRefEqual one NULL");
    CHECK(wolfCLU_PathsRefEqual("same.txt", "same.txt") == 1,
            "PathsRefEqual identical");
    CHECK(wolfCLU_PathsRefEqual("a.txt", "b.txt") == 0,
            "PathsRefEqual different");

    XSNPRINTF(relPath, sizeof(relPath), "test_ref_equal_%d.tmp",
            (int)GETPID());
    XSNPRINTF(dotRelPath, sizeof(dotRelPath), "./%s", relPath);

    /* Non-existent files drop through to canonicalization */
    CHECK(wolfCLU_PathsRefEqual(relPath, dotRelPath) == 1,
          "PathsRefEqual absolute/relative non-existent");

    f = fopen(relPath, "wb");
    if (f) {
        fclose(f);
        /* Tests the dev/ino check for existing files. */
        CHECK(wolfCLU_PathsRefEqual(relPath, dotRelPath) == 1,
              "PathsRefEqual absolute/relative existing");
        remove(relPath);
    }
    else {
        CHECK(0, "PathsRefEqual absolute/relative: fopen failed");
    }

#ifndef _WIN32
    /* A symlink aliasing the same target must be caught even though its
     * canonicalized parent-dir+basename string never matches the target's:
     * this is the case wolfCLU_OpenOutFile() following the symlink and
     * truncating the target mid-read depends on being detected. */
    {
        char target[64];
        char link[64];

        XSNPRINTF(target, sizeof(target), "test_ref_equal_tgt_%d.tmp",
                (int)GETPID());
        XSNPRINTF(link, sizeof(link), "test_ref_equal_link_%d.tmp",
                (int)GETPID());
        remove(target);
        remove(link);

        f = fopen(target, "wb");
        if (f == NULL) {
            CHECK(0, "PathsRefEqual symlink fixture create target");
        }
        else {
            fclose(f);
            if (symlink(target, link) != 0) {
                SKIP("PathsRefEqual symlink alias: symlink() failed");
            }
            else {
                CHECK(wolfCLU_PathsRefEqual(target, link) == 1,
                      "PathsRefEqual symlink alias");
                remove(link);
            }
            remove(target);
        }
    }

    /* Two distinct names hard-linked to the same inode must likewise be
     * caught: writing through either truncates the other's data in place. */
    {
        char target[64];
        char hlink[64];

        XSNPRINTF(target, sizeof(target), "test_ref_equal_htgt_%d.tmp",
                (int)GETPID());
        XSNPRINTF(hlink, sizeof(hlink), "test_ref_equal_hlink_%d.tmp",
                (int)GETPID());
        remove(target);
        remove(hlink);

        f = fopen(target, "wb");
        if (f == NULL) {
            CHECK(0, "PathsRefEqual hardlink fixture create target");
        }
        else {
            fclose(f);
            if (link(target, hlink) != 0) {
                SKIP("PathsRefEqual hardlink alias: link() failed");
            }
            else {
                CHECK(wolfCLU_PathsRefEqual(target, hlink) == 1,
                      "PathsRefEqual hardlink alias");
                remove(hlink);
            }
            remove(target);
        }
    }

    /* A path whose parent directory doesn't exist can't already be (or
     * alias) an existing file, so this is a definite DISTINCT rather than
     * an UNDETERMINED fail-closed -- the caller's subsequent open attempt
     * is what should report the missing directory. */
    CHECK(wolfCLU_PathsRefEqual(relPath, "no_such_dir_xyz/out.tmp") ==
            WOLFCLU_PATHS_DISTINCT,
          "PathsRefEqual nonexistent parent dir is distinct");

    /* An oversized path can't be canonicalized at all; that ambiguity must
     * still fail closed as UNDETERMINED. PATH_MAX is what the internal
     * buffer sizes off of when defined; the fallback matches its own
     * fallback so this stays oversized either way. */
    {
#ifdef PATH_MAX
        char hugePath[PATH_MAX + 16];
#else
        char hugePath[4096 + 16];
#endif

        XMEMSET(hugePath, 'a', sizeof(hugePath) - 1);
        hugePath[sizeof(hugePath) - 1] = '\0';
        CHECK(wolfCLU_PathsRefEqual(relPath, hugePath) ==
                WOLFCLU_PATHS_UNDETERMINED,
              "PathsRefEqual oversized path is undetermined");
    }
#endif /* !_WIN32 */
}

#ifndef _WIN32
static void testOpenOutAndKeyFile(void)
{
    char  target[64];
    char  link[64];
    FILE* f;
    struct stat st;

    XSNPRINTF(target, sizeof(target), "test_openfile_%d.tmp", (int)GETPID());
    XSNPRINTF(link, sizeof(link), "test_openlink_%d.tmp", (int)GETPID());
    remove(target);
    remove(link);

    /* Non-secret output writes through a symlink and leaves it in place. */
    f = fopen(target, "wb");
    if (f == NULL) {
        CHECK(0, "OpenOutFile fixture create target");
        return;
    }
    fclose(f);
    if (symlink(target, link) != 0) {
        /* Filesystem without symlink support; nothing to assert. */
        SKIP("OpenOutFile/OpenKeyFile symlink assertions: symlink() failed");
    } else {
        f = wolfCLU_OpenOutFile(link);
        CHECK(f != NULL, "OpenOutFile follows symlink");
        if (f != NULL) {
            fputs("data", f);
            fclose(f);
        }
        CHECK(lstat(link, &st) == 0 && S_ISLNK(st.st_mode),
                "OpenOutFile leaves symlink intact");
        CHECK(stat(target, &st) == 0 && st.st_size == 4,
                "OpenOutFile wrote through symlink");

        /* Key output refuses the same symlink rather than following it. */
        f = wolfCLU_OpenKeyFile(link);
        CHECK(f == NULL, "OpenKeyFile refuses symlink");
        if (f != NULL) {
            fclose(f);
        }
        CHECK(lstat(link, &st) == 0 && S_ISLNK(st.st_mode),
                "OpenKeyFile leaves symlink intact");
        CHECK(stat(target, &st) == 0 && st.st_size == 4,
                "OpenKeyFile did not truncate symlink target");

        remove(link);
    }

    /* Key output re-tightens permissions on an existing loose file. */
    CHECK(chmod(target, 0666) == 0, "OpenKeyFile fixture chmod");
    f = wolfCLU_OpenKeyFile(target);
    CHECK(f != NULL, "OpenKeyFile plain path");
    if (f != NULL) {
        fclose(f);
        CHECK(stat(target, &st) == 0 &&
                (st.st_mode & (S_IRWXG | S_IRWXO)) == 0,
                "OpenKeyFile is owner-only");
    }

    remove(target);
}

/* The refusals below are reachable only from C: the Python end-to-end tests
 * cannot make wolfCLU aim a key write at a hard link or a FIFO. */
static void testKeyFileRefusals(void)
{
    char  target[64];
    char  hard[64];
    char  fifo[64];
    FILE* f;
    struct stat st;

    XSNPRINTF(target, sizeof(target), "test_refuse_%d.tmp", (int)GETPID());
    XSNPRINTF(hard, sizeof(hard), "test_refuse_link_%d.tmp", (int)GETPID());
    XSNPRINTF(fifo, sizeof(fifo), "test_refuse_fifo_%d.tmp", (int)GETPID());
    remove(target);
    remove(hard);
    remove(fifo);

    /* A second hard link would keep the old key readable through the other
     * name, so the write is refused with EMLINK. */
    f = fopen(target, "wb");
    if (f == NULL) {
        CHECK(0, "KeyFileRefusals fixture create");
        return;
    }
    fputs("old key", f);
    fclose(f);

    if (link(target, hard) == 0) {
        /* errno is only asserted against wolfCLU_CreateSecureFile(), which
         * returns without logging. wolfCLU_OpenKeyFile() calls
         * wolfCLU_LogError() on the way out, and a library call is allowed
         * to set errno even when it succeeds. */
        errno = 0;
        f = wolfCLU_CreateSecureFile(target, "wb", 1);
        CHECK(f == NULL, "CreateSecureFile refuses multiply linked file");
        CHECK(errno == EMLINK, "CreateSecureFile reports EMLINK");
        if (f != NULL) {
            fclose(f);
        }
        f = wolfCLU_OpenKeyFile(target);
        CHECK(f == NULL, "OpenKeyFile refuses multiply linked file");
        if (f != NULL) {
            fclose(f);
        }
        CHECK(stat(target, &st) == 0 && st.st_size == 7,
                "OpenKeyFile left the multiply linked file intact");
        remove(hard);
    }
    else {
        SKIP("OpenKeyFile hard link refusal: link() failed");
    }
    remove(target);

    /* A FIFO is not a regular file: refused with EEXIST, not followed. */
    if (mkfifo(fifo, 0600) == 0) {
        errno = 0;
        f = wolfCLU_CreateSecureFile(fifo, "wb", 1);
        CHECK(f == NULL, "CreateSecureFile refuses FIFO");
        CHECK(errno == EEXIST, "CreateSecureFile reports EEXIST for FIFO");
        if (f != NULL) {
            fclose(f);
        }
        f = wolfCLU_OpenKeyFile(fifo);
        CHECK(f == NULL, "OpenKeyFile refuses FIFO");
        if (f != NULL) {
            fclose(f);
        }
        CHECK(lstat(fifo, &st) == 0 && S_ISFIFO(st.st_mode),
                "OpenKeyFile left the FIFO in place");
        remove(fifo);
    }
    else {
        SKIP("OpenKeyFile FIFO refusal: mkfifo() failed");
    }
}

static void testOpenExistingSecureFile(void)
{
    char  target[64];
    char  symLink[64];
    char  hard[64];
    char  missing[64];
    FILE* f;
    struct stat st;
    char  buf[16];

    XSNPRINTF(target, sizeof(target), "test_existing_%d.tmp", (int)GETPID());
    XSNPRINTF(symLink, sizeof(symLink), "test_existing_link_%d.tmp",
            (int)GETPID());
    XSNPRINTF(hard, sizeof(hard), "test_existing_hard_%d.tmp", (int)GETPID());
    XSNPRINTF(missing, sizeof(missing), "test_existing_no_%d.tmp",
            (int)GETPID());
    remove(target);
    remove(symLink);
    remove(hard);
    remove(missing);

    /* A path that is not there is ENOENT, not a silent create. */
    errno = 0;
    f = wolfCLU_OpenExistingSecureFile(missing, "rb+", 1);
    CHECK(f == NULL, "OpenExistingSecureFile refuses missing path");
    CHECK(errno == ENOENT, "OpenExistingSecureFile reports ENOENT");
    CHECK(stat(missing, &st) != 0,
            "OpenExistingSecureFile did not create the missing path");
    if (f != NULL) {
        fclose(f);
    }

    f = fopen(target, "wb");
    if (f == NULL) {
        CHECK(0, "OpenExistingSecureFile fixture create");
        return;
    }
    fputs("keydata", f);
    fclose(f);

    /* Group/other bits are cleared on the way in. */
    CHECK(chmod(target, 0666) == 0, "OpenExistingSecureFile fixture chmod");
    f = wolfCLU_OpenExistingSecureFile(target, "rb+", 1);
    CHECK(f != NULL, "OpenExistingSecureFile opens regular file");
    if (f != NULL) {
        CHECK(fread(buf, 1, 7, f) == 7,
                "OpenExistingSecureFile did not truncate on rb+");
        fclose(f);
        CHECK(stat(target, &st) == 0 &&
                (st.st_mode & (S_IRWXG | S_IRWXO)) == 0,
                "OpenExistingSecureFile tightened to owner-only");
    }

    /* A symlink at the path is refused rather than followed. */
    if (symlink(target, symLink) == 0) {
        errno = 0;
        f = wolfCLU_OpenExistingSecureFile(symLink, "rb+", 1);
        CHECK(f == NULL, "OpenExistingSecureFile refuses symlink");
        CHECK(errno == ELOOP, "OpenExistingSecureFile reports ELOOP");
        if (f != NULL) {
            fclose(f);
        }
        remove(symLink);
    }
    else {
        SKIP("OpenExistingSecureFile symlink refusal: symlink() failed");
    }

    /* A second hard link is refused, the same way it is at creation time. */
    if (link(target, hard) == 0) {
        errno = 0;
        f = wolfCLU_OpenExistingSecureFile(target, "rb+", 1);
        CHECK(f == NULL, "OpenExistingSecureFile refuses hard-linked file");
        CHECK(errno == EMLINK, "OpenExistingSecureFile reports EMLINK");
        if (f != NULL) {
            fclose(f);
        }
        /* ownerOnly clear is the read path, which does not care. */
        f = wolfCLU_OpenExistingSecureFile(target, "rb", 0);
        CHECK(f != NULL, "OpenExistingSecureFile allows hard link without "
                "ownerOnly");
        if (f != NULL) {
            fclose(f);
        }
        remove(hard);
    }
    else {
        SKIP("OpenExistingSecureFile hard link refusal: link() failed");
    }

    /* NULL path is rejected rather than dereferenced. */
    errno = 0;
    f = wolfCLU_OpenExistingSecureFile(NULL, "rb", 1);
    CHECK(f == NULL, "OpenExistingSecureFile refuses NULL path");
    CHECK(errno == EINVAL, "OpenExistingSecureFile reports EINVAL");
    if (f != NULL) {
        fclose(f);
    }

    remove(target);
}
/* wolfCLU_PathsRefEqual() is a point-in-time check, so -out can be swapped
 * to alias -in between it and the open. wolfCLU_OpenOutFileDistinctFrom()
 * is the backstop: it must catch the alias by file identity and, crucially,
 * must not have truncated the input by the time it does. */
static void testOpenOutFileDistinctFrom(void)
{
    char  target[64];
    char  hard[64];
    FILE* in;
    FILE* out;
    struct stat st;

    XSNPRINTF(target, sizeof(target), "test_distinct_%d.tmp", (int)GETPID());
    XSNPRINTF(hard, sizeof(hard), "test_distinct_hard_%d.tmp", (int)GETPID());
    remove(target);
    remove(hard);

    in = fopen(target, "wb");
    if (in == NULL) {
        CHECK(0, "OpenOutFileDistinctFrom: fixture create");
        return;
    }
    fwrite("survive", 1, 7, in);
    fclose(in);

    if (link(target, hard) != 0) {
        SKIP("OpenOutFileDistinctFrom alias: link() failed");
    }
    else {
        in = fopen(target, "rb");
        if (in == NULL) {
            CHECK(0, "OpenOutFileDistinctFrom: reopen input");
        }
        else {
            /* Same inode reached by a different path string: exactly what
             * a lost race would hand the open. */
            out = wolfCLU_OpenOutFileDistinctFrom(hard, in);
            CHECK(out == NULL,
                    "OpenOutFileDistinctFrom refuses an aliasing -out");
            if (out != NULL) {
                fclose(out);
            }
            CHECK(stat(target, &st) == 0 && st.st_size == 7,
                    "OpenOutFileDistinctFrom left the input untruncated");
            fclose(in);
        }
        remove(hard);
    }

    /* A genuinely distinct -out must still open and truncate. */
    in = fopen(target, "rb");
    if (in == NULL) {
        CHECK(0, "OpenOutFileDistinctFrom: reopen input for distinct case");
    }
    else {
        XSNPRINTF(hard, sizeof(hard), "test_distinct_out_%d.tmp",
                (int)GETPID());
        remove(hard);
        out = wolfCLU_OpenOutFileDistinctFrom(hard, in);
        CHECK(out != NULL, "OpenOutFileDistinctFrom opens a distinct -out");
        if (out != NULL) {
            fclose(out);
            remove(hard);
        }
        fclose(in);
    }

    /* A NULL input means there is nothing to alias. */
    XSNPRINTF(hard, sizeof(hard), "test_distinct_null_%d.tmp", (int)GETPID());
    remove(hard);
    out = wolfCLU_OpenOutFileDistinctFrom(hard, NULL);
    CHECK(out != NULL, "OpenOutFileDistinctFrom accepts a NULL input");
    if (out != NULL) {
        fclose(out);
        remove(hard);
    }

    remove(target);
}

#else /* _WIN32 */

/* Available since Windows 10 1703; older SDK headers may not define it.
 * Without it CreateSymbolicLinkA() needs an elevated token, which a CI
 * runner will not have - callers below treat that as SKIP, not FAIL. */
#ifndef SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED
#define SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED 0x2
#endif

static void testOpenOutAndKeyFileWin(void)
{
    char  target[64];
    char  link[64];
    FILE* f;
    WIN32_FILE_ATTRIBUTE_DATA fad;

    XSNPRINTF(target, sizeof(target), "test_openfile_%d.tmp", (int)GETPID());
    XSNPRINTF(link, sizeof(link), "test_openlink_%d.tmp", (int)GETPID());
    remove(target);
    remove(link);

    /* Non-secret output writes through a reparse point and leaves it in
     * place, exactly as wolfCLU_OpenKeyFile() below must not. */
    f = fopen(target, "wb");
    if (f == NULL) {
        CHECK(0, "OpenOutFile fixture create target");
        return;
    }
    fclose(f);

    if (!CreateSymbolicLinkA(link, target,
            SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED)) {
        /* No Developer Mode / not elevated: nothing to assert. */
        SKIP("OpenOutFile/OpenKeyFile reparse point assertions: "
                "CreateSymbolicLinkA() failed");
    }
    else {
        f = wolfCLU_OpenOutFile(link);
        CHECK(f != NULL, "OpenOutFile follows reparse point");
        if (f != NULL) {
            fputs("data", f);
            fclose(f);
        }
        CHECK(GetFileAttributesExA(link, GetFileExInfoStandard, &fad) &&
                (fad.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0,
                "OpenOutFile leaves reparse point intact");

        /* Key output refuses the same reparse point rather than following
         * it. */
        errno = 0;
        f = wolfCLU_OpenKeyFile(link);
        CHECK(f == NULL, "OpenKeyFile refuses reparse point");
        if (f != NULL) {
            fclose(f);
        }
        CHECK(GetFileAttributesExA(link, GetFileExInfoStandard, &fad) &&
                (fad.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0,
                "OpenKeyFile leaves reparse point intact");
        CHECK(GetFileAttributesExA(target, GetFileExInfoStandard, &fad) &&
                fad.nFileSizeLow == 4,
                "OpenKeyFile did not truncate reparse point target");

        remove(link);
    }

    /* Plain path still opens normally. */
    f = wolfCLU_OpenKeyFile(target);
    CHECK(f != NULL, "OpenKeyFile plain path");
    if (f != NULL) {
        fclose(f);
    }

    remove(target);
}

/* The refusals below are reachable only from C: the Python end-to-end tests
 * cannot make wolfCLU aim a key write at a hard-linked file. */
static void testKeyFileRefusalsWin(void)
{
    char  target[64];
    char  hard[64];
    FILE* f;
    WIN32_FILE_ATTRIBUTE_DATA fad;

    XSNPRINTF(target, sizeof(target), "test_refuse_%d.tmp", (int)GETPID());
    XSNPRINTF(hard, sizeof(hard), "test_refuse_link_%d.tmp", (int)GETPID());
    remove(target);
    remove(hard);

    /* A second hard link would keep the old key readable through the other
     * name, so the write is refused with EMLINK. */
    f = fopen(target, "wb");
    if (f == NULL) {
        CHECK(0, "KeyFileRefusals fixture create");
        return;
    }
    fputs("old key", f);
    fclose(f);

    if (!CreateHardLinkA(hard, target, NULL)) {
        SKIP("OpenKeyFile hard link refusal: CreateHardLinkA() failed");
    }
    else {
        errno = 0;
        f = wolfCLU_CreateSecureFile(target, "wb", 1);
        CHECK(f == NULL, "CreateSecureFile refuses multiply linked file");
        CHECK(errno == EMLINK, "CreateSecureFile reports EMLINK");
        if (f != NULL) {
            fclose(f);
        }
        f = wolfCLU_OpenKeyFile(target);
        CHECK(f == NULL, "OpenKeyFile refuses multiply linked file");
        if (f != NULL) {
            fclose(f);
        }
        CHECK(GetFileAttributesExA(target, GetFileExInfoStandard, &fad) &&
                fad.nFileSizeLow == 7,
                "OpenKeyFile left the multiply linked file intact");
        remove(hard);
    }
    remove(target);
}

static void testOpenExistingSecureFileWin(void)
{
    char  target[64];
    char  symLink[64];
    char  hard[64];
    char  missing[64];
    FILE* f;
    char  buf[16];

    XSNPRINTF(target, sizeof(target), "test_existing_%d.tmp", (int)GETPID());
    XSNPRINTF(symLink, sizeof(symLink), "test_existing_link_%d.tmp",
            (int)GETPID());
    XSNPRINTF(hard, sizeof(hard), "test_existing_hard_%d.tmp", (int)GETPID());
    XSNPRINTF(missing, sizeof(missing), "test_existing_no_%d.tmp",
            (int)GETPID());
    remove(target);
    remove(symLink);
    remove(hard);
    remove(missing);

    /* A path that is not there is ENOENT, not a silent create. */
    errno = 0;
    f = wolfCLU_OpenExistingSecureFile(missing, "rb+", 1);
    CHECK(f == NULL, "OpenExistingSecureFile refuses missing path");
    CHECK(errno == ENOENT, "OpenExistingSecureFile reports ENOENT");
    CHECK(GetFileAttributesA(missing) == INVALID_FILE_ATTRIBUTES,
            "OpenExistingSecureFile did not create the missing path");
    if (f != NULL) {
        fclose(f);
    }

    f = fopen(target, "wb");
    if (f == NULL) {
        CHECK(0, "OpenExistingSecureFile fixture create");
        return;
    }
    fputs("keydata", f);
    fclose(f);

    f = wolfCLU_OpenExistingSecureFile(target, "rb+", 1);
    CHECK(f != NULL, "OpenExistingSecureFile opens regular file");
    if (f != NULL) {
        CHECK(fread(buf, 1, 7, f) == 7,
                "OpenExistingSecureFile did not truncate on rb+");
        fclose(f);
    }

    /* A reparse point at the path is refused rather than followed. */
    if (!CreateSymbolicLinkA(symLink, target,
            SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED)) {
        SKIP("OpenExistingSecureFile reparse point refusal: "
                "CreateSymbolicLinkA() failed");
    }
    else {
        errno = 0;
        f = wolfCLU_OpenExistingSecureFile(symLink, "rb+", 1);
        CHECK(f == NULL, "OpenExistingSecureFile refuses reparse point");
        CHECK(errno == ELOOP, "OpenExistingSecureFile reports ELOOP");
        if (f != NULL) {
            fclose(f);
        }
        remove(symLink);
    }

    /* A second hard link is refused, the same way it is at creation time. */
    if (!CreateHardLinkA(hard, target, NULL)) {
        SKIP("OpenExistingSecureFile hard link refusal: "
                "CreateHardLinkA() failed");
    }
    else {
        errno = 0;
        f = wolfCLU_OpenExistingSecureFile(target, "rb+", 1);
        CHECK(f == NULL, "OpenExistingSecureFile refuses hard-linked file");
        CHECK(errno == EMLINK, "OpenExistingSecureFile reports EMLINK");
        if (f != NULL) {
            fclose(f);
        }
        /* ownerOnly clear is the read path, which does not care. */
        f = wolfCLU_OpenExistingSecureFile(target, "rb", 0);
        CHECK(f != NULL, "OpenExistingSecureFile allows hard link without "
                "ownerOnly");
        if (f != NULL) {
            fclose(f);
        }
        remove(hard);
    }

    /* NULL path is rejected rather than dereferenced. */
    errno = 0;
    f = wolfCLU_OpenExistingSecureFile(NULL, "rb", 1);
    CHECK(f == NULL, "OpenExistingSecureFile refuses NULL path");
    CHECK(errno == EINVAL, "OpenExistingSecureFile reports EINVAL");
    if (f != NULL) {
        fclose(f);
    }

    remove(target);
}
#endif /* !_WIN32 */

/* The BIO wrappers hand the FILE* to wolfSSL with BIO_CLOSE, so freeing the
 * BIO must close the underlying file rather than leak it. */
static void testSecureFileBios(void)
{
    char         path[64];
    WOLFSSL_BIO* bio;
    struct stat  st;

    XSNPRINTF(path, sizeof(path), "test_bio_%d.tmp", (int)GETPID());
    remove(path);

    bio = wolfCLU_OpenOutFileBio(path);
    CHECK(bio != NULL, "OpenOutFileBio opens");
    if (bio != NULL) {
        CHECK(wolfSSL_BIO_write(bio, "bio", 3) == 3, "OpenOutFileBio writes");
        wolfSSL_BIO_free(bio);
        /* If BIO_free did not close the FILE*, the data would still be
         * sitting in the stdio buffer and the file would be short. */
        CHECK(stat(path, &st) == 0 && st.st_size == 3,
                "OpenOutFileBio flushed and closed on BIO_free");
    }
    remove(path);

    bio = wolfCLU_OpenKeyFileBio(path);
    CHECK(bio != NULL, "OpenKeyFileBio opens");
    if (bio != NULL) {
        CHECK(wolfSSL_BIO_write(bio, "key", 3) == 3, "OpenKeyFileBio writes");
        wolfSSL_BIO_free(bio);
        CHECK(stat(path, &st) == 0 && st.st_size == 3,
                "OpenKeyFileBio flushed and closed on BIO_free");
#ifndef _WIN32
        CHECK(stat(path, &st) == 0 && (st.st_mode & (S_IRWXG | S_IRWXO)) == 0,
                "OpenKeyFileBio is owner-only");
#endif
    }
    remove(path);

    /* isSecret picks the key variant, which is the owner-only one. */
    bio = wolfCLU_OpenOutOrKeyFileBio(path, 1);
    CHECK(bio != NULL, "OpenOutOrKeyFileBio opens");
    if (bio != NULL) {
        wolfSSL_BIO_free(bio);
#ifndef _WIN32
        CHECK(stat(path, &st) == 0 && (st.st_mode & (S_IRWXG | S_IRWXO)) == 0,
                "OpenOutOrKeyFileBio(isSecret=1) is owner-only");
#endif
    }
    remove(path);

    /* isSecret=0 opens as a regular output file. */
    bio = wolfCLU_OpenOutOrKeyFileBio(path, 0);
    CHECK(bio != NULL, "OpenOutOrKeyFileBio(isSecret=0) opens");
    if (bio != NULL) {
        wolfSSL_BIO_free(bio);
#ifndef _WIN32
        CHECK(stat(path, &st) == 0,
                "OpenOutOrKeyFileBio(isSecret=0) stat");
#endif
    }
    remove(path);
}

static void testDerSetLength(void)
{
    byte out[8];
    word32 sz;

    /* size-only mode (output == NULL) */
    CHECK(wolfCLU_DerSetLength(0, NULL) == 1, "DerSetLength size-only 0");
    CHECK(wolfCLU_DerSetLength(127, NULL) == 1, "DerSetLength size-only 127");
    CHECK(wolfCLU_DerSetLength(128, NULL) == 2, "DerSetLength size-only 128");
    CHECK(wolfCLU_DerSetLength(255, NULL) == 2, "DerSetLength size-only 255");
    CHECK(wolfCLU_DerSetLength(256, NULL) == 3, "DerSetLength size-only 256");
    CHECK(wolfCLU_DerSetLength(65535, NULL) == 3,
            "DerSetLength size-only 65535");
    CHECK(wolfCLU_DerSetLength(65536, NULL) == 4,
            "DerSetLength size-only 65536");
    CHECK(wolfCLU_DerSetLength(0xFFFFFF, NULL) == 4,
            "DerSetLength size-only 0xFFFFFF");
    CHECK(wolfCLU_DerSetLength(0x1000000, NULL) == 5,
            "DerSetLength size-only 0x1000000");
    CHECK(wolfCLU_DerSetLength(0xFFFFFFFF, NULL) == 5,
            "DerSetLength size-only 0xFFFFFFFF");

    /* short-form: length < 0x80 encodes as a single byte */
    XMEMSET(out, 0, sizeof(out));
    sz = wolfCLU_DerSetLength(0, out);
    CHECK(sz == 1 && out[0] == 0x00, "DerSetLength encode 0");

    XMEMSET(out, 0, sizeof(out));
    sz = wolfCLU_DerSetLength(127, out);
    CHECK(sz == 1 && out[0] == 0x7F, "DerSetLength encode 127");

    /* long-form boundary: 128 requires 0x81 0x80 */
    XMEMSET(out, 0, sizeof(out));
    sz = wolfCLU_DerSetLength(128, out);
    CHECK(sz == 2 && out[0] == 0x81 && out[1] == 0x80,
            "DerSetLength encode 128");

    XMEMSET(out, 0, sizeof(out));
    sz = wolfCLU_DerSetLength(255, out);
    CHECK(sz == 2 && out[0] == 0x81 && out[1] == 0xFF,
            "DerSetLength encode 255");

    /* long-form boundary: 256 requires 0x82 0x01 0x00 */
    XMEMSET(out, 0, sizeof(out));
    sz = wolfCLU_DerSetLength(256, out);
    CHECK(sz == 3 && out[0] == 0x82 && out[1] == 0x01 && out[2] == 0x00,
            "DerSetLength encode 256");

    XMEMSET(out, 0, sizeof(out));
    sz = wolfCLU_DerSetLength(65535, out);
    CHECK(sz == 3 && out[0] == 0x82 && out[1] == 0xFF && out[2] == 0xFF,
            "DerSetLength encode 65535");

    /* long-form boundary: 65536 requires 0x83 0x01 0x00 0x00 */
    XMEMSET(out, 0, sizeof(out));
    sz = wolfCLU_DerSetLength(65536, out);
    CHECK(sz == 4 && out[0] == 0x83 && out[1] == 0x01 &&
            out[2] == 0x00 && out[3] == 0x00, "DerSetLength encode 65536");

    /* This is the boundary the BytePrecisionCopy()-based encoder this
     * function replaced used to under-count: 3-byte lengths need a 4-byte
     * long form (0x83 + 3 length bytes). */
    XMEMSET(out, 0, sizeof(out));
    sz = wolfCLU_DerSetLength(0xFFFFFF, out);
    CHECK(sz == 4 && out[0] == 0x83 && out[1] == 0xFF && out[2] == 0xFF &&
            out[3] == 0xFF, "DerSetLength encode 0xFFFFFF");

    /* long-form boundary: 0x1000000 requires 5 bytes: 0x84 0x01 0x00 0x00
     * 0x00 */
    XMEMSET(out, 0, sizeof(out));
    sz = wolfCLU_DerSetLength(0x1000000, out);
    CHECK(sz == 5 && out[0] == 0x84 && out[1] == 0x01 && out[2] == 0x00 &&
            out[3] == 0x00 && out[4] == 0x00, "DerSetLength encode 0x1000000");

    /* largest word32 length: 0x84 0xFF 0xFF 0xFF 0xFF */
    XMEMSET(out, 0, sizeof(out));
    sz = wolfCLU_DerSetLength(0xFFFFFFFF, out);
    CHECK(sz == 5 && out[0] == 0x84 && out[1] == 0xFF && out[2] == 0xFF &&
            out[3] == 0xFF && out[4] == 0xFF,
            "DerSetLength encode 0xFFFFFFFF");
}


/* Every CHECK() in some fixtures (e.g. testKeyFileRefusals(), whose EMLINK/
 * FIFO-refusal coverage only runs when link()/mkfifo() succeed) is nested
 * inside an environment-dependent branch, with SKIP() on the other side.
 * `checked` is one process-wide counter, so a fixture that hit 0 CHECK()s
 * is otherwise invisible: main()'s overall pass/skip decision is masked by
 * unrelated fixtures that always assert. Make that visible per-fixture. */
static void runFixture(const char* name, void (*fn)(void))
{
    int before = checked;
    fn();
    if (checked == before) {
        printf("WARN: %s contributed 0 assertions (environment may lack "
                "the feature it tests)\n", name);
    }
}

int main(void)
{
    /* The BIO wrappers and every wolfCLU_LogError() path reach into the
     * wolfSSL compat layer, which src/clu_main.c brackets the same way. */
    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        printf("FAIL: wolfSSL_Init\n");
        return 1;
    }

    runFixture("testReadFileToBuffer", testReadFileToBuffer);
    runFixture("testPathsRefEqual", testPathsRefEqual);
#ifndef _WIN32
    runFixture("testOpenOutAndKeyFile", testOpenOutAndKeyFile);
    runFixture("testKeyFileRefusals", testKeyFileRefusals);
    runFixture("testOpenExistingSecureFile", testOpenExistingSecureFile);
    runFixture("testOpenOutFileDistinctFrom", testOpenOutFileDistinctFrom);
#else
    runFixture("testOpenOutAndKeyFileWin", testOpenOutAndKeyFileWin);
    runFixture("testKeyFileRefusalsWin", testKeyFileRefusalsWin);
    runFixture("testOpenExistingSecureFileWin", testOpenExistingSecureFileWin);
#endif
    runFixture("testSecureFileBios", testSecureFileBios);
    runFixture("testDerSetLength", testDerSetLength);

    wolfSSL_Cleanup();

    if (fail == 0) {
        if (skipped > 0) {
            printf("All tools_unit_test tests passed (%d skipped).\n", skipped);
        } else {
            printf("All tools_unit_test tests passed.\n");
        }
    }
    else {
        printf("%d tools_unit_test test(s) FAILED.\n", fail);
    }

    /* SKIP only when nothing ran at all; a partial run (some fixtures
     * unbuildable, everything else passed) is still a PASS. */
    return fail ? 1 : (checked > 0 ? 0 : 77);
}

#else /* WOLFCLU_NO_FILESYSTEM */

int main(void)
{
    printf("tools_unit_test skipped: built with --disable-filesystem.\n");
    return 77; /* automake SKIP */
}

#endif /* !WOLFCLU_NO_FILESYSTEM */
