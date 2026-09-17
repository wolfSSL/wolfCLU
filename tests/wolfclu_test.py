"""Shared helpers for wolfCLU Python tests."""

import os
import platform
import subprocess
import sys
import unittest
import socket

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_TESTS_DIR)
PROJECT_ROOT = _PROJECT_ROOT


def find_free_port():
     """Return an ephemeral TCP port number chosen by the OS.
     This does *not* reserve the port after the socket is closed, so callers that
     bind/listen should be prepared to retry if the port is claimed concurrently. """

     with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _find_wolfssl_bin():
    """Locate the wolfssl binary, searching common build output paths.

    Under `make distcheck`, the build directory differs from the source
    directory, so the binary is produced next to where tests are invoked
    (the current working directory) rather than under the source tree.
    Honour WOLFCLU_BUILDDIR if set by the test harness, then fall back to
    the current working directory, and finally the source tree.
    """
    builddir = os.environ.get("WOLFCLU_BUILDDIR") or os.getcwd()
    if platform.system() == "Windows":
        candidates = [
            os.path.join(builddir, "wolfssl.exe"),
            os.path.join(_PROJECT_ROOT, "x64", "Debug", "wolfssl.exe"),
            os.path.join(_PROJECT_ROOT, "x64", "Release", "wolfssl.exe"),
            os.path.join(_PROJECT_ROOT, "Debug", "wolfssl.exe"),
            os.path.join(_PROJECT_ROOT, "Release", "wolfssl.exe"),
            os.path.join(_PROJECT_ROOT, "wolfssl.exe"),
        ]
    else:
        candidates = [
            os.path.join(builddir, "wolfssl"),
            os.path.join(_PROJECT_ROOT, "wolfssl"),
        ]

    for path in candidates:
        if os.path.isfile(path):
            return path

    # Fall back to first candidate; tests will get a clear FileNotFoundError
    return candidates[0]


def _find_certs_dir():
    """Locate the certs directory (source tree or extracted tarball)."""
    srcdir = os.environ.get("WOLFCLU_SRCDIR")
    candidates = []
    if srcdir:
        candidates.append(os.path.join(srcdir, "certs"))
    candidates.append(os.path.join(_PROJECT_ROOT, "certs"))
    for path in candidates:
        if os.path.isdir(path):
            return path
    return candidates[-1]


WOLFSSL_BIN = _find_wolfssl_bin()
CERTS_DIR = _find_certs_dir()


def run_wolfssl(*args, stdin_data=None, timeout=60):
    """Run the wolfssl binary with the given arguments.

    Returns a CompletedProcess instance.
    A default timeout of 60 seconds prevents indefinite hangs in CI.
    Network-facing tests (s_client, ocsp) manage their own timeouts.
    """
    cmd = [WOLFSSL_BIN] + list(args)
    kwargs = dict(capture_output=True, text=True, timeout=timeout)
    if stdin_data is not None:
        kwargs["input"] = stdin_data
    else:
        kwargs["stdin"] = subprocess.DEVNULL
    return subprocess.run(cmd, **kwargs)


_NO_FILESYSTEM = None

# The probe names a file that cannot exist, so the command must always exit
# non-zero; exit 0 means it has stopped measuring anything.
_NO_FS_PROBE_ARGS = ("x509", "-in", "wolfclu-no-filesystem-probe")

# Case-insensitive: clu_cert_setup.c prints "No filesystem support",
# clu_request_setup.c "No Filesystem Support.".
_NO_FS_MESSAGE = "no filesystem support"


def no_filesystem():
    """True when the build under test has no filesystem support.

    Fails loud rather than open: returning False on a --disable-filesystem
    build would stop every suite below from skipping, turning a clean SKIP
    run into hundreds of unrelated failures. A missing binary, a timeout or
    an unexpectedly successful probe therefore raises instead of guessing.
    """
    global _NO_FILESYSTEM
    if _NO_FILESYSTEM is None:
        # OSError/SubprocessError deliberately uncaught: not a verdict.
        r = run_wolfssl(*_NO_FS_PROBE_ARGS)
        combined = r.stdout + r.stderr
        if r.returncode == 0:
            raise RuntimeError(
                "filesystem probe `%s %s` unexpectedly succeeded; it can no "
                "longer detect --disable-filesystem builds:\n%s"
                % (WOLFSSL_BIN, " ".join(_NO_FS_PROBE_ARGS), combined))
        _NO_FILESYSTEM = _NO_FS_MESSAGE in combined.lower()
    return _NO_FILESYSTEM


def is_fips():
    """True when linked against a FIPS wolfSSL build (per `wolfssl -v`)."""
    r = run_wolfssl("-v")
    return "FIPS" in (r.stdout + r.stderr)


# wolfSSL's NOT_COMPILED_IN.  wolfCLU returns it whenever an algorithm is
# named explicitly but is absent from the linked wolfSSL build, and main()
# reports it as "Error returned: -174.".
NOT_COMPILED_IN = -174


def not_compiled_in(result):
    """True when wolfCLU rejected the command because the requested algorithm
    is not compiled into the linked wolfSSL build.

    Lets tests for optional algorithms skip rather than fail on builds that
    omit them (e.g. wolfSSL built with NO_MD5 or without --enable-ed25519).
    """
    return "Error returned: {}.".format(NOT_COMPILED_IN) in (
        result.stdout + result.stderr)


def make_sparse(fileobj):
    """Mark an open file as sparse on Windows before it is extended.

    NTFS does not treat a file as sparse unless the sparse flag is set
    explicitly, so a subsequent truncate() physically allocates and
    zero-fills every byte.  Setting FSCTL_SET_SPARSE first keeps the
    extension sparse, matching the behaviour of ext4/APFS where truncate()
    is already sparse.  This must be called before extending the file.

    No-op on non-Windows platforms.
    """
    if sys.platform != "win32":
        return
    import ctypes
    import msvcrt
    from ctypes import wintypes

    FSCTL_SET_SPARSE = 0x000900C4
    handle = msvcrt.get_osfhandle(fileobj.fileno())
    bytes_returned = wintypes.DWORD(0)
    ok = ctypes.windll.kernel32.DeviceIoControl(
        wintypes.HANDLE(handle),
        FSCTL_SET_SPARSE,
        None, 0,        # no input buffer => set the sparse flag (TRUE)
        None, 0,        # no output buffer
        ctypes.byref(bytes_returned),
        None,
    )
    if not ok:
        raise ctypes.WinError()


def truncate_sparse(fileobj, size):
    """Extend an open file to `size` bytes without physically allocating it.

    On POSIX, truncate() already produces a sparse file. On Windows, Python's
    truncate() routes through the CRT _chsize_s, which *writes zeros* over the
    extended range and so allocates every cluster even when the sparse flag is
    set. Instead we mark the file sparse and move the end-of-file pointer with
    SetEndOfFile directly: no bytes are written, so the range stays sparse (and
    it is instant rather than a multi-GB zero-fill).
    """
    if sys.platform != "win32":
        fileobj.truncate(size)
        return

    import ctypes
    import msvcrt
    from ctypes import wintypes

    make_sparse(fileobj)  # set FSCTL_SET_SPARSE first

    k32 = ctypes.windll.kernel32
    handle = wintypes.HANDLE(msvcrt.get_osfhandle(fileobj.fileno()))

    set_ptr = k32.SetFilePointerEx
    set_ptr.argtypes = [wintypes.HANDLE, ctypes.c_longlong,
                        ctypes.POINTER(ctypes.c_longlong), wintypes.DWORD]
    set_ptr.restype = wintypes.BOOL
    FILE_BEGIN = 0
    if not set_ptr(handle, ctypes.c_longlong(size), None, FILE_BEGIN):
        raise ctypes.WinError()

    set_eof = k32.SetEndOfFile
    set_eof.argtypes = [wintypes.HANDLE]
    set_eof.restype = wintypes.BOOL
    if not set_eof(handle):
        raise ctypes.WinError()


class _CountingResult(unittest.TextTestResult):
    """TextTestResult that also counts the tests which actually ran.

    testsRun cannot answer "did anything run?" on its own: a SkipTest
    raised from setUpClass lands in result.skipped without incrementing
    testsRun, while @unittest.skipIf increments it once per skipped
    method.  Counting completions is exact under either style.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ran = 0

    def addSuccess(self, test):
        super().addSuccess(test)
        self.ran += 1

    def addExpectedFailure(self, test, err):
        super().addExpectedFailure(test, err)
        self.ran += 1


class _CountingRunner(unittest.TextTestRunner):
    resultclass = _CountingResult


def test_main():
    """Run tests with automake-compatible exit codes.

    Automake interprets exit 77 as SKIP.  Python's unittest exits 0 even
    when every test was skipped, so automake would report PASS.  This
    wrapper runs unittest with exit=False and translates the result:
      - failures/errors  -> exit 1
      - nothing actually ran -> exit 77  (automake SKIP)
      - otherwise        -> exit 0  (automake PASS)
    """
    prog = unittest.main(module='__main__', exit=False,
                         testRunner=_CountingRunner)
    result = prog.result
    if not result.wasSuccessful():
        sys.exit(1)
    if result.ran == 0:
        sys.exit(77)
    sys.exit(0)
