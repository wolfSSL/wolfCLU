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


def is_fips():
    """True when linked against a FIPS wolfSSL build (per `wolfssl -v`)."""
    r = run_wolfssl("-v")
    return "FIPS" in (r.stdout + r.stderr)


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


def config_defines():
    """Return the set of macros defined in the generated wolfclu/config.h.

    Some features are compile-time options (e.g. --enable-oid-table sets
    HAVE_OID_TABLE) with no runtime flag to query, so tests that exercise
    those paths need to read the build configuration.  config.h lives in the
    build directory, which differs from the source tree under distcheck;
    honour WOLFCLU_BUILDDIR, then fall back to the current working directory
    and the source tree.  Disabled options appear as `/* #undef NAME */`,
    which this deliberately does not count as defined.
    """
    defined = set()
    builddir = os.environ.get("WOLFCLU_BUILDDIR") or os.getcwd()
    for base in (builddir, _PROJECT_ROOT):
        path = os.path.join(base, "wolfclu", "config.h")
        if not os.path.isfile(path):
            continue
        with open(path) as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "#define":
                    defined.add(parts[1])
        break
    return defined


def test_main():
    """Run tests with automake-compatible exit codes.

    Automake interprets exit 77 as SKIP.  Python's unittest exits 0 even
    when every test was skipped, so automake would report PASS.  This
    wrapper runs unittest with exit=False and translates the result:
      - failures/errors  -> exit 1
      - all skipped / no tests run -> exit 77  (automake SKIP)
      - otherwise        -> exit 0  (automake PASS)
    """
    prog = unittest.main(module='__main__', exit=False)
    result = prog.result
    if not result.wasSuccessful():
        sys.exit(1)
    if result.testsRun == 0 or len(result.skipped) == result.testsRun:
        sys.exit(77)
    sys.exit(0)
