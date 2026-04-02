"""Shared helpers for wolfCLU Python tests."""

import os
import platform
import subprocess
import sys
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_TESTS_DIR)


def _find_wolfssl_bin():
    """Locate the wolfssl binary, searching common build output paths."""
    if platform.system() == "Windows":
        candidates = [
            os.path.join(_PROJECT_ROOT, "x64", "Debug", "wolfssl.exe"),
            os.path.join(_PROJECT_ROOT, "x64", "Release", "wolfssl.exe"),
            os.path.join(_PROJECT_ROOT, "Debug", "wolfssl.exe"),
            os.path.join(_PROJECT_ROOT, "Release", "wolfssl.exe"),
            os.path.join(_PROJECT_ROOT, "wolfssl.exe"),
        ]
    else:
        candidates = [
            os.path.join(_PROJECT_ROOT, "wolfssl"),
        ]

    for path in candidates:
        if os.path.isfile(path):
            return path

    # Fall back to first candidate; tests will get a clear FileNotFoundError
    return candidates[0]


WOLFSSL_BIN = _find_wolfssl_bin()
CERTS_DIR = os.path.join(_PROJECT_ROOT, "certs")


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
    if result.testsRun == 0:
        sys.exit(77)
    sys.exit(0)
