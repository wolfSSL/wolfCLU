"""Shared helpers for wolfCLU Python tests."""

import os
import platform
import subprocess


def _find_wolfssl_bin():
    """Locate the wolfssl binary, searching common build output paths."""
    if platform.system() == "Windows":
        candidates = [
            os.path.join(".", "x64", "Debug", "wolfssl.exe"),
            os.path.join(".", "x64", "Release", "wolfssl.exe"),
            os.path.join(".", "Debug", "wolfssl.exe"),
            os.path.join(".", "Release", "wolfssl.exe"),
            os.path.join(".", "wolfssl.exe"),
        ]
    else:
        candidates = [
            os.path.join(".", "wolfssl"),
        ]

    for path in candidates:
        if os.path.isfile(path):
            return path

    # Fall back to first candidate; tests will get a clear FileNotFoundError
    return candidates[0]


WOLFSSL_BIN = _find_wolfssl_bin()
CERTS_DIR = os.path.join(".", "certs")


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
