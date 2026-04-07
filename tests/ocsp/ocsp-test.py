#!/usr/bin/env python3
"""OCSP interoperability tests for wolfCLU.

Combines ocsp-test.sh and ocsp-interop-test.sh into a single Python
test module. Tests all client/responder combinations (wolfssl, openssl).
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import WOLFSSL_BIN, CERTS_DIR, test_main

HAS_OPENSSL = shutil.which("openssl") is not None
OCSP_PORT_BASE = 6960

INDEX_VALID = (
    "V\t991231235959Z\t\t01\tunknown\t"
    "/C=US/ST=Montana/L=Bozeman/O=wolfSSL/OU=Support"
    "/CN=www.wolfssl.com/emailAddress=info@wolfssl.com\n"
)

INDEX_REVOKED = (
    "R\t991231235959Z\t240101000000Z\t02\tunknown\t"
    "/C=US/ST=Montana/L=Bozeman/O=wolfSSL_revoked/OU=Support_revoked"
    "/CN=www.wolfssl.com/emailAddress=info@wolfssl.com\n"
)


def _ocsp_supported(binary):
    """Check if the given binary supports OCSP."""
    try:
        r = subprocess.run([binary, "ocsp", "-help"],
                           capture_output=True, timeout=5)
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


class _OCSPResponder:
    """Context manager that starts an OCSP responder and cleans up on exit."""

    def __init__(self, binary, port, index_path, rsigner, rkey, nrequest=10):
        self.cmd = [
            binary, "ocsp", "-port", str(port),
            "-index", index_path,
            "-CA", os.path.join(CERTS_DIR, "ca-cert.pem"),
            "-rsigner", rsigner,
            "-rkey", rkey,
            "-nrequest", str(nrequest),
        ]
        self.proc = None
        self.log_path = None

    def start(self, log_path):
        self.log_path = log_path
        self.log_file = open(log_path, "w")
        self.proc = subprocess.Popen(
            self.cmd,
            stdout=self.log_file,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
        )
        # Wait for responder to bind
        time.sleep(0.5)
        if self.proc.poll() is not None:
            self.log_file.close()
            raise RuntimeError(
                f"Responder exited early (rc={self.proc.returncode})")

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        if hasattr(self, "log_file") and self.log_file:
            self.log_file.close()

    def read_log(self):
        if self.log_path and os.path.isfile(self.log_path):
            with open(self.log_path, "r") as f:
                return f.read()
        return ""


def _run_client(binary, port, extra_args=None):
    """Run an OCSP client query and return (returncode, combined output)."""
    cmd = [
        binary, "ocsp",
        "-issuer", os.path.join(CERTS_DIR, "ca-cert.pem"),
        "-CAfile", os.path.join(CERTS_DIR, "ca-cert.pem"),
        "-url", f"http://127.0.0.1:{port}",
    ]
    if extra_args:
        cmd.extend(extra_args)
    r = subprocess.run(cmd, capture_output=True, text=True,
                       stdin=subprocess.DEVNULL, timeout=30)
    return r.returncode, r.stdout + r.stderr


class _OCSPInteropBase(unittest.TestCase):
    """Base class for a single client/responder combination.

    Not intended to be run directly -- only concrete subclasses that
    set CLIENT_BIN and RESPONDER_BIN are meaningful test classes.
    """

    CLIENT_BIN = None
    RESPONDER_BIN = None
    PORT = OCSP_PORT_BASE

    @classmethod
    def setUpClass(cls):
        if not os.path.isdir(CERTS_DIR):
            raise unittest.SkipTest("certs directory not found")
        if not _ocsp_supported(cls.CLIENT_BIN):
            raise unittest.SkipTest(f"OCSP not supported by {cls.CLIENT_BIN}")
        if not _ocsp_supported(cls.RESPONDER_BIN):
            raise unittest.SkipTest(
                f"OCSP not supported by {cls.RESPONDER_BIN}")

        cls._tmpdir = tempfile.mkdtemp()
        cls._responder = None

    @classmethod
    def tearDownClass(cls):
        if cls._responder:
            cls._responder.stop()
        if hasattr(cls, "_tmpdir") and os.path.isdir(cls._tmpdir):
            shutil.rmtree(cls._tmpdir, ignore_errors=True)

    def _write_index(self, entries):
        path = os.path.join(self._tmpdir, "index.txt")
        with open(path, "w") as f:
            f.write(entries)
        return path

    def _start_responder(self, index_text, rsigner=None, rkey=None,
                         nrequest=10):
        """Stop existing responder (if any) and start a new one."""
        if self._responder:
            self._responder.stop()

        index = self._write_index(index_text)
        if rsigner is None:
            rsigner = os.path.join(CERTS_DIR, "ca-cert.pem")
        if rkey is None:
            rkey = os.path.join(CERTS_DIR, "ca-key.pem")

        log = os.path.join(self._tmpdir,
                           f"responder-{time.monotonic_ns()}.log")
        resp = _OCSPResponder(self.RESPONDER_BIN, self.PORT, index,
                              rsigner, rkey, nrequest)
        resp.start(log)
        self.__class__._responder = resp
        return resp

    def _query(self, cert, extra_args=None):
        args = ["-cert", os.path.join(CERTS_DIR, cert)]
        if extra_args:
            args.extend(extra_args)
        return _run_client(self.CLIENT_BIN, self.PORT, args)

    # -- Positive tests --

    def test_01_basic_check(self):
        self._start_responder(INDEX_VALID)
        rc, out = self._query("server-cert.pem")
        self.assertEqual(rc, 0, f"basic OCSP check failed: {out}")
        self.assertIn("good", out.lower())

    def test_02_no_nonce(self):
        self._start_responder(INDEX_VALID)
        rc, out = self._query("server-cert.pem", ["-no_nonce"])
        self.assertEqual(rc, 0, f"no_nonce check failed: {out}")
        self.assertIn("good", out.lower())

    # -- Revoked cert --

    def test_03_revoked_cert(self):
        self._start_responder(INDEX_VALID + INDEX_REVOKED)
        rc, out = self._query("server-revoked-cert.pem")
        self.assertRegex(out, re.compile("revoked", re.IGNORECASE),
                         "expected 'revoked' in output")

    # -- Missing parameters --

    def test_04_missing_issuer(self):
        self._start_responder(INDEX_VALID)
        cmd = [
            self.CLIENT_BIN, "ocsp",
            "-cert", os.path.join(CERTS_DIR, "server-cert.pem"),
            "-CAfile", os.path.join(CERTS_DIR, "ca-cert.pem"),
            "-url", f"http://127.0.0.1:{self.PORT}",
        ]
        r = subprocess.run(cmd, capture_output=True, text=True,
                           stdin=subprocess.DEVNULL, timeout=30)
        self.assertNotEqual(r.returncode, 0)
        self.assertRegex(r.stdout + r.stderr,
                         re.compile("issuer", re.IGNORECASE))

    def test_05_missing_cert(self):
        self._start_responder(INDEX_VALID)
        cmd = [
            self.CLIENT_BIN, "ocsp",
            "-issuer", os.path.join(CERTS_DIR, "ca-cert.pem"),
            "-CAfile", os.path.join(CERTS_DIR, "ca-cert.pem"),
            "-url", f"http://127.0.0.1:{self.PORT}",
        ]
        r = subprocess.run(cmd, capture_output=True, text=True,
                           stdin=subprocess.DEVNULL, timeout=30)
        self.assertNotEqual(r.returncode, 0)
        self.assertRegex(r.stdout + r.stderr,
                         re.compile("cert|help|usage", re.IGNORECASE))

    # -- Invalid files --

    def test_06_invalid_cert_file(self):
        self._start_responder(INDEX_VALID)
        rc, out = self._query(os.path.join("nonexistent", "file.pem"))
        self.assertNotEqual(rc, 0)
        self.assertRegex(out,
                         re.compile("fail|error|not found|unable|could not|"
                                    "no such",
                                    re.IGNORECASE))

    def test_07_invalid_issuer_file(self):
        self._start_responder(INDEX_VALID)
        cmd = [
            self.CLIENT_BIN, "ocsp",
            "-issuer", os.path.join("nonexistent", "issuer.pem"),
            "-cert", os.path.join(CERTS_DIR, "server-cert.pem"),
            "-CAfile", os.path.join(CERTS_DIR, "ca-cert.pem"),
            "-url", f"http://127.0.0.1:{self.PORT}",
        ]
        r = subprocess.run(cmd, capture_output=True, text=True,
                           stdin=subprocess.DEVNULL, timeout=30)
        self.assertNotEqual(r.returncode, 0)
        self.assertRegex(r.stdout + r.stderr,
                         re.compile("fail|error|unable|issuer|could not|"
                                    "no such",
                                    re.IGNORECASE))

    # -- Delegated responder --

    def test_08_delegated_responder(self):
        self._start_responder(
            INDEX_VALID,
            rsigner=os.path.join(CERTS_DIR, "ocsp-responder-cert.pem"),
            rkey=os.path.join(CERTS_DIR, "ocsp-responder-key.pem"))
        rc, out = self._query("server-cert.pem")
        self.assertEqual(rc, 0, f"delegated responder failed: {out}")
        self.assertIn("good", out.lower())

    def test_09_delegated_no_nonce(self):
        self._start_responder(
            INDEX_VALID,
            rsigner=os.path.join(CERTS_DIR, "ocsp-responder-cert.pem"),
            rkey=os.path.join(CERTS_DIR, "ocsp-responder-key.pem"))
        rc, out = self._query("server-cert.pem", ["-no_nonce"])
        self.assertEqual(rc, 0, f"delegated no_nonce failed: {out}")
        self.assertIn("good", out.lower())

    def test_10_delegated_revoked(self):
        self._start_responder(
            INDEX_VALID + INDEX_REVOKED,
            rsigner=os.path.join(CERTS_DIR, "ocsp-responder-cert.pem"),
            rkey=os.path.join(CERTS_DIR, "ocsp-responder-key.pem"))
        rc, out = self._query("server-revoked-cert.pem")
        self.assertRegex(out, re.compile("revoked", re.IGNORECASE))

    # -- Unreachable responder --

    def test_11_unreachable_responder(self):
        # Make sure responder is stopped
        if self._responder:
            self._responder.stop()
            self.__class__._responder = None

        rc, out = self._query("server-cert.pem")
        self.assertNotEqual(rc, 0)
        self.assertRegex(out,
                         re.compile("fail|error|connect|timeout|refused",
                                    re.IGNORECASE))

    # -- Graceful shutdown (wolfssl responder only) --

    def test_12_graceful_shutdown(self):
        if self.RESPONDER_BIN != WOLFSSL_BIN:
            self.skipTest("graceful shutdown only checked for wolfssl")

        resp = self._start_responder(INDEX_VALID, nrequest=1)
        # Send one request to trigger the nrequest limit
        self._query("server-cert.pem")
        time.sleep(0.5)  # let responder shut down
        log = resp.read_log()
        self.assertIn("wolfssl exiting gracefully", log)


# Concrete test classes for each client/responder combination.
# Each gets a unique port to avoid conflicts if run in parallel.

class TestWolfsslClientWolfsslResponder(_OCSPInteropBase):
    CLIENT_BIN = WOLFSSL_BIN
    RESPONDER_BIN = WOLFSSL_BIN
    PORT = OCSP_PORT_BASE


@unittest.skipUnless(HAS_OPENSSL, "openssl not available")
class TestWolfsslClientOpensslResponder(_OCSPInteropBase):
    CLIENT_BIN = WOLFSSL_BIN
    RESPONDER_BIN = "openssl"
    PORT = OCSP_PORT_BASE + 1


@unittest.skipUnless(HAS_OPENSSL, "openssl not available")
class TestOpensslClientWolfsslResponder(_OCSPInteropBase):
    CLIENT_BIN = "openssl"
    RESPONDER_BIN = WOLFSSL_BIN
    PORT = OCSP_PORT_BASE + 2


@unittest.skipUnless(HAS_OPENSSL, "openssl not available")
class TestOpensslClientOpensslResponder(_OCSPInteropBase):
    CLIENT_BIN = "openssl"
    RESPONDER_BIN = "openssl"
    PORT = OCSP_PORT_BASE + 3


def load_tests(loader, tests, pattern):
    """Exclude the abstract _OCSPInteropBase from test discovery."""
    suite = unittest.TestSuite()
    for test_group in tests:
        for test in test_group:
            if type(test).mro()[0] is not _OCSPInteropBase:
                suite.addTest(test)
    return suite


if __name__ == "__main__":
    test_main()
