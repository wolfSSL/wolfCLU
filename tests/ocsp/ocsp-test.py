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
from wolfclu_test import WOLFSSL_BIN, CERTS_DIR, test_main, find_free_port

HAS_OPENSSL = shutil.which("openssl") is not None


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
    PORT = None

    @classmethod
    def setUpClass(cls):
        if not os.path.isdir(CERTS_DIR):
            raise unittest.SkipTest("certs directory not found")
        if not _ocsp_supported(cls.CLIENT_BIN):
            raise unittest.SkipTest(f"OCSP not supported by {cls.CLIENT_BIN}")
        if not _ocsp_supported(cls.RESPONDER_BIN):
            raise unittest.SkipTest(
                f"OCSP not supported by {cls.RESPONDER_BIN}")

        cls.PORT = find_free_port()
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

    def test_13_malformed_request_counts_toward_nrequest(self):
        """A malformed (non-OCSP) request that still gets an HTTP/OCSP-level
        error response must count toward -nrequest, same as a successful
        request -- otherwise a client sending only malformed requests could
        keep the responder running indefinitely."""
        if self.RESPONDER_BIN != WOLFSSL_BIN:
            self.skipTest("nrequest counting only checked for wolfssl")

        resp = self._start_responder(INDEX_VALID, nrequest=1)

        body = b"not a valid OCSP request"
        request = (
            b"POST / HTTP/1.0\r\n"
            b"Content-Type: application/ocsp-request\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"\r\n" + body
        )
        import socket
        with socket.create_connection(("127.0.0.1", self.PORT),
                                      timeout=5) as s:
            s.sendall(request)
            s.recv(4096)

        time.sleep(0.5)  # let responder shut down
        log = resp.read_log()
        self.assertIn("wolfssl exiting gracefully", log,
                "responder did not shut down after a single malformed "
                "request with -nrequest 1 -- malformed requests must "
                "still count toward the request budget")


# Concrete test classes for each client/responder combination.
# Each gets a dynamically assigned port in setUpClass to avoid conflicts.

class TestWolfsslClientWolfsslResponder(_OCSPInteropBase):
    CLIENT_BIN = WOLFSSL_BIN
    RESPONDER_BIN = WOLFSSL_BIN

    def test_01_client_start_up(self):
        """ successful round trip from client to server """
        resp = self._start_responder(INDEX_VALID, nrequest=1)
        rc, out = _run_client(self.CLIENT_BIN, self.PORT,
                              ["-cert", os.path.join(CERTS_DIR, "server-cert.pem")])

        resp.stop()
        self.assertEqual(rc, 0, out)
        self.assertIn("good", out.lower(), out)


@unittest.skipUnless(HAS_OPENSSL, "openssl not available")
class TestWolfsslClientOpensslResponder(_OCSPInteropBase):
    CLIENT_BIN = WOLFSSL_BIN
    RESPONDER_BIN = "openssl"

    def test_01_client_start_up(self):
        resp = self._start_responder(INDEX_VALID, nrequest=1)
        rc, out = _run_client(self.CLIENT_BIN, self.PORT,
                              ["-cert", os.path.join(CERTS_DIR, "server-cert.pem")])

        resp.stop()
        self.assertEqual(rc, 0, out)
        self.assertIn("good", out.lower(), out)


@unittest.skipUnless(HAS_OPENSSL, "openssl not available")
class TestOpensslClientWolfsslResponder(_OCSPInteropBase):
    CLIENT_BIN = "openssl"
    RESPONDER_BIN = WOLFSSL_BIN

    def test_01_client_start_up(self):
        resp = self._start_responder(INDEX_VALID, nrequest=1)
        rc, out = _run_client(self.CLIENT_BIN, self.PORT,
                              ["-cert", os.path.join(CERTS_DIR, "server-cert.pem")])

        resp.stop()
        self.assertEqual(rc, 0, out)
        self.assertIn("good", out.lower(), out)

@unittest.skipUnless(HAS_OPENSSL, "openssl not available")
class TestOpensslClientOpensslResponder(_OCSPInteropBase):
    CLIENT_BIN = "openssl"
    RESPONDER_BIN = "openssl"

    def test_01_client_start_up(self):
        resp = self._start_responder(INDEX_VALID, nrequest=1)
        rc, out = _run_client(self.CLIENT_BIN, self.PORT,
                              ["-cert", os.path.join(CERTS_DIR, "server-cert.pem")])

        resp.stop()
        self.assertEqual(rc, 0, out)
        self.assertIn("good", out.lower(), out)

class TestPortValidation(unittest.TestCase):
    """Boundary tests for the -port range check in wolfCLU_OcspSetup.

    Validation happens during argument parsing, so no live responder is
    needed -- an out-of-range or non-numeric port is rejected immediately.
    The exact upper boundary (65535) is asserted directly here; a valid port
    with no -CA fails the required-option check after parsing, so the bind
    loop is never reached.
    """

    @classmethod
    def setUpClass(cls):
        if not _ocsp_supported(WOLFSSL_BIN):
            raise unittest.SkipTest(f"OCSP not supported by {WOLFSSL_BIN}")

    def _run_port(self, port):
        r = subprocess.run(
            [WOLFSSL_BIN, "ocsp", "-port", str(port)],
            capture_output=True, text=True,
            stdin=subprocess.DEVNULL, timeout=10)
        return r.returncode, r.stdout + r.stderr

    def _assert_rejected(self, port):
        rc, out = self._run_port(port)
        self.assertNotEqual(rc, 0, f"port {port!r} should be rejected: {out}")
        self.assertRegex(out, re.compile("invalid port|1-65535",
                                         re.IGNORECASE),
                         f"expected range diagnostic for {port!r}: {out}")

    def test_port_zero_rejected(self):
        self._assert_rejected(0)

    def test_port_negative_rejected(self):
        self._assert_rejected(-1)

    def test_port_above_max_rejected(self):
        self._assert_rejected(65536)

    def test_port_truncation_value_rejected(self):
        # 65537 would have truncated to 1 under the old word16 cast.
        self._assert_rejected(65537)

    def test_port_non_numeric_rejected(self):
        self._assert_rejected("abc")

    def test_port_empty_rejected(self):
        self._assert_rejected("")

    def test_port_trailing_text_rejected(self):
        self._assert_rejected("80x")

    def test_port_int_overflow_rejected(self):
        # would wrap to a valid port under the old XATOI cast
        self._assert_rejected(4294967297)  # 2**32 + 1

    def test_port_huge_input_rejected(self):
        # wider than any integer type; parser must not overflow while scanning
        self._assert_rejected("9" * 40)

    def test_port_max_accepted(self):
        # exact upper boundary must pass the parser's overflow check; a regression
        # rejecting 65535 (e.g. > vs >= slip in the bound math) is caught here.
        # -CA is absent, so validation fails after parsing, never binding.
        rc, out = self._run_port(65535)
        self.assertNotRegex(out, re.compile("invalid port|1-65535",
                                            re.IGNORECASE),
                            f"port 65535 should be accepted by parser: {out}")

    def test_port_missing_argument_rejected(self):
        # trailing -port leaves optarg NULL; must emit a clean missing-argument
        # diagnostic, not crash formatting NULL with %s.
        r = subprocess.run(
            [WOLFSSL_BIN, "ocsp", "-port"],
            capture_output=True, text=True,
            stdin=subprocess.DEVNULL, timeout=10)
        self.assertNotEqual(r.returncode, 0,
                            "trailing -port should be rejected")
        self.assertRegex(r.stdout + r.stderr,
                         re.compile("requires an argument|1-65535",
                                    re.IGNORECASE),
                         "expected missing-argument diagnostic for -port")


class TestNrequestValidation(unittest.TestCase):
    """Boundary tests for the -nrequest range check in wolfCLU_OcspSetup.

    Validation happens during parsing. -nrequest alone never enters responder
    mode (that needs -port), so a valid count exits without blocking, letting
    us assert the accept path too.
    """

    @classmethod
    def setUpClass(cls):
        if not _ocsp_supported(WOLFSSL_BIN):
            raise unittest.SkipTest(f"OCSP not supported by {WOLFSSL_BIN}")

    def _run(self, nrequest):
        r = subprocess.run(
            [WOLFSSL_BIN, "ocsp", "-nrequest", str(nrequest)],
            capture_output=True, text=True,
            stdin=subprocess.DEVNULL, timeout=10)
        return r.stdout + r.stderr

    def _assert_rejected(self, nrequest):
        out = self._run(nrequest)
        self.assertRegex(out, re.compile("invalid -nrequest", re.IGNORECASE),
                         f"expected diagnostic for {nrequest!r}: {out}")

    def test_nrequest_negative_rejected(self):
        # old XATOI accepted -1 as a degenerate count
        self._assert_rejected(-1)

    def test_nrequest_non_numeric_rejected(self):
        # old XATOI returned 0, silently treated as unlimited
        self._assert_rejected("abc")

    def test_nrequest_overflow_rejected(self):
        self._assert_rejected(4294967297)  # 2**32 + 1

    def test_nrequest_valid_accepted(self):
        # 0-means-unlimited boundary, a small count, and the exact upper bound
        # (INT_MAX) must all pass parsing; INT_MAX locks in the overflow check.
        for nrequest in (0, 5, 2147483647):
            out = self._run(nrequest)
            self.assertNotRegex(
                out, re.compile("invalid -nrequest", re.IGNORECASE),
                f"-nrequest {nrequest!r} should be accepted by parser: {out}")


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
