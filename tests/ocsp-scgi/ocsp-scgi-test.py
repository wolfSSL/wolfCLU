#!/usr/bin/env python3
"""OCSP SCGI integration tests for wolfCLU.

Replaces nginx with a minimal Python HTTP-to-SCGI proxy, eliminating
the nginx dependency. The SCGI protocol is simple enough to implement
inline (netstring header + body).

Test flow:
  openssl ocsp (HTTP) -> Python proxy -> wolfssl ocsp -scgi (SCGI)
"""

import http.server
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import WOLFSSL_BIN, CERTS_DIR, test_main

HAS_OPENSSL = shutil.which("openssl") is not None

SCGI_PORT = 6961
HTTP_PORT = 8089

INDEX_VALID = (
    "V\t991231235959Z\t\t01\tunknown\t"
    "/C=US/ST=Montana/L=Bozeman/O=wolfSSL/OU=Support"
    "/CN=www.wolfssl.com/emailAddress=info@wolfssl.com\n"
)
INDEX_REVOKED = (
    "R\t991231235959Z\t200101000000Z\t01\tunknown\t"
    "/C=US/ST=Montana/L=Bozeman/O=wolfSSL/OU=Support"
    "/CN=www.wolfssl.com/emailAddress=info@wolfssl.com\n"
)


def _scgi_request(host, port, body, path="/ocsp"):
    """Send an SCGI request and return the raw response body."""
    headers = (
        "CONTENT_LENGTH\x00" + str(len(body)) + "\x00"
        "SCGI\x001\x00"
        "REQUEST_METHOD\x00POST\x00"
        "REQUEST_URI\x00" + path + "\x00"
        "CONTENT_TYPE\x00application/ocsp-request\x00"
    )
    header_bytes = headers.encode("ascii")
    # Netstring: <length>:<data>,
    netstring = str(len(header_bytes)).encode() + b":" + header_bytes + b","

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    try:
        sock.connect((host, port))
        sock.sendall(netstring + body)
        # Read full response
        chunks = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks)
    finally:
        sock.close()


class _SCGIProxyHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler that proxies POST requests to an SCGI backend."""

    scgi_host = "127.0.0.1"
    scgi_port = SCGI_PORT

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length > 0 else b""

        try:
            raw = _scgi_request(self.scgi_host, self.scgi_port,
                                body, self.path)
        except Exception as e:
            self.send_error(502, str(e))
            return

        # The SCGI response may include HTTP-style headers followed by
        # \r\n\r\n then the body, or it may be raw body only.
        if b"\r\n\r\n" in raw:
            header_part, resp_body = raw.split(b"\r\n\r\n", 1)
        else:
            resp_body = raw
        self.send_response(200)
        self.send_header("Content-Type", "application/ocsp-response")
        self.send_header("Content-Length", str(len(resp_body)))
        self.end_headers()
        self.wfile.write(resp_body)

    def log_message(self, format, *args):
        pass  # suppress request logging


class _HTTPProxy:
    """Runs the HTTP-to-SCGI proxy in a background thread."""

    def __init__(self, http_port, scgi_port):
        _SCGIProxyHandler.scgi_port = scgi_port
        self.server = http.server.HTTPServer(
            ("127.0.0.1", http_port), _SCGIProxyHandler)
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self.server.shutdown()
        self.thread.join(timeout=5)


@unittest.skipUnless(HAS_OPENSSL, "openssl not available")
class TestOCSPScgi(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not os.path.isdir(CERTS_DIR):
            raise unittest.SkipTest("certs directory not found")

        # Check OCSP support
        r = subprocess.run([WOLFSSL_BIN, "ocsp", "-help"],
                           capture_output=True, timeout=5)
        if r.returncode != 0:
            raise unittest.SkipTest("OCSP not supported")

        cls._tmpdir = tempfile.mkdtemp()
        cls._wolfclu_proc = None
        cls._wolfclu_log = None
        cls._proxy = _HTTPProxy(HTTP_PORT, SCGI_PORT)
        cls._proxy.start()

    @classmethod
    def tearDownClass(cls):
        if cls._wolfclu_proc:
            cls._wolfclu_proc.terminate()
            try:
                cls._wolfclu_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cls._wolfclu_proc.kill()
        if cls._wolfclu_log:
            cls._wolfclu_log.close()
        if hasattr(cls, "_proxy"):
            cls._proxy.stop()
        if hasattr(cls, "_tmpdir") and os.path.isdir(cls._tmpdir):
            shutil.rmtree(cls._tmpdir, ignore_errors=True)

    def _write_index(self, content):
        path = os.path.join(self._tmpdir, "index.txt")
        with open(path, "w") as f:
            f.write(content)
        return path

    def _start_responder(self, index_content,
                         rsigner=None, rkey=None):
        """Start wolfssl OCSP SCGI responder."""
        if self._wolfclu_proc and self._wolfclu_proc.poll() is None:
            self._wolfclu_proc.terminate()
            self._wolfclu_proc.wait(timeout=5)
        if self._wolfclu_log:
            self._wolfclu_log.close()

        index = self._write_index(index_content)
        if rsigner is None:
            rsigner = os.path.join(CERTS_DIR, "ca-cert.pem")
        if rkey is None:
            rkey = os.path.join(CERTS_DIR, "ca-key.pem")

        log_path = os.path.join(self._tmpdir, "scgi.log")
        log_file = open(log_path, "w")
        proc = subprocess.Popen(
            [WOLFSSL_BIN, "ocsp", "-scgi",
             "-port", str(SCGI_PORT),
             "-index", index,
             "-rsigner", rsigner,
             "-rkey", rkey,
             "-CA", os.path.join(CERTS_DIR, "ca-cert.pem")],
            stdout=log_file, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
        )
        time.sleep(0.5)
        if proc.poll() is not None:
            log_file.close()
            with open(log_path) as f:
                self.fail(f"SCGI responder exited early: {f.read()}")
        self.__class__._wolfclu_proc = proc
        self.__class__._wolfclu_log = log_file
        self._log_path = log_path

    def _ocsp_query(self):
        """Run openssl ocsp via the HTTP proxy."""
        r = subprocess.run(
            ["openssl", "ocsp",
             "-issuer", os.path.join(CERTS_DIR, "ca-cert.pem"),
             "-cert", os.path.join(CERTS_DIR, "server-cert.pem"),
             "-CAfile", os.path.join(CERTS_DIR, "ca-cert.pem"),
             "-url", f"http://127.0.0.1:{HTTP_PORT}/ocsp"],
            capture_output=True, text=True,
            stdin=subprocess.DEVNULL, timeout=30,
        )
        return r.returncode, r.stdout + r.stderr

    def test_01_valid_cert(self):
        """Valid certificate should return good status."""
        self._start_responder(INDEX_VALID)
        rc, out = self._ocsp_query()
        self.assertEqual(rc, 0, out)
        self.assertIn("good", out.lower())

    def test_02_revoked_cert(self):
        """Revoked certificate should return revoked status."""
        self._start_responder(INDEX_REVOKED)
        rc, out = self._ocsp_query()
        self.assertIn("revoked", out.lower())

    def test_03_valid_after_revoked(self):
        """Valid cert after revoked index (stateless)."""
        self._start_responder(INDEX_VALID)
        rc, out = self._ocsp_query()
        self.assertEqual(rc, 0, out)
        self.assertIn("good", out.lower())

    def test_04_multiple_requests(self):
        """Multiple sequential requests should all succeed."""
        self._start_responder(INDEX_VALID)
        for i in range(3):
            with self.subTest(request=i + 1):
                rc, out = self._ocsp_query()
                self.assertEqual(rc, 0, f"request {i+1} failed: {out}")

    def test_05_delegated_responder(self):
        """Valid cert with authorized/delegated responder."""
        self._start_responder(
            INDEX_VALID,
            rsigner=os.path.join(CERTS_DIR, "ocsp-responder-cert.pem"),
            rkey=os.path.join(CERTS_DIR, "ocsp-responder-key.pem"))
        rc, out = self._ocsp_query()
        self.assertEqual(rc, 0, out)
        self.assertIn("good", out.lower())

    def test_06_delegated_revoked(self):
        """Revoked cert with authorized/delegated responder."""
        self._start_responder(
            INDEX_REVOKED,
            rsigner=os.path.join(CERTS_DIR, "ocsp-responder-cert.pem"),
            rkey=os.path.join(CERTS_DIR, "ocsp-responder-key.pem"))
        rc, out = self._ocsp_query()
        self.assertIn("revoked", out.lower())

    def test_07_delegated_multiple(self):
        """Multiple requests with delegated responder."""
        self._start_responder(
            INDEX_VALID,
            rsigner=os.path.join(CERTS_DIR, "ocsp-responder-cert.pem"),
            rkey=os.path.join(CERTS_DIR, "ocsp-responder-key.pem"))
        for i in range(3):
            with self.subTest(request=i + 1):
                rc, out = self._ocsp_query()
                self.assertEqual(rc, 0, f"request {i+1} failed: {out}")

    @unittest.skipIf(sys.platform == "win32",
                      "TerminateProcess on Windows prevents graceful shutdown")
    def test_08_graceful_shutdown(self):
        """Responder should log graceful exit."""
        self._start_responder(INDEX_VALID)
        self._ocsp_query()  # at least one request

        self._wolfclu_proc.terminate()
        self._wolfclu_proc.wait(timeout=5)
        self._wolfclu_log.close()
        self.__class__._wolfclu_proc = None
        self.__class__._wolfclu_log = None

        with open(self._log_path) as f:
            log = f.read()
        self.assertIn("wolfssl exiting gracefully", log)


if __name__ == "__main__":
    test_main()
