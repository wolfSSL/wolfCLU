#!/usr/bin/env python3
"""Random number generation tests for wolfCLU."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import run_wolfssl, test_main


class RandTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        config_log = os.path.join(".", "config.log")
        if os.path.isfile(config_log):
            with open(config_log, "r") as f:
                if "disable-filesystem" in f.read():
                    raise unittest.SkipTest("filesystem support disabled")

    def test_base64_random(self):
        r = run_wolfssl("rand", "-base64", "10")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_base64_not_repeated(self):
        r1 = run_wolfssl("rand", "-base64", "10")
        self.assertEqual(r1.returncode, 0, r1.stderr)

        r2 = run_wolfssl("rand", "-base64", "10")
        self.assertEqual(r2.returncode, 0, r2.stderr)

        self.assertNotEqual(r1.stdout, r2.stdout,
                            "back-to-back random calls should differ")

    def test_output_file(self):
        out = "entropy.txt"
        self.addCleanup(lambda: os.remove(out)
                        if os.path.exists(out) else None)

        r = run_wolfssl("rand", "-out", out, "20")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.isfile(out), "entropy.txt not created")

    def test_hex_stdout_length(self):
        """`-hex` to stdout produces 2 hex chars per byte plus trailing \\n."""
        r = run_wolfssl("rand", "-hex", "16")
        self.assertEqual(r.returncode, 0, r.stderr)
        # 32 hex chars + newline so the next shell prompt isn't on the same
        # line (matches `openssl rand -hex` behavior).
        self.assertEqual(len(r.stdout), 33,
                         "expected 32 hex chars + newline from -hex 16")
        self.assertEqual(r.stdout[-1], "\n", "missing trailing newline")
        self.assertTrue(all(c in "0123456789abcdef" for c in r.stdout[:-1]),
                        "output is not lowercase hex")

    def test_hex_to_file(self):
        """`-hex -out file` writes a hex-only file (no trailing newline)
        suitable for direct use as -inkey input."""
        out = "hex_rand.hex"
        self.addCleanup(lambda: os.remove(out)
                        if os.path.exists(out) else None)

        r = run_wolfssl("rand", "-hex", "-out", out, "32")
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(out, "rb") as f:
            data = f.read()
        self.assertEqual(len(data), 64,
                         "expected 64 bytes for 32 random bytes in hex")
        self.assertTrue(all(chr(b) in "0123456789abcdef" for b in data),
                        "hex file should contain only lowercase hex")

    def test_hex_and_base64_mutually_exclusive(self):
        """`-hex` and `-base64` cannot be combined."""
        r = run_wolfssl("rand", "-hex", "-base64", "8")
        self.assertNotEqual(r.returncode, 0,
                            "-hex with -base64 must error out")

    def test_hex_size_overflow_rejected(self):
        """`-hex` must reject sizes that would overflow size*2 rather than
        silently allocating an undersized buffer and writing past it."""
        # 2^30 fits in int but 2^30 * 2 == 2^31 wraps signed int. The
        # binary should refuse this size, not crash or silently truncate.
        r = run_wolfssl("rand", "-hex", str(2**30))
        self.assertNotEqual(r.returncode, 0,
                            "rand -hex with overflow-prone size must error")

    def test_hex_flag_not_swallowed_by_help_check(self):
        """Regression: `-hex` must not match the `-h`/`-help` prefix detector.

        Putting -hex *last* on the command line previously triggered the
        rand help screen because the first two characters ("-h") matched.
        Help text must only fire for an exact -h/-help argument."""
        r = run_wolfssl("rand", "16", "-hex")
        # Either the user gets a "missing size" error (because "-hex" is
        # not the documented size-as-last-arg) or actual hex output —
        # but never a silent help screen with exit 0.
        out = (r.stdout or "")
        self.assertNotIn("wolfssl rand <num bytes>", out,
                         "rand 16 -hex must not be treated as help")


if __name__ == "__main__":
    test_main()
