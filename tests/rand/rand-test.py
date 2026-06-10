#!/usr/bin/env python3
"""Random number generation tests for wolfCLU."""

import base64
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import WOLFSSL_BIN, run_wolfssl, test_main


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

    def test_count_after_out_value(self):
        """`rand -out <file> <count>` binds <file> to -out and <count> as the
        byte count, even though <count> sits immediately after the -out value.

        Locks the positional rescan's binding contract against
        wolfCLU_GetOpt (see clu_rand.c / clu_funcs.c optarg binding)."""
        out = "count_after_out.bin"
        self.addCleanup(lambda: os.remove(out)
                        if os.path.exists(out) else None)

        r = run_wolfssl("rand", "-out", out, "16")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.isfile(out), "%s not created" % out)
        self.assertEqual(os.path.getsize(out), 16,
                         "expected 16 raw bytes; count after -out value "
                         "must still be read as the byte count")

    def test_hex_stdout_length(self):
        """`-hex N` emits 2 lowercase hex chars per byte plus a trailing \\n."""
        r = run_wolfssl("rand", "-hex", "16")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(len(r.stdout), 33,
                         "expected 32 hex chars + newline from -hex 16")
        self.assertEqual(r.stdout[-1], "\n", "missing trailing newline")
        self.assertTrue(all(c in "0123456789abcdef" for c in r.stdout[:-1]),
                        "output is not lowercase hex")

    def test_plain_raw_to_stdout(self):
        """`rand N` with no flags writes exactly N raw bytes to stdout.

        No encoding, no trailing newline. Captured as raw bytes because
        run_wolfssl decodes as text and would choke on non-UTF-8 output."""
        n = 16
        r = subprocess.run([WOLFSSL_BIN, "rand", str(n)],
                           capture_output=True, stdin=subprocess.DEVNULL,
                           timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(len(r.stdout), n,
                         "plain `rand %d` must emit exactly %d raw bytes "
                         "(no encoding, no trailing newline)" % (n, n))

    def test_hex_to_file(self):
        """`-hex -out file` writes a hex-only file with no trailing newline."""
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

    def _assert_dup_errors_no_leak(self, args, what):
        """Run `rand <args>`, asserting it errors and emits no stdout bytes.

        stdout is captured as RAW bytes (not text=True like run_wolfssl): the
        leak these tests guard against is ~16 random bytes, which are almost
        always invalid UTF-8, so a reintroduced leak would raise
        UnicodeDecodeError during decoding and ERROR the test before the
        assertions ran. Raw capture makes a leak fail on the explicit length
        assertion with a clear message instead, mirroring
        test_plain_raw_to_stdout."""
        r = subprocess.run([WOLFSSL_BIN, "rand", *args],
                           capture_output=True, stdin=subprocess.DEVNULL,
                           timeout=60)
        self.assertNotEqual(r.returncode, 0, "%s must error out" % what)
        self.assertEqual(len(r.stdout), 0,
                         "%s must not leak random bytes to stdout" % what)
        return r

    def test_duplicate_out_does_not_leak_to_stdout(self):
        """Regression: `rand -out f1 N -out f2` must error, not leak bytes.

        wolfCLU_GetOpt rejects a repeated -out (argument found twice) and
        never binds the filename, so outFile stays NULL while the positional
        rescan still recovers N. That combination once dumped N random bytes
        to stdout. The rescan now rejects the duplicate before any RNG output."""
        f1 = "dup_out_1.bin"
        f2 = "dup_out_2.bin"
        for f in (f1, f2):
            self.addCleanup(lambda p=f: os.remove(p)
                            if os.path.exists(p) else None)

        self._assert_dup_errors_no_leak(["-out", f1, "16", "-out", f2],
                                        "duplicate -out")
        self.assertFalse(os.path.exists(f1),
                         "no output file should be created on duplicate -out")
        self.assertFalse(os.path.exists(f2),
                         "no output file should be created on duplicate -out")

    def test_duplicate_out_in_value_slot_does_not_leak(self):
        """Regression: `rand -out -out 16` must error, not leak bytes.

        Here the repeated -out lands in the slot the positional rescan would
        swallow as the first -out's bound value (skipNext), so the seen[]
        guard never ran for it. GetOpt still refused to bind optarg (argument
        found twice), leaving outFile NULL, and 16 random bytes once reached
        stdout with exit 0. The skipNext path now checks the swallowed token
        against the option table before discarding it."""
        # Guard against a regression that bound the second -out to a "-out" or
        # "16" filename: no stray artifact should appear either.
        for f in ("-out", "16"):
            self.addCleanup(lambda p=f: os.remove(p)
                            if os.path.exists(p) else None)
        self._assert_dup_errors_no_leak(["-out", "-out", "16"],
                                        "duplicate -out in value slot")
        self.assertFalse(os.path.exists("-out"),
                         "no '-out' file should be created on duplicate -out")
        self.assertFalse(os.path.exists("16"),
                         "no '16' file should be created on duplicate -out")

    def test_duplicate_out_trailing_repeat_rejected(self):
        """`rand -out f1 16 -out`: the trailing -out repeat (count already
        consumed) must error too, exercising the main-loop seen[] path."""
        f1 = "dup_out_trailing.bin"
        self.addCleanup(lambda: os.remove(f1) if os.path.exists(f1) else None)
        self._assert_dup_errors_no_leak(["-out", f1, "16", "-out"],
                                        "trailing duplicate -out")

    def test_duplicate_hex_flag_rejected(self):
        """`rand -hex -hex 16`: a repeated no_argument flag must error.

        GetOpt drops the duplicated -hex (useHex=0) while the rescan still
        recovers count=16, which once wrote 16 raw bytes to stdout at exit 0 —
        the same leak class as duplicate -out, so assert empty stdout too."""
        self._assert_dup_errors_no_leak(["-hex", "-hex", "16"],
                                        "duplicate -hex")

    def test_duplicate_base64_flag_rejected(self):
        """`rand -base64 -base64 16`: a repeated no_argument flag must error,
        with no raw bytes leaking to stdout (mirrors the -hex/-out cases)."""
        self._assert_dup_errors_no_leak(["-base64", "-base64", "16"],
                                        "duplicate -base64")

    def test_duplicate_flag_first_seen_in_value_slot_rejected(self):
        """`rand -out -base64 -base64 16`: duplicate detection is symmetric.

        The first -base64 is swallowed as the -out value; the rescan marks it
        seen there so the second -base64 is still rejected as a duplicate,
        rather than being silently dropped (which once produced exit 0 and a
        file literally named '-base64')."""
        for f in ("-base64",):
            self.addCleanup(lambda p=f: os.remove(p)
                            if os.path.exists(p) else None)
        self._assert_dup_errors_no_leak(
                ["-out", "-base64", "-base64", "16"],
                "duplicate -base64 with first occurrence in a value slot")

    def test_hex_size_overflow_rejected(self):
        """`-hex` must reject sizes that overflow size*2.

        2^30 fits in int, but 2^30 * 2 wraps signed int. The binary must
        refuse it, not allocate an undersized buffer and write past it."""
        r = run_wolfssl("rand", "-hex", str(2**30))
        self.assertNotEqual(r.returncode, 0,
                            "rand -hex with overflow-prone size must error")

    def test_base64_size_overflow_rejected(self):
        """`-base64` must reject sizes whose ~4/3 encoded length wraps the
        signed int `size`, mirroring the -hex cap. The guard fires before
        the RNG allocation, so it errors without allocating ~1 GiB."""
        r = run_wolfssl("rand", "-base64", str(2**30))
        self.assertNotEqual(r.returncode, 0,
                            "rand -base64 with overflow-prone size must error")

    def test_hex_flag_not_swallowed_by_help_check(self):
        """Regression: `-hex` must not match the `-h`/`-help` prefix detector.

        Putting -hex last once triggered the help screen because "-h"
        matched. Help must fire only for an exact -h/-help argument."""
        r = run_wolfssl("rand", "16", "-hex")
        # Acceptable: a "missing size" error or actual hex output, but
        # never a silent help screen with exit 0.
        out = (r.stdout or "")
        self.assertNotIn("wolfssl rand <num bytes>", out,
                         "rand 16 -hex must not be treated as help")

    def test_large_raw_request_allowed(self):
        """A large raw request must still work (no arbitrary size cap),
        keeping large keyfiles/blobs supported like `openssl rand`."""
        out = "big_rand.bin"
        self.addCleanup(lambda: os.remove(out)
                        if os.path.exists(out) else None)

        r = run_wolfssl("rand", "-out", out, "1048576")  # 1 MiB
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(os.path.getsize(out), 1048576,
                         "expected a full 1 MiB of raw random output")

        # Size alone won't catch a chunk-fill regression that zeroed or
        # repeated a chunk, so also check the bytes look random. The slices
        # assume the default 64 KiB chunk; on other builds they just compare
        # two arbitrary offsets, still a valid randomness check.
        with open(out, "rb") as f:
            data = f.read()
        chunk = 65536  # default RNG_MAX_BLOCK_LEN
        self.assertNotEqual(data, b"\x00" * len(data),
                            "output must not be all zeros")
        self.assertNotEqual(data[:chunk], data[chunk:2 * chunk],
                            "consecutive chunks must differ (no chunk repeat)")

    def test_large_base64_request_allowed(self):
        """A large -base64 request must work too: it forces the multi-chunk
        fill loop and then base64-expands, guarding that interaction."""
        out = "big_rand.b64"
        self.addCleanup(lambda: os.remove(out)
                        if os.path.exists(out) else None)

        n = 100000
        r = run_wolfssl("rand", "-base64", "-out", out, str(n))
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(out, "rb") as f:
            data = f.read()
        decoded = base64.b64decode(data)
        self.assertEqual(len(decoded), n,
                         "base64 output must decode to the requested size")

        # n crosses one chunk boundary; verify the decoded bytes look random
        # rather than zeroed or repeated. On builds with a different chunk
        # size these compare two arbitrary offsets, still a valid check.
        chunk = 65536  # default RNG_MAX_BLOCK_LEN
        self.assertNotEqual(decoded, b"\x00" * n,
                            "decoded output must not be all zeros")
        self.assertNotEqual(decoded[:n - chunk], decoded[chunk:],
                            "the two chunks must differ (no chunk repeat)")

    def test_chunk_boundary_exact_and_plus_one(self):
        """Pin the single/multi-chunk transition in the fill loop.

        Exactly RNG_MAX_BLOCK_LEN (65536) must take one chunk; +1 (65537)
        must take a second 1-byte chunk. Locks the `>` vs `>=` boundary that
        the large-request tests only catch indirectly. Assumes the default
        64 KiB chunk; other builds still produce the full size."""
        chunk = 65536  # default RNG_MAX_BLOCK_LEN
        for n in (chunk, chunk + 1):
            out = "chunk_boundary_%d.bin" % n
            self.addCleanup(lambda p=out: os.remove(p)
                            if os.path.exists(p) else None)
            r = run_wolfssl("rand", "-out", out, str(n))
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(os.path.getsize(out), n,
                             "expected exactly %d raw bytes" % n)
            with open(out, "rb") as f:
                data = f.read()
            self.assertNotEqual(data, b"\x00" * n,
                                "output must not be all zeros")

    def test_count_before_out_with_flag(self):
        """`rand -hex 16 -out f` must keep 16 as the count even though it
        sits ahead of the -out <value> pair: 16 bytes -> 32 hex chars."""
        out = "count_before_out.hex"
        self.addCleanup(lambda: os.remove(out)
                        if os.path.exists(out) else None)

        r = run_wolfssl("rand", "-hex", "16", "-out", out)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(os.path.getsize(out), 32,
                         "16 byte count before -out must yield 32 hex chars")

    def test_flag_as_out_value_is_consistent(self):
        """`rand -out -hex 16`: -hex is BOTH bound as the -out filename and
        matched as the -hex flag (pre-existing GetOpt whole-argv scan), while
        the positional rescan treats it only as the bound value. Both agree on
        count=16 and a file named '-hex', so the outcome is self-consistent:
        16 random bytes hex-encoded (32 chars) to a file literally named '-hex'.

        Locks the documented parser/rescan divergence (clu_rand.c) as benign;
        a future GetOpt binding change that broke the agreement would fail
        here instead of silently mis-reading the byte count."""
        out = "-hex"
        self.addCleanup(lambda: os.remove(out)
                        if os.path.exists(out) else None)

        r = run_wolfssl("rand", "-out", "-hex", "16")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.isfile(out),
                        "file named '-hex' must be created (it is the -out "
                        "value)")
        self.assertEqual(os.path.getsize(out), 32,
                         "count 16 with -hex must yield 32 hex chars, proving "
                         "parser and rescan agree on the byte count")
        with open(out, "rb") as f:
            data = f.read()
        self.assertTrue(all(chr(b) in "0123456789abcdef" for b in data),
                        "the -hex flag must still take effect (lowercase hex)")

    def test_missing_count_errors(self):
        """`-out` with no byte count must error, not size from the path."""
        out = "missing_count.bin"
        self.addCleanup(lambda: os.remove(out)
                        if os.path.exists(out) else None)

        r = run_wolfssl("rand", "-out", out)
        self.assertNotEqual(r.returncode, 0,
                            "rand -out <file> with no count must error")

    def test_numeric_out_path_is_not_count(self):
        """`rand -out 32` must treat 32 as the path, not the count: it errors
        (no count given) and never creates a file named '32'."""
        self.addCleanup(lambda: os.remove("32")
                        if os.path.exists("32") else None)

        r = run_wolfssl("rand", "-out", "32")
        self.assertNotEqual(r.returncode, 0,
                            "rand -out 32 must error: 32 is the path, no num")
        self.assertFalse(os.path.exists("32"),
                         "file '32' must not be created on a count error")

    def test_extra_positional_errors(self):
        """More than one positional count must error, not silently pick one."""
        r = run_wolfssl("rand", "16", "32")
        self.assertNotEqual(r.returncode, 0,
                            "rand with two positional counts must error")

    def test_dangling_out_flag_with_count_errors(self):
        """`-out` as the final token with no filename must error, not fall
        through to stdout. Regressed once: the NULL filename skipped the open
        and random bytes hit the terminal with exit 0. Must fail with no
        stdout even when a valid count is present (`rand 16 -out`)."""
        for args in (["-out"], ["16", "-out"], ["-hex", "16", "-out"]):
            with self.subTest(args=args):
                r = subprocess.run([WOLFSSL_BIN, "rand", *args],
                                   capture_output=True,
                                   stdin=subprocess.DEVNULL, timeout=60)
                self.assertNotEqual(r.returncode, 0,
                                    "rand %s (no filename) must error"
                                    % " ".join(args))
                self.assertEqual(r.stdout, b"",
                                 "no random bytes may reach stdout on error: "
                                 "%r" % (args,))

    def test_unknown_flag_errors(self):
        """An unrecognized flag must be rejected, not ignored nor treated as
        an extra positional. A valid count is present, so only -foo fails."""
        r = run_wolfssl("rand", "-foo", "16")
        self.assertNotEqual(r.returncode, 0,
                            "rand with an unrecognized flag must error")

    def test_bad_count_does_not_truncate_existing_out_file(self):
        """A bad/missing count must not truncate an existing -out file.

        The output BIO is opened only after the count validates, so every
        pre-open error path must leave the file intact. Each form below
        reaches that guard differently: count-scan failures, the size-overflow
        guards, and the -hex/-base64 mutual-exclusion guard."""
        out = "preexisting.key"
        self.addCleanup(lambda: os.remove(out)
                        if os.path.exists(out) else None)

        original = b"SECRET-KEY-MATERIAL\n"

        big = str(2**30)  # size*2 / base64 expansion wraps signed int -> error
        bad_arg_forms = (
            ["-out", out],                       # missing count
            ["-out", out, "abc"],                # non-numeric count
            ["-out", out, "0"],                  # zero count
            ["-out", out, "16", "32"],           # extra positional
            ["-hex", "-out", out, big],          # hex size overflow
            ["-base64", "-out", out, big],       # base64 size overflow
            ["-hex", "-base64", "-out", out, "8"],  # mutually exclusive
        )
        for args in bad_arg_forms:
            with self.subTest(args=args):
                with open(out, "wb") as f:
                    f.write(original)
                r = run_wolfssl("rand", *args)
                self.assertNotEqual(r.returncode, 0,
                                    "bad count must error: %r" % (args,))
                with open(out, "rb") as f:
                    self.assertEqual(f.read(), original,
                                     "existing -out file must be untouched "
                                     "on error: %r" % (args,))


if __name__ == "__main__":
    test_main()
