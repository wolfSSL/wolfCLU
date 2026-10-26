#!/usr/bin/env python3
"""asn1parse tests for wolfCLU."""

import base64
import functools
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import (
    CERTS_DIR,
    have_oid_table,
    oid_arcs_truncated,
    run_wolfssl,
    test_main,
    truncate_sparse,
)

# Two top-level DER INTEGERs (42, then 43): 02 01 2a 02 01 2b.
# Used to confirm -length truncates parsing and -offset skips ahead: the
# items are independent and minimally sized, so the count of "INTEGER" lines
# in the output is a direct measure of how much of the buffer was parsed.
TWO_INTEGERS = bytes([0x02, 0x01, 0x2a, 0x02, 0x01, 0x2b])

# Error fragment emitted when -oid is used in a build that compiled out OID
# encoding (see clu_asn1_setup.c).
_NO_OID_ENCODE_MSG = "not configured to handle encoding oids"


@functools.lru_cache(maxsize=None)
def oid_encoding_supported():
    """True when the build can DER-encode the OIDs from an -oid file.

    -oid relies on wc_EncodeObjectId, which configure compiles out via
    NO_WC_ENCODE_OBJECT_ID when the linked wolfSSL does not export it.  In
    that build -oid reports a fatal error instead of encoding anything.
    The flag is a -D in AM_CFLAGS, so probe the binary for the behaviour
    instead.  A nonexistent file is enough: the disabled path errors during
    argument handling before the file is ever opened.
    """
    result = run_wolfssl("asn1parse", "-oid", "asn1-oid-probe.nonexistent")
    return _NO_OID_ENCODE_MSG not in (result.stdout + result.stderr)


class TestBasicFunctions(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not os.path.isdir(CERTS_DIR):
            raise unittest.SkipTest("certs directory not found")

        cls.der = os.path.join(CERTS_DIR, "ca-cert.der")
        cls.pem = os.path.join(CERTS_DIR, "ca-cert.pem")

        # Skip when asn1parse is not compiled in (needs WOLFSSL_ASN_PRINT and a
        # filesystem). Every such path logs "Cannot parse Asn1."
        result = run_wolfssl("asn1parse", "-inform", "DER", "-in", cls.der)
        if "cannot parse asn1" in (result.stdout + result.stderr).lower():
            raise unittest.SkipTest("asn1parse support not compiled in")

        # Reference output produced from the DER form of the cert.
        cls.der_output = result.stdout

    def _write_der(self, name, data):
        """Write data to name, remove it at cleanup, and return name."""
        with open(name, "wb") as f:
            f.write(data)
        self.addCleanup(lambda: os.remove(name)
                        if os.path.exists(name) else None)
        return name

    def _write_text(self, name, text):
        """Text-mode _write_der, for -oid files."""
        return self._write_der(name, text.encode())

    def _remove_at_cleanup(self, name):
        self.addCleanup(lambda: os.remove(name)
                        if os.path.exists(name) else None)
        return name

    def _assert_fails_with(self, result, msg):
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(msg, result.stdout + result.stderr)

    def test_DER(self):
        """Parse a DER input and confirm the ASN.1 structure is printed."""
        result = run_wolfssl("asn1parse", "-inform", "DER", "-in", self.der)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("SEQUENCE", result.stdout)

    def test_PEM(self):
        """PEM input of the same cert yields the same parse as DER, and
        -inform is case insensitive."""
        for inform in ("PEM", "pem"):
            with self.subTest(inform=inform):
                result = run_wolfssl("asn1parse", "-inform", inform,
                                     "-in", self.pem)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, self.der_output)

    def test_base64(self):
        """Base64 (non-PEM) input yields the same parse as DER."""
        b64_file = self._remove_at_cleanup("test-asn1.b64")
        with open(self.der, "rb") as f:
            with open(b64_file, "w") as out:
                out.write(base64.encodebytes(f.read()).decode())

        result = run_wolfssl("asn1parse", "-inform", "B64", "-in", b64_file)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, self.der_output)

    def test_strparse_octet_string(self):
        """-strparse onto an OCTET STRING prints and -out writes exactly the
        nested DER.

        Build OCTET STRING { INTEGER 42 }:
            04 03 02 01 2a
        -strparse 0 descends into the OCTET STRING at offset 0, with no
        dependence on the bytes of any shipped cert.
        """
        der_file = self._write_der("test-asn1-strparse-out.der",
                                   bytes([0x04, 0x03, 0x02, 0x01, 0x2a]))
        out_file = self._remove_at_cleanup("test-asn1-strparse.out")

        result = run_wolfssl("asn1parse", "-inform", "DER", "-in", der_file,
                             "-strparse", "0", "-out", out_file)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("INTEGER", result.stdout)
        self.assertNotIn("OCTET STRING", result.stdout)
        with open(out_file, "rb") as out:
            self.assertEqual(out.read(), bytes([0x02, 0x01, 0x2a]))

    def test_indent(self):
        """-i swaps branch drawing for indentation, changing the output."""
        result = run_wolfssl("asn1parse", "-inform", "DER", "-in", self.der,
                             "-i")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("SEQUENCE", result.stdout)
        self.assertNotEqual(result.stdout, self.der_output)

    def test_noout_suppresses_stdout(self):
        """-noout suppresses stdout but the -out file still gets the input
        DER."""
        out_file = self._remove_at_cleanup("test-asn1-noout.out")

        result = run_wolfssl("asn1parse", "-inform", "DER", "-in", self.der,
                             "-out", out_file, "-noout")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")

        with open(out_file, "rb") as out:
            with open(self.der, "rb") as infile:
                self.assertEqual(out.read(), infile.read())

    def test_noout_without_out_errors(self):
        """-noout with no -out leaves no targets and is rejected."""
        result = run_wolfssl("asn1parse", "-inform", "DER", "-in", self.der,
                             "-noout")
        self.assertNotEqual(result.returncode, 0)

    def test_strparse_mixed_nesting(self):
        """-strparse drills through alternating BIT/OCTET STRING wrappers.

        Each comma-separated entry is an offset, relative to the current
        substructure, of the string to descend into.  certs/nested.der nests
        five SEQUENCE layers, each wrapping the next in a BIT STRING or OCTET
        STRING:
            27 -> BIT STRING in layer 1
            20 -> OCTET STRING in layer 2
             9 -> BIT STRING in layer 3
            20 -> OCTET STRING in layer 4
        leaving only the innermost layer 5 SEQUENCE to be printed.
        """
        nested = os.path.join(CERTS_DIR, "nested.der")
        result = run_wolfssl("asn1parse", "-inform", "DER", "-in", nested,
                             "-strparse", "27,20,9,20")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("innermost payload - layer 5", result.stdout)
        self.assertIn("rsaEncryption", result.stdout)
        self.assertNotIn("layer 1 - outermost", result.stdout)
        self.assertNotIn("layer 4 label", result.stdout)

    def test_strparse_cap(self):
        """-strparse accepts WOLFCLU_ASN1_STR_PARSE_CAP (30) offsets, not 31.

        Wrap INTEGER 42 in 30 OCTET STRINGs so "0" repeated 30 times peels
        every wrapper; one more entry exceeds the cap and is rejected while
        parsing arguments.
        """
        cap = 30
        der = bytes([0x02, 0x01, 0x2a])
        for _ in range(cap):
            der = bytes([0x04, len(der)]) + der
        der_file = self._write_der("test-asn1-strparse-cap.der", der)

        result = run_wolfssl("asn1parse", "-inform", "DER", "-in", der_file,
                             "-strparse", ",".join(["0"] * cap))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("INTEGER", result.stdout)
        self.assertNotIn("OCTET STRING", result.stdout)

        result = run_wolfssl("asn1parse", "-inform", "DER", "-in", der_file,
                             "-strparse", ",".join(["0"] * (cap + 1)))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Too many values passed to -strparse",
                      result.stdout + result.stderr)

    def test_strparse_empty_entry(self):
        """Empty -strparse entries are rejected, not silently skipped."""
        for arg in ("", ",", "0,,0", "0,"):
            with self.subTest(arg=arg):
                result = run_wolfssl("asn1parse", "-inform", "DER",
                                     "-in", self.der, "-strparse", arg)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Not a valid integer value",
                              result.stdout + result.stderr)

    def test_strparse_bit_string(self):
        """-strparse into a BIT STRING skips its leading unused-bits octet.

        Build BIT STRING { INTEGER 42 }:
            03 04 00 02 01 2a
        The 0x00 unused-bits octet is not part of the nested DER, so -strparse
        must step over it to reach and print the wrapped INTEGER.
        """
        der_file = self._write_der("test-asn1-strparse-bit.der",
                                   bytes([0x03, 0x04, 0x00, 0x02, 0x01, 0x2a]))

        result = run_wolfssl("asn1parse", "-inform", "DER", "-in", der_file,
                             "-strparse", "0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("INTEGER", result.stdout)

    @unittest.skipUnless(oid_encoding_supported(),
                         "built without wc_EncodeObjectId (-oid disabled)")
    def test_oid_file_whitespace(self):
        """-oid files tolerate blank lines, CRLF endings and tab separators.

        Blank lines (including whitespace-only and bare CRLF lines), a
        trailing extra newline and tab separators must all be skipped or
        accepted, and the CRLF '\\r' and surrounding spaces must not end up in
        the printed long name.
        """
        # DER: 06 04 2b ce 0f 05  == OBJECT IDENTIFIER 1.3.9999.5
        der_file = self._write_der("test-asn1-ws-oid.der",
                                   bytes([0x06, 0x04, 0x2b, 0xce, 0x0f, 0x05]))

        oid_file = self._write_der("test-asn1-ws-oid.conf",
                                   b"1.2.3.4 a First Oid\r\n"
                                   b"\r\n"
                                   b"   \t \n"
                                   b"  1.3.9999.5\tmyShort\t My Ws Oid  \r\n"
                                   b"\n\n")

        result = run_wolfssl("asn1parse", "-inform", "DER", "-in", der_file,
                             "-oid", oid_file)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(":My Ws Oid\n", result.stdout)

    @unittest.skipUnless(oid_encoding_supported(),
                         "built without wc_EncodeObjectId (-oid disabled)")
    def test_dump_keeps_oid_names(self):
        """-dump still prints OID names, including ones from -oid files."""
        # DER: 06 04 2b ce 0f 05  == OBJECT IDENTIFIER 1.3.9999.5
        der_file = self._write_der("test-asn1-dump-oid.der",
                                   bytes([0x06, 0x04, 0x2b, 0xce, 0x0f, 0x05]))
        oid_file = self._write_text("test-asn1-dump-oid.conf",
                                    "1.3.9999.5 myShort MyDumpOid\n")

        result = run_wolfssl("asn1parse", "-inform", "DER", "-in", der_file,
                             "-oid", oid_file, "-dump")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("MyDumpOid", result.stdout)

    @unittest.skipUnless(oid_encoding_supported(),
                         "built without wc_EncodeObjectId (-oid disabled)")
    def test_oid_multibyte_first_subidentifier(self):
        """A custom OID whose first subidentifier needs base-128 encoding maps.

        For OID 2.100.3 the first subidentifier is 40*2 + 100 = 180, which
        exceeds 127 and must be encoded over two base-128 bytes (0x81 0x34).
        Regression test: a single-byte encoding truncates and the -oid
        mapping silently fails to match.
        """
        # DER: 06 03 81 34 03  == OBJECT IDENTIFIER 2.100.3
        der_file = self._write_der("test-asn1-arc2-oid.der",
                                   bytes([0x06, 0x03, 0x81, 0x34, 0x03]))

        oid_file = self._write_text("test-asn1-arc2-oid.conf",
                                    "2.100.3 myShort MyArc2Oid\n")

        # Without the mapping the OID prints in dotted-decimal form.
        baseline = run_wolfssl("asn1parse", "-inform", "DER", "-in", der_file)
        self.assertEqual(baseline.returncode, 0, baseline.stderr)
        self.assertIn("2.100.3", baseline.stdout)
        self.assertNotIn("MyArc2Oid", baseline.stdout)

        # With the mapping the custom long name is resolved, which only
        # happens if the conf OID was DER-encoded to the same bytes.
        result = run_wolfssl("asn1parse", "-inform", "DER", "-in", der_file,
                             "-oid", oid_file)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("MyArc2Oid", result.stdout)

    @unittest.skipUnless(oid_encoding_supported(),
                         "built without wc_EncodeObjectId (-oid disabled)")
    def test_oid_multibyte_first_subidentifier_large_arc(self):
        """A custom OID with a two-byte first subidentifier and a >16-bit arc.

        2.100.111111.5 combines the 2.100 first subidentifier (180, two
        base-128 bytes) with an arc too large for the word16
        wc_EncodeObjectId, so the mapping only matches if wolfCLU_OidStrToDer
        encodes every arc in full via wc_EncodeObjectId32.  A build without
        wc_EncodeObjectId32 must reject the arc instead of truncating it.
        """
        # DER: 06 06 81 34 86 e4 07 05  == OBJECT IDENTIFIER 2.100.111111.5
        der_file = self._write_der("test-asn1-arc2-large-oid.der",
                                   bytes([0x06, 0x06, 0x81, 0x34, 0x86, 0xe4,
                                          0x07, 0x05]))

        oid_file = self._write_text("test-asn1-arc2-large-oid.conf",
                                    "2.100.111111.5 myShort MyCustomOid\n")

        baseline = run_wolfssl("asn1parse", "-inform", "DER", "-in", der_file)
        self.assertEqual(baseline.returncode, 0, baseline.stderr)
        self.assertNotIn("MyCustomOid", baseline.stdout)

        result = run_wolfssl("asn1parse", "-inform", "DER", "-in", der_file,
                             "-oid", oid_file)
        if oid_arcs_truncated():
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("OID arc 111111 would be truncated",
                          result.stdout + result.stderr)
            return
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("MyCustomOid", result.stdout)

    @unittest.skipUnless(oid_encoding_supported(),
                         "built without wc_EncodeObjectId (-oid disabled)")
    def test_oid_invalid_arcs(self):
        """wolfCLU_OidStrToDer rejects invalid dotted OIDs.

        -oid files and req -addext RID share this encoder, so its validation
        is covered once here.  The first two arcs share one subidentifier
        (40 * arc0 + arc1), so arc0 must be 0-2 and arc1 below 40 unless
        arc0 is 2; arcs must fit in 32 bits, and at most
        ASN1_OID_DOTTED_MAX_SZ (16) arcs are allowed.
        """
        cases = [
            ("3.1 s Bad", "first component must be 0, 1 or 2"),
            ("1.40 s Bad", "second component must be below 40"),
            ("2.4294967295 s Bad", "second component too large"),
            ("1 s Bad", "needs at least two components"),
            ("1..2 s Bad", "not a valid 32 bit integer"),
            ("2.999.4294967296 s Bad", "not a valid 32 bit integer"),
            ("2.999." + ".".join(str(i) for i in range(1, 16)) + " s Bad",
             "too many components"),
        ]
        oid_file = self._remove_at_cleanup("test-asn1-bad-arc-oid.conf")
        for line, msg in cases:
            with self.subTest(line=line):
                with open(oid_file, "w") as f:
                    f.write(line + "\n")
                result = run_wolfssl("asn1parse", "-inform", "DER",
                                     "-in", self.der, "-oid", oid_file)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(msg, result.stdout + result.stderr)

    @unittest.skipUnless(oid_encoding_supported(),
                         "built without wc_EncodeObjectId (-oid disabled)")
    def test_oid_file_many_entries(self):
        """An -oid file larger than one allocation chunk is fully loaded.

        Entries are stored in chunks of 10, so 25 entries grow the array
        twice.  Only the last entry maps the OID in the input, so its name is
        printed only if every grow kept the earlier entries and the count.
        """
        # DER: 06 04 2b ce 0f 05  == OBJECT IDENTIFIER 1.3.9999.5
        der_file = self._write_der("test-asn1-many-oid.der",
                                   bytes([0x06, 0x04, 0x2b, 0xce, 0x0f, 0x05]))
        lines = ["1.3.9998.{0} s{0} Filler{0}\n".format(i) for i in range(24)]
        lines.append("1.3.9999.5 myShort MyLastOid\n")
        oid_file = self._write_text("test-asn1-many-oid.conf", "".join(lines))

        result = run_wolfssl("asn1parse", "-in", der_file, "-oid", oid_file)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("MyLastOid", result.stdout)

    @unittest.skipUnless(have_oid_table() and oid_encoding_supported(),
                         "needs the built-in OID table and -oid support")
    def test_oid_file_overrides_builtin_table(self):
        """An -oid entry is searched before the built-in table."""
        # DER: OBJECT IDENTIFIER 2.16.756.1.89.1.2.1.1, which the built-in
        # table names "SwissSign EV policy".  Every arc fits in 16 bits, so
        # the OID also encodes in TRUNCATED_ENCODE_OBJECT_ID builds.
        der_file = self._write_der("test-asn1-override-oid.der",
                                   bytes([0x06, 0x09, 0x60, 0x85, 0x74, 0x01,
                                          0x59, 0x01, 0x02, 0x01, 0x01]))
        oid_file = self._write_text("test-asn1-override-oid.conf",
                                    "2.16.756.1.89.1.2.1.1 s MyOverride\n")

        result = run_wolfssl("asn1parse", "-in", der_file, "-oid", oid_file)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("MyOverride", result.stdout)
        self.assertNotIn("SwissSign EV policy", result.stdout)

    @unittest.skipUnless(have_oid_table(),
                         "built with --disable-oid-table")
    def test_builtin_oid_table(self):
        """The built-in OID table resolves an OID with no -oid file supplied.

        Exercises the second loop in OidToNameCallback (the static
        oid_name_table), which is not compiled with --disable-oid-table.
        2.16.840.1.114171.500.9 ("Wells Fargo EV policy") is in the table but
        not otherwise known to wolfSSL, so the callback is consulted and the
        table name must be printed without any -oid mapping.
        """
        # DER: 06 0a 60 86 48 01 86 fb 7b 83 74 09
        #   == OBJECT IDENTIFIER 2.16.840.1.114171.500.9
        der_file = self._write_der("test-asn1-builtin-oid.der",
                                   bytes([0x06, 0x0a, 0x60, 0x86, 0x48, 0x01,
                                          0x86, 0xfb, 0x7b, 0x83, 0x74, 0x09]))

        result = run_wolfssl("asn1parse", "-inform", "DER", "-in", der_file)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Wells Fargo EV policy", result.stdout)

    def test_length_truncates(self):
        """A valid -length stops parsing at the byte limit.

        TWO_INTEGERS holds two independent top-level INTEGERs.  Parsed whole,
        both appear; with -length 3 (exactly the first INTEGER's TLV) only the
        first is parsed, confirming the limit is honoured rather than ignored.
        """
        der_file = self._write_der("test-asn1-twoint.der", TWO_INTEGERS)

        full = run_wolfssl("asn1parse", "-inform", "DER", "-in", der_file)
        self.assertEqual(full.returncode, 0, full.stderr)
        self.assertEqual(full.stdout.count("INTEGER"), 2)

        truncated = run_wolfssl("asn1parse", "-inform", "DER", "-in", der_file,
                                "-length", "3")
        self.assertEqual(truncated.returncode, 0, truncated.stderr)
        self.assertEqual(truncated.stdout.count("INTEGER"), 1)

    def test_offset_skips_leading_bytes(self):
        """A valid -offset begins parsing past the skipped bytes.

        With -offset 3 the first INTEGER's TLV in TWO_INTEGERS is skipped, so
        only the second INTEGER remains to be parsed.
        """
        der_file = self._write_der("test-asn1-twoint-off.der", TWO_INTEGERS)

        result = run_wolfssl("asn1parse", "-inform", "DER", "-in", der_file,
                             "-offset", "3")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count("INTEGER"), 1)

    def test_strparse_then_offset_length(self):
        """-strparse runs first, then -offset/-length pick within the result.

        Bytes: INTEGER 42, then OCTET STRING { INTEGER 43, INTEGER 44 }:
            02 01 2a 04 06 02 01 2b 02 01 2c
        The -strparse offset counts from the start of the input even when
        -offset is given, and -offset/-length then apply to the six nested
        bytes.  Applying -offset first would land -strparse 3
        on 0x01 and fail.
        """
        der_file = self._write_der("test-asn1-strparse-window.der",
                                   bytes([0x02, 0x01, 0x2a, 0x04, 0x06, 0x02,
                                          0x01, 0x2b, 0x02, 0x01, 0x2c]))

        result = run_wolfssl("asn1parse", "-in", der_file,
                             "-offset", "3", "-strparse", "3")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count("INTEGER"), 1)
        self.assertIn(":2c", result.stdout)

        result = run_wolfssl("asn1parse", "-in", der_file,
                             "-strparse", "3", "-length", "3")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count("INTEGER"), 1)
        self.assertIn(":2b", result.stdout)

        # A -length past the nested data is clamped to it.
        result = run_wolfssl("asn1parse", "-in", der_file,
                             "-strparse", "3", "-length", "99")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count("INTEGER"), 2)
        self.assertNotIn(":2a", result.stdout)

        # -offset is checked against the nested data, not the whole input.
        result = run_wolfssl("asn1parse", "-in", der_file,
                             "-strparse", "3", "-offset", "6")
        self._assert_fails_with(result, "past the end of the data to parse")

    def test_length_too_large(self):
        """A -length larger than the remaining input is clamped, so the whole
        input is parsed."""
        result = run_wolfssl("asn1parse", "-inform", "DER", "-in", self.der,
                             "-length", "9999999")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, self.der_output)

    def test_negative_integer_arg(self):
        """A non-integer / negative argument to -offset is rejected."""
        result = run_wolfssl("asn1parse", "-inform", "DER", "-in", self.der,
                             "-offset", "-5")
        self.assertNotEqual(result.returncode, 0)

    def test_strparse_non_octet_string(self):
        """-strparse onto a non-OCTET/BIT STRING node errors out."""
        # The top-level node of the cert is a SEQUENCE, not an OCTET STRING.
        result = run_wolfssl("asn1parse", "-inform", "DER", "-in", self.der,
                             "-strparse", "0")
        self.assertNotEqual(result.returncode, 0)

    def test_input_file_too_large(self):
        """A file larger than the 0x7FFFFFFEU byte max is rejected up front.

        asn1_ReadFile caps the input at 0x7FFFFFFEU bytes so that the +1 for the
        null terminator still fits in an int/long on Windows.  A file one byte over that limit
        (0x7FFFFFFFU) must be refused before any ~2GB buffer is allocated or
        read, so the check has to fire on file size alone.  The file is created
        sparse (no real disk use) via truncate; skip if the platform/filesystem
        cannot represent a file that large.
        """
        big_file = "test-asn1-toobig.der"
        # 0x7FFFFFFF == one byte past the 0x7FFFFFFEU maximum accepted length.
        size = 0x7FFFFFFF
        try:
            with open(big_file, "wb") as f:
                truncate_sparse(f, size)
        except (OSError, OverflowError) as e:
            if os.path.exists(big_file):
                os.remove(big_file)
            raise unittest.SkipTest(
                "cannot create a {}-byte sparse file: {}".format(size, e))
        self.addCleanup(lambda: os.remove(big_file)
                        if os.path.exists(big_file) else None)

        # A filesystem may silently cap the length; only meaningful if the file
        # really reports a size past the limit.
        if os.path.getsize(big_file) != size:
            raise unittest.SkipTest("filesystem did not honour the sparse size")

        result = run_wolfssl("asn1parse", "-inform", "DER", "-in", big_file)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("longer than", result.stdout + result.stderr)

    def test_malformed_oid_file(self):
        """A malformed -oid definition file is rejected."""
        # Missing the short and long name tokens.
        oid_file = self._write_text("test-asn1-bad-oid.conf", "1.2.3.4\n")

        result = run_wolfssl("asn1parse", "-inform", "DER", "-in", self.der,
                             "-oid", oid_file)
        self.assertNotEqual(result.returncode, 0)

    def test_dump_alone(self):
        """-dump prints the data as hex and drops the INTEGER text form."""
        der_file = self._write_der("test-asn1-dump.der", TWO_INTEGERS)
        plain = run_wolfssl("asn1parse", "-in", der_file)
        self.assertEqual(plain.returncode, 0, plain.stderr)
        self.assertIn(":2a", plain.stdout)

        result = run_wolfssl("asn1parse", "-in", der_file, "-dump")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("0000: 2a", result.stdout)
        self.assertIn("0000: 2b", result.stdout)
        self.assertNotIn(":2a", result.stdout)

    def test_help(self):
        result = run_wolfssl("asn1parse", "-help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("-strparse", result.stdout + result.stderr)

    def test_inform_invalid(self):
        """An unknown or missing -inform value is rejected."""
        for args in (("-inform", "XYZ"), ("-inform",)):
            with self.subTest(args=args):
                result = run_wolfssl("asn1parse", "-in", self.der, *args)
                self._assert_fails_with(result, "-inform argument either "
                                        "missing or is not valid value")

    def test_missing_in(self):
        result = run_wolfssl("asn1parse", "-inform", "DER")
        self._assert_fails_with(result, "Must have input via file passed "
                                "to -in")

    def test_nonexistent_in(self):
        result = run_wolfssl("asn1parse", "-in", "asn1-missing.nonexistent")
        self._assert_fails_with(result, "file could not be opened")

    def test_empty_in(self):
        der_file = self._write_der("test-asn1-empty.der", b"")
        result = run_wolfssl("asn1parse", "-in", der_file)
        self._assert_fails_with(result, "Input file is empty")

    def test_pem_errors(self):
        """Malformed PEM input is rejected with the specific reason."""
        cases = (
            (b"AgEq\n-----END X-----\n", "No PEM header found"),
            (b"-----BEGIN X-----\nAgEq\n", "No PEM footer found"),
            (b"-----BEGIN X\nAgEq\n", "Invalid PEM header"),
            (b"-----BEGIN X-----\n!!!!\n-----END X-----\n",
             "PEM input is not base64 encoded"),
            (b"-----BEGIN X-----\n-----END X-----\n", "No data to parse"),
        )
        for i, (data, msg) in enumerate(cases):
            with self.subTest(msg=msg):
                pem_file = self._write_der("test-asn1-bad{}.pem".format(i),
                                           data)
                result = run_wolfssl("asn1parse", "-inform", "PEM",
                                     "-in", pem_file)
                self._assert_fails_with(result, msg)

    def test_b64_not_base64(self):
        """-inform B64 on input that is not base64 is rejected."""
        b64_file = self._write_der("test-asn1-bad.b64", b"!!!!\n")
        result = run_wolfssl("asn1parse", "-inform", "B64", "-in", b64_file)
        self._assert_fails_with(result, "input is not base64 encoded")

    def test_length_zero(self):
        result = run_wolfssl("asn1parse", "-in", self.der, "-length", "0")
        self._assert_fails_with(result, "-length arg must be greater than 0")

    def test_strparse_missing_arg(self):
        """-strparse as the final argument reports the missing value."""
        result = run_wolfssl("asn1parse", "-in", self.der, "-strparse")
        self._assert_fails_with(result, "-strparse argument missing argument")

    def test_out_unopenable(self):
        """An -out path that cannot be created is reported."""
        result = run_wolfssl("asn1parse", "-in", self.der, "-out",
                             os.path.join("asn1-no-such-dir.nonexistent",
                                          "out.der"))
        self._assert_fails_with(result, "Unable to open file passed by -out")

    def test_pem_without_inform_hint(self):
        """PEM parsed as the default DER suggests -inform PEM."""
        result = run_wolfssl("asn1parse", "-in", self.pem)
        self._assert_fails_with(result, "try -inform PEM")

    def test_strparse_past_end(self):
        """-strparse beyond the input is rejected before any read."""
        der_file = self._write_der("test-asn1-strparse-past.der",
                                   bytes([0x02, 0x01, 0x2a]))
        result = run_wolfssl("asn1parse", "-in", der_file, "-strparse", "5")
        self._assert_fails_with(result, "tried to jump to invalid location")

    def test_strparse_bit_string_no_nested_der(self):
        """A BIT STRING that is empty or has non-zero unused bits holds no
        nested DER."""
        cases = (
            ("empty", bytes([0x03, 0x01, 0x00])),
            ("unused", bytes([0x03, 0x02, 0x01, 0x00])),
        )
        for name, data in cases:
            with self.subTest(case=name):
                der_file = self._write_der(
                    "test-asn1-strparse-{}.der".format(name), data)
                result = run_wolfssl("asn1parse", "-in", der_file,
                                     "-strparse", "0")
                self._assert_fails_with(result, "BIT STRING has no nested DER")

    def test_strparse_constructed_octet_string(self):
        """A constructed (BER) OCTET STRING is not descended into."""
        der_file = self._write_der("test-asn1-strparse-cons.der",
                                   bytes([0x24, 0x03, 0x02, 0x01, 0x2a]))
        result = run_wolfssl("asn1parse", "-in", der_file, "-strparse", "0")
        self._assert_fails_with(result, "did not find an OCTET STRING or "
                                "BIT STRING")

    def test_strparse_length_past_window(self):
        """An OCTET STRING length running past the input is rejected."""
        der_file = self._write_der("test-asn1-strparse-len.der",
                                   bytes([0x04, 0x05, 0x02, 0x01, 0x2a]))
        result = run_wolfssl("asn1parse", "-in", der_file, "-strparse", "0")
        self._assert_fails_with(result, "invalid length encoding")

    def test_arg_found_twice(self):
        result = run_wolfssl("asn1parse", "-in", self.der, "-in", self.der)
        self._assert_fails_with(result, "Arg found twice for asn1parse")

    def test_out_same_as_in(self):
        """-out naming the -in file overwrites it only after it is read."""
        der_file = self._write_der("test-asn1-inout.der", TWO_INTEGERS)
        result = run_wolfssl("asn1parse", "-in", der_file, "-out", der_file,
                             "-offset", "3", "-noout")
        self.assertEqual(result.returncode, 0, result.stderr)
        with open(der_file, "rb") as f:
            self.assertEqual(f.read(), TWO_INTEGERS[3:])

    def test_offset_past_end(self):
        """An -offset past the end of the input is rejected, not read OOB,
        and an existing -out file is left as it was."""
        out_file = self._write_der("test-asn1-keep.out", b"keep")
        result = run_wolfssl("asn1parse", "-in", self.der, "-out", out_file,
                             "-offset", "9999999")
        self._assert_fails_with(result, "past the end of the data to parse")
        with open(out_file, "rb") as f:
            self.assertEqual(f.read(), b"keep")

    @unittest.skipUnless(oid_encoding_supported(),
                         "built without wc_EncodeObjectId (-oid disabled)")
    def test_empty_oid_file(self):
        """An empty -oid file adds no names rather than failing."""
        oid_file = self._write_der("test-asn1-empty-oid.conf", b"")
        result = run_wolfssl("asn1parse", "-in", self.der, "-oid", oid_file)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, self.der_output)


if __name__ == "__main__":
    test_main()
