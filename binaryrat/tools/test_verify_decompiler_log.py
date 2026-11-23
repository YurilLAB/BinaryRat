"""Coverage for the upstream decompiler test gate.

SPDX-License-Identifier: Apache-2.0
Copyright 2026 YurilLAB. New BinaryRat tests.
"""

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import verify_decompiler_log


UNIT_SUMMARY = "204/204 tests passed."
APPLIED = "Total tests applied = 733"
PASSING = "Total passing tests = 733"
COMPLETE = (UNIT_SUMMARY, APPLIED, PASSING)


class DecompilerLogTests(unittest.TestCase):
    def test_clean_log_with_test_detail_and_crlf(self):
        lines = ("testing : toy_test ...\r\n", "  passed.\r\n", UNIT_SUMMARY + "\r\n", "",
                 "PASS -- control\r\n", APPLIED + "\r\n", PASSING + "\r\n")
        self.assertEqual(verify_decompiler_log.verify_log(iter(lines)), (204, 733))

    def test_failing_fixture_cannot_hide_behind_matching_counts(self):
        cases = (
            "Error parsing ../datatests/broken.xml: unrecognized XML tag",
            "Error executing ../datatests/broken.xml: missing architecture",
            "Error: Did not apply tests in ../datatests/broken.xml",
            "  Execution failed for ../datatests/broken.xml",
            "  No output for ../datatests/broken.xml",
            "Failures: ",
            "FAIL -- expected field width",
            "  fail: unexpected result",
            "  fail",
        )
        for marker in cases:
            for lines in ((marker, *COMPLETE), (*COMPLETE, marker)):
                with self.subTest(marker=marker, lines=lines), self.assertRaisesRegex(
                    ValueError, "upstream test failure"
                ):
                    verify_decompiler_log.verify_log(lines)

    def test_rejects_missing_duplicate_malformed_and_nonpassing_totals(self):
        cases = (
            (),
            (APPLIED, PASSING),
            (UNIT_SUMMARY, APPLIED),
            (UNIT_SUMMARY, PASSING),
            (*COMPLETE, UNIT_SUMMARY),
            (*COMPLETE, APPLIED),
            (*COMPLETE, PASSING),
            (*COMPLETE, "Total passing tests = nonsense"),
            (*COMPLETE, "Total passing tests ="),
            ("0/0 tests passed.", APPLIED, PASSING),
            ("203/204 tests passed.", APPLIED, PASSING),
            (UNIT_SUMMARY, "Total tests applied = 0", "Total passing tests = 0"),
            (UNIT_SUMMARY, APPLIED, "Total passing tests = 732"),
            (UNIT_SUMMARY, APPLIED, "Total passing tests = 734"),
        )
        for lines in cases:
            with self.subTest(lines=lines), self.assertRaises(ValueError):
                verify_decompiler_log.verify_log(lines)

    def test_cli_returns_an_error_for_unapplied_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "combined output.log"
            command = [sys.executable, verify_decompiler_log.__file__, str(log)]
            log.write_text("\n".join(COMPLETE), encoding="utf-8")
            success = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertEqual(success.returncode, 0, success.stderr)
            self.assertIn("204 upstream unit tests and 733 data tests", success.stdout)

            log.write_text("\n".join((*COMPLETE, "Failures: ", "  No output for broken.xml")),
                           encoding="utf-8")
            failure = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertEqual(failure.returncode, 1)
            self.assertEqual(failure.stdout, "")
            self.assertIn("upstream test failure", failure.stderr)
            self.assertIn("No output for broken.xml", failure.stderr)


if __name__ == "__main__":
    unittest.main()
