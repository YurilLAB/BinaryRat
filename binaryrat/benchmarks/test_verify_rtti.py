# Copyright 2026 YurilLAB
# SPDX-License-Identifier: Apache-2.0
"""Keep host CI failures readable even when the full Ghidra log is unavailable."""

import unittest

from verify_rtti import log_diagnostic, workflow_error


class RttiDiagnosticTests(unittest.TestCase):
    def test_prefers_the_bounded_compiler_line(self):
        messages = ("ERROR REPORT SCRIPT ERROR: script couldn't load\n"
                    "BinaryRatRecoverRtti.java:42: error: " + "a" * 900)
        diagnostic = log_diagnostic(messages)
        self.assertTrue(diagnostic.startswith("BinaryRatRecoverRtti.java:42: error:"))
        self.assertEqual(len(diagnostic), 320)

    def test_uses_script_error_line_when_there_is_no_compiler_line(self):
        self.assertEqual(log_diagnostic("INFO report\nERROR REPORT SCRIPT ERROR: probe\n"),
                         "ERROR REPORT SCRIPT ERROR: probe")

    def test_annotation_cannot_start_a_second_workflow_command(self):
        message = workflow_error("gcc/O0/classes", "recovering", ValueError("bad%\r\n::warning::probe"))
        self.assertEqual(message,
                         "::error::gcc/O0/classes while recovering [ValueError]. bad%25%0D%0A::warning::probe")
        self.assertNotIn("\n", message)


if __name__ == "__main__":
    unittest.main()
