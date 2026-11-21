"""Retries of network setup commands.

SPDX-License-Identifier: Apache-2.0
Copyright 2026 YurilLAB. New BinaryRat tests.
"""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import retry_command


class Runner:
    def __init__(self, *codes):
        self.codes = list(codes)
        self.commands = []

    def __call__(self, command):
        self.commands.append(command)
        return subprocess.CompletedProcess(command, self.codes.pop(0))


class RetryTests(unittest.TestCase):
    def test_first_success_runs_once(self):
        runner, waits = Runner(0), []
        self.assertEqual(retry_command.run(["gradlew", "--version"], runner=runner, sleep=waits.append), 0)
        self.assertEqual(runner.commands, [["gradlew", "--version"]])
        self.assertEqual(waits, [])

    def test_failures_are_retried_with_growing_waits(self):
        runner, waits = Runner(1, 1, 0), []
        self.assertEqual(retry_command.run(["fetch"], runner=runner, sleep=waits.append), 0)
        self.assertEqual(len(runner.commands), 3)
        self.assertEqual(waits, [10.0, 30.0])

    def test_last_exit_code_is_returned_after_every_attempt_fails(self):
        runner, waits = Runner(1, 2, 7), []
        self.assertEqual(retry_command.run(["fetch"], runner=runner, sleep=waits.append), 7)
        self.assertEqual(len(waits), 2)

    def test_real_process_exit_codes_pass_through(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "ran"
            # Fails until the marker exists: the second attempt succeeds.
            script = ("import pathlib, sys; m = pathlib.Path(sys.argv[1]); "
                      "ok = m.exists(); m.touch(); sys.exit(0 if ok else 3)")
            code = retry_command.run([sys.executable, "-c", script, str(marker)],
                                     first_delay=0, sleep=lambda _: None)
            self.assertEqual(code, 0)

    def test_command_line_takes_the_command_after_a_separator(self):
        code = retry_command.main(["--attempts", "1", "--", sys.executable, "-c", "raise SystemExit(5)"])
        self.assertEqual(code, 5)
        with self.assertRaises(SystemExit):
            retry_command.main(["--attempts", "2"])


if __name__ == "__main__":
    unittest.main()
