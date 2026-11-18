# SPDX-License-Identifier: Apache-2.0
import copy
from pathlib import Path
import tempfile
import unittest

from profile_auto_analysis import (PROFILE_FINISHED, PROFILE_STARTED, START, SUCCEEDED,
                                   TIMED_OUT, comparable, diagnose, summarize)


class AnalysisProfileTests(unittest.TestCase):
    def setUp(self):
        self.logs = tempfile.TemporaryDirectory()
        self.addCleanup(self.logs.cleanup)
        self.log = Path(self.logs.name) / "analysis.log"
        self.sha256 = "a" * 64
        self.program = {
            "schema_version": 1, "input_sha256": self.sha256, "analysis_active": False,
            "program_marked_analyzed": True, "timed_out": False, "analysis_wall_ns": 5_200_000_000,
            "recorded_task_total_ms": 4800, "task_times_ms": {"Stack": 3200, "Reference": 1600},
            "work": {"instructions": 80, "functions": 12, "inventory_sha256": "b" * 64},
            "language": "x86:LE:64:default", "compiler_spec": "gcc", "image_base": "00100000",
            "analysis_options": {"Stack": "true"}, "java_version": "25", "heap_max_bytes": 200,
            "analyzer_messages": "", "analyzer_message_characters": 0,
        }
        self.metrics = {"returncode": 0, "sampled_process_tree_peak_rss_bytes": 200,
                        "memory_sampling_errors": [], "wall_seconds": 11}
        self.success_log = [PROFILE_STARTED, START + " fixture", SUCCEEDED + " fixture", PROFILE_FINISHED]

    def status(self, lines, program, metrics=None):
        self.log.write_text("\n".join(lines), encoding="utf-8")
        values = self.metrics if metrics is None else metrics
        return diagnose(self.log, program, self.sha256, values)["status"]

    def test_require_fresh_completion_and_valid_identity(self):
        self.assertEqual(self.status(self.success_log, self.program), "completed")
        self.assertEqual(self.status(self.success_log[:-1], self.program), "missing_evidence")
        self.assertEqual(self.status(self.success_log, self.program | {"input_sha256": "b" * 64}), "invalid_evidence")
        self.assertEqual(self.status(self.success_log, self.program | {"work": {}}), "invalid_evidence")

    def test_failing_analyzer_overrides_apparent_headless_success(self):
        self.assertEqual(self.status(self.success_log + ["ERROR Unexpected analyzer failure"], self.program), "failed")
        self.assertEqual(self.status(self.success_log, self.program, self.metrics | {"returncode": 2}), "failed")

    def test_preserve_soft_timeout_and_hard_process_timeout(self):
        logs = self.success_log[:2] + ["ERROR " + TIMED_OUT + "1 second", PROFILE_FINISHED]
        partial = self.program | {"timed_out": True, "program_marked_analyzed": False}
        self.assertEqual(self.status(logs, partial), "analysis_timeout")
        self.assertEqual(self.status(logs, partial | {"timed_out": False}), "missing_evidence")
        self.assertEqual(self.status(logs[:2], None, {"hard_timeout": True}), "process_timeout")

    def test_require_reconciling_task_times_and_rss(self):
        self.assertEqual(self.status(self.success_log, self.program | {"recorded_task_total_ms": 1}), "invalid_evidence")
        self.assertEqual(self.status(self.success_log, self.program | {"task_times_ms": {"Stack": True}}), "invalid_evidence")
        self.assertEqual(self.status(self.success_log, self.program, self.metrics | {"memory_sampling_errors": ["denied"]}),
                         "invalid_evidence")

    def test_compare_equivalent_work_not_performance_values(self):
        stock = {"status": "completed", "program": self.program, "measurements": self.metrics}
        candidate = copy.deepcopy(stock)
        candidate["program"]["task_times_ms"]["Stack"] = 2000
        candidate["program"]["analysis_wall_ns"] = 3_800_000_000
        self.assertTrue(comparable(stock, candidate))
        candidate["program"]["work"]["inventory_sha256"] = "c" * 64
        report = summarize({"stock": [stock], "candidate": [candidate]})
        self.assertEqual(report["status"], "work_mismatch")
        self.assertFalse(report["equivalent_inventory"])
        self.assertEqual(summarize({"stock": [stock, {"status": "analysis_timeout"}]})["status"], "incomplete")


if __name__ == "__main__":
    unittest.main()
