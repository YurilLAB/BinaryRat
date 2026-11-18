"""Checks that persistent-cache evidence cannot pass by doing fresh work.

SPDX-License-Identifier: Apache-2.0
Copyright 2026 YurilLAB.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import verify_ghidra


def rows(revision: int = 4) -> list[dict]:
    return [{"schema_version": 1, "program_id": "a" * 64, "revision": revision,
             "address_space": "ram", "address": f"{4096 + index * 16:x}",
             "name": f"function_{index}", "body_sha256": "b" * 64,
             "body_ranges": [], "c": f"int function_{index}(void) {{ return {index}; }}\n",
             "prototype": f"int function_{index}(void)", "completed": True,
             "timed_out": False, "cancelled": False, "failed_to_start": False, "error": ""}
            for index in range(2)]


def evidence(prefix: Path, log: Path, state: str, revision: int = 4) -> dict:
    data = "".join(json.dumps(row) + "\n" for row in rows(revision))
    Path(str(prefix) + ".serial.jsonl").write_text(data, encoding="utf-8")
    Path(str(prefix) + ".scheduled.jsonl").write_text(data, encoding="utf-8")
    log.write_text("BinaryRat exact serial/scheduled comparison passed:\n", encoding="utf-8")
    compute = 0 if state == "warm" else 2
    cache = {"enabled": state != "disabled", "hits": 0,
             "replayed": 2 if state == "warm" else 0,
             "misses": 2 if state == "cold" else 0,
             "lookup_rejected": 0, "stored": 2 if state == "cold" else 0,
             "store_rejected": 0, "store_diagnostics": {}, "lookup_diagnostics": {}}
    summary = {"cache": cache, "leases": compute,
               "lease_status_counts": {"completed": compute} if compute else {},
               "traced_leases": compute if state == "cold" else 0,
               "engine_stats": {"peak_running": compute, "running": 0, "queued": 0},
               "engine_configuration": {"workers": 2, "memory_watch": True},
               "memory_watched_leases": compute, "max_peak_resident_bytes": 4096 if compute else 0}
    Path(str(prefix) + ".scheduled.jsonl.schedule.json").write_text(json.dumps(summary), encoding="utf-8")
    return summary


class ProcessMeasurementTests(unittest.TestCase):
    def test_denied_process_list_still_times_out_and_reaps_root(self):
        children = []
        spawn = subprocess.Popen

        def capture(*args, **kwargs):
            process = spawn(*args, **kwargs)
            children.append(process)
            self.addCleanup(process.wait)
            self.addCleanup(process.kill)
            return process

        with tempfile.TemporaryDirectory() as directory, patch.object(
            verify_ghidra.psutil.Process, "children", side_effect=verify_ghidra.psutil.AccessDenied()
        ), patch.object(subprocess, "Popen", side_effect=capture):
            with self.assertRaises(TimeoutError):
                verify_ghidra.measured_run([sys.executable, "-c", "import time; time.sleep(10)"],
                                           Path(directory) / "timeout.log", 0.2)
            self.assertIsNotNone(children[0].returncode)

    def test_nonfinite_deadline_rejected_before_launch(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(subprocess, "Popen") as spawn:
            for timeout in (float("nan"), float("inf"), 0, -1):
                with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                    verify_ghidra.measured_run([], Path(directory) / "invalid.log", timeout)
            spawn.assert_not_called()


class ScheduledEvidenceTests(unittest.TestCase):
    def test_disabled_cold_and_warm_account_for_every_function(self):
        with tempfile.TemporaryDirectory() as directory:
            for state, leases in (("disabled", 2), ("cold", 2), ("warm", 0)):
                prefix, log = Path(directory) / state, Path(directory) / (state + ".log")
                evidence(prefix, log, state)
                result = verify_ghidra.verify_scheduled(prefix, log, 2, state)
                self.assertEqual(result["function_count"], 2)
                self.assertEqual(result["compute_leases"], leases)

    def test_uncached_run_rejects_unnecessary_traces(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix, log = Path(directory) / "uncached", Path(directory) / "uncached.log"
            summary = evidence(prefix, log, "disabled")
            summary["traced_leases"] = 2
            Path(str(prefix) + ".scheduled.jsonl.schedule.json").write_text(json.dumps(summary))
            with self.assertRaisesRegex(RuntimeError, "dependency traces"):
                verify_ghidra.verify_scheduled(prefix, log, 2, "disabled")

    def test_streaming_raw_comparison_at_chunk_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            left, right = Path(directory) / "left", Path(directory) / "right"
            body = b"a" * 131072
            left.write_bytes(body)
            for position in (0, 65535, 65536, len(body) - 1, len(body)):
                with self.subTest(position=position):
                    right.write_bytes(body[:position] + b"b" + body[position + 1:])
                    self.assertEqual(verify_ghidra.first_differing_byte(left, right), position)
            right.write_bytes(body[:65536])
            self.assertEqual(verify_ghidra.first_differing_byte(left, right), 65536)
            right.write_bytes(body)
            self.assertIsNone(verify_ghidra.first_differing_byte(left, right))

    def test_warm_evidence_rejects_a_recomputed_result(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix, log = Path(directory) / "warm", Path(directory) / "warm.log"
            summary = evidence(prefix, log, "warm")
            summary["cache"].update(replayed=1, misses=1)
            Path(str(prefix) + ".scheduled.jsonl.schedule.json").write_text(json.dumps(summary))
            with self.assertRaisesRegex(RuntimeError, "warm cache did not avoid"):
                verify_ghidra.verify_scheduled(prefix, log, 2, "warm")

    def test_matching_failed_exports_do_not_prove_cache_correctness(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix, log = Path(directory) / "warm", Path(directory) / "warm.log"
            evidence(prefix, log, "warm")
            invalid = rows()
            invalid[0].update(completed=False, c="")
            data = "".join(json.dumps(row) + "\n" for row in invalid)
            for suffix in (".serial.jsonl", ".scheduled.jsonl"):
                Path(str(prefix) + suffix).write_text(data)
            with self.assertRaisesRegex(RuntimeError, "incomplete scheduled"):
                verify_ghidra.verify_scheduled(prefix, log, 2, "warm")

    def test_rejected_replay_cannot_be_reported_as_a_clean_warm_hit(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix, log = Path(directory) / "warm", Path(directory) / "warm.log"
            summary = evidence(prefix, log, "warm")
            summary["cache"]["lookup_rejected"] = 1
            Path(str(prefix) + ".scheduled.jsonl.schedule.json").write_text(json.dumps(summary))
            with self.assertRaisesRegex(RuntimeError, "could not reuse/store"):
                verify_ghidra.verify_scheduled(prefix, log, 2, "warm")

    def test_fresh_import_revision_is_reported_but_other_metadata_must_match(self):
        with tempfile.TemporaryDirectory() as directory:
            cold, warm = Path(directory) / "cold.jsonl", Path(directory) / "warm.jsonl"
            cold.write_text("".join(json.dumps(row) + "\n" for row in rows(4)))
            changed = rows(7)
            warm.write_text("".join(json.dumps(row) + "\n" for row in changed))
            result = verify_ghidra.compare_fresh_jvm_exports(cold, warm)
            self.assertFalse(result["exact_bytes_including_revision"])
            self.assertEqual(result["revision_pairs"], [{"cold": 4, "warm": 7, "functions": 2}])
            changed[0]["prototype"] = "void function_0(void)"
            warm.write_text("".join(json.dumps(row) + "\n" for row in changed))
            with self.assertRaisesRegex(RuntimeError, "stable metadata"):
                verify_ghidra.compare_fresh_jvm_exports(cold, warm)

    def test_persistent_check_uses_owned_space_path_and_removes_it(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory)
            environments = []
            commands = []

            def run(argv, log, timeout, env):
                environments.append(env.copy())
                commands.append(argv)
                state = "cold" if "-import" in argv else "warm"
                prefix = Path(argv[argv.index("-postScript") + 2])
                evidence(prefix, log, state)
                return {"returncode": 0}

            user_environment = {"BINARYRAT_CACHE_DIR": "untouched-user-cache", "EXAMPLE": "value"}
            with patch.object(verify_ghidra, "measured_run", run):
                report = verify_ghidra.check_persistent_cache(
                    Path("headless"), Path("fixture"), Path("scripts"), "fixture", destination,
                    2, 30, user_environment)
            self.assertEqual(len(environments), 2)
            self.assertEqual(environments[0], environments[1])
            owned = Path(environments[0]["BINARYRAT_CACHE_DIR"])
            self.assertIn(" ", str(owned))
            self.assertFalse(owned.exists())
            self.assertEqual(commands[0][1:3], commands[1][1:3])
            self.assertNotIn("-deleteProject", commands[0])
            self.assertNotIn("-import", commands[1])
            self.assertEqual(commands[1][3:7], ["-process", "fixture", "-noanalysis", "-readOnly"])
            self.assertEqual(user_environment["BINARYRAT_CACHE_DIR"], "untouched-user-cache")
            self.assertTrue(report["cache_directory_test_owned_and_removed"])
            self.assertTrue(report["saved_program_database_test_owned_reused_and_removed"])

    def test_redirected_call_proof_rejects_stale_hit_or_missing_case(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory)
            evidence = {"stock_output_changed": True, "add_fixup": "MISS", "clear_fixup": "MISS",
                        "unrelated_entry_unchanged": True, "precise_invalidation": True}
            proof = {"passed": True, "primary_call": evidence.copy(),
                     "explicit_call_override": evidence.copy(), "inherited_thunk_fixup": evidence.copy()}

            def run(argv, log, timeout, env):
                self.assertIn("-preScript", argv)
                self.assertIn(" ", argv[-2])
                Path(argv[-1]).write_text(json.dumps(proof), encoding="utf-8")
                log.write_text("BinaryRat redirected call cache checks passed", encoding="utf-8")
                return {"returncode": 0, "wall_seconds": 0}

            def check():
                return verify_ghidra.check_redirected_call_cache(
                    Path("headless"), Path("scripts"), destination, Path("engine"), 30, {})

            with patch.object(verify_ghidra, "measured_run", run):
                self.assertTrue(check()["passed"])
                proof["primary_call"]["add_fixup"] = "HIT"
                with self.assertRaisesRegex(RuntimeError, "proof failed"):
                    check()
                proof["primary_call"]["add_fixup"] = "MISS"
                del proof["explicit_call_override"]
                with self.assertRaisesRegex(RuntimeError, "proof failed"):
                    check()


if __name__ == "__main__":
    unittest.main()
