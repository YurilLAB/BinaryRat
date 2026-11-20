"""Regression tests for decompiler parity and persistent-cache evidence.

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
    refused = {verify_ghidra.REFUSED_PUT + "replace cache record: Is a directory": 2}
    cache = {"enabled": state != "disabled", "hits": 0,
             "replayed": 2 if state == "warm" else 0,
             "misses": 2 if state in ("cold", "refused") else 0,
             "lookup_rejected": 0, "stored": 2 if state == "cold" else 0,
             "store_rejected": 2 if state == "refused" else 0,
             "store_diagnostics": refused if state == "refused" else {}, "lookup_diagnostics": {}}
    summary = {"cache": cache, "leases": compute,
               "lease_status_counts": {"completed": compute} if compute else {},
               "traced_leases": compute if state != "disabled" else 0,
               "engine_stats": {"peak_running": compute, "running": 0, "queued": 0},
               "engine_configuration": {"workers": 2, "memory_watch": True},
               "memory_watched_leases": compute, "max_peak_resident_bytes": 4096 if compute else 0}
    Path(str(prefix) + ".scheduled.jsonl.schedule.json").write_text(json.dumps(summary), encoding="utf-8")
    return summary


class SavedProjectTests(unittest.TestCase):
    def test_only_rotating_index_backups_are_excluded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "example.gpr"
            marker.touch()
            idata = root / "example.rep/idata"
            nested = idata / "00"
            nested.mkdir(parents=True)
            paths = [idata / name for name in ("~index.bak", "~journal.bak", "~index.dat")]
            paths.append(nested / "~index.bak")
            for path in paths:
                path.write_bytes(b"original")
            before = verify_ghidra.saved_project_hashes(root, "example")
            self.assertEqual(before.keys(), {"example.gpr", "example.rep/idata/~index.dat",
                                             "example.rep/idata/00/~index.bak"})
            for path in paths[:2]:
                path.write_bytes(b"rotated")
            self.assertEqual(verify_ghidra.saved_project_hashes(root, "example"), before)
            paths[2].write_bytes(b"changed")
            self.assertNotEqual(verify_ghidra.saved_project_hashes(root, "example"), before)
            marker.unlink()
            with self.assertRaises(FileNotFoundError):
                verify_ghidra.saved_project_hashes(root, "example")


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


class KnownStockFailureTests(unittest.TestCase):
    stock_error = ("Low-level Error: Bad instruction count exceeded:\n    ...\n"
                   "    No pcode could be generated at address: r0x000140020137")
    crt_bodies = {
        "O1": ("140001260", "acaf5da83d08fcacb43565cb74f5335281aadb71ac27f5ae67a8bd5d21dbd517"),
        "O2": ("1400012d0", "1b87dfa37f3c9194cf5633ae849049f688cd8c8bb5d4640378c749e3be93acca"),
        "Ox": ("140001300", "8d7bd4dedd921e18b863a6cddd371e1e3cc72ee42a324453bf1110758b2d9b3b"),
    }

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.prefix = Path(directory.name) / "fixture"
        self.log = Path(directory.name) / "fixture.log"

    def known_failure(self, optimization="O1"):
        successful, failed = rows()
        address, digest = self.crt_bodies[optimization]
        failed.update(address=address, name=f"FUN_{address}", body_sha256=digest, c="", prototype="",
                      completed=False, error=self.stock_error)
        return successful, failed

    def compare(self, mode, records, artifact_id="msvc/O1/types", *, candidate=None,
                cache_state="disabled"):
        evidence(self.prefix, self.log, cache_state)
        if mode == "parallel":
            count = len(records)
            self.log.write_text(
                "BinaryRat exact serial/parallel comparison passed:\n"
                f"BinaryRat exported functions={count} mode=serial workers=1 excluded_external=0 elapsed_seconds=1\n"
                f"BinaryRat exported functions={count} mode=parallel workers=2 excluded_external=0 elapsed_seconds=1\n",
                encoding="utf-8")
        for phase, data in (("serial", records), (mode, records if candidate is None else candidate)):
            export = Path(str(self.prefix) + f".{phase}.jsonl")
            export.write_text("".join(json.dumps(row) + "\n" for row in data), encoding="utf-8")
        if mode == "parallel":
            return verify_ghidra.verify_pair(self.prefix, self.log, artifact_id=artifact_id)
        return verify_ghidra.verify_scheduled(self.prefix, self.log, 2, cache_state, artifact_id=artifact_id)

    def test_known_crt_failures_remain_in_parity_and_are_reported(self):
        for mode in ("parallel", "scheduled"):
            for optimization in self.crt_bodies:
                with self.subTest(mode=mode, optimization=optimization):
                    result = self.compare(mode, self.known_failure(optimization), f"msvc/{optimization}/types")
                    self.assertEqual(result["function_count"], 2)
                    self.assertEqual(result["completed_count"], 1)
                    failure, = result["expected_stock_failures"]
                    address, digest = self.crt_bodies[optimization]
                    self.assertEqual(failure["address"].split(":")[-1], address)
                    self.assertEqual(failure["body_sha256"], digest)
                    self.assertEqual(failure["symbol"], "__GSHandlerCheckCommon")
                    self.assertEqual(failure["error"], self.stock_error)
                    if mode == "scheduled":
                        self.assertEqual(result["compute_leases"], 2)

    def test_unexpected_failure_in_either_mode_is_rejected(self):
        successful, failure = self.known_failure()
        changes = (
            {"address": "1400012d0"},
            {"address_space": "other"},
            {"body_sha256": "c" * 64},
            {"error": self.stock_error + " changed"},
            {"completed": True},
            {"timed_out": True},
            {"cancelled": True},
            {"failed_to_start": True},
            {"prototype": "int partial(void)"},
            {"c": "partial output"},
        )
        for mode in ("parallel", "scheduled"):
            for change in changes:
                with self.subTest(mode=mode, change=change), self.assertRaisesRegex(RuntimeError, "incomplete"):
                    self.compare(mode, [successful, failure | change])
            for artifact_id in (None, "msvc/Od/types", "msvc/O1/classes", "msvc-arm64/O1/types",
                                "msvc/O2/types"):
                with self.subTest(mode=mode, artifact_id=artifact_id), self.assertRaisesRegex(
                        RuntimeError, "incomplete"):
                    self.compare(mode, [successful, failure], artifact_id)
            with self.subTest(mode=mode), self.assertRaisesRegex(RuntimeError, "incomplete.*ram:1010"):
                _, extra = rows()
                extra.update(completed=False, c="")
                self.compare(mode, [successful, failure, extra])

    def test_successful_exports_need_no_exception_for_known_fixture(self):
        for mode in ("parallel", "scheduled"):
            with self.subTest(mode=mode):
                result = self.compare(mode, rows())
                self.assertEqual(result["function_count"], 2)
                self.assertEqual(result["completed_count"], 2)
                self.assertEqual(result["expected_stock_failures"], [])

    def test_parity_mismatch_cannot_be_classified_as_an_expected_failure(self):
        records = self.known_failure()
        candidate = [records[0], records[1] | {"error": self.stock_error + " changed"}]
        for mode in ("parallel", "scheduled"):
            with self.subTest(mode=mode), self.assertRaisesRegex(RuntimeError, "exact output mismatch"):
                self.compare(mode, records, candidate=candidate)

    def test_empty_and_all_incomplete_exports_are_rejected(self):
        _, failure = self.known_failure()
        for mode in ("parallel", "scheduled"):
            for records in ([], [failure]):
                with self.subTest(mode=mode, count=len(records)), self.assertRaisesRegex(
                        RuntimeError, "no complete"):
                    self.compare(mode, records)

    def test_cache_enabled_runs_still_require_complete_output(self):
        for state in ("cold", "warm"):
            with self.subTest(state=state), self.assertRaisesRegex(RuntimeError, "incomplete scheduled"):
                self.compare("scheduled", self.known_failure(), cache_state=state)


class ScheduledEvidenceTests(unittest.TestCase):
    def test_disabled_cold_warm_and_refused_account_for_every_function(self):
        with tempfile.TemporaryDirectory() as directory:
            for state, leases in (("disabled", 2), ("cold", 2), ("warm", 0), ("refused", 2)):
                prefix, log = Path(directory) / state, Path(directory) / (state + ".log")
                evidence(prefix, log, state)
                result = verify_ghidra.verify_scheduled(prefix, log, 2, state)
                self.assertEqual(result["function_count"], 2)
                self.assertEqual(result["compute_leases"], leases)

    def test_refused_writes_must_be_decompiled_and_reported_per_function(self):
        # Each change breaks one rule only, so every rule is shown to be needed.
        def stored(cache):
            cache["stored"] = 1

        def overcounted(cache):
            cache["store_rejected"] = 3

        def foreign_reason(cache):
            cache["store_diagnostics"] = {"program changed during decompilation": 2}

        def short_count(cache):
            cache["store_diagnostics"] = {verify_ghidra.REFUSED_PUT + "x": 1}

        def served(cache):
            cache.update(hits=1, misses=1)

        def silent(cache):
            cache.update(store_rejected=0, store_diagnostics={})

        def rejected_lookup(cache):
            cache["lookup_rejected"] = 1

        def boolean_count(cache):
            cache["store_diagnostics"] = {verify_ghidra.REFUSED_PUT + "x": True, verify_ghidra.REFUSED_PUT + "y": 1}

        with tempfile.TemporaryDirectory() as directory:
            for change in (stored, overcounted, foreign_reason, short_count, served, silent, rejected_lookup,
                           boolean_count):
                with self.subTest(change=change.__name__):
                    prefix, log = Path(directory) / "refused", Path(directory) / "refused.log"
                    summary = evidence(prefix, log, "refused")
                    change(summary["cache"])
                    Path(str(prefix) + ".scheduled.jsonl.schedule.json").write_text(json.dumps(summary))
                    with self.assertRaisesRegex(RuntimeError, "refused cache writes|cover every"):
                        verify_ghidra.verify_scheduled(prefix, log, 2, "refused")

    def test_blocking_replaces_only_cache_records_with_occupied_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            with self.assertRaisesRegex(RuntimeError, "stored no cache records"):
                verify_ghidra.block_cache_records(cache)
            records = [cache / (("%064x" % index) + ".json") for index in (1, 2)]
            for record in records:
                record.write_text("{}", encoding="utf-8")
            (cache / ".owner.lock").write_text("", encoding="utf-8")
            (cache / ("A" * 64 + ".json")).write_text("{}", encoding="utf-8")
            self.assertEqual(verify_ghidra.block_cache_records(cache), 2)
            for record in records:
                self.assertTrue(record.is_dir())
                self.assertTrue(any(record.iterdir()))
            self.assertTrue((cache / ".owner.lock").is_file())
            self.assertTrue((cache / ("A" * 64 + ".json")).is_file())
            with self.assertRaisesRegex(RuntimeError, "stored no cache records"):
                verify_ghidra.block_cache_records(cache)

    def test_cache_edge_proof_needs_every_case_and_its_marker(self):
        kinds = ["byte-mapped 1:1", "byte-mapped 2:4", "bit-mapped", "shared file bytes",
                 "write through the mirror", "view created during the session"]
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory)
            state = {}

            def reset():
                state.update(report={"passed": True, "aliases": [{"kind": kind, "lookup": "MISS"} for kind in kinds],
                                     "refusals": [{"case": index} for index in range(5)]},
                             # Counts follow the report, so each break below trips one rule only.
                             marker="BINARYRAT_CACHE_EDGES_OK aliases={aliases} refusals={refusals} "
                                    "pinning=open-handle "
                                    "stale_served=0 export_safe=true", returncode=0)

            def run(argv, log, timeout, env):
                self.assertEqual(argv[argv.index("-preScript") + 1], "BinaryRatCacheEdgeProof.java")
                self.assertIn(" ", argv[1])
                Path(argv[-1]).write_text(json.dumps(state["report"]), encoding="utf-8")
                marker = state["marker"].format(aliases=len(state["report"]["aliases"]),
                                                refusals=len(state["report"]["refusals"]))
                log.write_text(f"INFO\n{marker}\n", encoding="utf-8")
                return {"returncode": state["returncode"], "wall_seconds": 0}

            def check():
                return verify_ghidra.check_cache_edges(Path("headless"), Path("scripts"), destination, 30, {})

            breaks = {
                "stale alias": lambda: state["report"]["aliases"][2].update(lookup="HIT"),
                "missing kind": lambda: state["report"]["aliases"].pop(1),
                "missing refusal": lambda: state["report"]["refusals"].pop(),
                "not passed": lambda: state["report"].update(passed=False),
                "marker count": lambda: state.update(marker=state["marker"].replace("{aliases}", "7")),
                "no marker": lambda: state.update(marker="nothing"),
                "unknown pinning": lambda: state.update(marker=state["marker"].replace("open-handle", "none")),
                "script error": lambda: state.update(marker=state["marker"] + "\nREPORT SCRIPT ERROR: x"),
                "exit code": lambda: state.update(returncode=1),
            }
            with patch.object(verify_ghidra, "measured_run", run):
                reset()
                result = check()
                self.assertEqual((result["alias_cases"], result["refusal_cases"], result["pinning"]),
                                 (6, 5, "open-handle"))
                reset()
                state["marker"] = state["marker"].replace("open-handle", "directory-permissions")
                self.assertEqual(check()["pinning"], "directory-permissions")
                for name, damage in breaks.items():
                    with self.subTest(case=name):
                        reset()
                        damage()
                        with self.assertRaisesRegex(RuntimeError, "cache-edge"):
                            check()

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
                state = ("cold", "warm", "refused")[len(commands) - 1]
                self.assertEqual("-import" in argv, state == "cold")
                cache = Path(env["BINARYRAT_CACHE_DIR"])
                if state == "cold":
                    cache.mkdir()
                    for index in (1, 2):
                        (cache / (("%064x" % index) + ".json")).write_text("{}", encoding="utf-8")
                else:
                    records = [path for path in cache.iterdir() if path.name.endswith(".json")]
                    self.assertEqual(len(records), 2)
                    self.assertTrue(all(path.is_dir() if state == "refused" else path.is_file()
                                        for path in records))
                prefix = Path(argv[argv.index("-postScript") + 2])
                evidence(prefix, log, state)
                return {"returncode": 0}

            user_environment = {"BINARYRAT_CACHE_DIR": "untouched-user-cache", "EXAMPLE": "value"}
            with patch.object(verify_ghidra, "measured_run", run):
                report = verify_ghidra.check_persistent_cache(
                    Path("headless"), Path("fixture"), Path("scripts"), "fixture", destination,
                    2, 30, user_environment)
            self.assertEqual(len(environments), 3)
            self.assertTrue(environments[0] == environments[1] == environments[2])
            owned = Path(environments[0]["BINARYRAT_CACHE_DIR"])
            self.assertIn(" ", str(owned))
            self.assertFalse(owned.exists())
            self.assertEqual(commands[0][1:3], commands[1][1:3])
            self.assertNotIn("-deleteProject", commands[0])
            self.assertNotIn("-import", commands[1])
            for command in commands[1:]:
                self.assertEqual(command[3:7], ["-process", "fixture", "-noanalysis", "-readOnly"])
            self.assertEqual(user_environment["BINARYRAT_CACHE_DIR"], "untouched-user-cache")
            self.assertTrue(report["cache_directory_test_owned_and_removed"])
            self.assertTrue(report["saved_program_database_test_owned_reused_and_removed"])
            self.assertEqual(report["fresh_jvms"], 3)
            self.assertEqual(report["refused_writes"]["records_blocked"], 2)
            self.assertEqual(report["runs"]["refused"]["compute_leases"], 2)

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
