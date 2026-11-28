# Copyright 2026 YurilLAB
# SPDX-License-Identifier: Apache-2.0
"""Validate sampling, raw parity comparison and coverage checks without a JVM."""

import json
from pathlib import Path
import tempfile
import unittest

import verify_large_llvm as probe


class LargeFixtureTests(unittest.TestCase):
    def test_midpoints_are_order_independent_and_resolve_versioned_aliases(self):
        symbols = [
            "LLVMFour T 400 40",
            "LLVMThree T 300 40",
            "LLVMOne T 100 40",
            "LLVMTwoA@@LLVM_19 T 200 40",
            "LLVMTwoB@@LLVM_19 T 200 40",
            "LLVMTextButSmall T 500 3f",
            "LLVMData D 600 40",
            "NotLLVM T 700 40",
        ]
        expected = ([(0x200, 0x40, "LLVMTwoB"), (0x400, 0x40, "LLVMFour")], 4)
        self.assertEqual(probe.select_sample("\n".join(symbols), 2), expected)
        self.assertEqual(probe.select_sample("\n".join(reversed(symbols)), 2), expected)

    def test_sample_rejects_unavailable_count_and_overlap(self):
        symbols = "LLVMOne T 100 80\nLLVMTwo T 120 80\n"
        with self.assertRaisesRegex(ValueError, "found 2"):
            probe.select_sample(symbols, 3)
        with self.assertRaisesRegex(ValueError, "overlap"):
            probe.select_sample(symbols, 2)

    def test_stock_reference_requires_the_tagged_public_build(self):
        with tempfile.TemporaryDirectory() as directory:
            installation = Path(directory)
            launcher = installation / "support" / "analyzeHeadless"
            launcher.parent.mkdir()
            launcher.touch()
            properties = installation / "Ghidra" / "application.properties"
            properties.parent.mkdir()
            properties.write_text("application.version=12.2\napplication.release.name=PUBLIC\n",
                                  encoding="utf-8")
            self.assertEqual(probe.launcher(installation), launcher)
            with self.assertRaisesRegex(ValueError, "official pinned"):
                probe.launcher(installation, stock_reference=True)

    def test_launcher_selects_batch_file_on_windows_from_the_same_installation(self):
        with tempfile.TemporaryDirectory() as directory:
            installation = Path(directory)
            properties = installation / "Ghidra" / "application.properties"
            properties.parent.mkdir()
            properties.write_text("application.version=12.2\n", encoding="utf-8")
            shell = installation / "support" / "analyzeHeadless"
            shell.parent.mkdir()
            shell.touch()
            batch = shell.with_suffix(".bat")
            batch.touch()
            self.assertEqual(probe.launcher(installation), shell)
            self.assertEqual(probe.launcher(installation, windows=True), batch)
            batch.unlink()
            with self.assertRaisesRegex(ValueError, r"analyzeHeadless\.bat$"):
                probe.launcher(installation, windows=True)


class LargeParityTests(unittest.TestCase):
    def setUp(self):
        directory = self.enterContext(tempfile.TemporaryDirectory())
        self.stock = Path(directory) / "stock.jsonl"
        self.candidate = Path(directory) / "candidate.jsonl"
        self.identity = "a" * 64
        self.base = 0x100000

    def sample_rows(self, count=2):
        sample = [(0x1000 + i * 64, 64, f"LLVMFunction{i}") for i in range(count)]
        rows = [{"schema_version": 1, "program_id": f"sha256:{self.identity}", "revision": 3,
                 "address_space": "ram", "address": f"{self.base + offset:x}", "name": name,
                 "body_sha256": "b" * 64, "body_ranges": [], "completed": True,
                 "timed_out": False, "cancelled": False, "failed_to_start": False, "error": "",
                 "prototype": f"int {name}(void)", "c": f"int {name}(void) {{ return 1; }}\n"}
                for offset, _, name in sample]
        return sample, rows

    @staticmethod
    def write(path, rows, ending="\n"):
        path.write_bytes("".join(json.dumps(row) + ending for row in rows).encode("utf-8"))

    def test_comparison_requires_raw_lines_including_revision_and_endings(self):
        _, rows = self.sample_rows()
        self.write(self.stock, rows)
        self.write(self.candidate, rows)
        self.assertTrue(probe.compare_exports(self.stock, self.candidate)["exact_bytes"])
        rows[0]["revision"] = 4
        self.write(self.candidate, rows)
        report = probe.compare_exports(self.stock, self.candidate)
        self.assertFalse(report["exact_bytes"])
        self.assertEqual(report["differences"][0]["fields"], ["revision"])
        self.assertEqual(len(report["differences"]), 1)
        rows[0]["revision"] = 3
        self.write(self.candidate, rows, ending="\r\n")
        report = probe.compare_exports(self.stock, self.candidate)
        self.assertFalse(report["exact_bytes"])
        self.assertEqual(len(report["differences"]), 2)
        self.assertEqual(report["differences"][0]["fields"], [])

    def test_trailing_missing_and_extra_rows_keep_mismatch_diagnostics(self):
        _, rows = self.sample_rows()
        for path, other, missing in ((self.stock, self.candidate, "candidate"),
                                     (self.candidate, self.stock, "stock")):
            with self.subTest(missing=missing):
                self.write(path, rows)
                self.write(other, rows[:1])
                result = probe.compare_exports(self.stock, self.candidate)
                self.assertEqual(result["first_differing_byte"], other.stat().st_size)
                self.assertEqual(result["differences"], [{"name": rows[1]["name"],
                                 "address": rows[1]["address"], "missing_from": missing}])

    def test_coverage_tracks_native_errors_and_rejects_engine_stops(self):
        sample, rows = self.sample_rows(100)
        rows[-1].update(completed=False, c="", error="Low-level Error")
        self.write(self.stock, rows)
        report = probe.validate_export(self.stock, sample, self.base, self.identity)
        self.assertEqual(report["completed"], 99)
        self.assertEqual(report["incomplete"][0]["error"], "Low-level Error")
        rows[-1]["timed_out"] = True
        self.write(self.stock, rows)
        with self.assertRaisesRegex(ValueError, "timed-out"):
            probe.validate_export(self.stock, sample, self.base, self.identity)

    def test_coverage_rejects_reordering_wrong_identity_and_empty_results(self):
        sample, rows = self.sample_rows()
        self.write(self.stock, rows[::-1])
        with self.assertRaisesRegex(ValueError, "entries or order"):
            probe.validate_export(self.stock, sample, self.base, self.identity)
        self.write(self.stock, rows)
        with self.assertRaisesRegex(ValueError, "identity"):
            probe.validate_export(self.stock, sample, self.base, "c" * 64)
        rows[0].update(completed=False, c="", error="Low-level Error")
        self.write(self.stock, rows)
        with self.assertRaisesRegex(ValueError, "fewer than 99%"):
            probe.validate_export(self.stock, sample, self.base, self.identity)

    def test_stock_verified_sidecar_accounts_for_all_published_rows(self):
        path = Path(f"{self.candidate}.parity.json")
        self.write(self.candidate, self.sample_rows()[1])
        summary = {"function_count": 2, "reference": "stock-reused-serial",
                   "scheduled_matches": 1, "stock_fallbacks": 1,
                   "admitted_workers": 2, "candidate_workers": 1, "peak_running": 2,
                   "reference_watched_leases": 2, "execution": "overlapped",
                   "candidate_cache": {"enabled": False}, "candidate_compute_leases": 2,
                   "output_sha256": probe.sha256(self.candidate)}
        path.write_text(json.dumps(summary), encoding="utf-8")
        self.assertEqual(probe.validate_candidate("stock-verified", self.candidate, 2, 2), summary)
        for update in ({"candidate_cache": {"enabled": True}}, {"candidate_compute_leases": 1}):
            path.write_text(json.dumps(summary | update), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "one uncached candidate lease"):
                probe.validate_candidate("stock-verified", self.candidate, 2, 2)
        path.write_text(json.dumps(summary | {"peak_running": 1}), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "must exercise overlapping"):
            probe.validate_candidate("stock-verified", self.candidate, 2, 2, require_overlap=True)
        summary["stock_fallbacks"] = 0
        path.write_text(json.dumps(summary), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "cover every prepared function"):
            probe.validate_candidate("stock-verified", self.candidate, 2, 2)

        summary["stock_fallbacks"] = 1
        path.write_text(json.dumps(summary), encoding="utf-8")
        rows = self.sample_rows()[1]
        rows[0]["revision"] = 4
        self.write(self.candidate, rows)
        with self.assertRaisesRegex(ValueError, "digest differs"):
            probe.validate_candidate("stock-verified", self.candidate, 2, 2)

    def test_reference_coverage_and_total_admission_include_both_lanes(self):
        self.write(self.candidate, self.sample_rows()[1])
        audit = {"function_count": 2, "reference": "stock-reused-serial", "scheduled_matches": 2,
                 "stock_fallbacks": 0, "output_sha256": probe.sha256(self.candidate)}
        overlap = dict(audit, admitted_workers=2, candidate_workers=1, reference_watched_leases=2,
                       peak_running=2, execution="overlapped")
        sequential = dict(audit, admitted_workers=1, candidate_workers=1, reference_watched_leases=2,
                          peak_running=1, execution="sequential", fallback_reason="single_worker")
        for update in ({"admitted_workers": 3}, {"candidate_workers": 2}, {"peak_running": 3},
                       {"peak_running": False}, {"peak_running": 0}, {"reference_watched_leases": 1},
                       {"execution": "sequential"}, {"function_count": True},
                       {"fallback_reason": "single_worker"}):
            with self.subTest(update=update), self.assertRaises(ValueError):
                probe.validate_stock_audit(overlap | update, self.candidate, 2, 2)
        # A constrained host can admit just one of two requested slots.
        probe.validate_stock_audit(sequential, self.candidate, 2, 2)
        # A compatible open session lends a worker while keeping its entire candidate pool.
        shared = sequential | {"admitted_workers": 2, "candidate_workers": 2,
                               "fallback_reason": "shared_candidate_session"}
        probe.validate_stock_audit(shared, self.candidate, 2, 2)
        with self.assertRaisesRegex(ValueError, "invalid sequential"):
            probe.validate_stock_audit(shared | {"fallback_reason": "single_worker"}, self.candidate, 2, 2)
        Path(f"{self.candidate}.parity.json").write_text(json.dumps(sequential), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "must exercise overlapping"):
            probe.validate_candidate("stock-verified", self.candidate, 2, 2, require_overlap=True)
        for update in ({"execution": "overlapped"}, {"reference_watched_leases": 1}):
            with self.subTest(update=update), self.assertRaises(ValueError):
                probe.validate_stock_audit(sequential | update, self.candidate, 2, 2)
        # Archived pre-overlap scripts can still be compared via --candidate-scripts.
        with self.assertRaises(ValueError):
            probe.validate_stock_audit(audit, self.candidate, 2, 2)
        probe.validate_stock_audit(audit, self.candidate, 2, 2, allow_legacy=True)
        with self.assertRaises(ValueError):
            probe.validate_stock_audit(audit | {"peak_running": 2}, self.candidate, 2, 2,
                                       allow_legacy=True)
        with self.assertRaisesRegex(ValueError, "JSON object"):
            probe.validate_stock_audit([], self.candidate, 2, 2)


if __name__ == "__main__":
    unittest.main()
