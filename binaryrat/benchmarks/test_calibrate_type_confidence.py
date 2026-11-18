# Copyright 2026 YurilLAB
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import copy
import hashlib
import json
import math
from pathlib import Path
import random
import tempfile
import unittest

from calibrate_type_confidence import MAX_INPUT_BYTES, _bin, evaluate, load_json


FIELD = "struct.field_footprint"
UNION = "union.storage_views"
DEFINITIONS = {
    FIELD: {"score_kind": "uncalibrated_evidence_strength", "truth_rule": "exact byte range"},
    UNION: {"score_kind": "union_evidence_strength", "truth_rule": "declared union and matching views"},
}


def sha(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def case(name: str, split: str, rows: list[tuple[float | None, bool]], *, family: str | None = None,
         kind: str = FIELD) -> dict:
    family = family or name
    return {
        "case_id": name, "source_family": family, "source_sha256": sha(f"source:{family}"),
        "binary_sha256": sha(f"binary:{name}"), "kind": kind, "split": split,
        "proposals": [{"proposal_id": str(index), "score": score, "correct": correct}
                      for index, (score, correct) in enumerate(rows)],
    }


def dataset(cases: list[dict]) -> dict:
    return {"schema_version": 1, "kinds": copy.deepcopy(DEFINITIONS), "cases": cases}


def trained_cases() -> list[dict]:
    return [case(f"fit{i}", "fit", [(0.2, False), (0.8, True)]) for i in range(5)]


class CalibrationTests(unittest.TestCase):
    def test_family_split_rejects_compiler_variants_and_digest_aliases(self):
        first = case("gcc-O0", "fit", [], family="types")
        for reason, second in (
            ("source family", case("gcc-O3", "holdout", [], family="types")),
            ("source SHA-256", case("gcc-O3", "holdout", []) | {"source_sha256": first["source_sha256"]}),
            ("binary SHA-256", case("gcc-O3", "holdout", []) | {"binary_sha256": first["binary_sha256"]}),
        ):
            with self.subTest(reason=reason), self.assertRaisesRegex(ValueError, reason):
                evaluate(dataset([first, second]))

    def test_fit_predictions_depend_only_on_fit_partition(self):
        holdout = [case(f"holdout{i}", "holdout", [(0.2, False), (0.8, True)]) for i in range(8)]
        data = dataset(trained_cases() + holdout)
        first = evaluate(data)["kinds"][FIELD]
        bins = first["model"]["bins"]
        self.assertEqual([item["index"] for item in bins], [2, 8])
        self.assertAlmostEqual(bins[0]["estimated_probability"], 1 / 7)
        self.assertAlmostEqual(bins[1]["estimated_probability"], 6 / 7)
        self.assertAlmostEqual(first["holdout"]["calibrated"]["brier"]["estimate"], 1 / 49)
        self.assertAlmostEqual(first["holdout"]["paired_raw_brier"]["estimate"], 0.04)
        self.assertEqual(first["holdout"]["paired_score_coverage"], 1)
        for entry in holdout:
            for proposal in entry["proposals"]:
                proposal["correct"] = not proposal["correct"]
        second = evaluate(data)["kinds"][FIELD]
        self.assertEqual(first["model"], second["model"])
        self.assertAlmostEqual(second["holdout"]["calibrated"]["brier"]["estimate"], 36 / 49)

    def test_monotonic_pooling_and_sparse_bin_abstention(self):
        fit = [case(f"fit{i}", "fit", [(0.21, True), (0.81, False)]) for i in range(5)]
        fit[0]["proposals"].append({"proposal_id": "sparse", "score": 0.54, "correct": True})
        holdout = case("held", "holdout", [(0.2, False), (0.5, True), (0.8, True), (0.99, True)])
        result = evaluate(dataset(fit + [holdout]))["kinds"][FIELD]
        self.assertEqual([item["index"] for item in result["model"]["bins"]], [2, 8])
        low, high = [item["estimated_probability"] for item in result["model"]["bins"]]
        self.assertEqual(low, high)
        self.assertEqual(result["holdout"]["paired_score_coverage"], 0.5)
        self.assertEqual(result["holdout"]["calibration_predictions"], 2)
        self.assertAlmostEqual(result["holdout"]["paired_raw_brier"]["estimate"], 0.04)
        self.assertNotEqual(result["holdout"]["raw_diagnostic"]["brier"]["estimate"],
                            result["holdout"]["paired_raw_brier"]["estimate"])

    def test_family_balance_and_separate_kind_coverage(self):
        inputs = [case(f"gcc-O{i}", "holdout", [(1, False)], family="duplicated")
                  for i in range(12)] + [
            case("other", "holdout", [(1, True)]),
            case("abstains", "holdout", [], kind=UNION),
            case("unscored", "holdout", [(None, True)], kind=UNION),
        ]
        report = evaluate(dataset(inputs))["kinds"]
        held = report[FIELD]["holdout"]
        self.assertEqual(held["raw_diagnostic"]["brier"], {"estimate": 0.5, "family_bootstrap_95": None})
        self.assertEqual(held["raw_diagnostic"]["reliability"][-1]["observed_correct"]["estimate"],
                         0.5)
        self.assertEqual(held["raw_diagnostic"]["families"], 2)
        self.assertEqual(held["raw_diagnostic"]["proposals"], 13)
        union = report[UNION]["holdout"]
        self.assertEqual(union["case_proposal_coverage"], 0.5)
        self.assertEqual(union["cases_without_proposals"], 1)
        self.assertEqual(union["cases_with_calibration_predictions"], 0)
        self.assertIsNone(union["paired_score_coverage"])

    def test_bootstrap_requires_families_and_is_input_order_independent(self):
        varied = [case(f"holdout{i}", "holdout", [(0.8, i % 3 != 0), (0.2, i % 2 != 0)])
                  for i in range(8)]
        original = trained_cases() + varied
        report = evaluate(dataset(original))
        interval = report["kinds"][FIELD]["holdout"]["calibrated"]["brier"]["family_bootstrap_95"]
        self.assertLess(interval[0], interval[1])
        reversed_input = copy.deepcopy(list(reversed(original)))
        for entry in reversed_input:
            entry["proposals"].reverse()
        self.assertEqual(report, evaluate(dataset(reversed_input)))
        seven = evaluate(dataset(trained_cases() + varied[:7]))["kinds"][FIELD]["holdout"]
        self.assertIsNone(seven["calibrated"]["brier"]["family_bootstrap_95"])

    def test_requires_both_outcomes_on_independent_fit_families(self):
        fit = [case(f"fit{i}", "fit", [(0.5, True)]) for i in range(5)]
        held = case("held", "holdout", [(0.5, False)])
        result = evaluate(dataset(fit + [held]))["kinds"][FIELD]
        self.assertEqual(result["model"]["status"], "insufficient_fit_support")
        self.assertIsNone(result["holdout"]["calibrated"]["brier"]["estimate"])

    def test_score_boundaries_and_malformed_case_rejection(self):
        for score, expected in ((0, 0), (1, 9), (0.7, 7), (math.nextafter(0.7, 0), 6)):
            self.assertEqual(_bin(score), expected)
        for score, verdict in ((math.nan, True), (math.inf, False), (-0.01, True), (True, True),
                               (1.01, False), (0.5, 1)):
            with self.subTest(score=score, verdict=verdict), self.assertRaises(ValueError):
                evaluate(dataset([case("invalid", "fit", [(score, verdict)])]))
        duplicate = case("duplicate", "fit", [(0.5, True)])
        duplicate["proposals"] *= 2
        with self.assertRaisesRegex(ValueError, "duplicate proposal"):
            evaluate(dataset([duplicate]))

    def test_reader_checks_schema_and_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            input_file = Path(directory) / "scores.json"
            for data in ('{"dup":1,"dup":2}', '{"score":NaN}', "[" * 2000 + "]" * 2000):
                input_file.write_text(data, encoding="utf-8")
                with self.assertRaises(ValueError):
                    load_json(input_file)
            with input_file.open("wb") as stream:
                stream.truncate(MAX_INPUT_BYTES + 1)
            with self.assertRaisesRegex(ValueError, "size"):
                load_json(input_file)
            payload = dataset([case("holdout", "holdout", [])])
            input_file.write_text(json.dumps(payload), encoding="utf-8")
            self.assertEqual(load_json(input_file), payload)

    def test_seeded_metrics_never_leave_probability_or_coverage_bounds(self):
        rng = random.Random(20261118)
        for count in range(1, 21):
            cases = trained_cases()
            for index in range(count):
                rows = [(rng.random(), bool(rng.getrandbits(1))) for _ in range(rng.randrange(8))]
                cases.append(case(f"holdout{index}", "holdout", rows, family=f"project{index % 9}"))
            result = evaluate(dataset(cases))["kinds"][FIELD]["holdout"]
            self.assertGreaterEqual(result["case_proposal_coverage"], 0)
            self.assertLessEqual(result["case_proposal_coverage"], 1)
            for name in ("raw_diagnostic", "calibrated"):
                value = result[name]["brier"]["estimate"]
                if value is not None:
                    self.assertLessEqual(0, value)
                    self.assertLessEqual(value, 1)
                self.assertEqual(sum(bin["proposals"] for bin in result[name]["reliability"]),
                                 result[name]["proposals"])


if __name__ == "__main__":
    unittest.main()
