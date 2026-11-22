#!/usr/bin/env python3
# Copyright 2026 YurilLAB
# SPDX-License-Identifier: Apache-2.0
"""Measure offline calibration of proposal scores against a family-disjoint oracle."""

from __future__ import annotations

import argparse
from bisect import bisect_right
from collections import Counter, defaultdict
from dataclasses import dataclass
import json
import math
from pathlib import Path
import random
import re
from statistics import mean
import sys

from bounded_io import read_limited

SCHEMA_VERSION = 1
MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_JSON_DEPTH = 32
MAX_CASES = 20_000
MAX_PROPOSALS = 60_000
MAX_KINDS = 32
BIN_COUNT = 10
BIN_EDGES = tuple(index / BIN_COUNT for index in range(1, BIN_COUNT))
MIN_FIT_FAMILIES = 5
MIN_FIT_LABEL_FAMILIES = 2
MIN_FIT_BIN_FAMILIES = 3
MIN_INTERVAL_FAMILIES = 8
BOOTSTRAP_REPLICATES = 399
BOOTSTRAP_SEED = 20261118
THRESHOLDS = (0.5, 0.6, 0.7, 0.8, 0.9, 0.95)
ID = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_./:-]{0,127}")
SHA256 = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class Proposal:
    score: float | None
    correct: bool


@dataclass(frozen=True)
class Case:
    family: str
    kind: str
    split: str
    proposals: tuple[Proposal, ...]


@dataclass(frozen=True)
class Scored:
    family: str
    score: float
    correct: bool


def _keys(value: object, keys: set[str], label: str) -> dict:
    if type(value) is not dict or value.keys() != keys:
        raise ValueError(f"{label} must have exactly the fields {', '.join(sorted(keys))}")
    return value


def _match(value: object, pattern: re.Pattern, label: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ValueError(f"invalid {label}")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 256 or not value.isprintable():
        raise ValueError(f"invalid {label}")
    return value


def _bind(values: dict, key: str, expected: str, label: str) -> None:
    if values.setdefault(key, expected) != expected:
        raise ValueError(f"{label} crosses source families or partitions")


def parse_dataset(dataset: object) -> tuple[dict, list[Case]]:
    root = _keys(dataset, {"schema_version", "kinds", "cases"}, "dataset")
    if type(root["schema_version"]) is not int or root["schema_version"] != SCHEMA_VERSION:
        raise ValueError("unsupported calibration dataset schema")
    definitions, entries = root["kinds"], root["cases"]
    if type(definitions) is not dict or not 1 <= len(definitions) <= MAX_KINDS:
        raise ValueError("invalid number of proposal kinds")
    for kind, definition in definitions.items():
        _match(kind, ID, "proposal kind")
        _keys(definition, {"score_kind", "truth_rule"}, "kind definition")
        _match(definition["score_kind"], ID, "score kind")
        _text(definition["truth_rule"], "truth rule")
    if type(entries) is not list or not 1 <= len(entries) <= MAX_CASES:
        raise ValueError("invalid number of oracle cases")

    families: dict[str, str] = {}
    sources: dict[str, str] = {}
    binaries: dict[str, str] = {}
    cases: dict[str, Case] = {}
    proposal_count = 0
    for entry in entries:
        _keys(entry, {"case_id", "source_family", "source_sha256", "binary_sha256",
                      "kind", "split", "proposals"}, "case")
        case_id = _match(entry["case_id"], ID, "case ID")
        family = _match(entry["source_family"], ID, "source family")
        source = _match(entry["source_sha256"], SHA256, "source SHA-256")
        binary = _match(entry["binary_sha256"], SHA256, "binary SHA-256")
        kind = _match(entry["kind"], ID, "proposal kind")
        split = entry["split"]
        if case_id in cases or kind not in definitions or split not in ("fit", "holdout"):
            raise ValueError("duplicate case ID, undeclared kind or invalid partition")
        _bind(families, family, split, "source family")
        _bind(sources, source, family, "source SHA-256")
        _bind(binaries, binary, family, "binary SHA-256")
        observations = entry["proposals"]
        if type(observations) is not list or proposal_count + len(observations) > MAX_PROPOSALS:
            raise ValueError("invalid number of proposals")
        proposal_count += len(observations)
        proposals: dict[str, Proposal] = {}
        for observation in observations:
            _keys(observation, {"proposal_id", "score", "correct"}, "proposal")
            proposal_id = _match(observation["proposal_id"], ID, "proposal ID")
            score, correct = observation["score"], observation["correct"]
            if proposal_id in proposals or type(correct) is not bool:
                raise ValueError("duplicate proposal ID or invalid oracle verdict")
            if score is not None and (type(score) not in (int, float) or not 0 <= score <= 1):
                raise ValueError("proposal score must be finite and in [0, 1], or null")
            proposals[proposal_id] = Proposal(None if score is None else float(score), correct)
        cases[case_id] = Case(family, kind, split, tuple(proposals[key] for key in sorted(proposals)))
    return definitions, [cases[key] for key in sorted(cases)]


def _unique_keys(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _invalid_constant(_: str) -> None:
    raise ValueError("JSON non-finite number")


def _check_depth(data: bytes) -> None:
    depth = 0
    quoted = escaped = False
    quote, backslash = ord('"'), ord("\\")
    for char in data:
        if quoted:
            if escaped:
                escaped = False
            elif char == backslash:
                escaped = True
            elif char == quote:
                quoted = False
        elif char == quote:
            quoted = True
        elif char in b"[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise ValueError("input JSON is too deeply nested")
        elif char in b"]}":
            depth -= 1
            if depth < 0:
                raise ValueError("invalid JSON brackets")


def load_json(path: Path, limit: int = MAX_INPUT_BYTES) -> object:
    if not path.is_file() or not 0 < path.stat().st_size <= limit:
        raise ValueError("input must be a regular JSON file in the supported size range")
    with path.open("rb") as stream:
        data = read_limited(stream, limit + 1)
    if len(data) > limit:
        raise ValueError("input exceeded the JSON size limit while reading")
    _check_depth(data)
    return json.loads(data.decode("utf-8"), object_pairs_hook=_unique_keys,
                      parse_constant=_invalid_constant)


def _bin(score: float) -> int:
    return bisect_right(BIN_EDGES, score)


def _buckets(rows: list[Scored]) -> list[list[Scored]]:
    bins: list[list[Scored]] = [[] for _ in range(BIN_COUNT)]
    for row in rows:
        bins[_bin(row.score)].append(row)
    return bins


def _fit(rows: list[Scored]) -> tuple[dict, dict[int, float]]:
    totals = Counter(row.family for row in rows)
    true_families = len({row.family for row in rows if row.correct})
    false_families = len({row.family for row in rows if not row.correct})
    model = {"status": "insufficient_fit_support", "scored_families": len(totals),
             "correct_families": true_families, "incorrect_families": false_families,
             "bins": []}
    if len(totals) < MIN_FIT_FAMILIES or min(true_families, false_families) < MIN_FIT_LABEL_FAMILIES:
        return model, {}

    # Each family has total fit weight one per kind. One neutral pseudo-family is
    # added whose proposals fall in the bins like the fit families' own, so every
    # bin shrinks toward one half by 1 / (families + 1) and a sparse bin is not
    # pulled further than a dense one. Neighboring supported bins are pooled when
    # their estimates violate monotonicity.
    blocks: list[tuple[list[int], float, float]] = []
    details = {}
    for index, bucket in enumerate(_buckets(rows)):
        counts = Counter(row.family for row in bucket)
        if len(counts) < MIN_FIT_BIN_FAMILIES:
            continue
        correct = Counter(row.family for row in bucket if row.correct)
        observed = math.fsum(counts[family] / totals[family] for family in counts)
        mass = observed * (1 + 1 / len(totals))
        positive = (math.fsum(correct[family] / totals[family] for family in counts) +
                    0.5 * observed / len(totals))
        details[index] = {"index": index, "fit_families": len(counts), "fit_proposals": len(bucket)}
        blocks.append(([index], mass, positive))
        while len(blocks) >= 2:
            left, right = blocks[-2:]
            if left[2] / left[1] <= right[2] / right[1]:
                break
            blocks[-2:] = [(left[0] + right[0], left[1] + right[1], left[2] + right[2])]
    predictions = {index: positive / mass for indexes, mass, positive in blocks for index in indexes}
    model["bins"] = [details[index] | {"estimated_probability": predictions[index]}
                     for index in sorted(predictions)]
    model["status"] = "fit" if predictions else "insufficient_fit_bin_support"
    return model, predictions


def _family_means(rows: list[Scored], measure) -> list[float]:
    samples = defaultdict(list)
    for row in rows:
        samples[row.family].append(measure(row))
    return [mean(samples[family]) for family in sorted(samples)]


def _estimate(values: list[float]) -> dict:
    if not values:
        return {"estimate": None, "family_bootstrap_95": None}
    interval = None
    if len(values) >= MIN_INTERVAL_FAMILIES:
        randomizer = random.Random(BOOTSTRAP_SEED)
        replicates = sorted(math.fsum(randomizer.choices(values, k=len(values))) / len(values)
                            for _ in range(BOOTSTRAP_REPLICATES))
        interval = [replicates[int(0.025 * (BOOTSTRAP_REPLICATES - 1))],
                    replicates[int(0.975 * (BOOTSTRAP_REPLICATES - 1))]]
    return {"estimate": mean(values), "family_bootstrap_95": interval}


def _squared_error(row: Scored) -> float:
    return (row.score - row.correct) ** 2


def _reliability_error(rows: list[Scored]) -> float | None:
    """Expected calibration error over the fixed bins, every family weighted equally."""
    if not rows:
        return None
    totals = Counter(row.family for row in rows)
    error = 0.0
    for bucket in _buckets(rows):
        if not bucket:
            continue
        counts = Counter(row.family for row in bucket)
        weight = math.fsum(counts[family] / totals[family] for family in counts) / len(totals)
        observed = mean(_family_means(bucket, lambda row: int(row.correct)))
        predicted = mean(_family_means(bucket, lambda row: row.score))
        error += weight * abs(observed - predicted)
    return error


def _thresholds(rows: list[Scored]) -> list[dict]:
    """Precision of the proposals at or above each score, and the correct ones it keeps.

    Recall counts correct scored proposals only: fields the analysis never proposed are
    outside this dataset.
    """
    correct = Counter(row.family for row in rows if row.correct)
    result = []
    for threshold in THRESHOLDS:
        accepted = [row for row in rows if row.score >= threshold]
        kept = Counter(row.family for row in accepted if row.correct)
        precision = _family_means(accepted, lambda row: int(row.correct))
        recall = [kept[family] / correct[family] for family in sorted(correct)]
        result.append({"threshold": threshold, "accepted_proposals": len(accepted),
                       "accepted_families": len(precision), "precision": _estimate(precision),
                       "recall_of_correct_proposals": _estimate(recall)})
    return result


def _metrics(rows: list[Scored]) -> dict:
    reliability = []
    for index, bucket in enumerate(_buckets(rows)):
        observed = _family_means(bucket, lambda row: int(row.correct))
        predicted = _family_means(bucket, lambda row: row.score)
        reliability.append({"lower": index / BIN_COUNT, "upper": (index + 1) / BIN_COUNT,
                            "families": len(observed), "proposals": len(bucket),
                            "mean_score": mean(predicted) if predicted else None,
                            "observed_correct": _estimate(observed)})
    return {"proposals": len(rows), "families": len({row.family for row in rows}),
            "brier": _estimate(_family_means(rows, _squared_error)),
            "reliability_error": _reliability_error(rows), "thresholds": _thresholds(rows),
            "reliability": reliability}


def _scored(cases: list[Case]) -> list[Scored]:
    return [Scored(case.family, proposal.score, proposal.correct)
            for case in cases for proposal in case.proposals if proposal.score is not None]


def _counts(cases: list[Case], predictions: dict[int, float]) -> dict:
    predicted = [sum(proposal.score is not None and _bin(proposal.score) in predictions
                     for proposal in case.proposals) for case in cases]
    cases_with_proposals = sum(bool(case.proposals) for case in cases)
    return {"cases": len(cases), "families": len({case.family for case in cases}),
            "cases_with_proposals": cases_with_proposals,
            "cases_without_proposals": len(cases) - cases_with_proposals,
            "case_proposal_coverage": cases_with_proposals / len(cases) if cases else None,
            "proposals": sum(len(case.proposals) for case in cases),
            "scored_proposals": sum(proposal.score is not None for case in cases
                                    for proposal in case.proposals),
            "cases_with_calibration_predictions": sum(count > 0 for count in predicted),
            "calibration_predictions": sum(predicted)}


def evaluate(dataset: object) -> dict:
    definitions, cases = parse_dataset(dataset)
    reports = {}
    for kind, definition in sorted(definitions.items()):
        fit = [case for case in cases if case.kind == kind and case.split == "fit"]
        holdout = [case for case in cases if case.kind == kind and case.split == "holdout"]
        model, predictions = _fit(_scored(fit))
        raw = _scored(holdout)
        paired = [row for row in raw if _bin(row.score) in predictions]
        calibrated = [Scored(row.family, predictions[_bin(row.score)], row.correct) for row in paired]
        calibration_metrics = _metrics(calibrated)
        status = "insufficient_holdout_predictions"
        if calibrated:
            status = ("evaluated" if calibration_metrics["families"] >= MIN_INTERVAL_FAMILIES
                      else "descriptive_only")
        reports[kind] = definition | {
            "model": model, "fit": _counts(fit, predictions),
            "holdout": _counts(holdout, predictions) | {
                "status": status,
                "paired_score_coverage": len(paired) / len(raw) if raw else None,
                "raw_diagnostic": _metrics(raw),
                "calibrated": calibration_metrics,
                "paired_raw_brier": _estimate(_family_means(paired, _squared_error)),
            },
        }
    return {
        "schema_version": SCHEMA_VERSION,
        "purpose": "offline calibration evidence",
        "method": "equal-family weighted score bins with monotone pooling and one neutral pseudo-family",
        "minimum_fit_families": MIN_FIT_FAMILIES,
        "minimum_fit_families_per_label": MIN_FIT_LABEL_FAMILIES,
        "minimum_fit_bin_families": MIN_FIT_BIN_FAMILIES,
        "family_bootstrap": {"minimum_families": MIN_INTERVAL_FAMILIES,
                             "replicates": BOOTSTRAP_REPLICATES, "seed": BOOTSTRAP_SEED},
        "kinds": reports,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="versioned labeled cases")
    args = parser.parse_args()
    try:
        result = evaluate(load_json(args.input))
    except (OSError, ValueError) as error:
        print(f"calibration evaluation failed: {error}", file=sys.stderr)
        return 1
    json.dump(result, sys.stdout, indent=2, sort_keys=True, allow_nan=False)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
