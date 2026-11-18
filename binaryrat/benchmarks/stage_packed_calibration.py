#!/usr/bin/env python3
# Copyright 2026 YurilLAB
# SPDX-License-Identifier: Apache-2.0
"""Stage independently verified PackedRecord byte-layout evidence as one source family."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import sys

from calibrate_type_confidence import SCHEMA_VERSION, load_json, parse_dataset
from verify_type_accuracy import (
    FUNCTION,
    PROJECT,
    checked_artifact_pair,
    digest,
    footprint,
    oracle_layout,
    verified_fields,
)


FAMILY = "binaryrat-packed-record"
KIND = "struct.field_footprint"
SCORE_KIND = "uncalibrated_evidence_strength"
MAX_FIXTURES = 128
DEFINITION = {
    "score_kind": SCORE_KIND,
    "truth_rule": "Byte offset and width match a declared PackedRecord field in separate DWARF or PDB.",
}


def _evidence_path(parent: Path, name: str) -> Path:
    if not isinstance(name, str) or not name.endswith(".layout.json") or Path(name).name != name:
        raise ValueError("invalid layout evidence filename")
    evidence = (parent / name).resolve(strict=True)
    if evidence.parent != parent:
        raise ValueError("layout evidence must be inside the accuracy report directory")
    return evidence


def stage(manifest_path: Path, report_path: Path, fixture_source: Path,
          split: str, pdbutil: str) -> dict:
    manifest = load_json(manifest_path)
    report = load_json(report_path)
    if (manifest["schema_version"] != 1 or manifest["status"] != "passed" or
            report["schema_version"] != 1 or not 0 < len(report["fixtures"]) <= MAX_FIXTURES):
        raise ValueError("invalid corpus manifest or layout accuracy report")
    artifacts = {row["id"]: row for row in manifest["artifacts"]}
    if len(artifacts) != len(manifest["artifacts"]):
        raise ValueError("duplicate corpus artifact ID")
    root = Path(manifest["root"]).resolve(strict=True)
    source_digest = digest(fixture_source)
    cases = []
    seen = set()
    for fixture in report["fixtures"]:
        artifact = artifacts[fixture["artifact"]]
        if artifact["id"] in seen:
            raise ValueError("duplicate accuracy evidence for one corpus artifact")
        seen.add(artifact["id"])
        if (artifact["source"] != "types.c" or source_digest != artifact["source_sha256"] or
                fixture["binary_sha256"] != artifact["binary_sha256"] or
                fixture["debug_sha256"] != artifact["debug_sha256"]):
            raise ValueError("accuracy evidence does not bind to the declared corpus source and artifacts")
        _, debug = checked_artifact_pair(root, artifact)
        export = load_json(_evidence_path(report_path.parent, fixture["evidence"]))
        if (export["score_kind"] != SCORE_KIND or export["analysis_mode"] != "read_only_layout_evidence"
                or type(export["follow_depth"]) is not int or export["follow_depth"] != 0):
            raise ValueError("layout report has the wrong score semantics or analysis mode")
        fields = verified_fields(export, artifact, FUNCTION)
        actual = footprint(fields)
        if len(actual) != len(fields):
            raise ValueError("duplicate proposed field")
        oracle = oracle_layout(debug, artifact, pdbutil)
        if oracle != fixture["oracle"] or oracle["kind"] != "struct":
            raise ValueError("separate debug oracle does not reproduce the accuracy record")
        expected = footprint(oracle["members"])
        if not expected:
            raise ValueError("oracle structure has no field ranges")
        proposals = []
        for field in fields:
            key = field["offset"], field["width"]
            support = len(field["evidence_ids"])
            score = field["evidence_strength"]
            if type(score) not in (int, float) or score != support / (support + 1):
                raise ValueError("field score disagrees with the documented evidence-strength formula")
            proposals.append({"proposal_id": f"bytes:{key[0]}:{key[1]}",
                              "score": score, "correct": key in expected})
        cases.append({
            "case_id": f"{KIND}/{artifact['id']}/{artifact['binary_sha256'][:16]}",
            "source_family": FAMILY, "source_sha256": source_digest,
            "binary_sha256": artifact["binary_sha256"], "split": split,
            "kind": KIND, "proposals": proposals,
        })
    dataset = {"schema_version": SCHEMA_VERSION, "kinds": {KIND: DEFINITION}, "cases": cases}
    parse_dataset(dataset)
    return dataset


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--accuracy-report", type=Path, required=True)
    parser.add_argument("--fixture-source", type=Path,
                        default=PROJECT / "binaryrat/corpus/fixtures/types.c")
    parser.add_argument("--split", choices=("fit", "holdout"), default="holdout")
    parser.add_argument("--pdbutil", default=shutil.which("llvm-pdbutil") or "llvm-pdbutil")
    args = parser.parse_args()
    try:
        dataset = stage(args.manifest, args.accuracy_report.resolve(), args.fixture_source,
                        args.split, args.pdbutil)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RuntimeError) as error:
        print(f"calibration staging failed: {error}", file=sys.stderr)
        return 1
    json.dump(dataset, sys.stdout, indent=2, sort_keys=True, allow_nan=False)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
