#!/usr/bin/env python3
# Copyright 2026 YurilLAB
# SPDX-License-Identifier: Apache-2.0
"""Label layout-survey field proposals from the calibration families against DWARF.

One case is one pointer parameter that the debug file places in an argument register at the
function entry and declares as a pointer to a structure, union or class. Its proposals are the
fields the survey recovered for that register. Functions are deduplicated by identity across
every family before any case is written, and each access may support one proposal only.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

from calibrate_type_confidence import SCHEMA_VERSION, load_json, parse_dataset
from dwarf_targets import classify_range, read_dwarf_targets, target_status
from corpus_artifacts import checked_artifact_pair


KIND = "struct.field_footprint"
SCORE_KIND = "uncalibrated_evidence_strength"
DEFINITION = {
    "score_kind": SCORE_KIND,
    "truth_rule": "Byte range is exactly one declared member, array element or base subobject "
                  "of the DWARF pointee type.",
}
SURVEY_MODE = "read_only_layout_survey"
DEFAULT_SPACE = "ram"
MAX_SURVEY_BYTES = 256 * 1024 * 1024
MAX_ARTIFACTS = 256
MAX_FUNCTIONS = 65_536
MAX_PARAMETERS = 8
MAX_FIELDS = 4_096
MAX_EXTENT = 1 << 32
ID = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")
ARTIFACT_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,31}/O[0-3]/[a-z0-9][a-z0-9-]{0,31}")
HEX = re.compile(r"[0-9a-f]{1,16}")
SHA256 = re.compile(r"[0-9a-f]{64}")
REGISTER = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,15}")


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _integer(value: object, minimum: int, maximum: int, label: str) -> int:
    _require(type(value) is int and minimum <= value <= maximum, f"invalid {label}")
    return value


def _hex(value: object, label: str) -> int:
    _require(isinstance(value, str) and HEX.fullmatch(value) is not None, f"invalid {label}")
    return int(value, 16)


def survey_name(artifact_id: str) -> str:
    return artifact_id.replace("/", "-") + ".survey.json"


def _identity(function: dict) -> str | None:
    """The instructions with linked addresses masked, else the exact body bytes."""
    for key, label in (("code_sha256", "code"), ("body_sha256", "body")):
        value = function.get(key)
        if value is not None:
            _require(isinstance(value, str) and SHA256.fullmatch(value) is not None,
                     f"invalid {label} digest")
            return f"{label}:{value}"
    return None


def _fields(parameter: dict, evidence: set[str]) -> list[dict]:
    layout = parameter.get("layout")
    if layout is None:
        return []
    _require(type(layout) is dict and type(layout.get("fields")) is list and
             len(layout["fields"]) <= MAX_FIELDS, "invalid surveyed layout")
    prefix = parameter["object_id"] + "/"
    fields, ranges = [], set()
    for field in layout["fields"]:
        _require(type(field) is dict, "invalid surveyed field")
        offset = _integer(field.get("offset"), 0, MAX_EXTENT - 1, "field offset")
        width = _integer(field.get("width"), 1, MAX_EXTENT - offset, "field width")
        cited = field.get("evidence_ids")
        _require(type(cited) is list and cited and len(set(map(str, cited))) == len(cited),
                 "field evidence must be nonempty and unique")
        for identity in cited:
            _require(isinstance(identity, str) and identity.startswith(prefix) and
                     len(identity) <= 512, "field cites evidence from another object")
            # Each access is an origin: it may support one proposal in the whole report.
            _require(identity not in evidence, "one access supports several proposals")
            evidence.add(identity)
        score = field.get("evidence_strength")
        _require(type(score) in (int, float) and score == len(cited) / (len(cited) + 1),
                 "field score disagrees with the documented evidence-strength formula")
        _require((offset, width) not in ranges, "duplicate surveyed field")
        ranges.add((offset, width))
        fields.append({"offset": offset, "width": width, "score": score})
    return fields


def parse_survey(report: object, binary_sha256: str) -> dict:
    """Validates one survey report and indexes its functions by entry address."""
    _require(type(report) is dict, "survey report must be an object")
    _require(type(report.get("schema_version")) is int and report["schema_version"] == 1 and
             report.get("analysis_mode") == SURVEY_MODE and report.get("score_kind") == SCORE_KIND and
             type(report.get("follow_depth")) is int and report["follow_depth"] == 0,
             "survey report has the wrong schema, mode or score semantics")
    _require(report.get("program_id") == "sha256:" + binary_sha256,
             "survey report describes a different Program")
    base = _hex(report.get("image_base"), "image base")
    original = report.get("original_image_base")
    _require(original is not None, "survey report lacks the original ELF image base")
    functions = report.get("functions")
    _require(type(functions) is list and len(functions) <= MAX_FUNCTIONS, "invalid function list")
    evidence: set[str] = set()
    indexed: dict[int, dict] = {}
    for function in functions:
        _require(type(function) is dict and isinstance(function.get("address_space"), str),
                 "invalid surveyed function")
        address = _hex(function.get("address"), "function address")
        status = function.get("status")
        _require(status in ("surveyed", "refused"), "invalid survey status")
        parameters = function.get("parameters")
        _require(type(parameters) is list and len(parameters) <= MAX_PARAMETERS and
                 (status == "surveyed" or not parameters), "invalid surveyed parameters")
        by_register: dict[str, list[dict]] = {}
        slots = set()
        for parameter in parameters:
            _require(type(parameter) is dict and isinstance(parameter.get("object_id"), str),
                     "invalid surveyed parameter")
            slot = _integer(parameter.get("index"), 0, MAX_PARAMETERS - 1, "parameter index")
            register = parameter.get("register")
            _require(isinstance(register, str) and REGISTER.fullmatch(register) is not None and
                     register not in by_register and slot not in slots,
                     "duplicate or invalid parameter register")
            slots.add(slot)
            by_register[register] = _fields(parameter, evidence)
        if function["address_space"] != DEFAULT_SPACE:
            continue
        _require(address not in indexed, "duplicate surveyed function")
        indexed[address] = {"status": status, "identity": _identity(function),
                            "parameters": by_register}
    return {"bias": base - _hex(original, "original image base"), "functions": indexed}


def _count(table: dict, key: str, amount: int = 1) -> None:
    table[key] = table.get(key, 0) + amount


def stage(manifest_path: Path, surveys: Path) -> tuple[dict, dict]:
    """Returns the calibration dataset and a summary of every exclusion."""
    manifest = load_json(manifest_path)
    _require(type(manifest) is dict and manifest.get("schema_version") == 1 and
             manifest.get("kind") == "calibration-families" and manifest.get("status") == "passed",
             "family build did not pass")
    artifacts = manifest.get("artifacts")
    _require(type(artifacts) is list and 0 < len(artifacts) <= MAX_ARTIFACTS, "invalid artifact list")
    root = manifest_path.resolve(strict=True).parent
    seen: set[str] = set()
    for artifact in artifacts:
        _require(type(artifact) is dict and isinstance(artifact.get("id"), str) and
                 ARTIFACT_ID.fullmatch(artifact["id"]) is not None and artifact["id"] not in seen,
                 "duplicate or invalid artifact ID")
        seen.add(artifact["id"])
        _require(isinstance(artifact.get("family"), str) and ID.fullmatch(artifact["family"]) is not None
                 and artifact["id"].endswith("/" + artifact["family"]) and
                 artifact.get("split") in ("fit", "holdout") and artifact.get("format") == "ELF64",
                 "invalid family artifact")

    cases: list[dict] = []
    families: dict[str, dict] = {}
    claimed: dict[str, str] = {}
    # Sorted order decides which copy of a duplicated function is kept.
    for artifact in sorted(artifacts, key=lambda row: row["id"]):
        _, debug = checked_artifact_pair(root, artifact)
        survey = parse_survey(load_json(surveys / survey_name(artifact["id"]), MAX_SURVEY_BYTES),
                              artifact["binary_sha256"])
        # The survey file is complete: Ghidra has exited before the debug file is opened.
        oracle = read_dwarf_targets(debug)
        types = oracle["types"]
        summary = families.setdefault(artifact["family"], {
            "split": artifact["split"], "artifacts": 0, "subprograms_with_code": 0,
            "oracle_functions": 0, "surveyed_functions": 0, "cases": 0, "cases_with_proposals": 0,
            "proposals": 0, "correct_proposals": 0, "excluded_functions": {},
            "excluded_targets": {}, "abstentions": {}, "excluded_proposals": {}})
        summary["artifacts"] += 1
        summary["subprograms_with_code"] += oracle["subprograms_with_code"]
        summary["oracle_functions"] += len(oracle["functions"])
        summary["surveyed_functions"] += len(survey["functions"])
        for reason, count in oracle["excluded"].items():
            _count(summary["excluded_functions"], reason, count)
        for function in oracle["functions"]:
            address = function["low_pc"] + survey["bias"]
            surveyed = survey["functions"].get(address)
            if surveyed is not None:
                identity = surveyed["identity"]
                if identity is None:
                    _count(summary["excluded_functions"], "function has no identity")
                    continue
                owner = claimed.setdefault(identity, f"{artifact['id']}/{address:x}")
                if owner != f"{artifact['id']}/{address:x}":
                    _count(summary["excluded_functions"], "duplicate of a function kept elsewhere")
                    continue
            for parameter in function["parameters"]:
                reason = target_status(types, parameter["type"])
                if reason is not None:
                    _count(summary["excluded_targets"], reason)
                    continue
                proposals = []
                if surveyed is None:
                    _count(summary["abstentions"], "no function at the entry address")
                elif surveyed["status"] != "surveyed":
                    _count(summary["abstentions"], "function refused by the survey")
                elif parameter["register"] not in surveyed["parameters"]:
                    _count(summary["abstentions"], "register is not a surveyed parameter")
                else:
                    for field in surveyed["parameters"][parameter["register"]]:
                        verdict = classify_range(types, parameter["type"], field["offset"],
                                                 field["width"])
                        if verdict not in ("member", "none"):
                            _count(summary["excluded_proposals"], verdict + " storage")
                            continue
                        proposals.append({"proposal_id": f"bytes:{field['offset']}:{field['width']}",
                                          "score": field["score"], "correct": verdict == "member"})
                    if not proposals:
                        _count(summary["abstentions"], "no scorable field proposal")
                summary["cases"] += 1
                summary["cases_with_proposals"] += bool(proposals)
                summary["proposals"] += len(proposals)
                summary["correct_proposals"] += sum(item["correct"] for item in proposals)
                cases.append({
                    "case_id": f"{artifact['id']}/{address:x}/{parameter['register']}",
                    "source_family": artifact["family"], "source_sha256": artifact["source_sha256"],
                    "binary_sha256": artifact["binary_sha256"], "split": artifact["split"],
                    "kind": KIND, "proposals": proposals})
    dataset = {"schema_version": SCHEMA_VERSION, "kinds": {KIND: DEFINITION}, "cases": cases}
    parse_dataset(dataset)
    return dataset, {"schema_version": 1, "families": dict(sorted(families.items()))}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True, help="family build manifest")
    parser.add_argument("--surveys", type=Path, required=True, help="directory of survey reports")
    parser.add_argument("--summary", type=Path, help="write exclusion counts to this file")
    args = parser.parse_args()
    try:
        dataset, summary = stage(args.manifest, args.surveys.resolve())
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RuntimeError) as error:
        print(f"family calibration staging failed: {error}", file=sys.stderr)
        return 1
    if args.summary:
        args.summary.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    json.dump(dataset, sys.stdout, indent=2, sort_keys=True, allow_nan=False)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
