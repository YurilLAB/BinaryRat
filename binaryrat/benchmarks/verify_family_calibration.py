#!/usr/bin/env python3
# Copyright 2026 YurilLAB
# SPDX-License-Identifier: Apache-2.0
"""Survey every calibration family in Ghidra and measure score calibration on held-out families."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import tempfile

from calibrate_type_confidence import evaluate as evaluate_calibration
from corpus_artifacts import checked_artifact_pair, digest
from stage_family_calibration import KIND, stage, survey_name
from verify_ghidra import PROJECT, measured_run
from verify_type_accuracy import json_file


MINIMUM_HOLDOUT_FAMILIES = 5
CROSS_CHECK_TARGETS = 8


def run_survey(launcher: Path, binary: Path, output: Path, log: Path, timeout: int,
               environment: dict[str, str]) -> dict:
    output.unlink(missing_ok=True)
    with tempfile.TemporaryDirectory(prefix="family survey ", dir=log.parent) as directory:
        measured = measured_run([
            str(launcher), directory, "family", "-import", str(binary), "-readOnly",
            "-scriptPath", str(PROJECT / "binaryrat/bridge/ghidra_scripts"),
            "-postScript", "BinaryRatSurveyLayouts.java", str(output), "30", str(timeout),
            "-deleteProject",
        ], log, timeout, environment)
    log_text = log.read_text(encoding="utf-8", errors="replace")
    if measured["returncode"] or "REPORT SCRIPT ERROR" in log_text or not output.is_file():
        raise RuntimeError(f"Ghidra did not produce the layout survey (see {log})")
    return measured


def cross_check_targets(survey: dict) -> list[tuple[str, int, list[dict]]]:
    """The surveyed parameters with the most fields: (entry, slot, fields), in a fixed order."""
    candidates = []
    for function in survey["functions"]:
        for parameter in function["parameters"]:
            fields = (parameter["layout"] or {}).get("fields", [])
            if fields and function["address_space"] == "ram":
                candidates.append((-len(fields), function["address"], parameter["index"], fields))
    return [(address, slot, fields) for _, address, slot, fields in
            sorted(candidates, key=lambda item: item[:3])[:CROSS_CHECK_TARGETS]]


def compare_layout(single: dict, survey: dict, address: str, slot: int, fields: list[dict]) -> None:
    """Requires the single-parameter extractor to report exactly the surveyed fields."""
    if (single["program_id"] != survey["program_id"] or
            single["function"]["address"] != address or single["parameter_index"] != slot or
            single["follow_depth"] != 0 or single["score_kind"] != survey["score_kind"]):
        raise RuntimeError(f"layout report for {address} parameter {slot} describes another target")
    layouts = single["layouts"]
    if len(layouts) != 1:
        raise RuntimeError(f"expected one layout for {address} parameter {slot}")
    key = lambda field: (field["offset"], field["width"], field["evidence_strength"],
                         field["evidence_ids"])
    if [key(field) for field in layouts[0]["fields"]] != [key(field) for field in fields]:
        raise RuntimeError(f"survey and single-parameter layouts differ for {address} parameter {slot}")


def cross_check(launcher: Path, binary: Path, survey_path: Path, timeout: int,
                environment: dict[str, str]) -> dict:
    """Runs the analyst's single-parameter extractor on surveyed targets and compares.

    The same session asks for two surveys that must be refused without writing anything: one
    over its function limit, and one whose destination already exists.
    """
    survey = json_file(survey_path)
    targets = cross_check_targets(survey)
    if not targets:
        raise RuntimeError("the survey has no parameter with fields to cross-check")
    log = survey_path.with_suffix(".cross-check.log")
    published = digest(survey_path)
    with tempfile.TemporaryDirectory(prefix="family cross-check ", dir=log.parent) as directory:
        outputs = [Path(directory) / f"layout-{index}.json" for index in range(len(targets))]
        limited = Path(directory) / "limited-survey.json"
        extraction = ["-postScript", "BinaryRatSurveyLayouts.java", str(limited), "30", "600", "1",
                      "-postScript", "BinaryRatSurveyLayouts.java", str(survey_path)]
        for output, (address, slot, _) in zip(outputs, targets):
            extraction.extend(["-postScript", "BinaryRatRecoverLayouts.java", str(output),
                               address, str(slot), "60", "0"])
        measured = measured_run([
            str(launcher), directory, "family", "-import", str(binary), "-readOnly",
            "-scriptPath", str(PROJECT / "binaryrat/bridge/ghidra_scripts"),
            *extraction, "-deleteProject",
        ], log, timeout, environment)
        log_text = log.read_text(encoding="utf-8", errors="replace")
        if (measured["returncode"] or log_text.count("REPORT SCRIPT ERROR") != 2 or
                "layout survey exceeds the function limit of 1" not in log_text or
                "layout survey destination already exists" not in log_text or
                limited.exists() or digest(survey_path) != published):
            raise RuntimeError(f"a survey that must be refused was not refused cleanly (see {log})")
        if any(not output.is_file() for output in outputs):
            raise RuntimeError(f"Ghidra did not produce the cross-check layouts (see {log})")
        for output, (address, slot, fields) in zip(outputs, targets):
            compare_layout(json_file(output), survey, address, slot, fields)
    return {"passed": True, "refused_surveys": 2,
            "targets": [{"address": address, "parameter_index": slot, "fields": len(fields)}
                        for address, slot, fields in targets]}


def check(report: dict, summary: dict) -> list[str]:
    """Structural requirements of the measurement. Accuracy itself is reported, not gated."""
    problems = []
    families = summary["families"]
    for name, family in families.items():
        if not family["surveyed_functions"] or not family["cases"]:
            problems.append(f"{name}: no surveyed function or no oracle case")
    scored = {name for name, family in families.items() if family["proposals"]}
    held = {name for name in scored if families[name]["split"] == "holdout"}
    if len(held) < MINIMUM_HOLDOUT_FAMILIES:
        problems.append(f"only {len(held)} held-out families have scored proposals")
    result = report["kinds"][KIND]
    if result["model"]["status"] != "fit":
        problems.append(f"calibration model was not fitted: {result['model']['status']}")
    if result["holdout"]["status"] not in ("evaluated", "descriptive_only"):
        problems.append(f"held-out evaluation failed: {result['holdout']['status']}")
    if result["holdout"]["calibrated"]["families"] < MINIMUM_HOLDOUT_FAMILIES:
        problems.append("fewer than five held-out families received calibrated estimates")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for argument in ("ghidra", "engine", "families", "output"):
        parser.add_argument("--" + argument, required=True, type=Path)
    parser.add_argument("--timeout", type=int, default=900, help="seconds per family binary")
    parser.add_argument("--reuse", action="store_true",
                        help="keep survey reports already in the output directory")
    args = parser.parse_args()
    if not 1 <= args.timeout <= 14_400:
        parser.error("timeout must be in [1, 14400] seconds")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    manifest_path = args.families.resolve(strict=True)
    manifest = json_file(manifest_path)
    if manifest.get("kind") != "calibration-families" or manifest.get("status") != "passed":
        raise ValueError("family build did not pass")
    root = manifest_path.parent

    ghidra = args.ghidra.resolve(strict=True)
    properties = (ghidra / "Ghidra/application.properties").read_text(encoding="utf-8")
    if "application.version=12.2" not in properties.splitlines():
        raise ValueError("this verifier requires Ghidra 12.2")
    launcher = ghidra / "support" / ("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
    engine = args.engine.resolve(strict=True)
    if not engine.is_file():
        raise ValueError("native engine executable is missing")
    environment = {key: value for key, value in os.environ.items() if not key.startswith("BINARYRAT_")}
    environment.update(BINARYRAT_ENGINE=str(engine), GHIDRA_HEADLESS_MAXMEM="2G")

    report: dict = {"schema_version": 1, "passed": False, "surveys": [],
                    "scope": "Local field footprints for pointer parameters of twelve source families",
                    "limitations": [
                        "x86-64 ELF shared objects from one compiler and optimization level.",
                        "Byte offsets and widths only. No names or member types are scored.",
                        "Recall counts proposed fields; fields the code never touches are not cases.",
                        "Bit-field storage and layouts with virtual bases are excluded and counted."]}
    try:
        for artifact in sorted(manifest["artifacts"], key=lambda row: row["id"]):
            # Only the stripped binary reaches Ghidra; staging opens the debug file afterwards.
            binary, _ = checked_artifact_pair(root, artifact)
            destination = output / survey_name(artifact["id"])
            record = {"artifact": artifact["id"], "report": destination.name}
            if not (args.reuse and destination.is_file()):
                record["measured"] = run_survey(launcher, binary, destination,
                                                destination.with_suffix(".log"), args.timeout,
                                                environment)
            report["surveys"].append(record)
            print(f"{artifact['id']}: surveyed", flush=True)
            if "cross_check" not in report and not args.reuse:
                report["cross_check"] = cross_check(launcher, binary, destination, args.timeout,
                                                    environment) | {"artifact": artifact["id"]}
                print(f"{artifact['id']}: survey equals the single-parameter extractor on "
                      f"{len(report['cross_check']['targets'])} targets", flush=True)
        dataset, summary = stage(manifest_path, output)
        (output / "cases.json").write_text(json.dumps(dataset, sort_keys=True) + "\n", encoding="utf-8")
        calibration = evaluate_calibration(dataset)
        report["staging"] = summary
        report["calibration"] = calibration
        problems = check(calibration, summary)
        if problems:
            raise RuntimeError("; ".join(problems))
        report["passed"] = True
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    held = calibration["kinds"][KIND]["holdout"]
    for label, metrics in (("raw", held["raw_diagnostic"]), ("calibrated", held["calibrated"])):
        print(f"held-out {label}: families={metrics['families']} proposals={metrics['proposals']} "
              f"brier={metrics['brier']['estimate']:.4f} "
              f"reliability_error={metrics['reliability_error']:.4f}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
