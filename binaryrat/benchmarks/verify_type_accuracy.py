#!/usr/bin/env python3
# Copyright 2026 YurilLAB
# SPDX-License-Identifier: Apache-2.0
"""Score read-only layout evidence from a stripped fixture against separate debug data."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile

from bounded_io import read_limited
from dwarf_oracle import read_dwarf_layout
from verify_ghidra import PROJECT, measured_run


MAX_JSON_BYTES = 32 * 1024 * 1024
REFERENCE_TYPE = "PackedRecord"
FUNCTION = "read_packed"
PARAMETER_INDEX = 0


def digest(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def checked_file(root: Path, artifact: dict, path_key: str, digest_key: str) -> Path:
    path = (root / artifact[path_key]).resolve(strict=True)
    if root not in path.parents or not path.is_file() or digest(path) != artifact[digest_key]:
        raise ValueError(f"corpus path or SHA-256 check failed for {path_key}")
    return path


def checked_artifact_pair(root: Path, artifact: dict) -> tuple[Path, Path]:
    binary = checked_file(root, artifact, "binary", "binary_sha256")
    debug = checked_file(root, artifact, "debug_file", "debug_sha256")
    if binary.parent == debug.parent or artifact["binary_sha256"] == artifact["debug_sha256"]:
        raise ValueError("analysis input and oracle must be separate artifacts with distinct content")
    return binary, debug


def json_file(path: Path) -> dict:
    if not 0 < path.stat().st_size <= MAX_JSON_BYTES:
        raise ValueError(f"JSON size outside the supported range: {path}")
    with path.open("rb") as stream:
        data = read_limited(stream, MAX_JSON_BYTES + 1)
    if len(data) > MAX_JSON_BYTES:
        raise ValueError(f"JSON size outside the supported range: {path}")
    value = json.loads(data.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected a JSON object: {path}")
    return value


def footprint(fields: list[dict]) -> set[tuple[int, int]]:
    result = set()
    for field in fields:
        offset, width = field["offset"], field["width"]
        if type(offset) is not int or type(width) is not int or not (
                0 <= offset < (1 << 32) and 0 < width <= (1 << 32) - offset):
            raise ValueError("invalid byte range in layout")
        result.add((offset, width))
    return result


def rates(true: int, extra: int, missing: int) -> dict:
    return {
        "matched": true, "unexpected": extra, "missing": missing,
        "precision": true / (true + extra) if true + extra else None,
        "recall": true / (true + missing) if true + missing else None,
    }


def score_fields(inferred: list[dict], oracle: dict) -> dict:
    expected = footprint(oracle["members"])
    if not expected:
        raise ValueError("cannot score an oracle with no declared fields")
    actual = footprint(inferred)
    return {
        **rates(len(actual & expected), len(actual - expected), len(expected - actual)),
        "extra_ranges": sorted(actual - expected),
        "missing_ranges": sorted(expected - actual),
    }


def verified_fields(export: dict, artifact: dict, function: str = FUNCTION) -> list[dict]:
    if (type(export.get("schema_version")) is not int or export["schema_version"] != 1 or
            export["program_id"] != f"sha256:{artifact['binary_sha256']}" or
            export["function"]["name"] != function or
            type(export["parameter_index"]) is not int or export["parameter_index"] != PARAMETER_INDEX or
            export["assumption"] != "analyst_selected_object_start"):
        raise ValueError("layout report identifies a different Program, selected function or assumption")
    observations = {row["evidence_id"]: row for row in export["observations"]}
    if len(observations) != len(export["observations"]):
        raise ValueError("duplicate p-code evidence identity")
    sites = {(row["function_address_space"], row["function_address"],
              row["address_space"], row["address"], row["pcode_order"]) for row in observations.values()}
    if len(sites) != len(observations):
        raise ValueError("duplicate p-code evidence site")
    layouts = export["layouts"]
    if len(layouts) > 1:
        raise ValueError("multiple object roots reported for a single selected parameter")
    fields = layouts[0]["fields"] if layouts else []
    for field in fields:
        evidence = field["evidence_ids"]
        if not evidence or len(set(evidence)) != len(evidence):
            raise ValueError("field evidence must be nonempty and unique")
        for identity in evidence:
            source = observations[identity]
            if (source["object_start_known"] is not True or
                    source["object_id"] != layouts[0]["object_id"] or
                    (source["offset"], source["width"]) != (field["offset"], field["width"]) or
                    source["operation"] not in ("LOAD", "STORE")):
                raise ValueError("field is unsupported by its p-code evidence")
    return fields


def oracle_layout(debug: Path, artifact: dict, pdbutil: str, name: str = REFERENCE_TYPE) -> dict:
    if artifact["format"] == "ELF64":
        return read_dwarf_layout(debug, name)
    if artifact["format"] == "PE32+":
        from pdb_oracle import read_pdb_layout
        return read_pdb_layout(debug, name, pdbutil)
    raise ValueError("unsupported corpus debug format")


def run_layouts(launcher: Path, binary: Path, log: Path, timeout: int,
                environment: dict[str, str], selections: list[tuple[Path, str, int]],
                override_call: bool = False) -> dict:
    scripts = [str(PROJECT / "binaryrat/bridge/ghidra_scripts")]
    setup = []
    if override_call:
        _, function, _ = selections[0]
        scripts.append(str(PROJECT / "binaryrat/corpus/ghidra_scripts"))
        setup = ["-postScript", "BinaryRatOverrideLayoutCallFixture.java",
                 function, FUNCTION, "read_alternate_layout"]
    extraction = []
    for output, function, depth in selections:
        output.unlink(missing_ok=True)
        extraction.extend(["-postScript", "BinaryRatRecoverLayouts.java", str(output),
                           f"name:{function}", str(PARAMETER_INDEX), "60", str(depth)])
    with tempfile.TemporaryDirectory(prefix="layout oracle ", dir=log.parent) as directory:
        measured = measured_run([
            str(launcher), directory, "fixture", "-import", str(binary), "-readOnly",
            "-scriptPath", ";".join(scripts), *setup, *extraction, "-deleteProject",
        ], log, timeout, environment)
    log_text = log.read_text(encoding="utf-8", errors="replace")
    if (measured["returncode"] or "REPORT SCRIPT ERROR" in log_text or
            any(not output.is_file() for output, _, _ in selections) or
            (override_call and "BINARYRAT_LAYOUT_CALL_OVERRIDE_SET" not in log_text)):
        raise RuntimeError(f"Ghidra did not produce the selected layouts (see {log})")
    return measured


def collect_layout(launcher: Path, binary: Path, prefix: Path, timeout: int,
                   environment: dict[str, str], function: str,
                   follow_depth: int = 0, override_call: bool = False) -> tuple[dict, str, dict]:
    output, log = prefix.with_suffix(".layout.json"), prefix.with_suffix(".log")
    measured = run_layouts(launcher, binary, log, timeout, environment,
                           [(output, function, follow_depth)], override_call)
    return json_file(output), output.name, measured


def verify_union_views(export: dict, control: dict, artifact: dict,
                       oracle: dict, control_oracle: dict) -> dict:
    fields = verified_fields(export, artifact, "read_overlay_number")
    control_fields = verified_fields(control, artifact, "read_separate_numbers")
    if oracle["kind"] != "union" or control_oracle["kind"] != "struct":
        raise ValueError("the union and its control must have different aggregate kinds")
    metrics = score_fields(fields, oracle)
    control_metrics = score_fields(control_fields, control_oracle)
    if metrics["missing"] or metrics["unexpected"] or control_metrics["missing"] or control_metrics["unexpected"]:
        raise RuntimeError("union or control fields do not match their separate debug oracles")
    if export["revision"] != control["revision"]:
        raise RuntimeError("collecting the union evidence modified the Program")

    inferred, = export["layouts"]
    candidate, = inferred["union_candidates"]
    if any(layout["union_candidates"] for layout in control["layouts"]):
        raise RuntimeError("separate integer and floating fields produced a union candidate")
    views = candidate["views"]
    if {view["kind"] for view in views} != {"integer", "floating_point"} or len(views) != 2:
        raise RuntimeError("the union candidate is missing a typed member view")
    if {(candidate["offset"], view["width"]) for view in views} != footprint(oracle["members"]):
        raise RuntimeError("union candidate extent differs from the union oracle")

    observations = {row["evidence_id"]: row for row in export["observations"]}
    field_evidence = {(field["offset"], field["width"]): set(field["evidence_ids"])
                      for field in fields}
    for view in views:
        identities = view["evidence_ids"]
        if (not identities or len(set(identities)) != len(identities) or
                not set(identities) <= field_evidence[(candidate["offset"], view["width"])]):
            raise RuntimeError("union view lacks evidence from its rooted field")
        for identity in identities:
            row = observations[identity]
            typed_use = row["typed_use"]
            prefix = "FLOAT_" if view["kind"] == "floating_point" else "INT_"
            if (row["operation"] != "LOAD" or row["storage_view"] != view["kind"]
                    or not typed_use["operation"].startswith(prefix)):
                raise RuntimeError("union view lacks independent typed p-code evidence")
    if {row.get("storage_view") for row in control["observations"]} != {"integer", "floating_point"}:
        raise RuntimeError("control evidence is missing an independent typed load")
    return metrics


def check_union_views(launcher: Path, binary: Path, debug: Path, artifact: dict,
                      prefix: Path, args: argparse.Namespace, environment: dict[str, str]) -> dict:
    positive = prefix.with_suffix(".union.json")
    negative = prefix.with_suffix(".union-control.json")
    measured = run_layouts(launcher, binary, prefix.with_suffix(".union.log"), args.timeout,
                           environment, [(positive, "read_overlay_number", 0),
                                         (negative, "read_separate_numbers", 0)])
    oracle = oracle_layout(debug, artifact, args.pdbutil, "OverlayNumber")
    control_oracle = oracle_layout(debug, artifact, args.pdbutil, "SeparateNumberViews")
    metrics = verify_union_views(json_file(positive), json_file(negative), artifact, oracle, control_oracle)
    return {"passed": True, "evidence": positive.name, "control_evidence": negative.name,
            "oracle": oracle, "metrics": metrics, "measured": measured}


def check_forwarding(launcher: Path, binary: Path, artifact: dict, oracle: dict,
                     args: argparse.Namespace, environment: dict[str, str]) -> dict:
    function = "forward_packed"
    local, _, _ = collect_layout(launcher, binary, args.output / "forward-local", args.timeout,
                                 environment, function)
    if verified_fields(local, artifact, function) or local["forwarded_calls"]:
        raise RuntimeError("local layout unexpectedly included callee evidence")
    forwarded, report_name, _ = collect_layout(
        launcher, binary, args.output / "forward-depth1", args.timeout, environment, function, 1)
    fields = verified_fields(forwarded, artifact, function)
    calls = forwarded["forwarded_calls"]
    if len(calls) != 1 or calls[0]["callee_parameter_index"] != 0 or not fields or not all(
            (row["function_address_space"], row["function_address"]) ==
            (calls[0]["callee_address_space"], calls[0]["callee_address"])
            for row in forwarded["observations"]):
        raise RuntimeError("direct forwarded evidence lost its callee origin")
    metrics = score_fields(fields, oracle)
    if metrics["missing"] or metrics["unexpected"]:
        raise RuntimeError("direct forwarded evidence differs from the packed-layout oracle")

    redirected, redirected_name, _ = collect_layout(
        launcher, binary, args.output / "forward-override", args.timeout,
        environment, function, 1, override_call=True)
    if (verified_fields(redirected, artifact, function) or redirected["forwarded_calls"] or
            redirected["observations"] != local["observations"] or
            redirected["variable_accesses"] != local["variable_accesses"]):
        raise RuntimeError("a call override was treated as a decoded direct call")
    return {"passed": True, "evidence": report_name, "metrics": metrics,
            "override_excluded": True, "override_evidence": redirected_name}


def check_variable_evidence(launcher: Path, binary: Path, debug: Path, artifact: dict,
                            args: argparse.Namespace, environment: dict[str, str]) -> dict:
    function = "update_record"
    export, evidence, _ = collect_layout(launcher, binary, args.output / "indexed-access",
                                         args.timeout, environment, function)
    fields = verified_fields(export, artifact, function)
    record = read_dwarf_layout(debug, "Record")
    samples, = (member for member in record["members"] if member["name"] == "samples")
    first = samples["offset"]
    past_last = first + samples["width"]
    ranges = export["variable_accesses"]
    if not ranges or not all(
            first == row["minimum_offset"] < row["maximum_offset"] and
            row["maximum_offset"] + row["width"] == past_last and
            row["width"] == row["stride"] == 4 for row in ranges):
        raise RuntimeError("indexed p-code accesses did not retain their bounded ranges")
    if any(field["offset"] < past_last and field["offset"] + field["width"] > first for field in fields):
        raise RuntimeError("a possible indexed address was promoted to an exact field")
    return {"passed": True, "evidence": evidence, "range_observations": len(ranges)}


def evaluate(args: argparse.Namespace, report: dict) -> None:
    manifest = json_file(args.corpus)
    if manifest.get("schema_version") != 1 or manifest.get("status") != "passed":
        raise ValueError("corpus build did not pass")
    root = Path(manifest["root"]).resolve(strict=True)
    fixtures = [row for row in manifest["artifacts"]
                if row["id"].endswith("/types") and (not args.artifact or row["id"] in args.artifact)]
    identifiers = {row["id"] for row in fixtures}
    if (not fixtures or len(identifiers) != len(fixtures) or
            (args.artifact and identifiers != set(args.artifact))):
        raise ValueError("no unique set of requested C layout fixtures")

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
    groups: dict[str, list[int]] = {}

    for artifact in fixtures:
        binary, debug = checked_artifact_pair(root, artifact)
        prefix = args.output / hashlib.sha256(artifact["id"].encode()).hexdigest()[:12]
        layout, evidence_name, measured = collect_layout(launcher, binary, prefix, args.timeout,
                                                         environment, FUNCTION)
        # The inference process received only the stripped artifact. Resolve its
        # explicit anchor and read the debug layout after that process has exited.
        fields = verified_fields(layout, artifact)
        oracle = oracle_layout(debug, artifact, args.pdbutil)
        metrics = score_fields(fields, oracle)
        report["fixtures"].append({"artifact": artifact["id"], "binary_sha256": artifact["binary_sha256"],
                                   "debug_sha256": artifact["debug_sha256"], "oracle": oracle,
                                   "metrics": metrics, "measured": measured, "evidence": evidence_name})
        if artifact["id"] == "gcc/O0/types":
            report["direct_call_forwarding"] = check_forwarding(
                launcher, binary, artifact, oracle, args, environment)
            report["variable_offsets"] = check_variable_evidence(
                launcher, binary, debug, artifact, args, environment)
        totals = groups.setdefault(oracle["kind"], [0, 0, 0])
        for index, key in enumerate(("matched", "unexpected", "missing")):
            totals[index] += metrics[key]
        print(f"{artifact['id']} {oracle['kind']} footprint: "
              f"precision={metrics['precision']} recall={metrics['recall']}", flush=True)
        if artifact["optimization"] in ("O0", "Od"):
            union = check_union_views(launcher, binary, debug, artifact, prefix, args, environment)
            report["union_views"][artifact["id"]] = union
            totals = groups.setdefault("union", [0, 0, 0])
            for index, key in enumerate(("matched", "unexpected", "missing")):
                totals[index] += union["metrics"][key]

    report["by_reference_kind"] = {kind: rates(*counts) for kind, counts in groups.items()}
    if any(score["unexpected"] or score["missing"] for score in report["by_reference_kind"].values()):
        raise RuntimeError("inferred byte ranges differ from the packed-layout regression oracle")
    report["passed"] = True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for argument in ("ghidra", "engine", "corpus", "output"):
        parser.add_argument("--" + argument, required=True, type=Path)
    llvm = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "LLVM/bin/llvm-pdbutil.exe"
    parser.add_argument("--pdbutil", default=shutil.which("llvm-pdbutil") or (
        str(llvm) if os.name == "nt" and llvm.is_file() else "llvm-pdbutil"))
    parser.add_argument("--artifact", action="append", help="optional C artifact ID filter")
    parser.add_argument("--timeout", type=int, default=300)
    args = parser.parse_args()
    if not 1 <= args.timeout <= 3600:
        parser.error("timeout must be in [1, 3600] seconds")
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=True)
    report = {"schema_version": 1, "passed": False, "fixtures": [], "union_views": {},
              "scope": "Byte ranges for analyst-selected packed structures and typed union views",
              "limitations": ["Field offsets and widths only. No source names or type semantics are scored.",
                              "Union evaluation uses one source family and a separate-storage control.",
                              "Intervals shared by multiple declared members count once."]}
    try:
        evaluate(args, report)
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
