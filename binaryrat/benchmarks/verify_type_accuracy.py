#!/usr/bin/env python3
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


def json_file(path: Path) -> dict:
    if not 0 < path.stat().st_size <= MAX_JSON_BYTES:
        raise ValueError(f"JSON size outside the supported range: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
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


def oracle_layout(debug: Path, artifact: dict, pdbutil: str) -> dict:
    if artifact["format"] == "ELF64":
        return read_dwarf_layout(debug, REFERENCE_TYPE)
    if artifact["format"] == "PE32+":
        from pdb_oracle import read_pdb_layout
        return read_pdb_layout(debug, REFERENCE_TYPE, pdbutil)
    raise ValueError("unsupported corpus debug format")


def collect_layout(launcher: Path, binary: Path, prefix: Path, timeout: int,
                   environment: dict[str, str], function: str,
                   follow_depth: int = 0) -> tuple[dict, str, dict]:
    output, log = prefix.with_suffix(".layout.json"), prefix.with_suffix(".log")
    output.unlink(missing_ok=True)
    scripts = PROJECT / "binaryrat/bridge/ghidra_scripts"
    with tempfile.TemporaryDirectory(prefix="layout oracle ", dir=prefix.parent) as directory:
        measured = measured_run([
            str(launcher), directory, "fixture", "-import", str(binary), "-readOnly",
            "-scriptPath", str(scripts), "-postScript", "BinaryRatRecoverLayouts.java",
            str(output), f"name:{function}", str(PARAMETER_INDEX), "60", str(follow_depth),
            "-deleteProject",
        ], log, timeout, environment)
    if measured["returncode"] or not output.is_file() or "REPORT SCRIPT ERROR" in log.read_text(
            encoding="utf-8", errors="replace"):
        raise RuntimeError(f"Ghidra did not produce a layout for {function} (see {log})")
    return json_file(output), output.name, measured


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
    return {"passed": True, "evidence": report_name, "metrics": metrics}


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
        binary = checked_file(root, artifact, "binary", "binary_sha256")
        debug = checked_file(root, artifact, "debug_file", "debug_sha256")
        if binary.parent == debug.parent or binary == debug:
            raise ValueError("analysis input and oracle must be separate")
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
    report = {"schema_version": 1, "passed": False, "fixtures": [],
              "scope": "Byte-range recovery for analyst-selected PackedRecord fixture roots",
              "limitations": ["Field offsets and widths only. No source names or type semantics are scored.",
                              "Only structure footprint accuracy is measured for this fixture.",
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
