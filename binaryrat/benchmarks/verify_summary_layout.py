#!/usr/bin/env python3
# Copyright 2026 YurilLAB
# SPDX-License-Identifier: Apache-2.0
"""Verify summary-based layout recovery on a stripped ELF fixture under Ghidra.

BinaryRatSolveLayouts.java summarizes each reached (function, pointer parameter)
and the engine's types.solve op propagates the summaries: shifted arguments keep
their exact offset and recursive cycles are solved instead of cut. Expected field
offsets come from the unstripped fixture's DWARF (separate truth), never from
the reports under test.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

from verify_ghidra import PROJECT, measured_run

LANGUAGES = {62: "x86:LE:64:default", 183: "AARCH64:LE:64:v8A"}
MODE = "read_only_summary_layout_evidence"
CASES = (
    ("chain", "layout_start"),
    ("deeper", "layout_deeper"),
    ("diamond", "layout_diamond"),
    ("shifted", "layout_shift"),
    ("cycle", "layout_cycle_a"),
    ("cycle-reverse", "layout_cycle_b"),
    ("cycle-nested", "layout_cycle_entry"),
    ("fanout", "layout_fanout"),
    ("broad", "layout_broad"),
)
LIMITS = {
    "summary-limit": ("layout_broad", "4", "summary traversal exceeds the summary limit of 4"),
    "invalid-limit": ("layout_start", "0", "summary limit must be between 1 and 256"),
}


def fixture_layout(debug_binary: Path) -> dict:
    """Field offsets of LayoutFixture from DWARF in the unstripped build."""
    from dwarf_oracle import read_dwarf_layout

    layout = read_dwarf_layout(debug_binary, "LayoutFixture")
    members = {member["name"]: member for member in layout["members"]}
    return {"size": layout["size"], "tag": members["tag"]["offset"],
            "payload": members["payload"]["offset"], "alternate": members["alternate"]["offset"],
            "width": members["payload"]["width"]}


def fields(report: dict) -> set[tuple[int, int]]:
    layout = report["solution"]["layout"]
    return set() if layout is None else {(f["offset"], f["width"]) for f in layout["fields"]}


def check_report(report: dict, name: str, language: str) -> dict[str, dict]:
    """Schema, identity and provenance checks shared by every case."""
    if (report["schema_version"] != 1 or report["analysis_mode"] != MODE or
            report["language_id"] != language or
            report["score_kind"] != "uncalibrated_evidence_strength" or
            report["assumption"] != "analyst_selected_object_start"):
        raise RuntimeError(f"{name}: unexpected report header")
    summaries = {summary["id"]: summary for summary in report["summaries"]}
    function = report["function"]
    root_id = (f"{report['program_id']}/{function['address_space']}/{function['address']}"
               f"/param/{report['parameter_index']}")
    if report["object_id"] != root_id or root_id not in summaries:
        raise RuntimeError(f"{name}: root summary does not name the selected parameter")
    solution = report["solution"]
    if solution["status"] != "solved" or solution["summary"] != root_id:
        raise RuntimeError(f"{name}: solution was not solved for the root")
    edges = report["edges"]
    for edge in edges:
        if edge["caller"] not in summaries or edge["callee"] not in summaries:
            raise RuntimeError(f"{name}: edge names an unknown summary: {edge}")
    states = solution["states"]
    if states[0] != dict(summary=root_id, offset=0, hops=0, edge=None, parent=None):
        raise RuntimeError(f"{name}: first state is not the root")
    for index, state in enumerate(states[1:], start=1):
        parent = states[state["parent"]]
        edge = edges[state["edge"]]
        if not (state["parent"] < index and edge["caller"] == parent["summary"] and
                edge["callee"] == state["summary"] and
                parent["offset"] + edge["offset"] == state["offset"] and
                parent["hops"] + 1 == state["hops"]):
            raise RuntimeError(f"{name}: state {index} is not a valid path step: {state}")
    access_ids = {access["evidence_id"]: summary_id for summary_id, summary in summaries.items()
                  for access in summary["accesses"]}
    for row in solution["derived"]:
        state = states[row["state"]]
        access = summaries[state["summary"]]["accesses"][row["access"]]
        if (access["evidence_id"] != row["evidence_id"] or
                access["offset"] + state["offset"] != row["offset"]):
            raise RuntimeError(f"{name}: derived row does not match its summary: {row}")
    if solution["layout"] is not None:
        for field in solution["layout"]["fields"]:
            if not set(field["evidence_ids"]) <= set(access_ids):
                raise RuntimeError(f"{name}: a field cites evidence no summary recorded")
    return summaries


def named_states(report: dict) -> dict[str, list[dict]]:
    names = {summary["id"]: summary["function_name"] for summary in report["summaries"]}
    result: dict[str, list[dict]] = {}
    for state in report["solution"]["states"]:
        result.setdefault(names[state["summary"]], []).append(state)
    return result


def check_results(directory: Path, language: str, truth: dict) -> dict:
    reports = {name: json.loads((directory / f"{name}.json").read_text(encoding="utf-8"))
               for name, _ in CASES}
    reports["redirected"] = json.loads((directory / "redirected.json").read_text(encoding="utf-8"))
    for name, report in reports.items():
        check_report(report, name, language)
    width = truth["width"]
    payload = (truth["payload"], width)

    def complete_without_cycles(name: str) -> None:
        solution = reports[name]["solution"]
        if not solution["complete"] or reports[name]["components"]:
            raise RuntimeError(f"{name}: an acyclic call graph must solve completely")

    for name in ("chain", "deeper", "diamond", "fanout", "broad"):
        complete_without_cycles(name)
        if fields(reports[name]) != {payload}:
            raise RuntimeError(f"{name}: expected only the payload field, got {fields(reports[name])}")
    leaf_hops = {name: [s["hops"] for s in named_states(reports[name])["layout_leaf"]]
                 for name in ("chain", "deeper", "diamond")}
    if leaf_hops != {"chain": [3], "deeper": [4], "diamond": [2]}:
        raise RuntimeError(f"leaf reached at unexpected depths or more than once: {leaf_hops}")
    broad_ids = reports["broad"]["solution"]["layout"]["fields"][0]["evidence_ids"]
    if len(broad_ids) != 12 or len(reports["broad"]["summaries"]) != 17:
        raise RuntimeError("broad call tree did not reach all twelve leaves exactly once")

    shifted = reports["shifted"]
    complete_without_cycles("shifted")
    element = truth["size"]
    if fields(shifted) != {payload, (element + truth["payload"], width)}:
        raise RuntimeError(f"shifted argument lost its exact offset: {fields(shifted)}")
    leaf_offsets = sorted(state["offset"] for state in named_states(shifted)["layout_leaf"])
    if leaf_offsets != [0, element]:
        raise RuntimeError(f"shifted leaf states wrong: {leaf_offsets}")

    for name in ("cycle", "cycle-reverse", "cycle-nested"):
        report = reports[name]
        components = report["components"]
        if (len(components) != 1 or not components[0]["consistent"] or
                len(components[0]["summaries"]) != 2 or not report["solution"]["complete"]):
            raise RuntimeError(f"{name}: the recursive pair is not one consistent component")
        if fields(report) != {(truth["tag"], width), payload}:
            raise RuntimeError(f"{name}: cycle evidence lost or invented: {fields(report)}")

    redirected = reports["redirected"]
    names = set(named_states(redirected))
    if "layout_leaf" in names or "layout_alternate" in names or fields(redirected):
        raise RuntimeError("a call redirected only in p-code was followed")
    return {"language_id": language, "cases": sorted(reports), "shifted_offset": element,
            "consistent_cycles": 3, "fixture": truth}


def verify(args: argparse.Namespace) -> dict:
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    summary = output / "report.json"
    summary.unlink(missing_ok=True)
    launcher = args.ghidra.resolve() / "support" / ("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
    fixture = PROJECT / "binaryrat/corpus/fixtures/layout_paths.c"
    scripts = ";".join(map(str, (PROJECT / "binaryrat/bridge/ghidra_scripts",
                                 PROJECT / "binaryrat/corpus/ghidra_scripts")))
    log = output / "ghidra.log"

    with tempfile.TemporaryDirectory(prefix="summary layouts ", dir=output) as working:
        directory = Path(working)
        if args.binary:
            binary, debug = args.binary.resolve(), args.debug_binary.resolve()
        else:
            binary, debug = directory / "layout_paths", directory / "layout_paths.debug"
            subprocess.run([args.cc, "-g", "-O0", "-fpie", "-pie", "-nostdlib",
                            "-Wl,-e,fixture_entry,--no-dynamic-linker,--export-dynamic",
                            "-o", str(debug), str(fixture)], check=True, timeout=60)
            subprocess.run([args.strip, "--strip-all", "-o", str(binary), str(debug)], check=True, timeout=60)
        truth = args.truth or fixture_layout(debug)
        with binary.open("rb") as executable:
            header = executable.read(20)
        machine = int.from_bytes(header[18:20], "little")
        if header[:6] != b"\x7fELF\x02\x01" or machine not in LANGUAGES:
            raise RuntimeError("expected a little-endian x86-64 or AArch64 ELF fixture")
        language = LANGUAGES[machine]

        command = [str(launcher), working, "fixture", "-import", str(binary),
                   "-scriptPath", scripts, "-readOnly", "-deleteProject"]

        def solve(name: str, function: str, *extra: str) -> None:
            command.extend(["-postScript", "BinaryRatSolveLayouts.java",
                            str(directory / f"{name}.json"), f"name:{function}", "0", "30", *extra])

        for name, function in CASES:
            solve(name, function)
        for name, (function, limit, _) in LIMITS.items():
            solve(name, function, limit)
        command.extend(["-postScript", "BinaryRatOverrideLayoutCallFixture.java",
                        "layout_middle", "layout_leaf", "layout_alternate"])
        solve("redirected", "layout_top")

        environment = os.environ | {"BINARYRAT_ENGINE": str(args.engine.resolve()),
                                    "XDG_CONFIG_HOME": str(directory / "config"),
                                    "XDG_CACHE_HOME": str(directory / "cache")}
        measured = measured_run(command, log, args.timeout, environment)
        log_text = log.read_text(encoding="utf-8", errors="replace")
        if measured["returncode"] or "BINARYRAT_LAYOUT_CALL_OVERRIDE_SET" not in log_text:
            raise RuntimeError(f"Ghidra verification did not complete (see {log})")
        for name, (_, _, diagnostic) in LIMITS.items():
            if (directory / f"{name}.json").exists() or diagnostic not in log_text:
                raise RuntimeError(f"{name} did not fail closed (see {log})")
        if list(directory.glob(".binaryrat-summary-*")):
            raise RuntimeError("summary extraction left a temporary workspace")
        try:
            report = check_results(directory, language, truth)
        finally:
            if args.keep:
                for path in directory.glob("*.json"):
                    (output / path.name).write_bytes(path.read_bytes())
        report["limits_rejected"] = sorted(LIMITS)

    summary.write_text(json.dumps(report | {"passed": True}, indent=2) + "\n", encoding="utf-8")
    print(f"Passed summary layout verification for {report['language_id']} in {summary}")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ghidra", required=True, type=Path)
    parser.add_argument("--engine", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--strip", default="strip")
    parser.add_argument("--binary", type=Path, help="prebuilt stripped fixture (with --debug-binary)")
    parser.add_argument("--debug-binary", type=Path, help="the same fixture before stripping, for DWARF")
    parser.add_argument("--keep", action="store_true", help="copy the reports to the output directory")
    parser.add_argument("--timeout", default=300, type=int)
    args = parser.parse_args()
    if (args.binary is None) != (args.debug_binary is None):
        parser.error("--binary and --debug-binary go together")
    args.truth = None
    verify(args)


if __name__ == "__main__":
    main()
