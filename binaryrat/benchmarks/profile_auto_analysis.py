#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Profile whole-program Ghidra 12.2 auto-analysis on fresh, pinned imports."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import re
import statistics
import sys
import tempfile
import time

from verify_ghidra import measured_run
from verify_large_llvm import ghidra_fingerprints, launcher, sha256


START = "ANALYZING all memory and code:"
SUCCEEDED = "REPORT: Analysis succeeded for file:"
TIMED_OUT = "REPORT: Analysis timed out at "
PROFILE_STARTED = "BinaryRat analysis profile started"
PROFILE_FINISHED = "BinaryRat analysis profile finished"
SCRIPTS = Path(__file__).resolve().parent / "ghidra_scripts"
DIGEST = re.compile(r"[a-f0-9]{64}")


def diagnose(log: Path, data: dict | None, expected_sha256: str,
             measurements: dict) -> dict:
    """Only completed fresh imports with valid evidence can certify equivalent work."""
    starts = successes = timeouts = begins = ends = count = warnings = 0
    relocation_failures = 0
    errors = []
    with log.open(encoding="utf-8", errors="replace") as stream:
        for line in stream:
            starts += START in line
            successes += SUCCEEDED in line
            timeouts += TIMED_OUT in line
            begins += PROFILE_STARTED in line
            ends += PROFILE_FINISHED in line
            warnings += line.startswith("WARN ")
            relocation_failures += line.startswith("ELF Relocation Failure:")
            if line.startswith(("ERROR ", "FATAL ")) and TIMED_OUT not in line:
                count += 1
                if len(errors) < 20:
                    errors.append(line.strip())

    evidence = {"app_error_count": count, "app_error_examples": errors,
                "app_warning_count": warnings, "loader_relocation_failures": relocation_failures,
                "whole_program_start_count": starts, "analysis_success_markers": successes,
                "analysis_timeout_markers": timeouts, "profile_start_markers": begins,
                "profile_finish_markers": ends}
    if measurements.get("hard_timeout"):
        return evidence | {"status": "process_timeout"}
    if measurements["returncode"] or count:
        return evidence | {"status": "failed"}
    if starts == begins == ends == timeouts == 1 and not successes and isinstance(data, dict):
        if (data.get("schema_version") == 1 and data.get("input_sha256") == expected_sha256
                and data.get("timed_out") is True and data.get("program_marked_analyzed") is False
                and data.get("analysis_active") is False):
            return evidence | {"status": "analysis_timeout"}
    if starts != 1 or successes != 1 or timeouts != 0 or begins != 1 or ends != 1 or not isinstance(data, dict):
        return evidence | {"status": "missing_evidence"}

    work = data.get("work", {})
    tasks = data.get("task_times_ms", {})
    rss = measurements.get("sampled_process_tree_peak_rss_bytes")
    if not isinstance(work, dict) or not isinstance(tasks, dict):
        return evidence | {"status": "invalid_evidence"}
    inventory_hash = work.get("inventory_sha256")
    if (data.get("schema_version") != 1 or data.get("input_sha256") != expected_sha256
            or data.get("program_marked_analyzed") is not True or data.get("analysis_active") is not False
            or data.get("timed_out") is not False or not isinstance(inventory_hash, str)
            or work.get("inventory_version") != 2 or not DIGEST.fullmatch(inventory_hash) or not tasks
            or any(type(value) is not int or value <= 0 for value in
                   (data.get("analysis_wall_ns"), work.get("instructions"), work.get("functions")))
            or any(type(ms) is not int or ms < 0 for ms in tasks.values())
            or sum(tasks.values()) != data.get("recorded_task_total_ms")
            or not isinstance(data.get("analysis_options"), dict)
            or any(not isinstance(data.get(key), str) for key in
                   ("language", "compiler_spec", "image_base", "java_version", "analyzer_messages"))
            or any(type(data.get(key)) is not int for key in ("heap_max_bytes", "analyzer_message_characters"))
            or not rss or measurements.get("memory_sampling_errors")):
        return evidence | {"status": "invalid_evidence"}
    return evidence | {"status": "completed"}


def profile(args: argparse.Namespace, launch: Path, label: str, output: Path,
            environment: dict[str, str]) -> dict:
    log = output / f"{label}.log"
    raw = output / f"{label}-program.json"
    start = time.monotonic()
    with tempfile.TemporaryDirectory(prefix=f"{label}-", dir=output) as project:
        run_environment = environment | {"XDG_CONFIG_HOME": str(Path(project) / "settings"),
                                         "XDG_CACHE_HOME": str(Path(project) / "cache")}
        command = [str(launch), project, "profile", "-import", str(args.input),
                   "-analysisTimeoutPerFile", str(args.analysis_timeout),
                   "-max-cpu", str(args.max_cpus), "-scriptPath", str(SCRIPTS),
                   "-preScript", "BinaryRatAnalysisProfile.java", "begin",
                   "-postScript", "BinaryRatAnalysisProfile.java", "finish", str(raw),
                   "-deleteProject"]
        try:
            measurements = measured_run(command, log, args.process_timeout, run_environment)
        except TimeoutError:
            measurements = {"hard_timeout": True, "wall_seconds": time.monotonic() - start}
    program = None
    read_error = None
    if raw.is_file():
        try:
            program = json.loads(raw.read_text(encoding="utf-8"))
        except (ValueError, UnicodeError) as e:
            read_error = str(e)
    evidence = diagnose(log, program, args.expected_sha256, measurements)
    result = {"label": label, "log": log.name, "measurements": measurements,
              "program": program} | evidence
    if read_error is not None:
        result["program_report_invalid"] = read_error
    print(f"{label}: {result['status']} ({measurements['wall_seconds']:.2f}s process wall)", flush=True)
    return result


def comparable(start: dict, end: dict) -> bool:
    if start["status"] != "completed" or end["status"] != "completed":
        return False
    left, right = start["program"], end["program"]
    keys = ("input_sha256", "language", "compiler_spec", "image_base", "analysis_options", "work",
            "analyzer_message_characters", "analyzer_messages", "java_version", "heap_max_bytes")
    return (all(left[key] == right[key] for key in keys)
            and left["task_times_ms"].keys() == right["task_times_ms"].keys()
            and start.get("loader_relocation_failures") == end.get("loader_relocation_failures"))


def summarize(runs: dict[str, list[dict]]) -> dict:
    all_complete = all(group and all(run["status"] == "completed" for run in group) for group in runs.values())
    reference = next((run for run in runs["stock"] if run["status"] == "completed"), None)
    comparisons = [
        comparable(reference, run) for group in runs.values() for run in group
        if reference is not None and run is not reference and run["status"] == "completed"
    ]
    equivalent = None
    if False in comparisons:
        equivalent = False
    elif all_complete and comparisons:
        equivalent = True
    metrics = {}
    for label, group in runs.items():
        if group and all(run["status"] == "completed" for run in group):
            metrics[label] = {
                "median_analysis_wall_seconds": statistics.median(
                    run["program"]["analysis_wall_ns"] / 1e9 for run in group),
                "median_process_tree_peak_rss_bytes": statistics.median(
                    run["measurements"]["sampled_process_tree_peak_rss_bytes"] for run in group),
            }
    status = "completed"
    if not all_complete:
        status = "incomplete"
    elif equivalent is False:
        status = "work_mismatch"
    return {"status": status, "equivalent_inventory": equivalent,
            "independent_comparisons": len(comparisons),
            "completed_run_metrics": metrics}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ghidra", required=True, type=Path, help="official 12.2 installation")
    parser.add_argument("--candidate-ghidra", type=Path, help="optional 12.2 candidate for equivalent-work checks")
    parser.add_argument("--input", required=True, type=Path, help="executable file to import in full")
    parser.add_argument("--expected-sha256", required=True, help="required SHA-256 of the input")
    parser.add_argument("--output", required=True, type=Path, help="new results directory")
    parser.add_argument("--analysis-timeout", type=int, default=360, help="Ghidra deadline in seconds")
    parser.add_argument("--process-timeout", type=int, default=445, help="hard deadline in seconds")
    parser.add_argument("--max-cpus", type=int, default=4, help="Ghidra CPU core limit")
    parser.add_argument("--heap", default="8G", help="Ghidra JVM heap limit")
    parser.add_argument("--repetitions", type=int, default=1)
    args = parser.parse_args()
    if (sys.platform != "linux" or not DIGEST.fullmatch(args.expected_sha256)
            or args.analysis_timeout < 1 or args.process_timeout <= args.analysis_timeout
            or args.max_cpus < 1 or args.repetitions < 1 or not re.fullmatch(r"[1-9][0-9]*[mMgG]", args.heap)):
        parser.error("requires Linux, a SHA-256, positive limits, and a process deadline beyond the analysis deadline")

    args.input = args.input.resolve(strict=True)
    if not args.input.is_file() or sha256(args.input) != args.expected_sha256:
        parser.error("supply a regular input file matching the requested SHA-256")
    launches = {"stock": launcher(args.ghidra.resolve(), stock_reference=True)}
    if args.candidate_ghidra is not None:
        launches["candidate"] = launcher(args.candidate_ghidra.resolve())
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    identity = {}
    for name, launch in launches.items():
        base = launch.parents[1] / "Ghidra" / "Features" / "Base" / "lib" / "Base.jar"
        identity[name] = ghidra_fingerprints(launch) | {"base_jar_sha256": sha256(base)}

    runs: dict[str, list[dict]] = {label: [] for label in launches}
    report = {
        "schema_version": 1, "input": {"path": str(args.input), "sha256": args.expected_sha256,
                                           "bytes": args.input.stat().st_size},
        "host": platform.platform(), "affinity_cpu_count": len(os.sched_getaffinity(0)),
        "ghidra": identity, "profile_script_sha256": sha256(SCRIPTS / "BinaryRatAnalysisProfile.java"),
        "settings": {"analysis_timeout_seconds": args.analysis_timeout, "process_timeout_seconds": args.process_timeout,
                     "max_cpus": args.max_cpus, "heap": args.heap, "repetitions": args.repetitions},
        "scope": ["Whole fresh import and default stock auto-analysis; source bytes are never executed.",
                  "The runner uses fresh XDG application settings and cache directories for each import; host filesystem cache is uncontrolled.",
                  "Analysis wall brackets scheduling and analysis with pre/post scripts; process wall and peak RSS also include import and inventory.",
                  "Task times are elapsed Ghidra command times, including waits for analyzer-owned workers.",
                  "Inventory v2 compares function entries, names, signatures, bodies and no-return flags including external functions, all bookmark addresses, types, categories and comments, instruction boundaries, mnemonics and flow overrides, defined data type paths and sizes, and references from Program memory."],
        "runs": runs,
    }
    environment = os.environ.copy()
    for option in ("GHIDRA_JAVA_OPTIONS", "GHIDRA_HEADLESS_JAVA_OPTIONS", "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS"):
        environment.pop(option, None)
    environment["GHIDRA_HEADLESS_MAXMEM"] = args.heap
    environment["LC_ALL"] = "C"
    try:
        for repetition in range(args.repetitions):
            order = list(launches)
            if repetition % 2:
                order.reverse()
            for label in order:
                result = profile(args, launches[label], f"{label}-{repetition + 1}", output, environment)
                runs[label].append(result)
        report["summary"] = summarize(runs)
    finally:
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Report: {output / 'report.json'}")
    return 0 if report["summary"]["status"] == "completed" else 1


if __name__ == "__main__":
    sys.exit(main())
