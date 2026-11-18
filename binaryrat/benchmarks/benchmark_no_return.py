#!/usr/bin/env python3
# Copyright 2026 YurilLAB
# SPDX-License-Identifier: Apache-2.0
"""Measure stock and BinaryRat no-return analysis on a generated x86-64 Program."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import re
import statistics
import sys

from verify_ghidra import measured_run
from verify_large_llvm import launcher, sha256

SCRIPT = Path(__file__).resolve().parent / "ghidra_scripts" / "BinaryRatBenchmarkNoReturn.java"
ORDER = ("stock", "candidate", "candidate", "stock")
HEAP_MIB = 512
EXPECTED_FIXTURE = {
    "schema_version": 1,
    "callers": 1800,
    "positive_calls": 3,
    "fixture_bytes": 28896,
    "bytes_sha256": "a0778a755b78b854d6404d7a72e2dcbca3cabdaf9bdec1c8d211b56d1ba458e5",
}
COMPARABLE = (*EXPECTED_FIXTURE, "effects_sha256", "java_version", "heap_max_bytes",
              "active_processors")


def analyzer_result(path: Path) -> dict:
    outcome = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(outcome, dict):
        raise ValueError(f"Expected a JSON object: {path}")
    for key, expected in EXPECTED_FIXTURE.items():
        actual = outcome.get(key)
        if type(actual) is not type(expected) or actual != expected:
            raise ValueError(f"Unexpected fixture {key}: {path}")
    digest = outcome.get("effects_sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
        raise ValueError(f"Missing Program effects digest: {path}")
    samples = outcome.get("timed_analyzer_wall_ns")
    if (not isinstance(samples, list) or len(samples) != 4 or
            any(type(sample) is not int or sample < 1 for sample in samples)):
        raise ValueError(f"Expected four positive timing samples: {path}")
    max_heap = outcome.get("heap_max_bytes")
    java_version = outcome.get("java_version")
    active_processors = outcome.get("active_processors")
    if (not isinstance(java_version, str) or not java_version or
            type(active_processors) is not int or active_processors != 1 or
            type(max_heap) is not int or not 0 < max_heap <= (HEAP_MIB << 20)):
        raise ValueError(f"Unexpected JVM runtime or resource limits: {path}")
    outcome["analyzer_wall_median_s"] = statistics.median(samples) / 1e9
    return outcome


def run(launch: Path, output: Path, label: str, index: int, timeout: int,
        environment: dict[str, str]) -> dict:
    project = output / f"{index}-{label}"
    project.mkdir()
    log = project / "headless.log"
    raw = project / "analyzer.json"
    values = measured_run([
        str(launch), str(project), "trial", "-import", str(output / "seed.bin"),
        "-loader", "BinaryLoader", "-processor", "x86:LE:64:default", "-cspec", "gcc",
        "-noanalysis", "-max-cpu", "1", "-scriptPath", str(SCRIPT.parent),
        "-postScript", SCRIPT.name, str(raw), "-deleteProject",
    ], log, timeout, environment | {"XDG_CONFIG_HOME": str(project / "settings"),
                                    "XDG_CACHE_HOME": str(project / "cache")})
    messages = log.read_text(encoding="utf-8", errors="replace")
    if (values["returncode"] or messages.count("BINARYRAT_NO_RETURN_TIMING passed") != 1 or
            re.search(r"^(?:ERROR|FATAL) ", messages, re.MULTILINE) or
            not values["sampled_process_tree_peak_rss_bytes"] or values["memory_sampling_errors"]):
        raise RuntimeError(f"{index}-{label} benchmark failed. See {log}")
    outcome = analyzer_result(raw)
    print(f"{index}-{label}: analyzer median {outcome['analyzer_wall_median_s'] * 1000:.3f} ms, "
          f"process wall {values['wall_seconds']:.3f} s, "
          f"peak process-tree RSS {values['sampled_process_tree_peak_rss_bytes']} bytes", flush=True)
    return {"label": label, "log": str(log.relative_to(output)), "process": values,
            "analyzer": outcome}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stock-ghidra", type=Path, required=True)
    parser.add_argument("--candidate-ghidra", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="new results directory")
    parser.add_argument("--timeout", type=int, default=85, help="process deadline per JVM in seconds")
    args = parser.parse_args()
    if sys.platform != "linux" or args.timeout < 1:
        parser.error("requires Linux and a positive timeout")
    launches = {
        "stock": launcher(args.stock_ghidra.resolve(), stock_reference=True),
        "candidate": launcher(args.candidate_ghidra.resolve()),
    }
    identity = {}
    for label, launch in launches.items():
        base_jar = launch.parents[1] / "Ghidra" / "Features" / "Base" / "lib" / "Base.jar"
        identity[label] = {"launcher": str(launch), "base_jar_sha256": sha256(base_jar)}

    output = args.output.resolve()
    output.mkdir(parents=True)
    (output / "seed.bin").write_bytes(b"\xc3")
    runs: list[dict] = []
    report = {
        "schema_version": 1,
        "status": "incomplete",
        "host": platform.platform(),
        "ghidra": identity,
        "benchmark_script_sha256": sha256(SCRIPT),
        "settings": {"order": ORDER, "timeout_s": args.timeout, "warmup_passes": 2,
                     "timed_passes": 4, "heap_mib": HEAP_MIB, "active_processors": 1},
        "runs": runs,
    }
    environment = os.environ.copy()
    for name in ("GHIDRA_JAVA_OPTIONS", "GHIDRA_HEADLESS_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS"):
        environment.pop(name, None)
    environment.update(GHIDRA_HEADLESS_MAXMEM=f"{HEAP_MIB}M", JAVA_TOOL_OPTIONS="-XX:ActiveProcessorCount=1")

    destination = output / "report.json"
    try:
        for index, label in enumerate(ORDER, start=1):
            runs.append(run(launches[label], output, label, index, args.timeout, environment))
        for key in COMPARABLE:
            if len({row["analyzer"][key] for row in runs}) != 1:
                raise ValueError(f"Stock and candidate runs differ on {key}")
        report["summary"] = {
            "effects_sha256": runs[0]["analyzer"]["effects_sha256"],
            "median_of_jvm_medians_s": {
                label: statistics.median(row["analyzer"]["analyzer_wall_median_s"]
                                         for row in runs if row["label"] == label)
                for label in launches
            },
        }
        report["status"] = "completed"
    except (OSError, ValueError, RuntimeError) as error:
        report["error"] = str(error)
        print(error, file=sys.stderr)
    finally:
        destination.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Report: {destination}")
    return 0 if report["status"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
