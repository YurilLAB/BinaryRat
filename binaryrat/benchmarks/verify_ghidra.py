#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exact stock/parallel integration checks with explicitly scoped measurements."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import statistics
import subprocess
import sys
import time

import psutil

PROJECT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT / "binaryrat" / "python" / "src"))
from binaryrat import load_export  # noqa: E402

PHASE = re.compile(r"BinaryRat export starting mode=(serial|parallel)")
TIMING = re.compile(r"BinaryRat exported functions=(\d+) mode=(serial|parallel) "
                    r"workers=(\d+) excluded_external=(\d+) elapsed_seconds=([0-9.eE+-]+)")


def measured_run(argv: list[str], log: Path, timeout: float) -> dict:
    """Sample simultaneous process-tree RSS, never sum independent peaks."""
    started = time.monotonic()
    peak, samples = 0, 0
    phase_peaks = {"serial": 0, "parallel": 0}
    current_phase = None
    errors: set[str] = set()
    with log.open("wb") as output, log.open("r", encoding="utf-8", errors="replace") as observer:
        process = subprocess.Popen(argv, stdout=output, stderr=subprocess.STDOUT)
        root = psutil.Process(process.pid)
        try:
            while process.poll() is None:
                for line in observer.readlines():
                    match = PHASE.search(line)
                    if match:
                        current_phase = match.group(1)
                total = 0
                try:
                    tree = [root, *root.children(recursive=True)]
                    for member in tree:
                        try:
                            total += member.memory_info().rss
                        except (psutil.NoSuchProcess, psutil.ZombieProcess):
                            pass
                        except psutil.AccessDenied:
                            errors.add("access_denied")
                except (psutil.NoSuchProcess, psutil.ZombieProcess):
                    pass
                peak = max(peak, total)
                if current_phase:
                    phase_peaks[current_phase] = max(phase_peaks[current_phase], total)
                samples += 1
                if time.monotonic() - started > timeout:
                    raise TimeoutError(f"Ghidra exceeded {timeout} seconds; see {log}")
                time.sleep(0.05)
        except BaseException:
            try:
                for child in root.children(recursive=True):
                    try:
                        child.kill()
                    except psutil.NoSuchProcess:
                        pass
            except psutil.NoSuchProcess:
                pass
            process.kill()
            process.wait()
            raise
    return {"returncode": process.returncode, "wall_seconds": time.monotonic() - started,
            "sampled_process_tree_peak_rss_bytes": peak, "memory_samples": samples,
            "phase_sampled_process_tree_peak_rss_bytes":
                {phase: peak or None for phase, peak in phase_peaks.items()},
            "memory_sampling_errors": sorted(errors), "sample_interval_seconds": 0.05}


def verify_pair(prefix: Path, log: Path) -> dict:
    serial = Path(str(prefix) + ".serial.jsonl")
    parallel = Path(str(prefix) + ".parallel.jsonl")
    content = log.read_text(encoding="utf-8", errors="replace")
    if "BinaryRat exact serial/parallel comparison passed:" not in content:
        raise RuntimeError(f"postScript success marker missing; see {log}")
    if not serial.is_file() or not parallel.is_file():
        raise RuntimeError(f"expected export missing; see {log}")
    if serial.read_bytes() != parallel.read_bytes():
        raise RuntimeError(f"exact output mismatch: {serial}, {parallel}")
    records = list(load_export(serial))
    if not records or not all(record.successful and record.c.strip() for record in records):
        raise RuntimeError(f"empty or incomplete decompiler coverage; see {serial}")
    phases = {}
    for match in TIMING.finditer(content):
        count, mode, workers, excluded, elapsed = match.groups()
        phases[mode] = {"function_count": int(count), "workers": int(workers),
                        "excluded_external_count": int(excluded),
                        "export_wall_seconds": float(elapsed)}
    if set(phases) != {"serial", "parallel"}:
        raise RuntimeError(f"missing phase timings; see {log}")
    if any(phase["function_count"] != len(records) for phase in phases.values()):
        raise RuntimeError("export count differs from parsed record count")
    return {"exact_match": True, "function_count": len(records),
            "completed_count": len(records),
            "export_sha256": hashlib.sha256(serial.read_bytes()).hexdigest(),
            "phases": phases}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ghidra", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workers", type=int, nargs="+", default=[1, 2, 4])
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--timeout", type=float, default=1800)
    args = parser.parse_args()
    if args.repetitions < 1 or any(value < 1 or value > 64 for value in args.workers):
        parser.error("repetitions must be positive and workers must be in 1..64")
    ghidra, destination = args.ghidra.resolve(), args.output.resolve()
    properties = (ghidra / "Ghidra" / "application.properties").read_text()
    if not re.search(r"^application.version=12\.2\s*$", properties, re.MULTILINE):
        raise RuntimeError("this baseline verifier requires Ghidra 12.2")
    headless = ghidra / "support" / ("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
    manifest = json.loads(args.corpus.read_text())
    if manifest.get("status") != "passed" or not manifest.get("artifacts"):
        raise RuntimeError("corpus manifest is incomplete or failed")
    corpus_root = Path(manifest["root"])
    destination.mkdir(parents=True, exist_ok=True)
    projects = destination / "projects"
    projects.mkdir(exist_ok=True)
    report = {"schema_version": 1, "ghidra_version": "12.2", "host": platform.platform(),
              "logical_cpus": os.cpu_count(), "correctness_passed": False, "runs": [],
              "limitations": [
                  "Initial small-fixture integration, not a 100MB+ scalability benchmark.",
                  "Bridge wraps stock serial and stock pooled DecompInterface; no new decompiler.",
                  "RSS samples include JVM/native descendants and may double-count shared pages.",
                  "Sampling may miss short-lived peaks; phase attribution follows log markers.",
                  "Headless wall time includes import/analysis and BOTH export phases.",
                  "Export timings include worker startup, hashing, serialization and I/O.",
                  "No type precision/recall or auto-analysis acceleration claim is made."]}
    try:
        for artifact in manifest["artifacts"]:
            binary = (corpus_root / artifact["binary"]).resolve()
            if corpus_root.resolve() not in binary.parents:
                raise RuntimeError("corpus binary is outside its declared root")
            if hashlib.sha256(binary.read_bytes()).hexdigest() != artifact["binary_sha256"]:
                raise RuntimeError(f"corpus binary hash mismatch: {binary}")
            identity = hashlib.sha256(artifact["id"].encode()).hexdigest()[:12]
            for workers in args.workers:
                for repetition in range(args.repetitions):
                    name = f"{identity}-w{workers}-r{repetition}"
                    prefix, log = destination / name, destination / (name + ".log")
                    # Never accept stale files from a prior run as fresh success.
                    for suffix in (".serial.jsonl", ".parallel.jsonl"):
                        Path(str(prefix) + suffix).unlink(missing_ok=True)
                    mode = "compare" if repetition % 2 == 0 else "compare-reverse"
                    argv = [str(headless), str(projects), name, "-import", str(binary),
                            "-overwrite", "-scriptPath", str(PROJECT / "binaryrat/bridge/ghidra_scripts"),
                            "-postScript", "BinaryRatExport.java", str(prefix), mode,
                            str(workers), "60", "128", "-deleteProject"]
                    measured = measured_run(argv, log, args.timeout)
                    if measured["returncode"]:
                        raise RuntimeError(f"Ghidra process failed; see {log}")
                    pair = verify_pair(prefix, log)
                    if pair["phases"]["serial"]["workers"] != 1 or \
                            pair["phases"]["parallel"]["workers"] != workers:
                        raise RuntimeError(f"logged worker counts differ from requested configuration; see {log}")
                    report["runs"].append({"artifact_id": artifact["id"], "workers": workers,
                                           "repetition": repetition, "phase_order": mode,
                                           **measured, **pair})
                    print(f"PASS {artifact['id']} workers={workers} repetition={repetition} "
                          f"functions={pair['function_count']}", flush=True)
        report["correctness_passed"] = True
        report["memory_evidence_complete"] = all(
            not run["memory_sampling_errors"] and all(
                value is not None for value in run["phase_sampled_process_tree_peak_rss_bytes"].values())
            for run in report["runs"])
    finally:
        (destination / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    report["summary"] = {
        "paired_runs": len(report["runs"]),
        "serial_export_median_seconds": statistics.median(
            run["phases"]["serial"]["export_wall_seconds"] for run in report["runs"]),
        "parallel_export_median_seconds": statistics.median(
            run["phases"]["parallel"]["export_wall_seconds"] for run in report["runs"])}
    (destination / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["summary"], indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
