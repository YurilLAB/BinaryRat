#!/usr/bin/env python3
# Copyright 2026 YurilLAB
# SPDX-License-Identifier: Apache-2.0
"""Verify raw export parity on a deterministic slice of a 100 MB+ LLVM ELF."""
from __future__ import annotations

import argparse
from itertools import zip_longest
import json
import os
from pathlib import Path
import re
import statistics
import subprocess
import sys
import tempfile

from verify_ghidra import (PROJECT, TIMING, first_differing_byte, load_export, measured_run,
                           sha256, validate_stock_audit)


LLVM19_SHA256 = "3523f50f635d2a1ea47518a392451f2854b92823ceaf1345fb806099dd1a3b8a"
PREPARED = re.compile(r"BinaryRat selected sample functions=(\d+) base=([a-fA-F0-9]+)\b")
BRIDGE = PROJECT / "binaryrat" / "bridge" / "ghidra_scripts"
FIXTURE_SCRIPTS = Path(__file__).resolve().parent / "ghidra_scripts"
Sample = tuple[int, int, str]


def select_sample(symbols: str, count: int) -> tuple[list[Sample], int]:
    """Midpoints of equal address-order groups, with deterministic alias selection."""
    eligible = []
    for row in symbols.splitlines():
        fields = row.split()
        if len(fields) != 4:
            continue
        name, kind, offset, size = fields
        if kind != "T" or not name.startswith("LLVM"):
            continue
        address, size = int(offset, 16), int(size, 16)
        if 64 <= size <= 3072 and 0 <= address <= (1 << 64) - size:
            eligible.append((address, size, name.split("@", 1)[0]))
    # Keep the lexicographically last (offset, size, name) at an aliased entry.
    ordered = list({row[0]: row for row in sorted(eligible)}.values())
    if not 1 <= count <= len(ordered):
        raise ValueError(f"requested {count} functions, found {len(ordered)} eligible LLVM exports")
    sample = [ordered[(2 * i + 1) * len(ordered) // (2 * count)] for i in range(count)]
    if any(start + size > next_start for (start, size, _), (next_start, _, _)
           in zip(sample, sample[1:])):
        raise ValueError("selected LLVM symbol ranges overlap")
    return sample, len(ordered)


def validate_export(path: Path, sample: list[Sample], base: int, identity: str) -> dict:
    failures = []
    for row, entry in zip_longest(load_export(path), sample):
        if row is None or entry is None:
            raise ValueError(f"export differs from prepared fixture identity, entries or order: {path}")
        offset, _, name = entry
        function = row.function
        if (function.entry.offset != base + offset or function.name != name or
                function.program_id != f"sha256:{identity}" or function.entry.space != "ram"):
            raise ValueError(f"export differs from prepared fixture identity, entries or order: {path}")
        if row.timed_out or row.cancelled or row.failed_to_start:
            raise ValueError(f"export contains timed-out, cancelled or unstarted work: {path}")
        if row.successful != bool(row.c.strip()) or (not row.successful and not row.error.strip()):
            raise ValueError(f"export contains an unexplained missing C body: {path}")
        if not row.successful:
            failures.append({"name": function.name, "address": str(function.entry), "error": row.error})
    completed = len(sample) - len(failures)
    if not sample or completed * 100 < len(sample) * 99:
        raise ValueError(f"fewer than 99% of sample functions have C output in {path}")
    return {"completed": completed, "incomplete": failures}


def compare_exports(stock: Path, candidate: Path) -> dict:
    """Compare whole files first. Parse rows only to locate and explain differences."""
    difference = first_differing_byte(stock, candidate)
    result = {"exact_bytes": difference is None, "stock_sha256": sha256(stock),
              "candidate_sha256": sha256(candidate), "differences": []}
    if difference is None:
        return result
    result["first_differing_byte"] = difference
    with stock.open("rb") as a, candidate.open("rb") as b:
        for stock_row, candidate_row in zip_longest(a, b):
            if stock_row == candidate_row:
                continue
            if stock_row is None or candidate_row is None:
                row = json.loads(stock_row or candidate_row)
                result["differences"].append({
                    "name": row["name"], "address": row["address"],
                    "missing_from": "candidate" if candidate_row is None else "stock",
                })
                continue
            left, right = json.loads(stock_row), json.loads(candidate_row)
            result["differences"].append({
                "name": left["name"],
                "address": left["address"],
                "fields": sorted(key for key in left.keys() | right.keys()
                                 if key not in left or key not in right or left[key] != right[key]),
            })
    return result


def validate_candidate(mode: str, output: Path, count: int, workers: int, *,
                       allow_legacy: bool = False, require_overlap: bool = False) -> dict | None:
    if mode == "stock-verified":
        summary = json.loads(Path(f"{output}.parity.json").read_text(encoding="utf-8"))
        validate_stock_audit(summary, output, count, workers, allow_legacy=allow_legacy)
        if require_overlap and (summary.get("execution") != "overlapped" or
                                (count > 1 and summary["peak_running"] < 2)):
            raise ValueError("large-binary verification must exercise overlapping stock and candidate work")
        if "execution" in summary:
            cache = summary.get("candidate_cache")
            leases = summary.get("candidate_compute_leases")
            if (not isinstance(cache, dict) or cache.get("enabled") is not False or
                    type(leases) is not int or leases != count):
                raise ValueError("large-binary verification requires one uncached candidate lease per function")
        return summary
    if mode == "scheduled":
        summary = json.loads(Path(f"{output}.schedule.json").read_text(encoding="utf-8"))
        if (summary["cache"]["enabled"] is not False or
                summary["lease_status_counts"] != {"completed": count}):
            raise ValueError("scheduled control must process every function under a lease with cache disabled")
        return summary
    return None


def run(launch: Path, project: Path, args: list[str], destination: Path, label: str,
        environment: dict[str, str], timeout: int) -> tuple[dict, str]:
    log = destination / f"{label}.log"
    report = measured_run([str(launch), str(project), "llvm-sample", "-noanalysis", *args],
                          log, timeout, environment)
    logs = log.read_text(encoding="utf-8", errors="replace")
    if report["returncode"]:
        raise RuntimeError(f"Ghidra process failed, see {log}")
    phases = []
    for functions, mode, workers, excluded, seconds in TIMING.findall(logs):
        phases.append({"mode": mode, "functions": int(functions), "workers": int(workers),
                       "excluded": int(excluded), "elapsed_seconds": float(seconds)})
    report["phases"] = phases
    report["log"] = log.name
    return report, logs


def launcher(installation: Path, stock_reference: bool = False, *, windows: bool = False) -> Path:
    properties = (installation / "Ghidra" / "application.properties").read_text(encoding="utf-8")
    if not re.search(r"^application.version=12\.2\s*$", properties, re.MULTILINE):
        raise ValueError(f"Ghidra 12.2 is required: {installation}")
    if stock_reference:
        upstream = json.loads((PROJECT / "binaryrat" / "UPSTREAM.json").read_text(encoding="utf-8"))
        lines = set(properties.splitlines())
        if not {"application.release.name=PUBLIC",
                f"application.revision.ghidra={upstream['commit']}"} <= lines:
            raise ValueError(f"stock reference must use the official pinned Ghidra 12.2: {installation}")
    launch = installation / "support" / ("analyzeHeadless.bat" if windows else "analyzeHeadless")
    if not launch.is_file():
        raise ValueError(f"missing Ghidra headless launcher: {launch}")
    return launch


def ghidra_fingerprints(launch: Path) -> dict:
    decompiler = launch.parents[1] / "Ghidra" / "Features" / "Decompiler"
    return {
        "launcher": str(launch),
        "decompiler_jar_sha256": sha256(decompiler / "lib" / "Decompiler.jar"),
        "native_decompiler_sha256": {
            executable.parent.name: sha256(executable)
            for executable in sorted((decompiler / "os").glob("linux_*/decompile"))
        },
    }


def verify(args: argparse.Namespace, destination: Path, report: dict) -> None:
    library = args.library.resolve(strict=True)
    with library.open("rb") as binary:
        header = binary.read(20)
    if (library.stat().st_size < 100_000_000 or header[:6] != b"\x7fELF\x02\x01"
            or header[18:20] != b"\x3e\x00"):
        raise ValueError("expected a 100 MB+ little-endian x86-64 ELF")
    identity = sha256(library)
    if identity != args.expect_sha256:
        raise ValueError(f"ELF SHA-256 mismatch: {identity}")
    symbols = subprocess.check_output(
        ["nm", "--dynamic", "--defined-only", "--print-size", "--format=posix", str(library)],
        text=True, timeout=args.process_timeout, env=os.environ | {"LC_ALL": "C"})
    sample, eligible = select_sample(symbols, args.samples)
    manifest = destination / "sample.tsv"
    manifest.write_bytes("".join(f"{offset:x}\t{size:x}\t{name}\n" for offset, size, name in sample)
                         .encode("utf-8"))
    report["fixture"] = {"file": str(library), "bytes": library.stat().st_size,
                         "sha256": identity, "eligible": eligible, "sample_count": len(sample),
                         "sample_symbol_bytes": sum(row[1] for row in sample),
                         "sample_sha256": sha256(manifest)}

    stock = launcher(args.ghidra.resolve(), stock_reference=True)
    candidate = launcher((args.candidate_ghidra or args.ghidra).resolve())
    stock_scripts = args.stock_scripts.resolve()
    candidate_scripts = args.candidate_scripts.resolve()
    engine = args.engine.resolve(strict=True)
    if not engine.is_file() or not os.access(engine, os.X_OK):
        raise ValueError(f"BinaryRat engine is not executable: {engine}")
    report["configuration"] = {
        "stock_ghidra": ghidra_fingerprints(stock), "candidate_ghidra": ghidra_fingerprints(candidate),
        "stock_script_sha256": sha256(stock_scripts / "BinaryRatExport.java"),
        "candidate_script_sha256": sha256(candidate_scripts / "BinaryRatExport.java"),
        "engine_sha256": sha256(engine), "candidate_mode": args.mode, "workers": args.workers,
        "jvm_max_heap": "2G", "process_timeout_seconds": args.process_timeout,
    }
    environment = {key: value for key, value in os.environ.items() if not key.startswith("BINARYRAT_")}
    environment.update(BINARYRAT_ENGINE=str(engine), GHIDRA_HEADLESS_MAXMEM="2G")

    with tempfile.TemporaryDirectory(prefix="ghidra project ", dir=destination) as directory:
        project = Path(directory)
        report["import"], log = run(stock, project, [
            "-import", str(library), "-scriptPath", str(FIXTURE_SCRIPTS),
            "-postScript", "BinaryRatLargeFixture.java", str(manifest),
        ], destination, "import", environment, args.process_timeout)
        prepared = PREPARED.findall(log)
        if len(prepared) != 1 or int(prepared[0][0]) != len(sample):
            raise RuntimeError("Ghidra fixture preparation did not export the expected sample")
        base = int(prepared[0][1], 16)
        report["fixture"]["image_base"] = hex(base)
        print(f"Prepared {len(sample)} functions from {library.name}", flush=True)

        reference_sha256 = None
        for i in range(args.repetitions):
            execution = {}
            order = ("stock", "candidate") if i % 2 == 0 else ("candidate", "stock")
            for label in order:
                name = f"{label}-{i + 1}"
                output = destination / f"{name}.jsonl"
                launch, scripts, mode, workers = (
                    (stock, stock_scripts, "serial", 1) if label == "stock" else
                    (candidate, candidate_scripts, args.mode, args.workers))
                measured, log = run(launch, project, [
                    "-process", library.name, "-readOnly", "-scriptPath", str(scripts),
                    "-postScript", "BinaryRatExport.java", str(output), mode, str(workers),
                    "60", "128", str(manifest),
                ], destination, name, environment, args.process_timeout)
                expected_phases = ["scheduled", "serial"] if mode == "stock-verified" else [mode]
                if ([phase["mode"] for phase in measured["phases"]] != expected_phases
                        or any(phase["functions"] != len(sample) for phase in measured["phases"])):
                    raise RuntimeError(f"export phases or coverage differ from workload: {name}")
                if ("BinaryRat export elapsed_seconds=" not in log or
                        measured["memory_sampling_errors"] or measured["memory_samples"] < 1 or
                        measured["sampled_process_tree_peak_rss_bytes"] <= 0):
                    raise RuntimeError(f"missing export completion or memory evidence: {name}")
                measured["coverage"] = validate_export(output, sample, base, identity)
                if label == "candidate":
                    historical = candidate_scripts != BRIDGE.resolve()
                    measured["sidecar"] = validate_candidate(
                        mode, output, len(sample), workers, allow_legacy=historical,
                        require_overlap=(not historical and workers > 1 and
                                         os.environ.get("BINARYRAT_REQUIRE_VERIFIED_OVERLAP") == "1"))
                    if mode == "stock-verified" and measured["sidecar"].get("execution") == "overlapped":
                        measured["phase_timing"] = "scheduled and serial share one elapsed interval"
                execution[label] = measured
                print(f"{name}: {measured['wall_seconds']:.2f}s, "
                      f"{measured['coverage']['completed']}/{len(sample)} completed", flush=True)

            comparison = compare_exports(destination / f"stock-{i + 1}.jsonl",
                                         destination / f"candidate-{i + 1}.jsonl")
            report["runs"].append(execution | {"comparison": comparison})
            if not comparison["exact_bytes"]:
                raise RuntimeError(f"raw output differs in repetition {i + 1} at byte "
                                   f"{comparison['first_differing_byte']}")
            if reference_sha256 is not None and comparison["stock_sha256"] != reference_sha256:
                raise RuntimeError("stock reference changed between repetitions")
            reference_sha256 = comparison["stock_sha256"]

    report["median"] = {
        label: {metric: statistics.median(row[label][metric] for row in report["runs"])
                for metric in ("wall_seconds", "sampled_process_tree_peak_rss_bytes")}
        for label in ("stock", "candidate")
    }
    report["exact_bytes"] = True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--expect-sha256", default=LLVM19_SHA256)
    parser.add_argument("--ghidra", type=Path, required=True, help="official Ghidra 12.2 for the stock reference")
    parser.add_argument("--candidate-ghidra", type=Path, help="candidate installation, defaults to --ghidra")
    parser.add_argument("--stock-scripts", type=Path, default=BRIDGE)
    parser.add_argument("--candidate-scripts", type=Path, default=BRIDGE)
    parser.add_argument("--engine", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="new report directory")
    parser.add_argument("--mode", choices=("stock-verified", "scheduled", "parallel"),
                        default="stock-verified")
    parser.add_argument("--samples", type=int, default=384)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--repetitions", type=int, default=1)
    parser.add_argument("--process-timeout", type=int, default=900)
    args = parser.parse_args()
    if (not sys.platform.startswith("linux") or not re.fullmatch("[0-9a-f]{64}", args.expect_sha256)
            or not 1 <= args.samples <= 1024 or not 1 <= args.workers <= 64
            or not 1 <= args.repetitions <= 8 or args.process_timeout < 1):
        parser.error("this probe requires Linux, a SHA-256, 1–1024 samples, 1–64 workers, "
                     "1–8 repetitions and a positive process timeout")
    destination = args.output.resolve()
    try:
        destination.mkdir(parents=True, exist_ok=False)
    except OSError as error:
        parser.error(str(error))
    report = {
        "exact_bytes": False, "runs": [],
        "scope": [
            "Full ELF import and bounded LLVM C API export sample. Auto-analysis disabled.",
            "Stock serial and each candidate run reopen the same saved Program read-only.",
            "Wall time includes JVM startup and candidate verification. Cache disabled.",
            "RSS is a sampled process-tree peak and can double-count shared pages.",
        ],
    }
    try:
        verify(args, destination, report)
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.SubprocessError) as error:
        report["failure"] = str(error)
        print(str(error), file=sys.stderr)
    finally:
        report_path = destination / "report.json"
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"Report: {report_path}")
    return 0 if report["exact_bytes"] else 1


if __name__ == "__main__":
    sys.exit(main())
