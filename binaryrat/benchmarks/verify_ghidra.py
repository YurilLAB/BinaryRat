#!/usr/bin/env python3
# Copyright 2026 YurilLAB
# SPDX-License-Identifier: Apache-2.0
"""Exact stock/parallel integration checks with explicitly scoped measurements."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
from itertools import zip_longest
import json
import math
import os
from pathlib import Path
import platform
import re
import statistics
import subprocess
import sys
import tempfile
import time

import psutil

PROJECT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT / "binaryrat" / "python" / "src"))
from binaryrat import load_export  # noqa: E402
from binaryrat.call_sites import load_call_sites_report  # noqa: E402

PHASE_NAME = r"(serial|parallel|scheduled)"
PHASE = re.compile(r"BinaryRat export starting mode=" + PHASE_NAME)
TIMING = re.compile(r"BinaryRat exported functions=(\d+) mode=" + PHASE_NAME + " "
                    r"workers=(\d+) excluded_external=(\d+) elapsed_seconds=([0-9.eE+-]+)")

# Stock 12.2 sometimes cannot decompile this static MSVC 19.52 CRT helper.
# The separate PDB identifies __GSHandlerCheckCommon in each verified fixture.
# These hashes cover the exact analyzed body bytes and address ranges.
MSVC_CRT_BODIES = {
    "msvc/O1/types": ("ram:140001260", "acaf5da83d08fcacb43565cb74f5335281aadb71ac27f5ae67a8bd5d21dbd517"),
    "msvc/O2/types": ("ram:1400012d0", "1b87dfa37f3c9194cf5633ae849049f688cd8c8bb5d4640378c749e3be93acca"),
    "msvc/Ox/types": ("ram:140001300", "8d7bd4dedd921e18b863a6cddd371e1e3cc72ee42a324453bf1110758b2d9b3b"),
}
MSVC_CRT_ERROR = ("Low-level Error: Bad instruction count exceeded:\n"
                  "    ...\n    No pcode could be generated at address: r0x000140020137")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(65536):
            digest.update(chunk)
    return digest.hexdigest()


def saved_project_hashes(directory: Path, project_name: str) -> dict[str, str]:
    """Hash the project marker, live indices and all saved Program artifacts."""
    repository = directory / f"{project_name}.rep"
    marker = directory / f"{project_name}.gpr"
    # IndexedLocalFileSystem can rotate these two backup copies on a read-only open.
    backups = {repository / "idata" / name for name in ("~index.bak", "~journal.bak")}
    files = {path.relative_to(directory).as_posix(): sha256(path)
             for path in repository.rglob("*") if path.is_file() and path not in backups}
    if not files:
        raise ValueError(f"No saved project artifacts in {repository}")
    files[marker.name] = sha256(marker)
    return files


def first_differing_byte(left: Path, right: Path) -> int | None:
    """Return the first raw byte offset, including a length-only difference."""
    with left.open("rb") as a, right.open("rb") as b:
        offset = 0
        while True:
            before, after = a.read(65536), b.read(65536)
            if before != after:
                return offset + next((i for i, (x, y) in enumerate(zip(before, after)) if x != y),
                                     min(len(before), len(after)))
            if not before:
                return None
            offset += len(before)


def measured_run(argv: list[str], log: Path, timeout: float,
                 env: dict[str, str] | None = None) -> dict:
    """Sample simultaneous process-tree RSS, never sum independent peaks."""
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("process timeout must be positive and finite")
    started = time.monotonic()
    peak, samples = 0, 0
    phase_peaks: dict[str, int] = {}
    current_phase = None
    errors: set[str] = set()
    with log.open("wb") as output, log.open("r", encoding="utf-8", errors="replace") as observer:
        process = subprocess.Popen(argv, stdout=output, stderr=subprocess.STDOUT, env=env)
        root = None
        try:
            try:
                root = psutil.Process(process.pid)
            except psutil.NoSuchProcess:
                process.wait()
            while process.poll() is None:
                for line in observer.readlines():
                    match = PHASE.search(line)
                    if match:
                        current_phase = match.group(1)
                        phase_peaks.setdefault(current_phase, 0)
                    elif TIMING.search(line):
                        current_phase = None
                total = 0
                try:
                    try:
                        children = root.children(recursive=True)
                    except psutil.AccessDenied:
                        errors.add("access_denied")
                        children = []
                    tree = [root, *children]
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
                if root is not None:
                    for child in root.children(recursive=True):
                        try:
                            child.kill()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            finally:
                process.kill()
                process.wait()
            raise
    return {"returncode": process.returncode, "wall_seconds": time.monotonic() - started,
            "sampled_process_tree_peak_rss_bytes": peak, "memory_samples": samples,
            "phase_sampled_process_tree_peak_rss_bytes":
                {phase: peak or None for phase, peak in phase_peaks.items()},
            "memory_sampling_errors": sorted(errors), "sample_interval_seconds": 0.05}


def decompiler_coverage(path: Path, phase: str, artifact_id: str | None) -> dict:
    """Count successful outputs and identify the one documented stock CRT limitation."""
    known = MSVC_CRT_BODIES.get(artifact_id)
    completed = 0
    expected_failures = []
    for record in load_export(path):
        if record.successful and record.c.strip():
            completed += 1
            continue
        address = str(record.function.entry)
        body = record.function.body_sha256
        if (known != (address, body) or expected_failures or record.completed or record.c or
                record.prototype or record.timed_out or record.cancelled or record.failed_to_start or
                record.error != MSVC_CRT_ERROR):
            raise RuntimeError(f"incomplete {phase} decompiler output at {address}; see {path}")
        expected_failures.append({"address": address, "body_sha256": body,
                                  "symbol": "__GSHandlerCheckCommon", "error": record.error})
    if not completed:
        raise RuntimeError(f"no complete {phase} decompiler output; see {path}")
    return {"function_count": completed + len(expected_failures), "completed_count": completed,
            "expected_stock_failures": expected_failures}


def verify_pair(prefix: Path, log: Path, *, artifact_id: str | None = None) -> dict:
    serial = Path(str(prefix) + ".serial.jsonl")
    parallel = Path(str(prefix) + ".parallel.jsonl")
    content = log.read_text(encoding="utf-8", errors="replace")
    if "BinaryRat exact serial/parallel comparison passed:" not in content:
        raise RuntimeError(f"postScript success marker missing; see {log}")
    if not serial.is_file() or not parallel.is_file():
        raise RuntimeError(f"expected export missing; see {log}")
    if first_differing_byte(serial, parallel) is not None:
        raise RuntimeError(f"exact output mismatch: {serial}, {parallel}")
    coverage = decompiler_coverage(serial, "serial", artifact_id)
    phases = {}
    for match in TIMING.finditer(content):
        logged_count, mode, workers, excluded, elapsed = match.groups()
        phases[mode] = {"function_count": int(logged_count), "workers": int(workers),
                        "excluded_external_count": int(excluded),
                        "export_wall_seconds": float(elapsed)}
    if set(phases) != {"serial", "parallel"}:
        raise RuntimeError(f"missing phase timings; see {log}")
    if any(phase["function_count"] != coverage["function_count"] for phase in phases.values()):
        raise RuntimeError("export count differs from parsed record count")
    return {"exact_match": True, **coverage,
            "export_sha256": sha256(serial),
            "phases": phases}


def verify_scheduled(prefix: Path, log: Path, workers: int,
                     cache_expected: str = "disabled", *, artifact_id: str | None = None) -> dict:
    """Engine-admitted decompilation must equal stock serial output byte for byte."""
    if cache_expected not in {"disabled", "cold", "warm"}:
        raise ValueError("cache_expected must be disabled, cold or warm")
    serial = Path(str(prefix) + ".serial.jsonl")
    scheduled = Path(str(prefix) + ".scheduled.jsonl")
    content = log.read_text(encoding="utf-8", errors="replace")
    if "BinaryRat exact serial/scheduled comparison passed:" not in content:
        raise RuntimeError(f"scheduled comparison marker missing; see {log}")
    if first_differing_byte(serial, scheduled) is not None:
        raise RuntimeError(f"exact output mismatch: {serial}, {scheduled}")
    summary = json.loads(Path(str(scheduled) + ".schedule.json").read_text())
    coverage = decompiler_coverage(scheduled, "scheduled",
                                   artifact_id if cache_expected == "disabled" else None)
    records = coverage["function_count"]
    cache = summary["cache"]
    if cache["enabled"] is not (cache_expected != "disabled"):
        raise RuntimeError(f"unexpected persistent cache configuration; see {log}")
    counters = ("hits", "replayed", "misses", "lookup_rejected", "stored", "store_rejected")
    if any(type(cache[name]) is not int or cache[name] < 0 for name in counters):
        raise RuntimeError(f"invalid persistent cache counters; see {log}")
    if cache_expected == "disabled":
        if any(cache[name] for name in counters):
            raise RuntimeError(f"disabled persistent cache reported activity; see {log}")
        compute_leases = records
    else:
        if cache["hits"] + cache["replayed"] + cache["misses"] != records:
            raise RuntimeError(f"cache outcomes do not cover every exported function; see {log}")
        if cache["lookup_rejected"] or cache["store_rejected"]:
            raise RuntimeError(f"unchanged fixture could not reuse/store its cache entries; see {log}")
        compute_leases = cache["misses"]
        if cache_expected == "cold" and (
                cache["misses"] != records or cache["stored"] != records or
                cache["hits"] or cache["replayed"]):
            raise RuntimeError(f"cold cache did not compute and store every function; see {log}")
        if cache_expected == "warm" and (
                cache["hits"] + cache["replayed"] != records or
                cache["misses"] or cache["stored"]):
            raise RuntimeError(f"warm cache did not avoid every compute lease; see {log}")
    expected_traces = compute_leases if cache["enabled"] else 0
    if type(summary["traced_leases"]) is not int or summary["traced_leases"] != expected_traces:
        raise RuntimeError(f"unexpected number of dependency traces collected; see {log}")
    engine = summary["engine_stats"]
    expected_statuses = {"completed": compute_leases} if compute_leases else {}
    if summary["lease_status_counts"] != expected_statuses or summary["leases"] != compute_leases:
        raise RuntimeError(f"not every lease completed: {summary['lease_status_counts']}")
    admitted = summary["engine_configuration"]["workers"]
    if (not 1 <= admitted <= workers or
            (compute_leases and not 1 <= engine["peak_running"] <= admitted) or
            (not compute_leases and engine["peak_running"] != 0)):
        raise RuntimeError(f"unexpected peak number of running decompiles; see {log}")
    if engine["running"] or engine["queued"]:
        raise RuntimeError(f"scheduler left work running or queued; see {log}")
    if (not summary["engine_configuration"]["memory_watch"] or
            summary["memory_watched_leases"] != compute_leases):
        raise RuntimeError(f"scheduled decompiler processes were not all memory-watched; see {log}")
    return {"exact_match": True, **coverage, "requested_workers": workers,
            "admitted_workers": admitted, "compute_leases": compute_leases,
            "peak_running": engine["peak_running"],
            "max_peak_resident_bytes": summary["max_peak_resident_bytes"],
            "memory_watched_leases": summary["memory_watched_leases"],
            "cache": cache}


def compare_fresh_jvm_exports(cold: Path, warm: Path) -> dict:
    """Match output and metadata across fresh JVMs, reporting local revisions.

    A Program's in-memory modification number is not a durable program identity.
    Every other exported field must match. Each JVM separately passed the
    byte-exact serial/scheduled comparison above.
    """
    revisions: Counter = Counter()
    with cold.open(encoding="utf-8") as left, warm.open(encoding="utf-8") as right:
        cold_rows = (json.loads(line) for line in left if line.strip())
        warm_rows = (json.loads(line) for line in right if line.strip())
        for before, after in zip_longest(cold_rows, warm_rows):
            if before is None or after is None:
                raise RuntimeError("cold/warm fresh JVMs exported different function coverage")
            revisions[(before.pop("revision"), after.pop("revision"))] += 1
            if before != after:
                raise RuntimeError("cold/warm fresh JVMs differ in output or stable metadata")
    if not revisions:
        raise RuntimeError("cold/warm fresh JVMs had no function coverage")
    return {"exact_bytes_including_revision": first_differing_byte(cold, warm) is None,
            "exact_output_and_metadata_except_local_revision": True,
            "revision_pairs": [{"cold": before, "warm": after, "functions": count}
                               for (before, after), count in sorted(revisions.items())]}


def check_persistent_cache(headless: Path, binary: Path, script_directory: Path | None,
                           identity: str, destination: Path, workers: int, timeout: float,
                           environment: dict[str, str]) -> dict:
    """Reopen one saved analyzed Program in a fresh JVM using its persistent cache.

    Independent imports may assign different private symbol/type identities even
    when their C text matches. Zero compute leases is therefore asserted for a
    reopened unchanged database, not for independently reconstructed analysis.
    """
    runs = {}
    exports = {}
    with tempfile.TemporaryDirectory(prefix="persistent cache-", dir=destination) as directory:
        session = Path(directory)
        projects = session / "projects"
        projects.mkdir()
        cache_env = environment | {"BINARYRAT_CACHE_DIR": str(session / "cache")}
        for state in ("cold", "warm"):
            name = f"{identity}-persistent-{state}"
            prefix, log = destination / name, destination / (name + ".log")
            for suffix in (".serial.jsonl", ".scheduled.jsonl", ".scheduled.jsonl.schedule.json"):
                Path(str(prefix) + suffix).unlink(missing_ok=True)
            argv = [str(headless), str(projects), "persistent"]
            if state == "cold":
                argv += ["-import", str(binary)]
            else:
                argv += ["-process", binary.name, "-noanalysis", "-readOnly"]
            if script_directory is not None:
                argv += ["-scriptPath", str(script_directory)]
            argv += ["-postScript", "BinaryRatExport.java", str(prefix), "compare-scheduled",
                     str(workers), "60", "128"]
            measured = measured_run(argv, log, timeout, cache_env)
            if measured["returncode"]:
                raise RuntimeError(f"Ghidra persistent {state} process failed; see {log}")
            runs[state] = {**measured, **verify_scheduled(prefix, log, workers, state)}
            exports[state] = Path(str(prefix) + ".scheduled.jsonl")
        comparison = compare_fresh_jvm_exports(exports["cold"], exports["warm"])
    return {"fresh_jvms": 2, "cache_directory_test_owned_and_removed": True,
            "saved_program_database_test_owned_reused_and_removed": True,
            "cache_directory_path_contains_space": True, "runs": runs,
            "cross_jvm_comparison": comparison}


def verify_stopped(output: Path, log: Path, expected: str) -> dict:
    """Require a real fixture decompilation to stop under the requested limit."""
    summary = json.loads(Path(str(output) + ".schedule.json").read_text(encoding="utf-8"))
    statuses = summary["lease_status_counts"]
    stopped = 0
    records = 0
    for record in load_export(output):
        records += 1
        if expected == "timed_out":
            stopped += record.timed_out and not record.completed
        else:
            stopped += (record.cancelled and not record.completed and
                        "exceeded its memory reservation" in record.error)
    if (not stopped or statuses.get(expected) != stopped or sum(statuses.values()) != records or
            set(statuses) - {"completed", expected}):
        raise RuntimeError(f"expected {expected} lease outcomes and matching export records; see {log}")
    if expected == "memory_exceeded" and (not summary["engine_configuration"]["memory_watch"] or
                                            summary["memory_watched_leases"] != records):
        raise RuntimeError(f"memory limit check requires watched decompiler processes; see {log}")
    if summary["engine_stats"]["running"] or summary["engine_stats"]["queued"]:
        raise RuntimeError(f"scheduler left work running or queued; see {log}")
    return {"limit": expected, "functions": records, "stopped": stopped}


def verify_cache_proof(report_path: Path, log: Path) -> dict:
    """Every cached result served while the program changed must equal fresh output."""
    content = log.read_text(encoding="utf-8", errors="replace")
    report = json.loads(report_path.read_text())
    if "BinaryRat cache proof passed:" not in content or not report.get("passed"):
        raise RuntimeError(f"cache proof failed; see {report_path} and {log}")
    if not report.get("injection_payload_contract", {}).get("passed"):
        raise RuntimeError(f"dynamic injection replay check missing or failed; see {report_path}")
    if not report.get("cache_resource_limits", {}).get("passed"):
        raise RuntimeError(f"cache resource limits check missing or failed; see {report_path}")
    reference_checks = [entry for entry in report["rounds"]
                        if entry.get("sentinel_dependency_tracking_only")]
    expected_reference_checks = {"add reference target dependency", "change reference target dependency",
                                 "remove reference target dependency"}
    if ({entry["name"] for entry in reference_checks} != expected_reference_checks or
            not all(entry["passed"] and entry["distinct_source_target_lines"] for entry in reference_checks)):
        raise RuntimeError("reference changes did not invalidate their target dependencies")
    rounds = [entry for entry in report["rounds"]
              if not entry.get("skipped") and not entry.get("sentinel_dependency_tracking_only")]
    if not any(entry["name"].startswith("NEGATIVE CONTROL") and entry["vouched_but_stale"] > 0
               for entry in rounds):
        raise RuntimeError("negative control did not detect the hidden change")
    if any(entry["served_different_from_fresh"] for entry in rounds
           if not entry["name"].startswith("NEGATIVE CONTROL")):
        raise RuntimeError("a cached result differed from fresh decompilation")
    return {"function_count": report["functions"], "rounds": len(rounds),
            "reference_dependency_checks": len(reference_checks),
            "skipped_rounds": [entry["name"] for entry in report["rounds"] if entry.get("skipped")],
            "timing": report.get("timing")}


def check_redirected_call_cache(headless: Path, script_directory: Path, destination: Path,
                                engine: Path, timeout: float, environment: dict[str, str]) -> dict:
    """Prove that in-session fixup edits invalidate an already redirected caller."""
    report_path = destination / "redirected-call-cache.json"
    log = destination / "redirected-call-cache.log"
    report_path.unlink(missing_ok=True)
    with tempfile.TemporaryDirectory(prefix="redirected call-", dir=destination) as directory:
        session = Path(directory)
        measured = measured_run([
            str(headless), str(session), "fixture", "-deleteProject", "-scriptPath",
            str(script_directory), "-preScript", "BinaryRatRedirectedCallCheck.java",
            str(engine), str(session / "cache"), str(report_path)],
            log, timeout, environment)
    if (measured["returncode"] or not report_path.is_file() or
            "BinaryRat redirected call cache checks passed" not in
            log.read_text(encoding="utf-8", errors="replace")):
        raise RuntimeError(f"redirected call cache proof did not complete; see {log}")
    proof = json.loads(report_path.read_text(encoding="utf-8"))
    expected = {"stock_output_changed": True, "add_fixup": "MISS", "clear_fixup": "MISS",
                "unrelated_entry_unchanged": True, "precise_invalidation": True}
    if proof.get("passed") is not True or any(proof.get(case) != expected for case in (
            "primary_call", "explicit_call_override", "inherited_thunk_fixup")):
        raise RuntimeError(f"redirected call cache proof failed; see {report_path} and {log}")
    return {**proof, "wall_seconds": measured["wall_seconds"]}


def check_call_sites(headless: Path, script_directory: Path, destination: Path, timeout: float,
                     environment: dict[str, str]) -> dict:
    """Run the call-site edge-case proof and parse its report with the Python decoder.

    A checkout script directory has no BinaryRat.jar, so the proof reports table=false;
    verify_extension.py runs the same proof against the installed table.
    """
    report_path = destination / "call-sites.json"
    log = destination / "call-sites.log"
    report_path.unlink(missing_ok=True)
    with tempfile.TemporaryDirectory(prefix="call sites-", dir=destination) as directory:
        measured = measured_run([
            str(headless), directory, "fixture", "-deleteProject", "-scriptPath", str(script_directory),
            "-preScript", "BinaryRatCallSitesProof.java", str(report_path)], log, timeout, environment)
    content = log.read_text(encoding="utf-8", errors="replace")
    passed = re.findall(r"BINARYRAT_CALL_SITES_OK sites=(\d+) statuses=6 .* checks=(\d+) .* "
                        r"table=(true|false)", content)
    if measured["returncode"] or "REPORT SCRIPT ERROR" in content or len(passed) != 1 or not report_path.is_file():
        raise RuntimeError(f"call-site proof failed; see {log}")
    parsed = load_call_sites_report(report_path)
    if len(parsed.sites) != int(passed[0][0]) or len(parsed.sites) != 10:
        raise RuntimeError(f"call-site report does not match the proof; see {report_path}")
    return {"passed": True, "sites": len(parsed.sites), "cancellation_checks": int(passed[0][1]),
            "statuses": sorted({site.status for site in parsed.sites}), "table": passed[0][2] == "true",
            "log": log.name, "wall_seconds": measured["wall_seconds"]}


def check_stock_verified(headless: Path, binary: Path, scripts: Path, destination: Path,
                         timeout: float, environment: dict[str, str]) -> dict:
    """Compare verified output with a separate stock pass and probe fail-closed behavior."""
    with tempfile.TemporaryDirectory(prefix="stock verified-", dir=destination) as directory:
        workspace = Path(directory)
        project = [str(headless), str(workspace), "fixture", "-scriptPath", str(scripts)]

        def script(output: Path, mode: str) -> list[str]:
            return ["-postScript", "BinaryRatExport.java", str(output), mode, "2", "60", "16"]

        verified, reference = workspace / "verified.jsonl", workspace / "reference.jsonl"
        log = destination / "stock-verified.log"
        measured = measured_run(project + ["-import", str(binary)] +
                                script(verified, "stock-verified") + script(reference, "serial"),
                                log, timeout, environment)
        if (measured["returncode"] or "BinaryRat stock verification passed:" not in
                log.read_text(encoding="utf-8", errors="replace") or
                first_differing_byte(verified, reference) is not None):
            raise RuntimeError(f"stock-verified export did not match the independent stock pass; see {log}")
        rows = list(load_export(verified))
        proof = json.loads(Path(str(verified) + ".parity.json").read_text(encoding="utf-8"))
        counts = [proof[key] for key in ("scheduled_matches", "stock_fallbacks")]
        if (not rows or not all(row.successful for row in rows) or
                any(type(count) is not int or count < 0 for count in counts) or
                proof["reference"] != "stock-reused-serial" or
                proof["output_sha256"] != sha256(verified) or
                proof["function_count"] != sum(counts) or sum(counts) != len(rows)):
            raise RuntimeError(f"invalid stock verification evidence; see {log}")

        stopped = workspace / "stopped.jsonl"
        sidecar = Path(str(stopped) + ".parity.json")
        stopped.write_bytes(b"existing export\n")
        sidecar.write_bytes(b"existing report\n")
        stop_log = destination / "stock-verified-stopped.log"
        process = project + ["-process", binary.name, "-noanalysis", "-readOnly"]
        measured_run(process + script(stopped, "stock-verified"), stop_log, timeout,
                     environment | {"BINARYRAT_LEASE_TIMEOUT_MS": "1"})
        if ("Cannot verify interrupted leases:" not in stop_log.read_text(
                encoding="utf-8", errors="replace") or
                stopped.read_bytes() != b"existing export\n" or
                sidecar.read_bytes() != b"existing report\n"):
            raise RuntimeError(f"interrupted verification replaced an existing export; see {stop_log}")

        blocked = workspace / "blocked.jsonl"
        blocked.write_bytes(b"existing export\n")
        Path(str(blocked) + ".parity.json").mkdir()
        blocked_log = destination / "stock-verified-report-collision.log"
        measured_run(process + script(blocked, "stock-verified"), blocked_log, timeout, environment)
        content = blocked_log.read_text(encoding="utf-8", errors="replace")
        if ("Choose a regular output file:" not in content or "BinaryRat export starting" in content or
                blocked.read_bytes() != b"existing export\n"):
            raise RuntimeError(f"invalid parity report destination was not rejected; see {blocked_log}")
    return {**proof, "exact_independent_stock_bytes": True,
            "interrupted_export_preserved": True, "report_collision_rejected": True}


def check_writeback_transactions(headless: Path, destination: Path, timeout: float,
                                 environment: dict[str, str]) -> dict:
    log = destination / "writeback-transaction-proof.log"
    with tempfile.TemporaryDirectory(prefix="writeback proof ", dir=destination) as directory:
        measured = measured_run([
            str(headless), directory, "transaction-proof", "-scriptPath",
            str(PROJECT / "binaryrat/benchmarks/ghidra_scripts"),
            "-preScript", "BinaryRatWriteBackTransactionProof.java", "-deleteProject",
        ], log, timeout, environment)
    content = log.read_text(encoding="utf-8", errors="replace")
    if (measured["returncode"] or "REPORT SCRIPT ERROR" in content or
            "BINARYRAT_WRITEBACK_TRANSACTION_PROOF_PASS" not in content):
        raise RuntimeError(f"Ghidra write-back transaction regression failed (see {log})")
    return {"passed": True, "wall_seconds": measured["wall_seconds"], "log": log.name}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ghidra", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workers", type=int, nargs="+", default=[1, 2, 4])
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--timeout", type=float, default=1800)
    parser.add_argument("--engine", type=Path,
                        help="binaryrat-engine; adds scheduled-decompile and live-cache proof runs")
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
                  "No type precision/recall or auto-analysis acceleration claim is made.",
                  "Scheduled and cache-proof runs use small fixtures; they prove exactness "
                  "and enforcement, not speed on large programs."]}
    engine = args.engine.resolve() if args.engine else None
    if engine:
        if not engine.is_file():
            raise RuntimeError(f"engine not found: {engine}")
        os.environ["BINARYRAT_ENGINE"] = str(engine)
        report["scheduled_runs"], report["cache_proofs"], report["limit_checks"] = [], [], []
        report["persistent_cache_checks"] = []
    # Baseline and limit checks explicitly exercise the optional-cache-unset path,
    # independent of an operator's environment. Only the owned cold/warm check
    # opts in to persistence; it never touches an existing user cache directory.
    environment = os.environ.copy()
    environment.pop("BINARYRAT_CACHE_DIR", None)
    try:
        if engine:
            report["writeback_transactions"] = check_writeback_transactions(
                headless, destination, args.timeout, environment)
            print("PASS Ghidra write-back abort, protection, and native undo/redo", flush=True)
            report["redirected_call_cache"] = check_redirected_call_cache(
                headless, PROJECT / "binaryrat/bridge/ghidra_scripts",
                destination, engine, args.timeout, environment)
            print("PASS live cache invalidation after editing an original call fixup", flush=True)
            report["call_sites"] = check_call_sites(
                headless, PROJECT / "binaryrat/bridge/ghidra_scripts", destination, args.timeout, environment)
            print("PASS call sites: statuses, thunks, limits, cancellation and program changes", flush=True)
        for artifact in manifest["artifacts"]:
            binary = (corpus_root / artifact["binary"]).resolve()
            if corpus_root.resolve() not in binary.parents:
                raise RuntimeError("corpus binary is outside its declared root")
            if sha256(binary) != artifact["binary_sha256"]:
                raise RuntimeError(f"corpus binary hash mismatch: {binary}")
            identity = hashlib.sha256(artifact["id"].encode()).hexdigest()[:12]

            def headless_script(name: str, filename: str, *script_args: str) -> list[str]:
                return [str(headless), str(projects), name, "-import", str(binary),
                        "-overwrite", "-scriptPath", str(PROJECT / "binaryrat/bridge/ghidra_scripts"),
                        "-postScript", filename, *script_args, "-deleteProject"]

            def export(name: str, output: Path, mode: str, workers: int) -> list[str]:
                return headless_script(name, "BinaryRatExport.java", str(output), mode,
                                       str(workers), "60", "128")
            for workers in args.workers:
                for repetition in range(args.repetitions):
                    name = f"{identity}-w{workers}-r{repetition}"
                    prefix, log = destination / name, destination / (name + ".log")
                    # Never accept stale files from a prior run as fresh success.
                    for suffix in (".serial.jsonl", ".parallel.jsonl"):
                        Path(str(prefix) + suffix).unlink(missing_ok=True)
                    mode = "compare" if repetition % 2 == 0 else "compare-reverse"
                    measured = measured_run(export(name, prefix, mode, workers), log, args.timeout,
                                            environment)
                    if measured["returncode"]:
                        raise RuntimeError(f"Ghidra process failed; see {log}")
                    pair = verify_pair(prefix, log, artifact_id=artifact["id"])
                    if pair["phases"]["serial"]["workers"] != 1 or \
                            pair["phases"]["parallel"]["workers"] != workers:
                        raise RuntimeError(f"logged worker counts differ from requested configuration; see {log}")
                    report["runs"].append({"artifact_id": artifact["id"], "workers": workers,
                                           "repetition": repetition, "phase_order": mode,
                                           **measured, **pair})
                    print(f"PASS {artifact['id']} workers={workers} repetition={repetition} "
                          f"functions={pair['function_count']} completed={pair['completed_count']}", flush=True)
            if engine:
                workers = max(args.workers)
                name = f"{identity}-scheduled-w{workers}"
                prefix, log = destination / name, destination / (name + ".log")
                for suffix in (".serial.jsonl", ".scheduled.jsonl", ".scheduled.jsonl.schedule.json"):
                    Path(str(prefix) + suffix).unlink(missing_ok=True)
                measured = measured_run(export(name, prefix, "compare-scheduled", workers), log,
                                        args.timeout, environment)
                if measured["returncode"]:
                    raise RuntimeError(f"Ghidra process failed; see {log}")
                scheduled = verify_scheduled(prefix, log, workers, artifact_id=artifact["id"])
                report["scheduled_runs"].append({"artifact_id": artifact["id"], **measured, **scheduled})
                print(f"PASS {artifact['id']} scheduled workers={workers} "
                      f"functions={scheduled['function_count']} completed={scheduled['completed_count']}", flush=True)
                name = f"{identity}-cache-proof"
                proof, log = destination / (name + ".json"), destination / (name + ".log")
                proof.unlink(missing_ok=True)
                measured = measured_run(export(name, proof, "cache-proof", 1), log, args.timeout,
                                        environment)
                if measured["returncode"]:
                    raise RuntimeError(f"Ghidra process failed; see {log}")
                report["cache_proofs"].append({"artifact_id": artifact["id"],
                                               "wall_seconds": measured["wall_seconds"],
                                               **verify_cache_proof(proof, log)})
                print(f"PASS {artifact['id']} cache proof", flush=True)
                if not report["persistent_cache_checks"]:
                    checked = check_persistent_cache(
                        headless, binary, PROJECT / "binaryrat/bridge/ghidra_scripts", identity,
                        destination, workers, args.timeout, environment)
                    report["persistent_cache_checks"].append({"artifact_id": artifact["id"], **checked})
                    print(f"PASS {artifact['id']} persistent cache cold/warm fresh JVMs", flush=True)
                if "stock_verified" not in report:
                    report["stock_verified"] = check_stock_verified(
                        headless, binary, PROJECT / "binaryrat/bridge/ghidra_scripts",
                        destination, args.timeout, environment)
                    print(f"PASS {artifact['id']} stock-verified export and failure cases", flush=True)
                if not report["limit_checks"]:
                    for expected, overrides in (
                        ("timed_out", {"BINARYRAT_LEASE_TIMEOUT_MS": "1"}),
                        ("memory_exceeded", {"BINARYRAT_WORKER_BYTES": str(1024 * 1024),
                                             "BINARYRAT_LEASE_TIMEOUT_MS": "60000"}),
                    ):
                        name = f"{identity}-limit-{expected}"
                        output, log = destination / (name + ".jsonl"), destination / (name + ".log")
                        output.unlink(missing_ok=True)
                        Path(str(output) + ".schedule.json").unlink(missing_ok=True)
                        measured = measured_run(export(name, output, "scheduled", 1), log,
                                                args.timeout, environment | overrides)
                        if measured["returncode"]:
                            raise RuntimeError(f"Ghidra process failed; see {log}")
                        report["limit_checks"].append({"artifact_id": artifact["id"],
                                                       **verify_stopped(output, log, expected)})
                        print(f"PASS {artifact['id']} scheduler {expected}", flush=True)
                    name = f"{identity}-lease-lifecycle"
                    log = destination / (name + ".log")
                    measured = measured_run(headless_script(name, "BinaryRatLeaseChecks.java"),
                                            log, args.timeout, environment)
                    if (measured["returncode"] or "BinaryRat lease lifecycle checks passed" not in
                            log.read_text(encoding="utf-8", errors="replace")):
                        raise RuntimeError(f"Ghidra lease lifecycle checks failed; see {log}")
                    report["lease_lifecycle"] = {"artifact_id": artifact["id"], "passed": True}
                    print(f"PASS {artifact['id']} lease lifecycle", flush=True)
        report["correctness_passed"] = True
        report["memory_evidence_complete"] = all(
            not run["memory_sampling_errors"] and all(
                run["phase_sampled_process_tree_peak_rss_bytes"].get(phase) is not None
                for phase in ("serial", "parallel"))
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
