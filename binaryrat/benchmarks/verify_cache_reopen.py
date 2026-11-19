#!/usr/bin/env python3
# Copyright 2026 YurilLAB
# SPDX-License-Identifier: Apache-2.0
"""Check persistent scheduled export across an edit made with the engine offline."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

from verify_ghidra import PROJECT, measured_run


def exported_rows(prefix, log):
    content = log.read_text(encoding="utf-8", errors="replace")
    if "BinaryRat exact serial/scheduled comparison passed:" not in content:
        raise RuntimeError(f"stock parity check failed; see {log}")
    serial = prefix.with_suffix(".serial.jsonl")
    scheduled = prefix.with_suffix(".scheduled.jsonl")
    if serial.read_bytes() != scheduled.read_bytes():
        raise RuntimeError(f"scheduled output differs from stock; see {log}")
    rows = [json.loads(line) for line in serial.read_text(encoding="utf-8").splitlines()]
    if not rows or any(not row["completed"] or not row["c"] for row in rows):
        raise RuntimeError(f"fixture did not decompile successfully; see {log}")
    summary = json.loads(Path(str(scheduled) + ".schedule.json").read_text(encoding="utf-8"))
    return rows, summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ghidra", type=Path, required=True)
    parser.add_argument("--engine", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads(args.corpus.read_text(encoding="utf-8"))
    if manifest.get("status") != "passed" or not manifest.get("artifacts"):
        raise RuntimeError("corpus manifest is incomplete or failed")
    artifact = manifest["artifacts"][0]
    corpus_root = Path(manifest["root"]).resolve()
    fixture = (corpus_root / artifact["binary"]).resolve()
    if corpus_root not in fixture.parents:
        raise RuntimeError("fixture is outside the corpus root")
    digest = hashlib.sha256(fixture.read_bytes()).hexdigest()
    if digest != artifact["binary_sha256"]:
        raise RuntimeError("fixture hash mismatch")

    launcher = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
    headless = args.ghidra.resolve() / "support" / launcher
    scripts = PROJECT / "binaryrat/bridge/ghidra_scripts"
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    report_path = output / "report.json"
    report_path.unlink(missing_ok=True)
    with tempfile.TemporaryDirectory(prefix="binaryrat reopen ", dir=output) as workspace:
        root = Path(workspace)
        cache = root / "engine cache"
        env = os.environ | {"BINARYRAT_ENGINE": str(args.engine.resolve()),
                            "BINARYRAT_CACHE_DIR": str(cache)}

        def run(label, *arguments, environment=env):
            log = output / (label + ".log")
            result = measured_run([str(headless), str(root), "fixture", "-scriptPath", str(scripts),
                                   *arguments], log, 300, environment)
            return log, result["returncode"]

        cold = root / "cold"
        cold_log, status = run("cold", "-import", str(fixture), "-postScript", "BinaryRatExport.java",
                               str(cold), "compare-scheduled", "2", "60", "16")
        if status:
            raise RuntimeError(f"cold fixture run failed; see {cold_log}")
        before, cold_summary = exported_rows(cold, cold_log)
        # Choose a user-visible identifier in stock output. A renamed thunk may
        # render as the target instead, so the fixture script rejects thunks.
        candidate = next((row for row in before if row["name"].startswith("FUN_") and re.search(
            r"\b" + re.escape(row["name"]) + r"\s*\(", row["c"])), None)
        if candidate is None:
            raise RuntimeError("fixture needs a local function named in stock C output")
        renamed = "binaryrat_reopened_" + digest[:16]
        process = ("-process", fixture.name, "-noanalysis")
        # No engine has the cache open while Ghidra edits its saved Program.
        edit_log, status = run("edit", *process, "-postScript", "BinaryRatCacheFixtureEdit.java",
                               digest, candidate["address_space"], candidate["address"], renamed)
        if status or f"BinaryRat fixture function renamed: {renamed}" not in edit_log.read_text(
                encoding="utf-8", errors="replace"):
            raise RuntimeError(f"offline fixture edit failed; see {edit_log}")

        reopened = root / "reopened"
        reopen_log, status = run("reopened", *process, "-readOnly", "-postScript",
                                  "BinaryRatExport.java", str(reopened), "compare-scheduled", "2", "60", "16")
        if status:
            raise RuntimeError(f"reopen run failed; see {reopen_log}")
        after, reopened_summary = exported_rows(reopened, reopen_log)
        edited = next((row for row in after if (row["address_space"], row["address"]) ==
                       (candidate["address_space"], candidate["address"])), None)
        cache_stats = reopened_summary["cache"]
        if not edited or edited["program_id"] != candidate["program_id"] or \
                edited["body_sha256"] != candidate["body_sha256"] or edited["name"] != renamed or \
                renamed not in edited["c"] or edited["c"] == candidate["c"]:
            raise RuntimeError(f"rename was not preserved in fresh output at the original key; see {reopen_log}")
        if (cold_summary["cache"]["stored"] == 0 or cache_stats["misses"] == 0 or
                cache_stats["replayed"] == 0 or reopened_summary["leases"] != cache_stats["misses"]):
            raise RuntimeError(f"reopen must refresh changed output and reuse unaffected entries; see {reopen_log}")

        unavailable = root / "unavailable cache"
        unavailable.write_bytes(b"preserve this file\n")
        rejected = root / "rejected.jsonl"
        reject_log, _ = run("unavailable-cache", *process, "-readOnly", "-postScript",
                            "BinaryRatExport.java", str(rejected), "scheduled", "2", "60", "16",
                            environment=env | {"BINARYRAT_CACHE_DIR": str(unavailable)})
        if (rejected.exists() or Path(str(rejected) + ".schedule.json").exists() or
                unavailable.read_bytes() != b"preserve this file\n" or
                "ERROR" not in reject_log.read_text(encoding="utf-8", errors="replace")):
            raise RuntimeError(f"unavailable cache did not fail cleanly; see {reject_log}")

        stopped = root / "stopped.jsonl"
        stopped_log, status = run("stopped", *process, "-readOnly", "-postScript",
                                  "BinaryRatExport.java", str(stopped), "scheduled", "1", "60", "16",
                                  environment=env | {"BINARYRAT_CACHE_DIR": str(root / "stopped cache"),
                                                     "BINARYRAT_LEASE_TIMEOUT_MS": "1"})
        if status or not stopped.is_file():
            raise RuntimeError(f"persistent deadline probe failed; see {stopped_log}")
        stopped_rows = [json.loads(line) for line in stopped.read_text(encoding="utf-8").splitlines()]
        stopped_summary = json.loads(Path(str(stopped) + ".schedule.json").read_text(encoding="utf-8"))
        deadline_rows = [row for row in stopped_rows if row["timed_out"]]
        deadline_cache = stopped_summary["cache"]
        if (not deadline_rows or any(row["completed"] or row["c"] for row in deadline_rows) or
                deadline_cache["store_rejected"] < len(deadline_rows) or
                deadline_cache["engine_stats"]["entries"] != deadline_cache["stored"] or
                deadline_cache["stored"] > sum(row["completed"] for row in stopped_rows)):
            raise RuntimeError(f"deadline responses must not enter the persistent cache; see {stopped_log}")

    report = {"passed": True, "fixture": artifact["id"], "unchanged_executable_sha256": digest,
              "stock_parity_after_offline_edit": True, "cold_stored": cold_summary["cache"]["stored"],
              "reopened_misses": cache_stats["misses"], "reopened_replays": cache_stats["replayed"],
              "unavailable_cache_rejected": True, "deadline_results_not_cached": len(deadline_rows)}
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
