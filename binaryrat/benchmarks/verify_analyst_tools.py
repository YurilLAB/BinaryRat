#!/usr/bin/env python3
# Copyright 2026 YurilLAB
# SPDX-License-Identifier: Apache-2.0
"""Exercise the installed analyst tools on the small Ghidra integration fixture."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time


def invoke(tool, *args, status=0):
    command = shutil.which(tool)
    if command is None:
        raise RuntimeError(f"{tool} is unavailable. Install binaryrat/python first.")
    start = time.perf_counter()
    run = subprocess.run([command, *args], capture_output=True, timeout=60, encoding="utf-8",
                         env={**os.environ, "PYTHONUTF8": "1"})
    elapsed = time.perf_counter() - start
    if run.returncode != status:
        raise RuntimeError(f"{tool} returned {run.returncode}, expected {status}: {run.stderr}")
    return run.stdout, elapsed


def read_fixture(path):
    # These are the controlled corpus prints, not the large-binary benchmark.
    with path.open("rb") as stream:
        data = stream.read(2 * 1024 * 1024 + 1)
    if len(data) > 2 * 1024 * 1024:
        raise ValueError(f"{path} exceeds the small fixture size")
    return data


def entries(data):
    rows = {}
    for line in data.splitlines():
        row = json.loads(line)
        key = row["address_space"], format(int(row["address"], 16), "x")
        if key in rows:
            raise ValueError(f"Duplicate fixture function at {key}")
        rows[key] = row
    return rows


def verify(exports, layout_path):
    deadline, = exports.glob("*-limit-timed_out.jsonl")
    prefix = deadline.name.removesuffix("-limit-timed_out.jsonl")
    baseline = exports / f"{prefix}-persistent-cold.serial.jsonl"
    reopened = exports / f"{prefix}-persistent-warm.scheduled.jsonl"
    inputs = {path: read_fixture(path) for path in (baseline, reopened, deadline, layout_path)}
    old, late = entries(inputs[baseline]), entries(inputs[deadline])
    if not old or old.keys() != late.keys():
        raise ValueError("Baseline and timeout captures need matching nonempty coverage")

    layout = json.loads(inputs[layout_path])
    identity = layout["program_id"]
    if any(row["program_id"] != identity for row in old.values()):
        raise ValueError("The layout and baseline were captured from different executables")
    same, same_time = invoke("binaryrat-diff", baseline, reopened, "--json")
    same = json.loads(same)
    if (same["schema_version"] != 1 or same["program_id"] != identity or same["changes"] or
            same["counts"] != {"added": 0, "removed": 0, "changed": 0, "unchanged": len(old)}):
        raise ValueError("The diff tool reported a change on the unedited, reopened Program")

    different, diff_time = invoke("binaryrat-diff", baseline, deadline, "--json", status=1)
    diff = json.loads(different)
    fields = ("name", "body_sha256", "body_ranges", "prototype", "c", "completed", "timed_out",
              "cancelled", "failed_to_start", "error")
    expected = {}
    for entry, before in old.items():
        after = late[entry]
        changed = {field for field in fields if before[field] != after[field]}
        if changed:
            expected[entry] = changed
    count = len(expected)
    if not any({"completed", "timed_out", "c"} <= changes for changes in expected.values()):
        raise ValueError("The timeout capture lacks a completed-to-timed-out decompilation")
    expected_counts = {"added": 0, "removed": 0, "changed": count, "unchanged": len(old) - count}
    if (diff["schema_version"] != 1 or diff["program_id"] != identity or
            diff["counts"] != expected_counts or len(diff["changes"]) != count):
        raise ValueError("The diff disagrees with the independently compared timeout capture")
    for row in diff["changes"]:
        key = (row["address_space"], row["address"])
        if (row["kind"] != "changed" or set(row["fields"]) != expected.pop(key) or
                row["before_name"] != old[key]["name"] or row["after_name"] != late[key]["name"]):
            raise ValueError(f"Wrong diff for fixture function {key}")

    # The corpus read_packed fixture reads four bytes at +1 behind its one-byte tag.
    text, lookup_time = invoke("binaryrat-explain", layout_path, "--offset", "0x1")
    reads = [obs for obs in layout["observations"] if obs["operation"] == "LOAD" and
             obs["offset"] == 1 and obs["width"] == 4]
    if layout["function"]["name"] != "read_packed" or not reads:
        raise ValueError("Expected the installed read_packed layout fixture")
    sites = [f"LOAD at {obs['address_space']}:{obs['address']} (p-code {obs['pcode_order']})"
             for obs in reads]
    if (identity not in text or "Field +0x1, 4 bytes" not in text or "Field +0x0," in text or
            any(site not in text for site in sites)):
        raise ValueError("The selected field explanation disagrees with recorded p-code evidence")

    return {
        "passed": True, "program_id": identity, "functions": len(old), "changed": count,
        "layout_citations": sites,
        "inputs": [{"name": path.name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                   for path, data in inputs.items()],
        "cli_wall_seconds_including_startup": {
            "unchanged": same_time, "changed": diff_time, "field_lookup": lookup_time,
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exports-dir", type=Path, required=True, help="output of verify_ghidra.py")
    parser.add_argument("--layout", type=Path, required=True,
                        help="installed-layout.json from verify_extension.py")
    parser.add_argument("--output", type=Path, required=True, help="new JSON evidence file")
    args = parser.parse_args()
    report = verify(args.exports_dir, args.layout)
    with args.output.open("x", encoding="utf-8") as out:
        out.write(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
