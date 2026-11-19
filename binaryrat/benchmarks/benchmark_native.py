#!/usr/bin/env python3
# Copyright 2026 YurilLAB
# SPDX-License-Identifier: Apache-2.0
"""Measure the implemented native artifact roundtrip, without a JVM-speed claim."""
import argparse
import hashlib
import json
from pathlib import Path
import statistics
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "python/src"))
from binaryrat import EngineClient


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", type=Path, required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--export", type=Path)
    source.add_argument("--exports-dir", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=100)
    args = parser.parse_args()
    if args.repetitions < 1:
        parser.error("repetitions must be positive")
    if args.exports_dir:
        exports = sorted(args.exports_dir.glob("*.serial.jsonl"))
        if not exports:
            raise RuntimeError("verification directory contains no serial export")
        args.export = exports[0]
    data = args.export.read_bytes()
    rows = [json.loads(line) for line in data.decode("utf-8").splitlines()]
    if not rows or not all(row.get("completed") and row.get("c") for row in rows):
        raise RuntimeError("requires a nonempty successful real Ghidra export")
    snapshot = hashlib.sha256(data).hexdigest()
    keys = [{"schema_version": 1, "ghidra_version": "12.2", "program_id": row["program_id"],
             "revision": row["revision"], "address_space": row["address_space"],
             "address": row["address"], "body_sha256": row["body_sha256"],
             "options_digest": hashlib.sha256(b"BinaryRatExport-v1-defaults").hexdigest(),
             "snapshot_sha256": snapshot} for row in rows]
    samples = []
    with tempfile.TemporaryDirectory(prefix="binaryrat-benchmark-") as root:
        with EngineClient(args.engine.resolve(), cache_dir=Path(root) / "cache") as client:
            client.ping()
            started = time.perf_counter()
            for key, row in zip(keys, rows):
                client.cache_put(key, row, dependencies=["snapshot:" + snapshot])
            store_seconds = time.perf_counter() - started
            for repetition in range(args.repetitions):
                key, expected = keys[repetition % len(keys)], rows[repetition % len(rows)]
                started = time.perf_counter()
                hit = client.cache_get(key)
                samples.append(time.perf_counter() - started)
                if not hit["hit"] or hit["value"] != expected:
                    raise RuntimeError("cache changed exact exported evidence")
        # This second process proves stored records outlive the first process.
        with EngineClient(args.engine.resolve(), cache_dir=Path(root) / "cache") as client:
            if client.cache_get(keys[0])["value"] != rows[0]:
                raise RuntimeError("cache persistence failed")
            invalidated = client.cache_invalidate(["snapshot:" + snapshot])["removed"]
            if invalidated != len(keys) or client.cache_get(keys[0])["hit"]:
                raise RuntimeError("dependency invalidation failed")
    report = {"schema_version": 1, "scope": "native JSONL artifact cache roundtrip",
              "source_export_sha256": snapshot, "function_count": len(rows),
              "put_total_seconds": store_seconds, "get_samples_seconds": samples,
              "get_median_seconds": statistics.median(samples),
              "restart_persistence_verified": True, "dependency_invalidation_verified": True,
              "limitations": ["Not a decompilation, type-accuracy, JVM-daemon or auto-analysis benchmark.",
                              "Snapshot digest here is an evidence-file identity, not live Program invalidation."]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Native cache: {len(rows)} records; median get {statistics.median(samples)*1000:.3f} ms")


if __name__ == "__main__":
    main()
