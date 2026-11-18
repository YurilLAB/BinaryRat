#!/usr/bin/env python3
# Copyright 2026 YurilLAB
# SPDX-License-Identifier: Apache-2.0
"""Compare stock and BinaryRat no-return decisions on a controlled x86-64 Program."""

import argparse
import hashlib
import os
from pathlib import Path

from verify_ghidra import measured_run


def run(installation: Path, output: Path, label: str, timeout: int) -> bytes:
    launcher = installation.resolve() / "support" / (
        "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
    if not launcher.is_file():
        raise FileNotFoundError(launcher)
    project = output / label
    project.mkdir()
    log = project / "headless.log"
    report = project / "effects.txt"
    scripts = Path(__file__).resolve().parent / "ghidra_scripts"
    run_values = measured_run([
        str(launcher), str(project), "fixture", "-import", str(output / "seed.bin"),
        "-loader", "BinaryLoader", "-processor", "x86:LE:64:default", "-cspec", "gcc",
        "-noanalysis", "-max-cpu", "1", "-scriptPath", str(scripts),
        "-postScript", "BinaryRatNoReturnParity.java", str(report), "-deleteProject",
    ], log, timeout, os.environ | {"GHIDRA_HEADLESS_MAXMEM": "512M",
                                  "XDG_CONFIG_HOME": str(project / "settings"),
                                  "XDG_CACHE_HOME": str(project / "cache")})
    messages = log.read_text(encoding="utf-8", errors="replace")
    if (run_values["returncode"] or not report.is_file() or
            "BINARYRAT_NO_RETURN_PARITY passed" not in messages or "REPORT SCRIPT ERROR" in messages):
        raise RuntimeError(f"{label} fixture failed. See {log}")
    return report.read_bytes()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stock-ghidra", type=Path, required=True)
    parser.add_argument("--candidate-ghidra", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()
    if args.timeout < 1:
        parser.error("--timeout must be positive")
    output = args.output.resolve()
    output.mkdir(parents=True)
    (output / "seed.bin").write_bytes(b"\xc3")
    stock = run(args.stock_ghidra, output, "stock", args.timeout)
    candidate = run(args.candidate_ghidra, output, "candidate", args.timeout)
    if stock != candidate:
        raise RuntimeError(f"Stock and candidate no-return effects differ. See {output}")
    print(f"Exact no-return fixture parity, SHA-256 {hashlib.sha256(stock).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
