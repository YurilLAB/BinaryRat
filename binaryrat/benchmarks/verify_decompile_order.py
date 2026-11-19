#!/usr/bin/env python3
# Copyright 2026 YurilLAB
# SPDX-License-Identifier: Apache-2.0
"""Check that the source-built decompiler output does not depend on decompile order.

The fixture is gcc 15.2 -O1 x86-64 code for:

    struct P16 { long a; long b; };   struct P12 { long a; int b; };
    struct P16 g16(long x);           struct P12 g12(long x);
    long first16(long x) { P16 p = g16(x); P12 q = g12(p.a + p.b); ... }
    long first12(long x) { P12 q = g12(x); P16 p = g16(q.a + q.b); ... }

Each caller joins RDX:RAX and EDX:RAX return values, in opposite first-use order.
Official Ghidra keeps join records across functions in one native process, so a
reused process can name a caller's temporaries differently from a new process.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re

from verify_ghidra import measured_run

FIXTURE = bytes.fromhex(
    "f30f1efa488d5701488d047f4892c3"
    "f30f1efa488d47f9ba0000000083f7054889d148be00000000ffffffff4821f14809f94889cac3"
    "f30f1efa55534883ec08e8bbffffff4889c34889d5488d3c10e8bbffffff480fafd84801eb4863d2"
    "488d04134883c4085b5dc3"
    "f30f1efa55534883ec08e897ffffff4889c34863ea488d7c0500e878ffffff480fafd84801d3488d04"
    "2b4883c4085b5dc3")
FUNCTIONS = ("g16", "g12", "first16", "first12")
PHASES = ("forward", "reverse", "fresh")


def run(installation: Path, output: Path, label: str, timeout: int) -> dict[tuple[str, str], str]:
    launcher = installation.resolve() / "support" / (
        "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
    if not launcher.is_file():
        raise FileNotFoundError(launcher)
    project = output / label
    project.mkdir()
    log = project / "headless.log"
    report = project / "digests.tsv"
    scripts = Path(__file__).resolve().parent / "ghidra_scripts"
    result = measured_run([
        str(launcher), str(project), "fixture", "-import", str(output / "fixture.bin"),
        "-loader", "BinaryLoader", "-processor", "x86:LE:64:default", "-cspec", "gcc",
        "-noanalysis", "-scriptPath", str(scripts),
        "-postScript", "BinaryRatDecompileOrder.java", str(report), "-deleteProject",
    ], log, timeout, os.environ | {"GHIDRA_HEADLESS_MAXMEM": "512M",
                                  "XDG_CONFIG_HOME": str(project / "settings"),
                                  "XDG_CACHE_HOME": str(project / "cache")})
    messages = log.read_text(encoding="utf-8", errors="replace")
    expected = len(FUNCTIONS) * len(PHASES)
    if (result["returncode"] or not report.is_file() or
            messages.count(f"BINARYRAT_DECOMPILE_ORDER passed {expected} decompilations") != 1 or
            "REPORT SCRIPT ERROR" in messages or re.search(r"^(?:ERROR|FATAL) ", messages, re.MULTILINE)):
        raise RuntimeError(f"{label} fixture failed. See {log}")
    digests = {}
    for line in report.read_text(encoding="utf-8").splitlines():
        phase, name, digest = line.split("\t")
        if (phase not in PHASES or name not in FUNCTIONS or (phase, name) in digests or
                not re.fullmatch("[0-9a-f]{64}", digest)):
            raise ValueError(f"Invalid digest row in {report}: {line!r}")
        digests[phase, name] = digest
    if len(digests) != expected:
        raise ValueError(f"Incomplete digest report: {report}")
    return digests


def compare(stock: dict[tuple[str, str], str], candidate: dict[tuple[str, str], str]) -> dict:
    """Require the stock order effect, then candidate output equal to a new stock process."""
    reused = sorted({name for name in FUNCTIONS for phase in ("forward", "reverse")
                     if stock[phase, name] != stock["fresh", name]})
    if not reused:
        raise RuntimeError("Official Ghidra no longer depends on decompile order here. "
                           "Revalidate and remove the join-record core patch.")
    differing = [f"{phase}:{name}" for name in FUNCTIONS for phase in PHASES
                 if candidate[phase, name] != stock["fresh", name]]
    if differing:
        raise RuntimeError("Source-built output differs from a new official decompiler process "
                           f"for {', '.join(differing)}")
    return {"stock_order_dependent": reused,
            "fresh_digests": {name: stock["fresh", name] for name in FUNCTIONS}}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--stock-ghidra", type=Path, required=True)
    parser.add_argument("--candidate-ghidra", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()
    if args.timeout < 1:
        parser.error("--timeout must be positive")
    output = args.output.resolve()
    output.mkdir(parents=True)
    (output / "fixture.bin").write_bytes(FIXTURE)
    stock = run(args.stock_ghidra, output, "stock", args.timeout)
    candidate = run(args.candidate_ghidra, output, "candidate", args.timeout)
    summary = compare(stock, candidate)
    summary["fixture_sha256"] = hashlib.sha256(FIXTURE).hexdigest()
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(f"Official Ghidra depends on decompile order for {', '.join(summary['stock_order_dependent'])}")
    print(f"Source-built output equals a new official process in all {len(PHASES)} orders")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
