#!/usr/bin/env python3
# Copyright 2026 YurilLAB
# SPDX-License-Identifier: Apache-2.0
"""Check that the fork can inspect a saved stock 12.2 local Ghidra project."""
import argparse
import json
import os
from pathlib import Path
import re
import tempfile

from verify_ghidra import measured_run, saved_project_hashes
from verify_large_llvm import launcher

SCRIPT = Path(__file__).resolve().parent / "project_scripts" / "BinaryRatProjectInterop.java"
PROJECT_NAME = "Investigation"


def build_revisions(installation: Path) -> dict[str, str]:
    properties = (installation / "Ghidra/application.properties").read_text(encoding="utf-8")
    return dict(re.findall(r"^application\.revision\.([^=\r\n]+)=([0-9a-f]{40})$", properties, re.MULTILINE))


def run(headless: Path, workspace: Path, output: Path, stage: str, timeout: int) -> None:
    log = output / f"{stage}.log"
    seed = stage == "stock-save"
    binary = workspace / "fixture.bin"
    entry = (["-import", str(binary), "-loader", "BinaryLoader", "-processor", "x86:LE:64:default",
              "-cspec", "gcc"] if seed else ["-process", binary.name, "-readOnly"])
    mode = "seed" if seed else "read"
    result = measured_run([
        str(headless), str(workspace), PROJECT_NAME, *entry, "-noanalysis", "-max-cpu", "1",
        "-scriptPath", str(SCRIPT.parent), "-postScript", str(SCRIPT), mode,
    ], log, timeout, os.environ | {
        "GHIDRA_HEADLESS_MAXMEM": "512M",
        "XDG_CONFIG_HOME": str(workspace / stage / "settings"),
        "XDG_CACHE_HOME": str(workspace / stage / "cache"),
    })
    messages = log.read_text(encoding="utf-8", errors="replace")
    if (result["returncode"] or messages.count(f"BINARYRAT_PROJECT_INTEROP_VERIFIED {mode}") != 1 or
            (not seed and f"Processing read-only project file: /{binary.name}" not in messages) or
            "REPORT SCRIPT ERROR" in messages or re.search(r"^(?:ERROR|FATAL) ", messages, re.MULTILINE)):
        raise RuntimeError(f"{stage} did not verify the project fixture. See {log}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stock-ghidra", type=Path, required=True)
    parser.add_argument("--candidate-ghidra", type=Path, required=True)
    parser.add_argument("--candidate-revision", required=True, help="full Git commit of the fork being tested")
    parser.add_argument("--output", type=Path, required=True, help="new directory for logs and evidence")
    parser.add_argument("--timeout", type=int, default=180, help="seconds per headless process")
    args = parser.parse_args()
    if args.timeout < 1:
        parser.error("--timeout must be positive")
    stock_home = args.stock_ghidra.resolve(strict=True)
    fork_home = args.candidate_ghidra.resolve(strict=True)
    stock = launcher(stock_home, stock_reference=True, windows=os.name == "nt")
    fork = launcher(fork_home, windows=os.name == "nt")
    # Upstream Gradle names the revision property after the source checkout directory.
    if (stock_home == fork_home or args.candidate_revision not in build_revisions(fork_home).values() or
            args.candidate_revision in build_revisions(stock_home).values()):
        parser.error("expected a separate source-built fork distribution with its matching Git revision")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="disposable project ", dir=output) as directory:
        workspace = Path(directory)
        (workspace / "fixture.bin").write_bytes(b"\x90\xc3" + b"\0" * 14)
        run(stock, workspace, output, "stock-save", args.timeout)
        before = saved_project_hashes(workspace, PROJECT_NAME)
        for stage, executable in (("fork-read", fork), ("stock-readback", stock)):
            run(executable, workspace, output, stage, args.timeout)
            after = saved_project_hashes(workspace, PROJECT_NAME)
            changed = sorted(name for name in before.keys() | after.keys()
                             if before.get(name) != after.get(name))
            if changed:
                raise RuntimeError(f"{stage} changed saved project artifacts: {changed}")
    report = {"schema_version": 1, "candidate_revision": args.candidate_revision, "saved_project_sha256": before,
              "stages_passed": ["stock-save", "fork-read", "stock-readback"],
              "excluded_index_backups": ["idata/~index.bak", "idata/~journal.bak"]}
    (output / "project-interop.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Stock and fork verified the saved analyst work. {len(before)} project files matched.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
