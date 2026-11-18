#!/usr/bin/env python3
# Copyright 2026 YurilLAB
# SPDX-License-Identifier: Apache-2.0
"""Run deterministic decoder and fingerprint checks against the packaged extension."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
from time import perf_counter
from zipfile import ZipFile

from verify_plugin_compatibility import jdk


def verify_parser(ghidra: Path, archive: Path, output: Path) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    report = output / "layout-parser.json"
    report.unlink(missing_ok=True)
    with tempfile.TemporaryDirectory(prefix="layout parser ", dir=output) as temporary:
        classes = Path(temporary)
        jar = classes / "BinaryRat.jar"
        with ZipFile(archive) as package:
            jar.write_bytes(package.read("BinaryRat/lib/BinaryRat.jar"))
        libraries = sorted((ghidra / "Ghidra/Framework").glob("*/lib"))
        classpath = os.pathsep.join(map(str, [classes, jar, *(lib / "*" for lib in libraries)]))
        source = Path(__file__).resolve().with_name("layout_parser_fixture") / "LayoutParserProof.java"
        subprocess.run([jdk("javac"), "-proc:none", "-classpath", classpath, "-d", str(classes),
                        str(source)], timeout=120, check=True)
        start = perf_counter()
        result = subprocess.run([jdk("java"), "-Xmx192m", "-classpath", classpath,
                                 "binaryrat.writeback.LayoutParserProof"], capture_output=True,
                                text=True, timeout=120)
        if result.returncode:
            raise RuntimeError(f"Layout parser proof failed\n{result.stdout}\n{result.stderr}")
        stats = json.loads(result.stdout)
        if (stats["valid_controls"] != 500 or stats["invalid_controls"] != 500 or
                stats["mutations_accepted"] + stats["mutations_rejected"] != 2000):
            raise ValueError("Incomplete layout parser proof")
        stats.update(passed=True, wall_seconds=perf_counter() - start)
    report.write_text(json.dumps(stats, indent=2) + "\n", encoding="utf-8")
    return stats


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("ghidra", "archive", "output"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify_parser(args.ghidra, args.archive, args.output)))
