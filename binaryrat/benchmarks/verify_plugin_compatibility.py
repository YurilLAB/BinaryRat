#!/usr/bin/env python3
# Copyright 2026 YurilLAB
# SPDX-License-Identifier: Apache-2.0
"""Build a plugin against stock Ghidra 12.2 and exercise the same JAR in both desktop runtimes."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
UPSTREAM = json.loads((HERE.parent / "UPSTREAM.json").read_text(encoding="utf-8"))
NAME = "SelectionSize"


def jdk(command: str) -> str:
    if home := os.environ.get("JAVA_HOME"):
        return str(Path(home) / "bin" / (command + ".exe" if os.name == "nt" else command))
    return command


def properties(installation: Path) -> dict[str, str]:
    text = (installation / "Ghidra/application.properties").read_text(encoding="utf-8")
    return dict(line.split("=", 1) for line in text.splitlines() if "=" in line and not line.startswith("#"))


def build(stock: Path, work: Path, jar: Path) -> None:
    ghidra = stock / "Ghidra"
    libraries = [*sorted((ghidra / "Framework").glob("*/lib")), ghidra / "Features/Base/lib"]
    classpath = os.pathsep.join(str(directory / "*") for directory in libraries)
    classes = work / "classes"
    classes.mkdir()
    subprocess.run([jdk("javac"), "-proc:none", "-classpath", classpath, "-d", str(classes),
                    *sorted((HERE / "plugin_fixture").glob("*.java"))], check=True, timeout=120)
    subprocess.run([jdk("jar"), "--create", "--file", str(jar), "--date=2026-01-01T00:00:00Z",
                    "-C", str(classes), ".", "-C", str(ROOT), "LICENSE", "-C", str(ROOT), "NOTICE"],
                   check=True, timeout=30)


def run(installation: Path, info: dict[str, str], home: Path, jar: Path, log: Path) -> None:
    # Create a disposable user profile in the normal Ghidra extension layout.
    versioned_name = f"ghidra_12.2_{info['application.release.name'].upper()}"
    module = home / "settings" / "ghidra" / versioned_name / "Extensions" / NAME
    (module / "lib").mkdir(parents=True)
    (module / "Module.manifest").touch()
    (module / "extension.properties").write_text(
        f"name={NAME}\nversion=12.2\ndescription=Selection size compatibility fixture\nauthor=YurilLAB\n",
        encoding="utf-8")
    installed = module / "lib" / jar.name
    shutil.copyfile(jar, installed)
    # Only the Ghidra bootstrap JAR is on the runtime classpath. The launcher has
    # to discover the fixture in the isolated user Extensions directory itself.
    command = [jdk("java"), "-Xmx512m", "--enable-native-access=ALL-UNNAMED",
               "-Djava.system.class.loader=ghidra.GhidraClassLoader", f"-Duser.home={home}",
               f"-Dapplication.settingsdir={home / 'settings'}", f"-Dapplication.cachedir={home / 'cache'}",
               f"-Dapplication.tempdir={home / 'temp'}", "-cp",
               str(installation / "Ghidra/Framework/Utility/lib/Utility.jar"),
               "ghidra.Ghidra", "pluginfixture.PluginCompatibilityProbe", str(installed)]
    with log.open("wb") as stream:
        result = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, timeout=120)
    lines = log.read_text(encoding="utf-8", errors="replace").splitlines()
    if (result.returncode or lines.count("PLUGIN_COMPATIBILITY_OK") != 1 or
            any(line.startswith(("ERROR ", "FATAL ")) for line in lines) or
            installed.read_bytes() != jar.read_bytes()):
        raise RuntimeError(f"Plugin test failed. See {log}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stock-ghidra", required=True, type=Path)
    parser.add_argument("--candidate-ghidra", required=True, type=Path)
    parser.add_argument("--candidate-revision", help="check the commit recorded in the fork distribution")
    parser.add_argument("--output", required=True, type=Path, help="new directory for the JAR and evidence")
    args = parser.parse_args()
    stock, candidate = args.stock_ghidra.resolve(), args.candidate_ghidra.resolve()
    baseline, fork = properties(stock), properties(candidate)
    if (baseline.get("application.revision.ghidra") != UPSTREAM["commit"] or
            baseline.get("application.release.name") != "PUBLIC" or
            any(info.get("application.version") != "12.2" for info in (baseline, fork))):
        parser.error("expected the pinned Ghidra 12.2 public baseline and a 12.2 fork build")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", fork.get("application.release.name", "")):
        parser.error("invalid candidate release name")
    revisions = {key: value for key, value in fork.items() if key.startswith("application.revision.")}
    if not any(re.fullmatch(r"[0-9a-f]{40}", value) and value not in baseline.values()
               for value in revisions.values()):
        parser.error("expected a source-built candidate with a revision distinct from stock")
    if args.candidate_revision and args.candidate_revision not in revisions.values():
        parser.error("candidate build revision does not match --candidate-revision")
    output = args.output.resolve()
    output.mkdir(parents=True)
    jar = output / f"{NAME}.jar"
    with tempfile.TemporaryDirectory(prefix="plugin compatibility ", dir=output) as temporary:
        work = Path(temporary)
        build(stock, work, jar)
        run(stock, baseline, work / "stock", jar, output / "stock.log")
        run(candidate, fork, work / "candidate", jar, output / "candidate.log")

    report = {"passed": True, "jar_sha256": hashlib.sha256(jar.read_bytes()).hexdigest(),
              "stock_revision": UPSTREAM["commit"],
              "candidate_revisions": revisions,
              "checks": ["plugin_discovery", "plugin_load", "service_registration", "empty_selection",
                         "overlapping_and_discontiguous_ranges", "service_removal"]}
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Stock-built plugin passed on both runtimes. See {output / 'report.json'}")


if __name__ == "__main__":
    main()
