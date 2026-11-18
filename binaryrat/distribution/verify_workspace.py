#!/usr/bin/env python3
"""Exercise an unpacked BinaryRat application on a real desktop.

Copyright 2026 YurilLAB
SPDX-License-Identifier: Apache-2.0
"""
from __future__ import annotations

import argparse
from collections import deque
import os
from pathlib import Path
import sys
import tempfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "benchmarks"))
from verify_ghidra import measured_run


def run(command: list[str], log: Path, env: dict[str, str], timeout: int) -> str:
    observed = measured_run(command, log, timeout, env)
    with log.open(encoding="utf-8", errors="replace") as stream:
        tail = "".join(deque(stream, maxlen=30))
    if observed["returncode"]:
        raise RuntimeError(f"Workspace command failed. See {log}\n{tail}")
    return log.read_text(encoding="utf-8", errors="replace")


def verify(bundle: Path, output: Path) -> None:
    suffix = ".exe" if os.name == "nt" else ""
    launcher = bundle / ("binaryrat-headless.bat" if suffix else "binaryrat-headless")
    example = bundle / "help/examples" / f"example{suffix}"
    libraries = bundle / "ghidra/Ghidra"
    jdk = bundle / "jdk/bin"
    output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="Workspace with spaces ", dir=output) as temporary:
        work = Path(temporary)
        home = work / "home"
        config, cache = home / "config", home / "cache"
        config.mkdir(parents=True)
        cache.mkdir()
        env = os.environ | {"XDG_CONFIG_HOME": str(config), "XDG_CACHE_HOME": str(cache),
                            "JAVA_TOOL_OPTIONS": f'"-Duser.home={home}"', "HOME": str(home)}
        if suffix:
            env["USERPROFILE"] = str(home)
        for key in ("BINARYRAT_ENGINE", "BINARYRAT_CACHE_DIR", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS",
                    "GHIDRA_JAVA_OPTIONS", "GHIDRA_HEADLESS_JAVA_OPTIONS"):
            env.pop(key, None)
        prepare = run([str(launcher), str(work), "workspace", "-import", str(example), "-max-cpu", "2"],
                      output / "headless.log", env, 180)
        if "Import succeeded" not in prepare:
            raise RuntimeError("Bundled headless launcher did not import the example")

        module = work / "WorkspaceTest"
        (module / "lib").mkdir(parents=True)
        (module / "Module.manifest").touch()
        jar = module / "lib/WorkspaceProbe.jar"
        classes = work / "classes"
        classes.mkdir()
        classpath = os.pathsep.join(str(path / "*") for path in [
            *sorted((libraries / "Framework").glob("*/lib")), libraries / "Features/Base/lib"])
        run([str(jdk / f"javac{suffix}"), "-proc:none", "-classpath", classpath, "-d",
             str(classes), str(HERE / "tests/WorkspaceProbe.java")], output / "javac.log", env, 60)
        run([str(jdk / f"jar{suffix}"), "--create", "--file", str(jar), "-C", str(classes), "."],
            output / "jar.log", env, 30)
        report = output / "workspace evidence.json"
        result = run([
            str(jdk / f"java{suffix}"), "-Xmx768m", "--enable-native-access=ALL-UNNAMED",
            "-Djava.system.class.loader=ghidra.GhidraClassLoader", f"-Duser.home={home}",
            f"-Dapplication.settingsdir={config / 'BinaryRat'}",
            f"-Dapplication.cachedir={cache / 'BinaryRat'}", f"-Dapplication.tempdir={home / 'temp'}",
            f"-Dghidra.external.modules={module}", "-cp",
            str(libraries / "Framework/Utility/lib/Utility.jar"), "ghidra.Ghidra",
            "distributionfixture.WorkspaceProbe", str(work), example.name, str(report)],
            output / "desktop.log", env, 240)
        if (result.count("BINARYRAT_WORKSPACE_OK") != 1 or
                'Exception in thread "AWT-EventQueue' in result):
            raise RuntimeError(f"Invalid bundled workspace evidence. See {output / 'desktop.log'}")
    print(f"Bundled CodeBrowser and native layout recovery passed. Evidence in {report}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True, help="Unpacked BinaryRat directory")
    parser.add_argument("--output", type=Path, required=True, help="New evidence directory")
    args = parser.parse_args()
    verify(args.bundle.resolve(strict=True), args.output.resolve())


if __name__ == "__main__":
    main()
