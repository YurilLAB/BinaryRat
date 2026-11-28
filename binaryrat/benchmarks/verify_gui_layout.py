#!/usr/bin/env python3
# Copyright 2026 YurilLAB
# SPDX-License-Identifier: Apache-2.0
"""Drive layout recovery and navigation in a real CodeBrowser on a disposable project."""

import argparse
from collections import deque
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

from verify_ghidra import measured_run
from verify_plugin_compatibility import jdk


HERE = Path(__file__).resolve().parent


def run(command, log, env, timeout):
    result = measured_run(command, log, timeout, env)
    if result["returncode"]:
        with log.open(encoding="utf-8", errors="replace") as output:
            tail = "".join(deque(output, maxlen=25))
        raise RuntimeError(f"GUI fixture command failed. See {log}\n{tail}")
    return log.read_text(encoding="utf-8", errors="replace")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ghidra", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True, help="packaged host BinaryRat extension")
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="new evidence directory")
    args = parser.parse_args()
    info = json.loads(args.corpus.read_text(encoding="utf-8"))
    root = Path(info["root"]).resolve()
    artifact = info["artifacts"][0]
    binary = (root / artifact["binary"]).resolve()
    if (info["status"] != "passed" or not artifact["id"].endswith("/types") or
            root not in binary.parents or hashlib.sha256(binary.read_bytes()).hexdigest() != artifact["binary_sha256"]):
        raise ValueError("Expected the first verified optimized-off types corpus fixture")
    ghidra = args.ghidra.resolve()
    ghidra_libs = ghidra / "Ghidra"
    launcher = ghidra / "support" / ("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
    output = args.output.resolve()
    output.mkdir(parents=True)
    report = output / "recovered layout.json"
    with tempfile.TemporaryDirectory(prefix="layout GUI ", dir=output) as scratch:
        work = Path(scratch)
        home = work / "home"
        settings, cache = home / "settings", home / "cache"
        settings.mkdir(parents=True)
        cache.mkdir()
        env = os.environ | {"XDG_CONFIG_HOME": str(settings), "XDG_CACHE_HOME": str(cache)}
        env["JAVA_TOOL_OPTIONS"] = env.get("JAVA_TOOL_OPTIONS", "") + f' "-Duser.home={home}"'
        if os.name == "nt":
            # Ghidra's launch.bat sets -Duser.home from USERPROFILE after JAVA_TOOL_OPTIONS.
            env["USERPROFILE"] = str(home)
            # The Windows shell resolves Desktop inside the profile. Swing's file dialogs
            # (Browse Layout Evidence) fail without it, as on a profile that lacks one.
            (home / "Desktop").mkdir()
        env.pop("BINARYRAT_ENGINE", None)
        env.pop("BINARYRAT_CACHE_DIR", None)
        prep = run([str(launcher), str(work), "layout", "-import", str(binary), "-max-cpu", "2",
                    "-scriptPath", str(HERE / "ghidra_scripts"), "-postScript",
                    "BinaryRatInstallExtensionFixture.java", str(args.archive.resolve())],
                   output / "prepare.log", env, 240)
        if "BinaryRat test extension installed" not in prep or "REPORT SCRIPT ERROR" in prep:
            raise ValueError("Extension installation or Program preparation failed")

        installed = list((settings / "ghidra").glob("*/Extensions/BinaryRat"))
        if len(installed) != 1:
            raise RuntimeError(f"Expected BinaryRat in the shared headless and GUI profile under {settings / 'ghidra'}")
        probe = installed[0].parent / "LayoutNavigationTest"
        (probe / "lib").mkdir(parents=True)
        (probe / "Module.manifest").touch()
        (probe / "extension.properties").write_text("name=LayoutNavigationTest\nversion=12.2\n", encoding="utf-8")
        classes = work / "classes"
        classes.mkdir()
        libraries = sorted((ghidra_libs / "Framework").glob("*/lib")) + [ghidra_libs / "Features/Base/lib"]
        classpath = os.pathsep.join(str(lib / "*") for lib in libraries)
        run([jdk("javac"), "-proc:none", "-classpath", classpath, "-d", str(classes),
             str(HERE / "gui_fixture/LayoutNavigationProbe.java")], output / "javac.log", env, 60)
        run([jdk("jar"), "--create", "--file", str(probe / "lib/LayoutNavigationTest.jar"),
             "-C", str(classes), "."], output / "jar.log", env, 30)
        log = run([jdk("java"), "-Xmx768m", "--enable-native-access=ALL-UNNAMED",
                   "-Djava.system.class.loader=ghidra.GhidraClassLoader", f"-Duser.home={home}",
                   f"-Dapplication.settingsdir={settings}", f"-Dapplication.cachedir={cache}",
                   f"-Dapplication.tempdir={home / 'temp'}", "-cp", str(ghidra_libs / "Framework/Utility/lib/Utility.jar"),
                   "ghidra.Ghidra", "guifixture.LayoutNavigationProbe", str(work),
                   binary.name, str(report)], output / "gui.log", env, 300)
        result = re.findall(r"^BINARYRAT_GUI_NAVIGATION_OK (\w+) (\w+) (\w+) ([0-9.]+) ([0-9.]+)$",
                            log, re.MULTILINE)
        foreground = re.findall(r"^BINARYRAT_GUI_FOREGROUND_OK (\d+) (\d+) (\d+)$", log, re.MULTILINE)
        arithmetic = re.findall(r"^BINARYRAT_GUI_ARITHMETIC_OK (\w+) (\w+) ([0-9.]+)$", log, re.MULTILINE)
        if 'Exception in thread "AWT-EventQueue' in log:
            raise RuntimeError(f"CodeBrowser raised an uncaught Swing exception. See {output / 'gui.log'}")
        if len(result) != 1 or len(foreground) != 1 or len(arithmetic) != 1:
            raise RuntimeError("Missing GUI layout, arithmetic navigation or foreground decompilation confirmation")
    entry, cursor, navigated, recovery_time, browse_time = result[0]
    first_ms, next_ms, cancellations = (int(value) for value in foreground[0])
    details = {"passed": True, "fixture": artifact["id"], "binary_sha256": artifact["binary_sha256"],
               "report_sha256": hashlib.sha256(report.read_bytes()).hexdigest(), "function_entry": entry,
               "recovery_cursor": cursor, "navigated_instruction": navigated,
               "cancelled_before_save": True, "interrupted_picker_closed": True,
               "closed_after_program_edit": True,
               "program_clean_after_navigation": True, "instruction_bytes_verified": True,
               "gui_wall_seconds_including_script_compilation_and_dialogs": {
                   "recover": float(recovery_time), "browse_and_navigate": float(browse_time)},
               "arithmetic_navigation": {"mouse_destination": arithmetic[0][0],
                                         "keyboard_destination": arithmetic[0][1],
                                         "explain_click_to_table_population_ms": float(arithmetic[0][2]),
                                         "active_unsaved_code": True, "stale_rows_cleared": True},
               "foreground_decompilation": {"first_ms": first_ms, "next_ms": next_ms,
                                             "cancelled_requests": cancellations,
                                             "inactive_tab_released_session": True,
                                             "program_clean": True}}
    (output / "report.json").write_text(json.dumps(details, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(details))


if __name__ == "__main__":
    main()
