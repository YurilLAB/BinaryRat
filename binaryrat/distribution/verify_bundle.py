#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise the delivered BinaryRat archive without installing Java or the extension."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from zipfile import BadZipFile, ZipFile

from build_bundle import (
    EXTENSION_ROOT, JDK_SOURCE_NAME, JDK_SOURCE_SHA256, JDK_VERSION, PREFIX, WORKSPACE_JAR,
    archive_entries, current_host, digest, read_properties,
)
from install_workspace import edit_workspace_jar


def extract(archive: Path, directory: Path) -> Path:
    directory.mkdir(parents=True)
    with ZipFile(archive) as bundle:
        entries = archive_entries(bundle)
        if not entries or any(not name.startswith(PREFIX) for name in entries):
            raise ValueError("expected a single BinaryRat folder")
        for name, info in entries.items():
            path = directory / name
            if info.is_dir():
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                with bundle.open(info) as source, path.open("xb") as output:
                    shutil.copyfileobj(source, output, length=1 << 20)
                if os.name != "nt":
                    path.chmod(0o755 if info.external_attr >> 16 & 0o111 else 0o644)
    return directory / PREFIX


def run(command: list[str], log: Path, cwd: Path, env: dict[str, str], timeout: int = 60) -> str:
    with log.open("wb") as stream:
        completed = subprocess.run(command, cwd=cwd, env=env, stdout=stream, stderr=subprocess.STDOUT,
                                   timeout=timeout, check=False)
    if completed.returncode:
        raise RuntimeError(f"bundled command exited {completed.returncode}. See {log}")
    return log.read_text(encoding="utf-8", errors="replace")


def verify(archive: Path, output: Path, extract_dir: Path) -> None:
    host = current_host()
    output.mkdir(parents=True, exist_ok=True)
    report = output / "report.json"
    report.unlink(missing_ok=True)
    archive_hash = digest(archive)
    checksum = f"{archive_hash} *{archive.name}\n".encode()
    with archive.with_suffix(".zip.sha256").open("rb") as stream:
        if stream.read(len(checksum) + 1) != checksum:
            raise ValueError("package checksum does not match")
    root = extract(archive, extract_dir)
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    props = read_properties((root / "ghidra/Ghidra/application.properties").read_bytes())
    if (manifest.get("platform") != host.name or
            props.get("application.revision.BinaryRat") != manifest.get("revision") or
            props.get("application.version") != manifest.get("ghidra_version")):
        raise ValueError("unexpected platform or source revision in bundle")
    jdk = root / "jdk"
    source = root / "sources" / JDK_SOURCE_NAME
    for license_path in ("LICENSE", "NOTICE", "jdk/legal/java.base/LICENSE",
                         "jdk/legal/java.base/ASSEMBLY_EXCEPTION", EXTENSION_ROOT + "LICENSE",
                         EXTENSION_ROOT + "NOTICE", "help/GettingStarted.html", "help/examples/walkthrough.c"):
        if not (root / license_path).is_file() or (root / license_path).stat().st_size == 0:
            raise ValueError(f"missing package content {license_path}")
    if manifest["jdk_source_sha256"] != JDK_SOURCE_SHA256 or digest(source) != JDK_SOURCE_SHA256:
        raise ValueError("package JDK source is missing or has the wrong SHA-256")
    example_path = "help/examples/example" + host.java_suffix
    example = root / example_path
    if manifest.get("example") != example_path or manifest.get("example_sha256") != digest(example):
        raise ValueError("unexpected packaged sample")
    wheel = manifest.get("python_wheel")
    if wheel and (wheel != Path(wheel).name or not (root / "python" / wheel).is_file()):
        raise ValueError("package manifest names a missing Python wheel")
    workspace = (root / "ghidra" / WORKSPACE_JAR).read_bytes()
    if edit_workspace_jar(workspace) != workspace:
        raise ValueError("packaged workspace does not include the BinaryRat plugins")

    desktop = root / ("binaryrat" + host.suffix)
    headless = root / ("binaryrat-headless" + host.suffix)
    engine = root / EXTENSION_ROOT / host.engine
    with tempfile.TemporaryDirectory(prefix="profile-", dir=output) as scratch:
        fresh = Path(scratch)
        home = fresh / "home"
        projects = home / "projects"
        projects.mkdir(parents=True)
        env = {key: value for key, value in os.environ.items() if not key.startswith("BINARYRAT_")}
        for key in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "GHIDRA_JAVA_OPTIONS",
                    "GHIDRA_HEADLESS_JAVA_OPTIONS"):
            env.pop(key, None)
        env.update({
            "HOME": str(home),
            "USERPROFILE": str(home),
            "XDG_CONFIG_HOME": str(home / "config"),
            "XDG_CACHE_HOME": str(home / "cache"),
            "JAVA_HOME": str(home / "invalid-java-home"),
            "BINARYRAT_ENGINE": str(home / "invalid-engine"),
            "GHIDRA_HEADLESS_MAXMEM": "768M",
        })
        expected_version = (root / "VERSION.txt").read_text(encoding="utf-8").strip()
        if not expected_version.startswith(f"BinaryRat {manifest['ghidra_version']} ({manifest['revision']})"):
            raise ValueError("incorrect version file")
        for launcher, log_name in ((desktop, "desktop-version.log"), (headless, "headless-version.log")):
            if run([str(launcher), "--version"], output / log_name, fresh, env).strip() != expected_version:
                raise RuntimeError("bundled launcher reported an inconsistent version")
        java_version = run([str(jdk / "bin" / ("java" + host.java_suffix)), "-version"],
                           output / "java-version.log", fresh, env)
        if f"Temurin-{JDK_VERSION}" not in java_version:
            raise RuntimeError("bundled Java did not report the tested Temurin build")
        engine_version = run([str(engine), "--version"], output / "engine-version.log", fresh, env)
        if not re.fullmatch(r"BinaryRat [^()]+ \(Ghidra " + re.escape(manifest["ghidra_version"]) +
                            r"; protocol \d+\)\s*", engine_version):
            raise RuntimeError("bundled engine did not report the matched Ghidra version")
        exports = output / "example.jsonl"
        exports.unlink(missing_ok=True)
        schedule_path = output / "example.jsonl.schedule.json"
        schedule_path.unlink(missing_ok=True)
        env["JDK_JAVA_OPTIONS"] = "-XshowSettings:properties"
        text = run([str(headless), str(projects), "demo", "-import", str(example), "-max-cpu", "2",
                    "-analysisTimeoutPerFile", "120", "-postScript", "BinaryRatExport.java",
                    str(exports), "scheduled", "1", "45", "64"],
                   output / "headless.log", fresh, env, timeout=300)
        if ("REPORT SCRIPT ERROR" in text or "mode=scheduled" not in text or
                not exports.is_file() or not schedule_path.is_file()):
            raise RuntimeError(f"bundled headless export did not finish. See {output / 'headless.log'}")
        homes = re.findall(r"^\s+java\.home\s+= (.+)$", text, re.MULTILINE)
        if not homes or any(Path(home).resolve() != jdk for home in homes):
            raise RuntimeError("headless launch did not report the bundled Java home")
        total = 0
        sample = None
        with exports.open(encoding="utf-8") as lines:
            for text in lines:
                row = json.loads(text)
                total += 1
                if row["name"] == "measurement_area":
                    if sample is not None:
                        raise RuntimeError("headless sample function is ambiguous")
                    sample = row
        if (sample is None or not sample["completed"] or not sample["c"].strip() or
                any(sample[key] for key in ("timed_out", "cancelled", "failed_to_start")) or
                sample["program_id"] != "sha256:" + manifest["example_sha256"]):
            raise RuntimeError("packaged example function did not decompile successfully")
        schedule = json.loads(schedule_path.read_text(encoding="utf-8"))
        if schedule["leases"] != total or schedule["lease_status_counts"] != {"completed": total}:
            raise RuntimeError("bundled headless run could not account for all scheduler leases")
    status = {
        "passed": True,
        "archive": archive.name,
        "archive_sha256": archive_hash,
        "revision": manifest["revision"],
        "jdk": manifest["jdk"],
        "platform": host.name,
        "engine": engine_version.strip(),
        "headless_sample": sample["name"],
        "scheduled_functions": total,
        "packaged_workspace": True,
    }
    report.write_text(json.dumps(status, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(status))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--extract-dir", type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    try:
        verify(args.archive.resolve(), output, (args.extract_dir or output / "extracted").resolve())
    except (BadZipFile, ValueError, OSError, KeyError, RuntimeError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"BinaryRat archive verification failed: {error}\n")


if __name__ == "__main__":
    main()
