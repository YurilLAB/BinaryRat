#!/usr/bin/env python3
"""Install the hash-pinned Temurin JDK that the standalone bundle ships.

CI builds and tests with the same JDK the bundle carries, on both Windows and Linux.
`binaryrat/distribution/build_bundle.py` checks the same version and source archive.

SPDX-License-Identifier: Apache-2.0
Copyright 2026 YurilLAB. New BinaryRat tooling.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import sys
import tarfile
from zipfile import ZipFile

from pinned_download import DownloadError, fetch


VERSION = "25.0.5.1+2"
BASE_URL = ("https://github.com/adoptium/temurin25-binaries/releases/download/"
            "jdk-25.0.5.1%2B2/")
HOME_NAME = "jdk-25.0.5.1+2"
ARCHIVES = {
    "windows": ("OpenJDK25U-jdk_x64_windows_hotspot_25.0.5.1_2.zip",
                "849d380ab0a64d9098e7d3a2de28beb73841c3b255c8284f019ccd8748c5eb5b"),
    "linux": ("OpenJDK25U-jdk_x64_linux_hotspot_25.0.5.1_2.tar.gz",
              "760f91b22c3efc9bd1b64ff950598231be82928cc807e30691a0e7a2995a62c0"),
}
SOURCES = ("OpenJDK25U-jdk-sources_25.0.5.1_2.tar.gz",
           "3fb4af3a690f6c0f47462f3f813a8f09dc4a237f0c6ab462a764f15bc15313a7")


def host() -> str:
    if sys.platform == "win32":
        return "windows"
    if sys.platform.startswith("linux"):
        return "linux"
    raise SystemExit(f"no pinned Temurin archive for {sys.platform}")


def installed(java_home: Path, platform: str) -> bool:
    """True when java_home holds this exact Temurin build with a compiler."""
    javac = java_home / "bin" / ("javac.exe" if platform == "windows" else "javac")
    release = java_home / "release"
    if not javac.is_file() or not release.is_file():
        return False
    fields = {}
    for line in release.read_text(encoding="utf-8", errors="replace").splitlines():
        key, separator, value = line.partition("=")
        if separator:
            fields[key.strip()] = value.strip().strip('"')
    return fields.get("IMPLEMENTOR_VERSION") == f"Temurin-{VERSION}"


def install(directory: Path, platform: str, **fetch_options) -> Path:
    """Return JAVA_HOME of the pinned JDK under directory, downloading it if needed."""
    java_home = directory / HOME_NAME
    if installed(java_home, platform):
        return java_home
    name, sha256 = ARCHIVES[platform]
    archive = fetch(BASE_URL + name, directory / name, sha256, **fetch_options)
    shutil.rmtree(java_home, ignore_errors=True)
    if name.endswith(".zip"):
        with ZipFile(archive) as package:
            if any(not entry.filename.startswith(HOME_NAME + "/") for entry in package.infolist()):
                raise SystemExit("unexpected path in the pinned Temurin archive")
            package.extractall(directory)
    else:
        with tarfile.open(archive, "r:gz") as package:
            if any(not (entry.name + "/").startswith(HOME_NAME + "/") for entry in package.getmembers()):
                raise SystemExit("unexpected path in the pinned Temurin archive")
            package.extractall(directory, filter="data")
    archive.unlink()
    if not installed(java_home, platform):
        raise SystemExit(f"the pinned archive did not contain a Temurin {VERSION} JDK")
    return java_home


def publish(java_home: Path) -> None:
    """Make java_home the JDK of later GitHub Actions steps."""
    with open(os.environ["GITHUB_ENV"], "a", encoding="utf-8") as env:
        print(f"JAVA_HOME={java_home}", file=env)
    with open(os.environ["GITHUB_PATH"], "a", encoding="utf-8") as path:
        print(java_home / "bin", file=path)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path,
                        help="install the JDK here (default: $RUNNER_TEMP/binaryrat-jdk)")
    parser.add_argument("--github-env", action="store_true",
                        help="set JAVA_HOME and PATH for later GitHub Actions steps")
    parser.add_argument("--sources", type=Path,
                        help="only download the pinned JDK source archive to this file")
    args = parser.parse_args()
    try:
        if args.sources is not None:
            name, sha256 = SOURCES
            if args.sources.name != name:
                raise SystemExit(f"the source archive must be named {name}")
            print(fetch(BASE_URL + name, args.sources, sha256))
            return
        directory = args.directory or Path(os.environ.get("RUNNER_TEMP", "build")) / "binaryrat-jdk"
        java_home = install(directory.resolve(), host())
    except DownloadError as error:
        raise SystemExit(str(error))
    if args.github_env:
        publish(java_home)
    print(java_home)


if __name__ == "__main__":
    main()
