#!/usr/bin/env python3
# Copyright 2026 YurilLAB
# SPDX-License-Identifier: Apache-2.0
"""Assemble the source-built BinaryRat application and its pinned, redistributable JDK."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
from io import BytesIO
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import struct
import tempfile
from typing import BinaryIO
from zipfile import BadZipFile, ZIP_DEFLATED, ZIP_STORED, ZipFile, ZipInfo

from install_workspace import edit_workspace_jar


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
PREFIX = "BinaryRat/"
JDK_VERSION = "25.0.5+8"
JDK_SOURCE_NAME = "OpenJDK25U-jdk-sources_25.0.5_8.tar.gz"
JDK_SOURCE_SHA256 = "f331d870d998f9c144c361c220960f8ad2de169dc1b1c4dc4145291c501c2341"
WORKSPACE_JAR = "Ghidra/Configurations/Public_Release/lib/Public_Release.jar"
LAUNCH_PROPERTIES = "support/launch.properties"
# CVE-2026-114938 (OpenJDK advisory 2026-11-17): on x86-64 CPUs with AVX-512 VBMI the
# C2 Base64 decoding intrinsic of JDK 17 to 27 builds up to 25.0.5 can write past its
# output array. The pinned Temurin predates the fix, so every JVM the bundle starts
# (desktop, headless and PyGhidra all read launch.properties) runs without the Base64
# intrinsics. Drop this when JDK_VERSION moves to a fixed Temurin build.
JVM_MITIGATIONS = ("-XX:-UseBASE64Intrinsics",)
EXTENSION_ROOT = "ghidra/Ghidra/Extensions/BinaryRat/"
STORED_SUFFIXES = frozenset({".jar", ".zip", ".gz", ".whl", ".png", ".jpg", ".gif", ".xz"})
DEVICE_NAME = re.compile(r"^(CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])$", re.IGNORECASE)


@dataclass(frozen=True)
class Host:
    name: str
    ghidra_platform: str
    os_name: str
    suffix: str
    java_suffix: str

    @property
    def engine(self) -> str:
        return f"os/{self.ghidra_platform}/binaryrat-engine{self.java_suffix}"


LINUX = Host("linux_x86_64", "linux_x86_64", "Linux", "", "")
WINDOWS = Host("windows_x86_64", "win_x86_64", "Windows", ".bat", ".exe")


def current_host() -> Host:
    if platform.machine().lower() not in ("x86_64", "amd64"):
        raise ValueError("standalone archives currently support x86-64 hosts")
    hosts = {"Linux": LINUX, "Windows": WINDOWS}
    if platform.system() not in hosts:
        raise ValueError("standalone archives currently support Linux and Windows")
    return hosts[platform.system()]


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def checked_path(name: str) -> str:
    """Use a single safe path representation for both host ZIP extractors."""
    path = name.removesuffix("/")
    if not path or any(
        part in ("", ".", "..") or part.endswith((" ", ".")) or
        any(char in '<>:"\\|?*' or ord(char) < 32 for char in part) or
        DEVICE_NAME.fullmatch(part.partition(".")[0].rstrip(" "))
        for part in path.split("/")
    ):
        raise ValueError(f"unsafe archive path {name!r}")
    return path


def archive_entries(archive: ZipFile) -> dict[str, ZipInfo]:
    entries = {}
    folded = set()
    for entry in archive.infolist():
        path = checked_path(entry.orig_filename)
        kind = stat.S_IFMT(entry.external_attr >> 16)
        if kind not in (0, stat.S_IFDIR if entry.is_dir() else stat.S_IFREG):
            raise ValueError(f"unsupported file type for {path}")
        key = path.casefold()
        if key in folded:
            raise ValueError(f"duplicate archive path {path}")
        folded.add(key)
        entries[path] = entry
    files = {path.casefold() for path, entry in entries.items() if not entry.is_dir()}
    for path in entries:
        if any(str(parent).casefold() in files for parent in PurePosixPath(path).parents):
            raise ValueError(f"a file is a parent of archive path {path}")
    return entries


def executable_format(header: bytes, host: Host) -> bool:
    if host == LINUX:
        return (len(header) >= 20 and header[:6] == b"\x7fELF\x02\x01" and
                struct.unpack_from("<H", header, 18)[0] == 62)
    if len(header) < 64 or header[:2] != b"MZ":
        return False
    offset = struct.unpack_from("<I", header, 60)[0]
    return header[offset:offset + 6] == b"PE\0\0\x64\x86"


def assert_binary(stream: BinaryIO, host: Host, label: str) -> None:
    if not executable_format(stream.read(4096), host):
        raise ValueError(f"{label} is not a native executable for {host.name}")


def read_properties(raw: bytes) -> dict[str, str]:
    properties = {}
    for line in raw.decode("utf-8").splitlines():
        key, equals, value = line.partition("=")
        if equals and not key.lstrip().startswith("#"):
            properties[key.strip()] = value.strip().strip('"')
    return properties


def mitigated_launch_properties(raw: bytes) -> bytes:
    """Append the bundle's JVM mitigations to Ghidra's launch.properties, once each."""
    text = raw.decode("utf-8")
    newline = "\r\n" if "\r\n" in text else "\n"
    present = {line.strip() for line in text.splitlines()}
    missing = [f"VMARGS={flag}" for flag in JVM_MITIGATIONS if f"VMARGS={flag}" not in present]
    if not missing:
        return raw
    if text and not text.endswith("\n"):
        text += newline
    lines = ["", "# BinaryRat bundle: the pinned JDK runs without the intrinsics affected by CVE-2026-114938.",
             *missing, ""]
    return (text + newline.join(lines)).encode("utf-8")


def read_small(archive: ZipFile, path: str, limit: int = 8 << 20) -> bytes:
    entry = archive.getinfo(path)
    if entry.is_dir() or entry.file_size > limit:
        raise ValueError(f"unexpected file size or type for {path}")
    return archive.read(entry)


def validate_ghidra(archive: ZipFile, entries: dict[str, ZipInfo], revision: str, host: Host) -> tuple[str, str]:
    roots = {name.partition("/")[0] for name in entries}
    if len(roots) != 1:
        raise ValueError("expected one source distribution root in the Ghidra archive")
    root = roots.pop() + "/"
    path = root + "Ghidra/application.properties"
    if path not in entries:
        raise ValueError("Ghidra application.properties is missing")
    properties = read_properties(read_small(archive, path))
    version = properties.get("application.version", "")
    upstream = json.loads((REPO / "binaryrat/UPSTREAM.json").read_text(encoding="utf-8"))
    if (upstream["tag"] != f"Ghidra_{version}_build" or
            properties.get("application.revision.BinaryRat") != revision or
            properties.get("application.release.name") != "DEV" or
            properties.get("application.java.min") != "25"):
        raise ValueError("Ghidra version, build revision or minimum JDK does not match this BinaryRat build")
    necessary = ("LICENSE", "support/LaunchSupport.jar", LAUNCH_PROPERTIES, WORKSPACE_JAR,
                 "ghidraRun" + host.suffix, "support/analyzeHeadless" + host.suffix)
    for entry in necessary:
        if root + entry not in entries or entries[root + entry].is_dir():
            raise ValueError(f"missing Ghidra distribution component {entry}")
    if any(name.startswith(root + "Ghidra/Extensions/BinaryRat/") for name in entries):
        raise ValueError("Ghidra distribution already contains a BinaryRat installation")
    with archive.open(root + f"Ghidra/Features/Decompiler/os/{host.ghidra_platform}/decompile{host.java_suffix}") as stream:
        assert_binary(stream, host, "Ghidra native decompiler")
    return root, version


def validate_extension(archive: ZipFile, entries: dict[str, ZipInfo], version: str, host: Host) -> None:
    if any(name != "BinaryRat" and not name.startswith(PREFIX) for name in entries):
        raise ValueError("expected one BinaryRat extension root")
    props = read_properties(read_small(archive, PREFIX + "extension.properties"))
    if props.get("version") != version or props.get("name") != "BinaryRat":
        raise ValueError("BinaryRat extension version does not match Ghidra")
    for name in ("LICENSE", "NOTICE"):
        if read_small(archive, PREFIX + name) != (REPO / name).read_bytes():
            raise ValueError(f"missing or altered extension {name}")
    for name in ("Module.manifest", "lib/BinaryRat.jar", "ghidra_scripts/BinaryRatExport.java"):
        if PREFIX + name not in entries or entries[PREFIX + name].is_dir():
            raise ValueError(f"missing extension component {name}")
    with ZipFile(BytesIO(read_small(archive, PREFIX + "lib/BinaryRat.jar"))) as library:
        plugins = {"binaryrat/desktop/BinaryRatWorkspacePlugin.class",
                   "binaryrat/desktop/BinaryRatForegroundPlugin.class"}
        if not plugins <= set(library.namelist()):
            raise ValueError("the extension does not contain the plugins used by the default workspace")
    with archive.open(PREFIX + host.engine) as stream:
        assert_binary(stream, host, "BinaryRat engine")


def validate_jdk(jdk: Path, source: Path, host: Host) -> dict[str, str]:
    properties = read_properties((jdk / "release").read_bytes())
    if (properties.get("IMPLEMENTOR") != "Eclipse Adoptium" or
            properties.get("IMPLEMENTOR_VERSION") != f"Temurin-{JDK_VERSION}" or
            properties.get("OS_NAME") != host.os_name or
            properties.get("OS_ARCH") not in ("x86_64", "amd64") or
            properties.get("IMAGE_TYPE") != "JDK"):
        raise ValueError(f"expected a Temurin {JDK_VERSION} JDK for {host.name}")
    required = ("lib/modules", "legal/java.base/LICENSE", "legal/java.base/ASSEMBLY_EXCEPTION",
                f"bin/javac{host.java_suffix}")
    for name in required:
        if not (jdk / name).is_file():
            raise ValueError(f"JDK is missing {name}")
    with (jdk / f"bin/java{host.java_suffix}").open("rb") as stream:
        assert_binary(stream, host, "Temurin java")
    if digest(source) != JDK_SOURCE_SHA256:
        raise ValueError("Temurin source archive SHA-256 mismatch")
    return properties


class Writer:
    def __init__(self, archive: ZipFile):
        self.archive = archive
        self.paths: set[str] = set()

    def entry(self, relative: str, size: int, executable: bool = False) -> ZipInfo:
        safe = checked_path(PREFIX + relative)
        if safe.casefold() in self.paths:
            raise ValueError(f"duplicate output file {safe}")
        self.paths.add(safe.casefold())
        entry = ZipInfo(safe)
        entry.create_system = 3
        entry.external_attr = (stat.S_IFREG | (0o755 if executable else 0o644)) << 16
        entry.compress_type = ZIP_STORED if PurePosixPath(safe).suffix in STORED_SUFFIXES else ZIP_DEFLATED
        entry.file_size = size
        return entry

    def stream(self, relative: str, stream: BinaryIO, size: int, executable: bool = False) -> None:
        with self.archive.open(self.entry(relative, size, executable), "w") as output:
            shutil.copyfileobj(stream, output, length=1 << 20)

    def bytes(self, relative: str, content: bytes, executable: bool = False) -> None:
        self.archive.writestr(self.entry(relative, len(content), executable), content)

    def file(self, relative: str, path: Path, executable: bool = False) -> None:
        with path.open("rb") as stream:
            self.stream(relative, stream, path.stat().st_size, executable)


def add_tree(writer: Writer, source: Path, destination: str) -> None:
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source).as_posix()
        resolved = path.resolve(strict=True)
        if not resolved.is_relative_to(source):
            raise ValueError(f"bundle file points outside its source tree: {path}")
        if resolved.is_dir():
            if path.is_symlink():
                raise ValueError(f"symbolic link to directory in source tree: {path}")
            continue
        if not resolved.is_file():
            raise ValueError(f"source tree entry is not a regular file: {path}")
        executable = bool(resolved.stat().st_mode & stat.S_IXUSR)
        writer.file(destination + relative, resolved, executable)


def add_ghidra(writer: Writer, archive: ZipFile, entries: dict[str, ZipInfo], root: str) -> None:
    for name, entry in sorted(entries.items()):
        if entry.is_dir():
            continue
        path = name.removeprefix(root)
        if path == WORKSPACE_JAR:
            writer.bytes("ghidra/" + path, edit_workspace_jar(read_small(archive, name)))
        elif path == LAUNCH_PROPERTIES:
            writer.bytes("ghidra/" + path, mitigated_launch_properties(read_small(archive, name)))
        else:
            with archive.open(entry) as stream:
                writer.stream("ghidra/" + path, stream, entry.file_size, bool(entry.external_attr >> 16 & 0o111))


def add_extension(writer: Writer, archive: ZipFile, entries: dict[str, ZipInfo], host: Host) -> None:
    for name, entry in sorted(entries.items()):
        if not entry.is_dir():
            path = name.removeprefix(PREFIX)
            with archive.open(entry) as stream:
                writer.stream(EXTENSION_ROOT + path, stream, entry.file_size, path == host.engine)


def build(args: argparse.Namespace, host: Host) -> Path:
    if not re.fullmatch(r"[0-9a-f]{40}", args.revision):
        raise ValueError("--revision must be a full lowercase Git commit SHA")
    source = args.jdk_source.resolve(strict=True)
    jdk = args.jdk.resolve(strict=True)
    properties = validate_jdk(jdk, source, host)
    if args.wheel and not re.fullmatch(r"binaryrat-[0-9][a-z0-9._+]*-py3-none-any\.whl", args.wheel.name):
        raise ValueError("expected a portable BinaryRat Python wheel")
    example_name = "help/examples/example" + host.java_suffix
    with args.example.open("rb") as stream:
        assert_binary(stream, host, "compiled example")
    with ZipFile(args.ghidra) as ghidra, ZipFile(args.extension) as extension:
        ghidra_entries = archive_entries(ghidra)
        extension_entries = archive_entries(extension)
        root, version = validate_ghidra(ghidra, ghidra_entries, args.revision, host)
        validate_extension(extension, extension_entries, version, host)
        args.output.mkdir(parents=True, exist_ok=True)
        name = f"BinaryRat-{version}-{args.revision[:12]}-{host.name}.zip"
        destination = args.output / name
        with tempfile.TemporaryDirectory(prefix=".binaryrat-dist-", dir=args.output) as work:
            temporary = Path(work) / name
            with ZipFile(temporary, "w", compression=ZIP_DEFLATED, compresslevel=6) as bundle:
                writer = Writer(bundle)
                add_ghidra(writer, ghidra, ghidra_entries, root)
                add_extension(writer, extension, extension_entries, host)
                add_tree(writer, jdk, "jdk/")
                if not (HERE / "help/GettingStarted.html").is_file():
                    raise ValueError("offline GettingStarted.html is missing")
                add_tree(writer, HERE / "help", "help/")
                writer.file("help/examples/walkthrough.c", HERE / "examples/walkthrough.c")
                writer.file(example_name, args.example)
                writer.file("sources/" + JDK_SOURCE_NAME, source)
                if args.wheel:
                    writer.file("python/" + args.wheel.name, args.wheel)
                for launcher, path in (("binaryrat", ""), ("binaryrat-headless", ""), ("launch", "launchers/")):
                    launcher += host.suffix
                    content = (HERE / "launchers" / launcher).read_text(encoding="utf-8")
                    if host == WINDOWS:
                        content = content.replace("\n", "\r\n")
                    writer.bytes(path + launcher, content.encode(), executable=host == LINUX)
                for license_name in ("LICENSE", "NOTICE"):
                    writer.file(license_name, REPO / license_name)
                writer.bytes("VERSION.txt", (f"BinaryRat {version} ({args.revision})\n"
                                             f"{host.name}, Temurin {JDK_VERSION}\n").encode())
                metadata = {
                    "application": "BinaryRat",
                    "revision": args.revision,
                    "source": f"https://github.com/YurilLAB/BinaryRat/tree/{args.revision}",
                    "platform": host.name,
                    "ghidra_version": version,
                    "ghidra_source_distribution_sha256": digest(args.ghidra),
                    "extension_archive_sha256": digest(args.extension),
                    "jdk": properties["IMPLEMENTOR_VERSION"],
                    "jdk_source_sha256": JDK_SOURCE_SHA256,
                    "jvm_mitigations": list(JVM_MITIGATIONS),
                    "example": example_name,
                    "example_sha256": digest(args.example),
                    "python_wheel": args.wheel.name if args.wheel else None,
                }
                writer.bytes("manifest.json", (json.dumps(metadata, indent=2, sort_keys=True) + "\n").encode())
            checksum = temporary.with_suffix(".zip.sha256")
            checksum.write_bytes(f"{digest(temporary)} *{name}\n".encode())
            temporary.replace(destination)
            checksum.replace(destination.with_suffix(".zip.sha256"))
    return destination


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("ghidra", "extension", "jdk", "jdk-source", "example", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--wheel", type=Path)
    args = parser.parse_args()
    try:
        print(build(args, current_host()))
    except (BadZipFile, KeyError, OSError, ValueError) as error:
        parser.exit(1, f"Cannot build BinaryRat archive: {error}\n")


if __name__ == "__main__":
    main()
