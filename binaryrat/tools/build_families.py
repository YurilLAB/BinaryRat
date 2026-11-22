#!/usr/bin/env python3
"""Build calibration source families as stripped shared objects with separate debug files.

Each family is one independent source project. Its sources are compiled without running any
of the project's own build scripts, linked into one shared object, and split into the stripped
analysis input and the debug file that only the oracle reads.

SPDX-License-Identifier: Apache-2.0
Copyright 2026 YurilLAB. New BinaryRat tooling.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import time

from build_corpus import digest, host_arch, inspect_binary
from pinned_download import DownloadError, fetch


SCHEMA_VERSION = 1
PROJECT = Path(__file__).resolve().parents[2]
DEFAULT_FAMILIES = PROJECT / "binaryrat/corpus/families.json"
SPLIT_RULE = "sha256-of-id order, first half fit"
TOOLCHAINS = {"gcc": ("gcc", "g++"), "clang": ("clang", "clang++")}
OPTIMIZATIONS = ("O1", "O2", "O3")
SUFFIXES = {"c": (".c",), "c++": (".cc", ".cpp", ".cxx")}
MAX_FAMILIES = 64
MAX_SOURCES = 4096
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_EXTRACTED_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 20_000
COMPILE_TIMEOUT = 600
ID = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")
SHA256 = re.compile(r"[0-9a-f]{64}")
ARCHIVE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}\.tar\.(?:gz|bz2|xz)")
URL = re.compile(r"https://[a-z0-9.-]+/[A-Za-z0-9._~/%+-]+")
PATTERN = re.compile(r"[A-Za-z0-9._*-]+(?:/[A-Za-z0-9._*-]+)*")
DEFINE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:=[A-Za-z0-9_.\"-]{0,64})?")
# -std and feature toggles only: an option that names a file or a program is refused.
FLAG = re.compile(r"-std=[a-z0-9+]{1,12}|-f[a-z][a-z-]{1,40}")
HEADER_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,47}\.h")
REQUIRED_KEYS = {"id", "split", "language", "license", "origin", "sources"}
OPTIONAL_KEYS = {"exclude", "include", "defines", "flags", "config_headers"}


def _keys(value: object, required: set[str], optional: set[str], label: str) -> dict:
    if type(value) is not dict or not required <= value.keys() <= required | optional:
        raise ValueError(f"{label} has missing or unknown fields")
    return value


def _strings(value: object, pattern: re.Pattern, label: str, limit: int = 64) -> list[str]:
    if type(value) is not list or len(value) > limit or len(set(map(str, value))) != len(value):
        raise ValueError(f"{label} must be a list of at most {limit} distinct strings")
    for item in value:
        if not isinstance(item, str) or not pattern.fullmatch(item):
            raise ValueError(f"invalid {label}: {item!r}")
    return value


def _relative(value: object, label: str) -> str:
    if (not isinstance(value, str) or not PATTERN.fullmatch(value) or "*" in value or
            ".." in PurePosixPath(value).parts):
        raise ValueError(f"invalid {label}: {value!r}")
    return value


def _patterns(value: object, label: str) -> list[str]:
    patterns = _strings(value, PATTERN, label)
    if any(".." in PurePosixPath(pattern).parts for pattern in patterns):
        raise ValueError(f"{label} must stay inside the source root")
    return patterns


def expected_splits(identifiers: list[str]) -> dict[str, str]:
    """Assigns the split from the IDs alone, so no outcome can influence it."""
    ordered = sorted(identifiers, key=lambda name: hashlib.sha256(name.encode()).hexdigest())
    fit = (len(ordered) + 1) // 2
    return {name: "fit" if index < fit else "holdout" for index, name in enumerate(ordered)}


def parse_families(document: object) -> list[dict]:
    root = _keys(document, {"schema_version", "split_rule", "families"}, set(), "family list")
    if type(root["schema_version"]) is not int or root["schema_version"] != SCHEMA_VERSION:
        raise ValueError("unsupported family list schema")
    if root["split_rule"] != SPLIT_RULE:
        raise ValueError("family list declares an unknown split rule")
    families = root["families"]
    if type(families) is not list or not 1 <= len(families) <= MAX_FAMILIES:
        raise ValueError("invalid number of families")
    archives: set[str] = set()
    roots: set[str] = set()
    for family in families:
        _keys(family, REQUIRED_KEYS, OPTIONAL_KEYS, "family")
        if not isinstance(family["id"], str) or not ID.fullmatch(family["id"]):
            raise ValueError(f"invalid family ID: {family['id']!r}")
        if family["language"] not in SUFFIXES:
            raise ValueError(f"unsupported language for {family['id']}")
        if not isinstance(family["license"], str) or not re.fullmatch(r"[A-Za-z0-9.+ ()-]{1,64}",
                                                                      family["license"]):
            raise ValueError(f"invalid license text for {family['id']}")
        origin = family["origin"]
        if type(origin) is not dict or len(origin) != 1:
            raise ValueError(f"{family['id']} needs exactly one origin")
        if "repository" in origin:
            location = _relative(origin["repository"], "repository source root")
        elif "archive" in origin:
            archive = _keys(origin["archive"], {"name", "url", "sha256", "prefix"}, set(), "archive")
            for key, pattern in (("name", ARCHIVE_NAME), ("url", URL), ("sha256", SHA256)):
                if not isinstance(archive[key], str) or not pattern.fullmatch(archive[key]):
                    raise ValueError(f"invalid archive {key} for {family['id']}")
            if not archive["url"].endswith("/" + archive["name"]):
                raise ValueError(f"archive URL and name disagree for {family['id']}")
            _relative(archive["prefix"], "archive prefix")
            if archive["name"] in archives:
                raise ValueError("one archive is assigned to several families")
            archives.add(archive["name"])
            location = "archive:" + archive["name"]
        else:
            raise ValueError(f"unknown origin for {family['id']}")
        if location in roots:
            raise ValueError("one source root is assigned to several families")
        roots.add(location)
        if not _patterns(family["sources"], "source pattern"):
            raise ValueError(f"{family['id']} lists no sources")
        _patterns(family.get("exclude", []), "exclude pattern")
        for directory in _strings(family.get("include", []), PATTERN, "include directory"):
            _relative(directory, "include directory")
        _strings(family.get("defines", []), DEFINE, "define")
        _strings(family.get("flags", []), FLAG, "compiler flag", 8)
        headers = family.get("config_headers", {})
        if type(headers) is not dict or len(headers) > 4:
            raise ValueError(f"invalid config headers for {family['id']}")
        for name, defines in headers.items():
            if not HEADER_NAME.fullmatch(name):
                raise ValueError(f"invalid config header name: {name!r}")
            _strings(defines, DEFINE, "config header define")
    identifiers = [family["id"] for family in families]
    if len(set(identifiers)) != len(identifiers):
        raise ValueError("duplicate family ID")
    splits = expected_splits(identifiers)
    for family in families:
        if family["split"] != splits[family["id"]]:
            raise ValueError(f"{family['id']} must be in the {splits[family['id']]} split ({SPLIT_RULE})")
    return families


def load_families(path: Path) -> list[dict]:
    return parse_families(json.loads(path.read_text(encoding="utf-8")))


def extract_archive(archive: Path, destination: Path) -> None:
    """Unpacks regular files and directories only, inside a new directory."""
    if archive.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError("source archive is larger than the supported size")
    destination.mkdir(parents=True)
    total = 0
    with tarfile.open(archive, "r:*") as bundle:
        members = []
        for member in bundle:
            if len(members) >= MAX_ARCHIVE_MEMBERS:
                raise ValueError("source archive has too many entries")
            if member.isdir():
                continue
            if not member.isreg():
                # Links and devices are never needed to compile the listed sources.
                continue
            total += member.size
            if total > MAX_EXTRACTED_BYTES:
                raise ValueError("source archive expands beyond the supported size")
            members.append(member)
        # The data filter refuses absolute names, parent references and special files.
        bundle.extractall(destination, members=members, filter="data")


def select_sources(root: Path, family: dict) -> list[Path]:
    root = root.resolve(strict=True)
    excluded = {path.resolve() for pattern in family.get("exclude", []) for path in root.glob(pattern)}
    selected: dict[Path, None] = {}
    for pattern in family["sources"]:
        matches = sorted(path.resolve() for path in root.glob(pattern))
        if not matches:
            raise ValueError(f"source pattern matches nothing: {pattern}")
        for path in matches:
            if path in excluded:
                continue
            if root not in path.parents or not path.is_file():
                raise ValueError(f"source is outside the family root: {pattern}")
            if path.suffix not in SUFFIXES[family["language"]]:
                raise ValueError(f"unexpected source type: {path.name}")
            selected[path] = None
    if not 1 <= len(selected) <= MAX_SOURCES:
        raise ValueError("family selects no sources or too many")
    return sorted(selected)


def source_digest(root: Path, sources: list[Path]) -> str:
    """SHA-256 of the canonical list of compiled sources and their content digests."""
    listing = hashlib.sha256()
    for path in sources:
        relative = path.relative_to(root.resolve()).as_posix()
        # Line endings differ between checkouts; the family identity must not.
        content = path.read_bytes().replace(b"\r\n", b"\n")
        listing.update(f"{relative}\0{hashlib.sha256(content).hexdigest()}\n".encode())
    return listing.hexdigest()


def _run(command: list[str], cwd: Path) -> float:
    started = time.monotonic()
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, errors="replace",
                            timeout=COMPILE_TIMEOUT)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {command!r}\n"
                           f"{result.stdout[-4000:]}\n{result.stderr[-4000:]}")
    return time.monotonic() - started


def build_family(family: dict, root: Path, output: Path, toolchain: str, tools: dict,
                 optimization: str, jobs: int) -> dict:
    identifier = family["id"]
    work = output / toolchain / optimization / identifier
    if work.exists():
        shutil.rmtree(work)
    objects, oracle, analysis = work / "objects", work / "oracle", work / "analysis"
    for directory in (objects, oracle, analysis):
        directory.mkdir(parents=True)
    root = root.resolve(strict=True)
    sources = select_sources(root, family)
    includes = []
    for directory in family.get("include", []):
        include = (root / directory).resolve(strict=True)
        if root != include and root not in include.parents:
            raise ValueError("include directory is outside the family root")
        includes.append(f"-I{include}")
    # A project's configure script is never run: the few macros it would write are listed.
    generated = work / "generated"
    for name, defines in family.get("config_headers", {}).items():
        generated.mkdir(exist_ok=True)
        lines = ["#define " + define.replace("=", " ", 1) for define in defines]
        (generated / name).write_text("".join(line + "\n" for line in lines), encoding="ascii")
        includes.append(f"-I{generated}")
    includes = list(dict.fromkeys(includes))
    compiler = tools["c" if family["language"] == "c" else "c++"]
    common = [compiler, f"-{optimization}", "-g", "-gdwarf-4", "-fno-eliminate-unused-debug-types",
              "-fPIC", "-fno-lto", "-w", f"-ffile-prefix-map={root}=/{identifier}",
              *family.get("flags", []), *(f"-D{define}" for define in family.get("defines", [])),
              *includes]

    def compile_one(item: tuple[int, Path]) -> tuple[Path, float]:
        index, source = item
        target = objects / f"{index:04d}.o"
        return target, _run([*common, "-c", str(source), "-o", str(target)], root)

    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        compiled = list(pool.map(compile_one, enumerate(sources)))
    original = oracle / f"{identifier}.so"
    stripped = analysis / f"{identifier}.so"
    debug = oracle / f"{identifier}.debug"
    _run([compiler, "-shared", f"-{optimization}", "-g", "-o", str(original),
          *(str(target) for target, _ in compiled)], root)
    before = inspect_binary(original)
    if before["architecture"] != host_arch():
        raise RuntimeError(f"wrong target architecture: {before['architecture']}")
    if not before["executable_sections"]:
        raise RuntimeError("family contains no executable sections")
    _run([tools["objcopy"], "--only-keep-debug", str(original), str(debug)], root)
    if not debug.is_file() or not debug.stat().st_size:
        raise RuntimeError("no ground-truth debug file was produced")
    _run([tools["strip"], "--strip-all", "-o", str(stripped), str(original)], root)
    after = inspect_binary(stripped)
    if before["executable_sections"] != after["executable_sections"]:
        raise RuntimeError("stripping changed executable section bytes or layout")
    if after["debug_sections"]:
        raise RuntimeError("stripped family still contains debug or symbol-table sections")
    shutil.rmtree(objects)
    relative = lambda path: path.relative_to(output).as_posix()
    return {"id": f"{toolchain}/{optimization}/{identifier}", "family": identifier,
            "split": family["split"], "toolchain": toolchain, "optimization": optimization,
            "architecture": after["architecture"], "language": family["language"],
            "format": after["format"], "source_files": len(sources),
            "source_sha256": source_digest(root, sources),
            "binary": relative(stripped), "binary_sha256": digest(stripped),
            "oracle_binary": relative(original), "oracle_binary_sha256": digest(original),
            "debug_file": relative(debug), "debug_sha256": digest(debug),
            "executable_sections": after["executable_sections"],
            "runtime_verification": {"status": "not-run-library"},
            "compile_command": [*common[1:], "-c"],
            "elapsed_seconds": time.monotonic() - started}


def family_root(family: dict, output: Path, archives: Path) -> Path:
    origin = family["origin"]
    if "repository" in origin:
        return PROJECT / origin["repository"]
    archive = origin["archive"]
    try:
        local = fetch(archive["url"], archives / archive["name"], archive["sha256"])
    except DownloadError as error:
        raise RuntimeError(str(error)) from error
    destination = output / "_sources" / family["id"]
    if destination.exists():
        shutil.rmtree(destination)
    extract_archive(local, destination)
    return destination / archive["prefix"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--families", type=Path, default=DEFAULT_FAMILIES)
    parser.add_argument("--archives", type=Path, help="directory of pinned source archives; "
                        "missing ones are downloaded and hash-checked (default OUTPUT/_archives)")
    parser.add_argument("--toolchain", action="append", choices=TOOLCHAINS)
    parser.add_argument("--optimization", action="append", choices=OPTIMIZATIONS)
    parser.add_argument("--only", action="append", help="build only this family ID (repeatable)")
    parser.add_argument("--jobs", type=int, default=min(8, os.cpu_count() or 1))
    args = parser.parse_args(argv)
    if not 1 <= args.jobs <= 64:
        parser.error("jobs must be between 1 and 64")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    archives = (args.archives or output / "_archives").resolve()
    archives.mkdir(parents=True, exist_ok=True)
    families = load_families(args.families)
    if args.only:
        unknown = set(args.only) - {family["id"] for family in families}
        if unknown:
            parser.error(f"unknown family: {', '.join(sorted(unknown))}")
        families = [family for family in families if family["id"] in args.only]
    manifest: dict = {"schema_version": SCHEMA_VERSION, "kind": "calibration-families",
                      "host": platform.platform(), "status": "passed", "split_rule": SPLIT_RULE,
                      "families_sha256": hashlib.sha256(
                          args.families.read_bytes().replace(b"\r\n", b"\n")).hexdigest(),
                      "toolchains": [], "artifacts": [], "errors": [],
                      "limitations": ["Inference must read the stripped files. Debug files are evaluation oracles.",
                                      "Shared objects are never executed; no project build script is run."]}
    for name in dict.fromkeys(args.toolchain or ["gcc"]):
        cc, cxx = TOOLCHAINS[name]
        tools = {"c": shutil.which(cc), "c++": shutil.which(cxx),
                 "objcopy": shutil.which("objcopy"), "strip": shutil.which("strip")}
        missing = sorted(key for key, value in tools.items() if not value)
        record: dict = {"name": name, "status": "passed"}
        manifest["toolchains"].append(record)
        if missing:
            record.update(status="unavailable", missing_tools=missing)
            manifest["status"] = "failed"
            continue
        version = subprocess.run([tools["c"], "--version"], capture_output=True, text=True,
                                 errors="replace")
        record["version"] = (version.stdout + version.stderr).strip().splitlines()[:1]
        for family in families:
            for optimization in dict.fromkeys(args.optimization or ["O2"]):
                try:
                    root = family_root(family, output, archives)
                    manifest["artifacts"].append(build_family(
                        family, root, output, name, tools, optimization, args.jobs))
                except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired,
                        tarfile.TarError) as error:
                    manifest["errors"].append({"family": family["id"], "toolchain": name,
                                               "optimization": optimization, "message": str(error)})
                    manifest["status"] = "failed"
    shutil.rmtree(output / "_sources", ignore_errors=True)
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    for error in manifest["errors"]:
        print(f"{error['family']}: {error['message']}", file=sys.stderr)
    print(f"{manifest['status']}: {len(manifest['artifacts'])} family builds; {output / 'manifest.json'}")
    return 0 if manifest["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
