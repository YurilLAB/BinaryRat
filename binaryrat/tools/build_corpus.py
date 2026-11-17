#!/usr/bin/env python3
"""Build real debug/oracle and stripped fixture pairs; Python standard library only.

SPDX-License-Identifier: Apache-2.0
Copyright 2026 YurilLAB. New BinaryRat tooling.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import sys
import time


FIXTURES = (("types", "types.c", "c"), ("classes", "classes.cpp", "c++"))
MACHINES = {62: "x86_64", 183: "aarch64", 0x8664: "x86_64", 0xAA64: "aarch64"}
TOOLCHAINS = {
    "gcc": ("gcc", "g++", "objcopy", "strip", None),
    "clang": ("clang", "clang++", "objcopy", "strip", None),
    "gcc-aarch64": ("aarch64-linux-gnu-gcc", "aarch64-linux-gnu-g++",
                    "aarch64-linux-gnu-objcopy", "aarch64-linux-gnu-strip", "aarch64"),
    "msvc": ("cl", "cl", None, None, None),
    "msvc-aarch64": ("cl", "cl", None, None, "aarch64"),
}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def host_arch() -> str:
    value = platform.machine().lower()
    return {"amd64": "x86_64", "arm64": "aarch64"}.get(value, value)


def checked_slice(data: bytes, offset: int, size: int) -> bytes:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise ValueError("binary contains an out-of-range file region")
    return data[offset:offset + size]


def inspect_binary(path: Path) -> dict:
    """Read enough ELF64/PE32+ to verify architecture and executable bytes."""
    data = path.read_bytes()
    sections = []
    if data.startswith(b"\x7fELF"):
        if checked_slice(data, 4, 2) != b"\x02\x01":
            raise ValueError("only little-endian ELF64 is supported by this corpus")
        machine = struct.unpack_from("<H", data, 18)[0]
        shoff = struct.unpack_from("<Q", data, 40)[0]
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 58)
        if shentsize < 64 or shnum == 0 or shstrndx >= shnum:
            raise ValueError("invalid or unsupported ELF section table")
        headers = [struct.unpack("<IIQQQQIIQQ", checked_slice(data, shoff + i * shentsize, 64))
                   for i in range(shnum)]
        names_header = headers[shstrndx]
        names = checked_slice(data, names_header[4], names_header[5])
        debug_sections = []
        for header in headers:
            name = names[header[0]:].split(b"\0", 1)[0].decode("ascii", "replace")
            if name.startswith((".debug", ".zdebug")) or header[1] == 2:
                debug_sections.append(name)
            if header[2] & 4 and header[5]:
                body = checked_slice(data, header[4], header[5])
                sections.append({"address": header[3], "size": header[5],
                                 "sha256": hashlib.sha256(body).hexdigest()})
        return {"format": "ELF64", "architecture": MACHINES.get(machine, str(machine)),
                "executable_sections": sections, "debug_sections": debug_sections}
    if data.startswith(b"MZ"):
        pe = struct.unpack("<I", checked_slice(data, 0x3C, 4))[0]
        if checked_slice(data, pe, 4) != b"PE\0\0":
            raise ValueError("invalid PE signature")
        machine, section_count = struct.unpack_from("<HH", data, pe + 4)
        optional_size = struct.unpack_from("<H", data, pe + 20)[0]
        optional = pe + 24
        if struct.unpack_from("<H", data, optional)[0] != 0x20B or optional_size < 168:
            raise ValueError("only PE32+ with a debug data-directory entry is supported")
        debug_rva, debug_size = struct.unpack_from("<II", data, optional + 112 + 6 * 8)
        for i in range(section_count):
            header = checked_slice(data, optional + optional_size + 40 * i, 40)
            address, size, offset = struct.unpack_from("<III", header, 12)
            characteristics = struct.unpack_from("<I", header, 36)[0]
            if characteristics & 0x20000000 and size:
                body = checked_slice(data, offset, size)
                sections.append({"address": address, "size": size,
                                 "sha256": hashlib.sha256(body).hexdigest()})
        return {"format": "PE32+", "architecture": MACHINES.get(machine, str(machine)),
                "executable_sections": sections, "debug_directory": [debug_rva, debug_size]}
    raise ValueError("fixture is neither ELF64 nor PE32+")


def strip_pe_debug(path: Path) -> None:
    """Remove PE debug directory and referenced CodeView/PDB-path payloads.

    MSVC stores types in the separate PDB. Removing only the PDB file would
    leave its lookup path in the PE, allowing accidental ground-truth import.
    """
    original = path.read_bytes()
    data = bytearray(original)
    inspect_binary(path)  # Validate format and bounds before mutation.
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    optional = pe + 24
    optional_size = struct.unpack_from("<H", data, pe + 20)[0]
    section_count = struct.unpack_from("<H", data, pe + 6)[0]
    directory = optional + 112 + 6 * 8
    rva, size = struct.unpack_from("<II", data, directory)
    ranges = []
    executable = []
    for i in range(section_count):
        header = checked_slice(original, optional + optional_size + i * 40, 40)
        virtual_size, address, raw_size, offset = struct.unpack_from("<IIII", header, 8)
        ranges.append((address, address + max(virtual_size, raw_size), offset, raw_size))
        if struct.unpack_from("<I", header, 36)[0] & 0x20000000:
            executable.append((offset, offset + raw_size))

    def erase(offset: int, length: int) -> None:
        checked_slice(original, offset, length)
        if any(offset < end and start < offset + length for start, end in executable):
            raise ValueError("refusing to erase a debug region overlapping executable bytes")
        data[offset:offset + length] = bytes(length)

    if rva or size:
        if not rva or not size or size % 28:
            raise ValueError("malformed PE debug directory")
        matches = [(start, offset, raw_size) for start, end, offset, raw_size in ranges
                   if start <= rva and rva + size <= end and rva - start + size <= raw_size]
        if len(matches) != 1:
            raise ValueError("PE debug directory cannot be mapped uniquely")
        start, offset, _ = matches[0]
        table = offset + rva - start
        for entry in range(table, table + size, 28):
            payload_size = struct.unpack_from("<I", original, entry + 16)[0]
            payload_offset = struct.unpack_from("<I", original, entry + 24)[0]
            if payload_size:
                erase(payload_offset, payload_size)
        erase(table, size)
    erase(directory, 8)
    # The checksum no longer describes the modified file; ordinary user-mode
    # executables accept zero. Drivers are deliberately outside this corpus.
    struct.pack_into("<I", data, optional + 64, 0)
    path.write_bytes(data)


def run_command(command: list[str], cwd: Path, commands: list[dict]) -> subprocess.CompletedProcess:
    started = time.monotonic()
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, errors="replace")
    commands.append({"argv": command, "elapsed_seconds": time.monotonic() - started,
                     "returncode": result.returncode})
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {command!r}\n{result.stdout}\n{result.stderr}")
    return result


def build_one(name: str, tools: tuple, optimization: str, fixture: tuple,
              output: Path, fixtures: Path) -> dict:
    identifier, filename, language = fixture
    work = output / name / optimization / identifier
    oracle, analysis = work / "oracle", work / "analysis"
    oracle.mkdir(parents=True, exist_ok=True)
    analysis.mkdir(parents=True, exist_ok=True)
    is_msvc = name.startswith("msvc")
    suffix = ".exe" if is_msvc else ""
    original = oracle / (identifier + suffix)
    stripped = analysis / (identifier + suffix)
    debug = oracle / (identifier + (".pdb" if is_msvc else ".debug"))
    commands: list[dict] = []
    cc, cxx, objcopy, strip, configured_arch = tools
    compiler = cc if language == "c" else cxx
    if is_msvc:
        command = [compiler, "/nologo", "/Zi", f"/{optimization}",
                   "/std:c11" if language == "c" else "/std:c++17",
                   f"/Fo{oracle / (identifier + '.obj')}",
                   f"/Fd{oracle / 'compiler.pdb'}", f"/Fe{original}"]
        if language == "c++":
            command += ["/EHsc", "/GR"]
        command += [str(fixtures / filename), "/link", "/DEBUG:FULL", "/INCREMENTAL:NO",
                    f"/PDB:{debug}", "/PDBALTPATH:oracle.pdb", "/OPT:REF", "/OPT:ICF"]
    else:
        command = [compiler, "-std=c11" if language == "c" else "-std=c++17",
                   "-g", "-gdwarf-4", "-fno-eliminate-unused-debug-types", f"-{optimization}",
                   str(fixtures / filename), "-o", str(original)]
    run_command(command, fixtures, commands)
    before = inspect_binary(original)
    expected_arch = configured_arch or host_arch()
    if before["architecture"] != expected_arch:
        raise RuntimeError(f"wrong target: expected {expected_arch}, got {before['architecture']}")
    if not before["executable_sections"]:
        raise RuntimeError("compiled fixture contains no executable sections")
    if not is_msvc:
        run_command([objcopy, "--only-keep-debug", str(original), str(debug)], fixtures, commands)
    if not debug.is_file() or not debug.stat().st_size:
        raise RuntimeError("compiler did not produce a nonempty ground-truth debug file")
    shutil.copy2(original, stripped)
    if is_msvc:
        strip_pe_debug(stripped)
    else:
        run_command([strip, "--strip-all", str(stripped)], fixtures, commands)
    after = inspect_binary(stripped)
    if before["executable_sections"] != after["executable_sections"]:
        raise RuntimeError("stripping changed executable section bytes or layout")
    if after.get("debug_sections") or any(after.get("debug_directory", [])):
        raise RuntimeError("stripped binary still contains debug metadata")
    runtime: dict = {"status": "not-run-cross-target"}
    if expected_arch == host_arch():
        baseline = run_command([str(original)], fixtures, commands)
        candidate = run_command([str(stripped)], fixtures, commands)
        if (baseline.returncode, baseline.stdout, baseline.stderr) != (
                candidate.returncode, candidate.stdout, candidate.stderr):
            raise RuntimeError("stripped and oracle executables behave differently")
        runtime = {"status": "passed", "stdout": candidate.stdout, "exit_code": candidate.returncode}
    relative = lambda path: path.relative_to(output).as_posix()
    return {"id": f"{name}/{optimization}/{identifier}", "toolchain": name,
            "architecture": expected_arch, "optimization": optimization, "language": language,
            "source": filename, "source_sha256": digest(fixtures / filename),
            "binary": relative(stripped), "binary_sha256": digest(stripped),
            "oracle_binary": relative(original), "oracle_binary_sha256": digest(original),
            "debug_file": relative(debug), "debug_sha256": digest(debug),
            "format": after["format"], "executable_sections": after["executable_sections"],
            "runtime_verification": runtime, "commands": commands}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--toolchain", action="append", choices=TOOLCHAINS,
                        help="required toolchain; repeat to select several")
    parser.add_argument("--optional-toolchain", action="append", default=[], choices=TOOLCHAINS,
                        help="record unavailable explicitly without failing")
    args = parser.parse_args(argv)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    fixtures = Path(__file__).resolve().parents[1] / "corpus" / "fixtures"
    required = args.toolchain or (["msvc"] if os.name == "nt" else ["gcc", "clang"])
    manifest: dict = {"schema_version": 1, "root": str(output), "host": platform.platform(),
                      "status": "passed", "toolchains": [], "artifacts": [],
                      "limitations": ["Debug-info extraction and type-accuracy scoring are not implemented.",
                                      "These small fixtures are not the required 100MB+ benchmark corpus."]}
    for name in dict.fromkeys(required + args.optional_toolchain):
        specification = TOOLCHAINS[name]
        missing = [tool for tool in specification[:4] if tool and not shutil.which(tool)]
        record: dict = {"name": name, "required": name in required}
        manifest["toolchains"].append(record)
        if missing:
            record.update(status="unavailable", missing_tools=missing)
            if record["required"]:
                manifest["status"] = "failed"
            continue
        resolved = tuple(shutil.which(tool) if tool else None for tool in specification[:4]) + specification[4:]
        version = subprocess.run([resolved[0]] + ([] if name.startswith("msvc") else ["--version"]),
                                 capture_output=True, text=True, errors="replace")
        record["version"] = (version.stdout + version.stderr).strip().splitlines()[:3]
        record["status"] = "passed"
        options = ("Od", "O1", "O2", "Ox") if name.startswith("msvc") else ("O0", "O1", "O2", "O3")
        for optimization in options:
            for fixture in FIXTURES:
                try:
                    artifact = build_one(name, resolved, optimization, fixture, output, fixtures)
                    manifest["artifacts"].append(artifact)
                except (OSError, ValueError, RuntimeError, struct.error) as error:
                    record.setdefault("errors", []).append(
                        {"optimization": optimization, "fixture": fixture[0], "message": str(error)})
                    record["status"] = "failed"
                    manifest["status"] = "failed"
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"{manifest['status']}: {len(manifest['artifacts'])} fixture pairs; {output / 'manifest.json'}")
    return 0 if manifest["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
