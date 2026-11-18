#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify ABI metadata against the existing stripped C++ inheritance fixture."""

from __future__ import annotations

import argparse
from io import BytesIO
import json
import os
from pathlib import Path
import re
import shutil
import struct
import tempfile

from elftools.elf.constants import P_FLAGS
from elftools.elf.elffile import ELFFile

from verify_ghidra import PROJECT, measured_run, saved_project_hashes
from verify_large_llvm import launcher, sha256

CORPUS_IDS = {
    "gcc/O0/classes", "clang/O0/classes", "gcc-aarch64/O0/classes",
    "msvc/Od/classes", "msvc-aarch64/Od/classes",
}

HIERARCHY = {
    "Left": (),
    "Right": (),
    "Item": (("Left", False), ("Right", False)),
    "Derived": (("Item", False),),
    "Root": (),
    "First": (("Root", True),),
    "Second": (("Root", True),),
    "Diamond": (("First", False), ("Second", False)),
}
BRIDGE = PROJECT / "binaryrat/bridge/ghidra_scripts"
TESTS = PROJECT / "binaryrat/benchmarks/rtti_scripts"


def classes_by_name(report: dict) -> dict[str, dict]:
    valid = {}
    for name in HIERARCHY:
        spellings = {f"{len(name)}{name}"} if report["abi"] == "itanium" else {
            f".?AU{name}@@", f".?AV{name}@@",
        }
        rows = [row for row in report["classes"] if row["encoded_name"] in spellings]
        if len(rows) > 1:
            raise AssertionError(f"ambiguous RTTI class {name}")
        if rows:
            valid[name] = rows[0]
    return valid


def check_hierarchy(report: dict) -> dict[str, dict]:
    classes = classes_by_name(report)
    if set(classes) != set(HIERARCHY):
        raise AssertionError(f"missing class metadata {sorted(set(HIERARCHY) - set(classes))}")
    names = {row["encoded_name"]: name for name, row in classes.items()}
    for name, expected in HIERARCHY.items():
        row = classes[name]
        bases = row["direct_bases"]
        actual = tuple((names[base["encoded_name"]], base["virtual_base"]) for base in bases)
        if actual != expected:
            raise AssertionError(f"{name} bases differ from C++ fixture: {actual} != {expected}")
        for base in bases:
            if (not base["evidence_address"] or
                    base["descriptor_address"] != classes[names[base["encoded_name"]]]["descriptor_address"]):
                raise AssertionError("direct base evidence is missing or refers to another class")
            if base["virtual_base"] and base["object_offset"] is not None:
                raise AssertionError("a virtual base was given a fixed object offset")
    for name in ("Item", "Derived", "Diamond"):
        tables = classes[name]["vtables"]
        if not tables:
            raise AssertionError(f"{name} lacks validated vtable evidence")
        if name != "Diamond" and (not any(table["subobject_offset"] == 0 for table in tables) or not any(
                table["subobject_offset"] > 0 for table in tables)):
            raise AssertionError(f"{name} lacks primary or secondary vtable evidence")
        if any(int(table["address_point"], 16) - int(table["metadata_slot"], 16) != 8 or
               not table["first_function_address"] for table in tables):
            raise AssertionError(f"{name} has incomplete slot provenance")
    return classes


def disk_offset(image: bytes, abi: str, address: int, image_base: int) -> int:
    if abi == "itanium":
        elf = ELFFile(BytesIO(image))
        loads = [segment for segment in elf.iter_segments() if segment["p_type"] == "PT_LOAD"]
        target = address - image_base + min(segment["p_vaddr"] for segment in loads)
        for segment in loads:
            displacement = target - segment["p_vaddr"]
            if 0 <= displacement <= segment["p_filesz"] - 4:
                return segment["p_offset"] + displacement
    else:
        pe, = struct.unpack_from("<I", image, 0x3c)
        if image[pe:pe + 4] != b"PE\0\0":
            raise ValueError("expected a portable executable")
        count, = struct.unpack_from("<H", image, pe + 6)
        optional_size, = struct.unpack_from("<H", image, pe + 20)
        for index in range(count):
            section = pe + 24 + optional_size + index * 40
            rva, raw_size, raw_start = struct.unpack_from("<III", image, section + 12)
            displacement = address - image_base - rva
            if 0 <= displacement <= raw_size - 4:
                return raw_start + displacement
    raise ValueError("RTTI field does not map to four file-backed bytes")


def malformed_copy(binary: Path, output: Path, report: dict, classes: dict) -> str:
    image = bytearray(binary.read_bytes())
    abi = report["abi"]
    image_base = int(report["image_base"], 16)
    if abi == "itanium":
        address = int(classes["Item"]["descriptor_address"], 16) + 20
        expected = 2
        bad_value = 0xffffffff
        asset = classes["Item"]["descriptor_address"]
    else:
        table = classes["Derived"]["vtables"][0]
        locator = int(table["locator_address"], 16)
        address = locator + 20
        expected = locator - image_base
        bad_value = expected + 4
        asset = table["address_point"]
    offset = disk_offset(image, abi, address, image_base)
    if struct.unpack_from("<I", image, offset)[0] != expected:
        raise AssertionError("on-disk field does not match linked metadata before corruption")
    struct.pack_into("<I", image, offset, bad_value)
    output.write_bytes(image)
    return asset


def writable_elf_names_copy(binary: Path, output: Path) -> None:
    image = bytearray(binary.read_bytes())
    elf = ELFFile(BytesIO(image))
    rodata = elf.get_section_by_name(".rodata")
    if elf.elfclass != 64 or not elf.little_endian or rodata is None:
        raise ValueError("expected a little-endian ELF64 fixture with .rodata")
    loads = [(index, segment) for index, segment in enumerate(elf.iter_segments())
             if segment["p_type"] == "PT_LOAD" and segment.section_in_segment(rodata)]
    if len(loads) != 1:
        raise ValueError("fixture .rodata must belong to one PT_LOAD segment")
    index, segment = loads[0]
    flags = segment["p_flags"]
    if flags & P_FLAGS.PF_W or not flags & P_FLAGS.PF_R:
        raise ValueError("expected a read-only .rodata PT_LOAD segment")
    position = elf["e_phoff"] + index * elf["e_phentsize"] + 4
    struct.pack_into("<I", image, position, flags | P_FLAGS.PF_W)
    output.write_bytes(image)


def log_diagnostic(messages: str) -> str:
    lines = messages.splitlines()
    for expression in (r"\.java:\d+: error:", r"REPORT SCRIPT ERROR", r"\bERROR "):
        for line in lines:
            if re.search(expression, line):
                return "".join(character for character in line.strip() if character.isprintable())[:320]
    return "No Ghidra error line was recorded"


def workflow_error(artifact: str, stage: str, error: Exception) -> str:
    text = f"{artifact} while {stage} [{type(error).__name__}]. {error}"[:1000]
    clean = "".join(character for character in text if character.isprintable() or character in "\r\n")
    return "::error::" + clean.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def run_report(headless: Path, binary: Path, output: Path, timeout: int,
               project_readback: bool, *, writable_names: bool = False) -> tuple[dict, dict]:
    log = output.with_suffix(".log")
    with tempfile.TemporaryDirectory(prefix="rtti project ", dir=output.parent) as directory:
        project = Path(directory)
        environment = {**os.environ, "GHIDRA_HEADLESS_MAXMEM": "1G",
                       "XDG_CONFIG_HOME": str(project / "settings"),
                       "XDG_CACHE_HOME": str(project / "cache")}
        scripts = project / "scripts"
        (scripts / "binaryrat").mkdir(parents=True)
        shutil.copyfile(BRIDGE / "BinaryRatRecoverRtti.java", scripts / "BinaryRatRecoverRtti.java")
        shutil.copyfile(BRIDGE / "binaryrat/RttiEvidence.java", scripts / "binaryrat/RttiEvidence.java")
        shutil.copyfile(TESTS / "BinaryRatRttiInvariants.java", scripts / "BinaryRatRttiInvariants.java")
        command = [str(headless), directory, "rtti"]
        if project_readback:
            import_log = output.with_suffix(".import.log")
            prepare = measured_run(command + ["-import", str(binary), "-noanalysis"],
                                   import_log, timeout, environment)
            if prepare["returncode"]:
                diagnostic = log_diagnostic(import_log.read_text(encoding="utf-8", errors="replace"))
                raise AssertionError(f"Ghidra failed to save the disposable RTTI project "
                                     f"with exit code {prepare['returncode']}. "
                                     f"{diagnostic}. See {import_log}")
            before = saved_project_hashes(project, "rtti")
            entry = ["-process", binary.name]
        else:
            entry = ["-import", str(binary)]
        proof_args = ["writable-rodata"] if writable_names else []
        measured = measured_run(command + entry + [
            "-noanalysis", "-readOnly", "-scriptPath", str(scripts),
            "-postScript", "BinaryRatRecoverRtti.java", str(output),
            "-postScript", "BinaryRatRttiInvariants.java", *proof_args,
        ], log, timeout, environment)
        messages = log.read_text(encoding="utf-8", errors="replace")
        if (measured["returncode"] or not output.is_file() or
                "BINARYRAT_RTTI_REPORT_PUBLISHED" not in messages or
                "BINARYRAT_RTTI_INVARIANTS_VERIFIED" not in messages or
                "REPORT SCRIPT ERROR" in messages):
            raise AssertionError(f"RTTI collection or invariant test failed "
                                 f"with Ghidra exit code {measured['returncode']}. "
                                 f"{log_diagnostic(messages)}. See {log}")
        if project_readback:
            after = saved_project_hashes(project, "rtti")
            changed = sorted(name for name in before.keys() | after.keys()
                             if before.get(name) != after.get(name))
            if changed:
                raise AssertionError(f"RTTI collection changed saved project artifacts: {changed}")
    report = json.loads(output.read_text(encoding="utf-8"))
    if report["schema_version"] != 1 or report["program_id"] != f"sha256:{sha256(binary)}":
        raise AssertionError("RTTI report has the wrong schema or executable identity")
    return report, measured


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ghidra", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--artifact", action="append", choices=sorted(CORPUS_IDS))
    parser.add_argument("--timeout", type=int, default=240)
    args = parser.parse_args()
    if not 1 <= args.timeout <= 1800:
        parser.error("timeout must be between 1 and 1800 seconds")

    artifact_id = "RTTI verifier setup"
    stage = "reading the corpus manifest"
    try:
        manifest = json.loads(args.corpus.read_text(encoding="utf-8"))
        if manifest["schema_version"] != 1 or manifest["status"] != "passed":
            raise ValueError("passing BinaryRat corpus is required")
        root = Path(manifest["root"]).resolve(strict=True)
        selected = set(args.artifact) if args.artifact else CORPUS_IDS
        artifacts = [row for row in manifest["artifacts"] if row["id"] in selected]
        if not artifacts or len({row["id"] for row in artifacts}) != len(artifacts) or (
                args.artifact and len(artifacts) != len(selected)):
            raise ValueError("missing or duplicate requested RTTI artifacts")

        stage = "selecting the host Ghidra launcher"
        headless = launcher(args.ghidra.resolve(strict=True), windows=os.name == "nt")
        print(f"RTTI verifier using {headless}", flush=True)
        stage = "preparing the report directory"
        output = args.output.resolve()
        output.mkdir(parents=True, exist_ok=False)
        runs = []
        for artifact in artifacts:
            artifact_id = artifact["id"]
            stage = "verifying the stripped fixture"
            binary = (root / artifact["binary"]).resolve(strict=True)
            if (root not in binary.parents or binary.stat().st_size > 16 * 1024 * 1024 or
                    binary.parent.name != "analysis" or sha256(binary) != artifact["binary_sha256"]):
                raise ValueError("invalid stripped RTTI fixture")
            stem = artifact["id"].replace("/", "-")
            print(f"Checking RTTI for {artifact['id']}", flush=True)
            stage = "collecting RTTI and checking read-only invariants"
            clean, measured = run_report(headless, binary, output / f"{stem}.json", args.timeout, True)
            expected_abi = {"ELF64": "itanium", "PE32+": "msvc"}[artifact["format"]]
            if clean["abi"] != expected_abi:
                raise AssertionError("collector used the wrong C++ ABI")
            stage = "comparing the class graph and vtable evidence"
            classes = check_hierarchy(clean)
            corrupt = output / f"{stem}-malformed{binary.suffix}"
            stage = "constructing the malformed ABI record"
            invalidated = malformed_copy(binary, corrupt, clean, classes)
            stage = "collecting evidence from the malformed fixture"
            altered, _ = run_report(headless, corrupt, output / f"{stem}-malformed.json", args.timeout, False)
            stage = "checking rejection of the malformed record"
            altered_classes = classes_by_name(altered)
            ignored = (all(row["descriptor_address"] != invalidated for row in altered["classes"])
                       if clean["abi"] == "itanium" else
                       all(table["address_point"] != invalidated
                           for row in altered["classes"] for table in row["vtables"]))
            if not ignored or "Diamond" not in altered_classes:
                raise AssertionError("malformed RTTI was emitted or unrelated metadata was discarded")
            run = {"artifact": artifact_id, "abi": clean["abi"], "classes": len(classes),
                   "malformed_excluded": True, "program_unchanged": True, "measurement": measured}
            if artifact_id == "gcc-aarch64/O0/classes":
                stage = "constructing the writable ELF class-name fixture"
                writable = output / f"{stem}-writable-names"
                writable_elf_names_copy(binary, writable)
                stage = "checking rejection of writable ELF class names"
                unsafe_names, _ = run_report(headless, writable, output / f"{stem}-writable-names.json",
                                             args.timeout, False, writable_names=True)
                if classes_by_name(unsafe_names):
                    raise AssertionError("class names from writable ELF memory entered the report")
                run["writable_names_excluded"] = True
            runs.append(run)
            print(f"{artifact['id']} verified {len(classes)} classes and rejected malformed RTTI", flush=True)
        stage = "writing the verification summary"
        (output / "report.json").write_text(json.dumps({"passed": True, "runs": runs}, indent=2) + "\n",
                                            encoding="utf-8")
    except Exception as error:
        if os.environ.get("GITHUB_ACTIONS") == "true":
            print(workflow_error(artifact_id, stage, error), flush=True)
        raise
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
