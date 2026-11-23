"""Compare two BinaryRat JSONL exports by executable and function entry.

Apache-2.0; Copyright 2026 YurilLAB.
"""

import argparse
from collections.abc import Callable, Set
from dataclasses import dataclass, fields
import difflib
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import BinaryIO, Iterator, Literal, TypedDict

from ._console import tolerant_output
from .exports import ExportError, parse_export
from .models import Address, Decompilation


@dataclass(frozen=True, slots=True)
class _Fingerprint:
    name: str
    body_sha256: str
    body_ranges: tuple[tuple[int, int], ...]
    prototype: bytes
    c: bytes
    completed: bool
    timed_out: bool
    cancelled: bool
    failed_to_start: bool
    error: bytes


_FIELDS = tuple(field.name for field in fields(_Fingerprint))
_DEFAULT_MIB = 64
_PATCHED_FIELDS = {"prototype": "Prototype", "c": "C text", "error": "Error text"}


class _FunctionChangeFields(TypedDict):
    kind: Literal["added", "removed", "changed"]
    address_space: str
    address: str
    before_name: str | None
    after_name: str | None
    fields: list[str]


class FunctionChange(_FunctionChangeFields, total=False):
    # Present only when a patch was requested and the prototype, C or error changed.
    patch: str


class DiffReport(TypedDict):
    schema_version: int
    program_id: str
    counts: dict[str, int]
    changes: list[FunctionChange]


def _digest(text: str) -> bytes:
    # Java's ASCII JSON escaping can represent individual UTF-16 surrogates.
    return hashlib.sha256(text.encode("utf-8", errors="surrogatepass")).digest()


def _body_ranges(record: Decompilation) -> tuple[tuple[int, int], ...]:
    function = record.function
    ranges = tuple((low.offset, high.offset) for low, high in function.body_ranges)
    if function.entry.offset.bit_length() > 64 or any(high.bit_length() > 64 for _, high in ranges):
        raise ExportError("address exceeds the unsigned 64-bit Ghidra offset")
    return ranges


def _fingerprint(record: Decompilation, ranges: tuple[tuple[int, int], ...]) -> _Fingerprint:
    function = record.function
    return _Fingerprint(
        function.name, function.body_sha256, tuple(sorted(ranges)), _digest(record.prototype),
        _digest(record.c), record.completed, record.timed_out, record.cancelled,
        record.failed_to_start, _digest(record.error),
    )


def _lines(stream: BinaryIO, limit: int, hash_line: Callable[[bytes], None] | None) -> Iterator[str]:
    number = 0
    while line := stream.readline(limit + 1):
        number += 1
        if len(line) > limit:
            raise ExportError(f"line {number} exceeds the {limit}-byte record limit")
        if hash_line is not None:
            hash_line(line)
        try:
            yield line.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ExportError(f"line {number} contains invalid UTF-8") from error


def _records(
    path: Path, limit: int, program_id: str | None, hash_line: Callable[[bytes], None] | None,
) -> Iterator[tuple[str, Decompilation, tuple[tuple[int, int], ...]]]:
    raw_id = None
    revision = None
    try:
        with path.open("rb") as stream:
            for record in parse_export(_lines(stream, limit, hash_line)):
                ident = record.function.program_id
                if not re.fullmatch(r"sha256:[0-9a-fA-F]{64}", ident):
                    raise ExportError("a verified comparison requires an executable SHA-256 program_id")
                if raw_id is not None and ident != raw_id:
                    raise ExportError("program_id mismatch within a single export")
                raw_id = ident
                ident = ident.lower()
                if program_id is not None and ident != program_id:
                    raise ExportError("program_id mismatch: the inputs must describe one executable")
                if revision is not None and record.revision != revision:
                    raise ExportError("a single export contains mixed revisions")
                program_id, revision = ident, record.revision
                yield ident, record, _body_ranges(record)
        if revision is None:
            raise ExportError("empty export has no executable identity")
    except (ExportError, RecursionError) as error:
        raise ExportError(f"{path}: {error}") from error


def _change(kind: Literal["added", "removed", "changed"], entry: Address,
            before: str | None, after: str | None, changed: list[str]) -> FunctionChange:
    return FunctionChange(kind=kind, address_space=entry.space, address=f"{entry.offset:x}",
                          before_name=before, after_name=after, fields=changed)


def _review_lines(record: Decompilation) -> list[str]:
    lines = [f"/* prototype: {record.prototype} */"]
    if record.error:
        lines += [f"/* error: {line} */" for line in record.error.splitlines()]
    return lines + record.c.splitlines()


def _patches(before: Path, after: Path, limit: int, program_id: str,
             wanted: dict[Address, tuple[_Fingerprint, _Fingerprint]],
             context: int, input_digests: tuple[bytes, bytes]) -> dict[Address, str]:
    """Diff the prototype, error and C of changed functions in a second pass.

    Only the earlier export's text for those functions is held in memory. The second
    pass verifies the bytes of each export, including metadata and unselected records.
    """
    earlier: dict[Address, tuple[str, list[str]]] = {}
    patches: dict[Address, str] = {}
    for side, path in enumerate((before, after)):
        digest = hashlib.sha256()
        for _, record, _ in _records(path, limit, program_id, digest.update):
            entry = record.function.entry
            prints = wanted.get(entry)
            if prints is None:
                continue
            if side == 0:
                earlier[entry] = (record.function.name, _review_lines(record))
                continue
            previous = earlier.pop(entry, None)
            if previous is None:
                raise ExportError(f"{path}: the export changed while it was being compared")
            old_name, old_text = previous
            new_text = _review_lines(record)
            if old_text == new_text:
                # Display lines omit their endings. Show the exact text digests
                # when a change such as LF to CRLF has no visible line diff.
                changed = [field for field in _PATCHED_FIELDS
                           if getattr(prints[0], field) != getattr(prints[1], field)]
                old_text, new_text = ([
                    f"/* {_PATCHED_FIELDS[field]} raw SHA-256: {getattr(item, field).hex()} */"
                    for field in changed
                ] for item in prints)
            patches[entry] = "\n".join(difflib.unified_diff(
                old_text, new_text, f"before {entry} {old_name}",
                f"after {entry} {record.function.name}", n=context, lineterm=""))
        if digest.digest() != input_digests[side]:
            raise ExportError(f"{path}: the export changed while it was being compared")
    return patches


def compare_exports(before: Path, after: Path, *, max_record_mib: int = _DEFAULT_MIB,
                    patch_context: int | None = None, entries: Set[Address] | None = None) -> DiffReport:
    """Compare exported records, keeping fingerprints in memory instead of decompiled C.

    With ``patch_context``, each change to a prototype, error or C text also carries a
    unified diff with that many context lines, from a second pass over both files.
    With ``entries``, only those function entries contribute to the result.
    """
    if type(max_record_mib) is not int or not 1 <= max_record_mib <= (sys.maxsize - 1) // (1024 * 1024):
        raise ValueError("max_record_mib is outside the supported positive range")
    if patch_context is not None and (type(patch_context) is not int or not 0 <= patch_context <= 10_000):
        raise ValueError("patch_context must be an integer from 0 to 10000")
    limit = max_record_mib * 1024 * 1024
    before_hash = hashlib.sha256() if patch_context is not None else None
    after_hash = hashlib.sha256() if patch_context is not None else None
    previous: dict[Address, _Fingerprint] = {}
    missing = set(entries) if entries is not None else set()
    program_id = ""
    for program_id, record, ranges in _records(
            before, limit, None, before_hash.update if before_hash is not None else None):
        entry = record.function.entry
        if entries is None or entry in entries:
            previous[entry] = _fingerprint(record, ranges)
            missing.discard(entry)

    counts = {"added": 0, "removed": 0, "changed": 0, "unchanged": 0}
    changes: dict[Address, FunctionChange] = {}
    patched: dict[Address, tuple[_Fingerprint, _Fingerprint]] = {}
    for _, record, ranges in _records(
            after, limit, program_id, after_hash.update if after_hash is not None else None):
        entry = record.function.entry
        if entries is not None and entry not in entries:
            continue
        current = _fingerprint(record, ranges)
        missing.discard(entry)
        old = previous.pop(entry, None)
        if old is None:
            counts["added"] += 1
            changes[entry] = _change("added", entry, None, current.name, [])
        elif old == current:
            counts["unchanged"] += 1
        else:
            counts["changed"] += 1
            changed = [name for name in _FIELDS if getattr(old, name) != getattr(current, name)]
            changes[entry] = _change("changed", entry, old.name, current.name, changed)
            if patch_context is not None and any(field in _PATCHED_FIELDS for field in changed):
                patched[entry] = (old, current)
    counts["removed"] = len(previous)
    for entry, old in previous.items():
        changes[entry] = _change("removed", entry, old.name, None, [])
    if missing:
        raise ExportError(f"requested function {str(min(missing))!r} is absent from both exports")
    if patched and patch_context is not None and before_hash is not None and after_hash is not None:
        digests = (before_hash.digest(), after_hash.digest())
        for entry, patch in _patches(before, after, limit, program_id, patched, patch_context, digests).items():
            changes[entry]["patch"] = patch
    return DiffReport(schema_version=1, program_id=program_id, counts=counts,
                      changes=[changes[key] for key in sorted(changes)])


def _entry_argument(value: str) -> Address:
    space, _, offset = value.rpartition(":")
    if not space or not re.fullmatch(r"(?:0[xX])?[0-9a-fA-F]+", offset):
        raise argparse.ArgumentTypeError("expected an address-space name and hex offset (ram:401000)")
    address = Address(space, int(offset, 16))
    if address.offset.bit_length() > 64:
        raise argparse.ArgumentTypeError("function entry exceeds the unsigned 64-bit Ghidra offset")
    return address


def _print_text(report: DiffReport) -> None:
    print(report["program_id"])
    print(", ".join(f"{count} {kind}" for kind, count in report["counts"].items()))
    for change in report["changes"]:
        before, after = change["before_name"], change["after_name"]
        names = json.dumps(after if after is not None else before)
        if before is not None and after is not None and before != after:
            names = f"{json.dumps(before)} -> {json.dumps(after)}"
        # Escape analyst-controlled text for terminals, including control characters.
        space = json.dumps(change["address_space"])[1:-1]
        detail = ", ".join(change["fields"])
        print(f'{change["kind"]} {space}:{change["address"]} {names}' +
              (f" ({detail})" if detail else ""))
        for line in change.get("patch", "").splitlines():
            print(line if line.replace("\t", " ").isprintable() else ascii(line)[1:-1])


def main(argv: list[str] | None = None) -> int:
    tolerant_output()
    parser = argparse.ArgumentParser(
        prog="binaryrat-diff",
        description="Compare two BinaryRat decompiler exports of the same executable SHA-256.",
        epilog="Use the same selection and address layout to track edits. Added and removed "
               "describe records in the exports. --patch reads both files twice and holds the "
               "earlier text of changed functions in memory. Exit 0 for identical records, "
               "1 for differences, and 2 for errors.",
    )
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    parser.add_argument("--json", action="store_true", help="emit a versioned JSON report")
    parser.add_argument("--patch", action="store_true",
                        help="show a unified diff of each changed prototype, error and C text")
    parser.add_argument("--function", type=_entry_argument, action="append", metavar="SPACE:HEX",
                        help="compare only this function entry (repeatable)")
    parser.add_argument("--context", type=int, metavar="LINES",
                        help="context lines around each --patch hunk (default: 3)")
    parser.add_argument("--max-record-mib", type=int, default=_DEFAULT_MIB,
                        help="maximum input line size in MiB, including newline (default: 64)")
    args = parser.parse_args(argv)
    if args.context is not None and not args.patch:
        parser.error("--context only applies to --patch")
    try:
        report = compare_exports(args.before, args.after, max_record_mib=args.max_record_mib,
                                 patch_context=(args.context if args.context is not None else 3)
                                 if args.patch else None,
                                 entries=set(args.function) if args.function else None)
    except (OSError, ValueError) as error:
        print(f"binaryrat-diff: {error}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, ensure_ascii=True, allow_nan=False))
    else:
        _print_text(report)
    return int(bool(report["changes"]))


if __name__ == "__main__":
    sys.exit(main())
