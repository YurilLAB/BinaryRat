"""Compare two BinaryRat JSONL exports by executable and function entry.

Apache-2.0; Copyright 2026 YurilLAB.
"""

import argparse
from dataclasses import dataclass, fields
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import BinaryIO, Iterator, Literal, TypedDict

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


class FunctionChange(TypedDict):
    kind: Literal["added", "removed", "changed"]
    address_space: str
    address: str
    before_name: str | None
    after_name: str | None
    fields: list[str]


class DiffReport(TypedDict):
    schema_version: int
    program_id: str
    counts: dict[str, int]
    changes: list[FunctionChange]


def _digest(text: str) -> bytes:
    # Java's ASCII JSON escaping can represent individual UTF-16 surrogates.
    return hashlib.sha256(text.encode("utf-8", errors="surrogatepass")).digest()


def _fingerprint(record: Decompilation) -> _Fingerprint:
    function = record.function
    ranges = tuple(sorted((low.offset, high.offset) for low, high in function.body_ranges))
    if function.entry.offset.bit_length() > 64 or any(high.bit_length() > 64 for _, high in ranges):
        raise ExportError("address exceeds the unsigned 64-bit Ghidra offset")
    return _Fingerprint(
        function.name, function.body_sha256, ranges, _digest(record.prototype),
        _digest(record.c), record.completed, record.timed_out, record.cancelled,
        record.failed_to_start, _digest(record.error),
    )


def _lines(stream: BinaryIO, limit: int) -> Iterator[str]:
    number = 0
    while line := stream.readline(limit + 1):
        number += 1
        if len(line) > limit:
            raise ExportError(f"line {number} exceeds the {limit}-byte record limit")
        try:
            yield line.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ExportError(f"line {number} contains invalid UTF-8") from error


def _records(
    path: Path, limit: int, program_id: str | None = None,
) -> Iterator[tuple[str, Address, _Fingerprint]]:
    raw_id = None
    revision = None
    try:
        with path.open("rb") as stream:
            for record in parse_export(_lines(stream, limit)):
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
                yield ident, record.function.entry, _fingerprint(record)
        if revision is None:
            raise ExportError("empty export has no executable identity")
    except (ExportError, RecursionError) as error:
        raise ExportError(f"{path}: {error}") from error


def _change(kind: Literal["added", "removed", "changed"], entry: Address,
            before: str | None, after: str | None, changed: list[str]) -> FunctionChange:
    return FunctionChange(kind=kind, address_space=entry.space, address=f"{entry.offset:x}",
                          before_name=before, after_name=after, fields=changed)


def compare_exports(before: Path, after: Path, *, max_record_mib: int = _DEFAULT_MIB) -> DiffReport:
    """Compare exported records, keeping fingerprints in memory instead of decompiled C."""
    if type(max_record_mib) is not int or not 1 <= max_record_mib <= (sys.maxsize - 1) // (1024 * 1024):
        raise ValueError("max_record_mib is outside the supported positive range")
    limit = max_record_mib * 1024 * 1024
    previous: dict[Address, _Fingerprint] = {}
    program_id = ""
    for program_id, entry, fingerprint in _records(before, limit):
        previous[entry] = fingerprint

    counts = {"added": 0, "removed": 0, "changed": 0, "unchanged": 0}
    changes: dict[Address, FunctionChange] = {}
    for _, entry, current in _records(after, limit, program_id):
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
    counts["removed"] = len(previous)
    for entry, old in previous.items():
        changes[entry] = _change("removed", entry, old.name, None, [])
    return DiffReport(schema_version=1, program_id=program_id, counts=counts,
                      changes=[changes[key] for key in sorted(changes)])


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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="binaryrat-diff",
        description="Compare two BinaryRat decompiler exports of the same executable SHA-256.",
        epilog="Use the same selection and address layout to track edits. Added and removed "
               "describe records in the exports. Exit 0 for identical records, 1 for differences, "
               "and 2 for errors.",
    )
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    parser.add_argument("--json", action="store_true", help="emit a versioned JSON report")
    parser.add_argument("--max-record-mib", type=int, default=_DEFAULT_MIB,
                        help="maximum input line size in MiB, including newline (default: 64)")
    args = parser.parse_args(argv)
    try:
        report = compare_exports(args.before, args.after, max_record_mib=args.max_record_mib)
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
