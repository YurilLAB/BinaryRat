"""Strict, streaming ingestion of the Java bridge's version-1 JSONL export.

Apache-2.0; Copyright 2026 YurilLAB.
"""

import json
import re
from pathlib import Path
from typing import Any, Iterable, Iterator

from .models import Address, Decompilation, Function


class ExportError(ValueError):
    """An invalid export, annotated with its one-based input line number."""


def _field(row: dict[str, Any], name: str, kind: type) -> Any:
    value = row.get(name)
    if type(value) is not kind:
        raise ValueError(f"{name} must be {kind.__name__}")
    return value


def _address(space: str, text: Any) -> Address:
    if not isinstance(text, str) or not re.fullmatch(r"(?:0[xX])?[0-9a-fA-F]+", text):
        raise ValueError("address must be an unsigned hexadecimal string")
    return Address(space, int(text, 16))


def _record(row: dict[str, Any]) -> Decompilation:
    if _field(row, "schema_version", int) != 1:
        raise ValueError("unsupported schema_version")
    program_id = _field(row, "program_id", str)
    if not program_id:
        raise ValueError("program_id must not be empty")
    revision = _field(row, "revision", int)
    if revision < 0:
        raise ValueError("revision must be nonnegative")
    space = _field(row, "address_space", str)
    entry = _address(space, row.get("address"))
    digest = _field(row, "body_sha256", str)
    if not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
        raise ValueError("body_sha256 must contain 64 hexadecimal digits")
    raw_ranges = row.get("body_ranges", [])
    if not isinstance(raw_ranges, list):
        raise ValueError("body_ranges must be a list of inclusive [start, end] pairs")
    ranges = []
    for pair in raw_ranges:
        if not isinstance(pair, list) or len(pair) != 2:
            raise ValueError("body range must be an inclusive [start, end] pair")
        start, end = (_address(space, value) for value in pair)
        if start.offset > end.offset:
            raise ValueError("body range start exceeds end")
        ranges.append((start, end))
    return Decompilation(
        function=Function(program_id, entry, _field(row, "name", str), digest.lower(), tuple(ranges)),
        revision=revision,
        c=_field(row, "c", str),
        prototype=_field(row, "prototype", str),
        completed=_field(row, "completed", bool),
        timed_out=_field(row, "timed_out", bool),
        cancelled=_field(row, "cancelled", bool),
        failed_to_start=_field(row, "failed_to_start", bool),
        error=_field(row, "error", str),
    )


def parse_export(lines: Iterable[str]) -> Iterator[Decompilation]:
    """Parse one function per nonblank line; unknown fields are forward-compatible.

    Entries in different address spaces are distinct. Duplicate identities within
    the same program revision are rejected rather than silently overwritten.
    """
    seen: set[tuple[str, int, Address]] = set()
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError("record must be an object")
            result = _record(row)
            identity = (result.function.program_id, result.revision, result.function.entry)
            if identity in seen:
                raise ValueError("duplicate function identity in this program revision")
            seen.add(identity)
        except (ValueError, TypeError) as error:
            raise ExportError(f"line {number}: {error}") from error
        yield result


def load_export(path: str | Path) -> Iterator[Decompilation]:
    """Read an UTF-8 export without loading all decompiler output into memory."""
    with Path(path).open(encoding="utf-8") as stream:
        yield from parse_export(stream)
