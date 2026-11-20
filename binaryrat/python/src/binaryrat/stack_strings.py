"""Typed, versioned stack-string reports.

Reports come from ``BinaryRatStackStrings.java`` or ``ProgramView.stack_strings``; both use the
Java ``binaryrat.StackStrings`` service and the engine's ``strings.stack`` op. Each string is
text a function builds on its stack with constant stores, at the stack offset Ghidra's stack
analysis gives, with the instructions that wrote it. Parsing is strict: every field is typed
and bounded, and each string's length, encoding and citations agree.

Apache-2.0; Copyright 2026 YurilLAB.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
import re
from typing import Any

from .models import Address

SCHEMA_VERSION = 1
ANALYSIS_MODE = "read_only_stack_strings"
MAX_REPORT_BYTES = 16 * 1024 * 1024
MAX_FUNCTIONS = 200_000
MAX_STRINGS = 10_000
MAX_TEXT = 1024
ENCODINGS = ("ascii", "utf16le")
_INT64 = (-(1 << 63), (1 << 63) - 1)
_HEX = re.compile(r"[0-9a-f]{1,16}")
_PROGRAM_ID = re.compile(r"sha256:[0-9a-f]{64}")
_TEXT = re.compile(r"[\x20-\x7e\t\n\r]+")


class StackStringsReportError(ValueError):
    """A stack-string report is malformed, inconsistent or unsupported."""


@dataclass(frozen=True, slots=True)
class StackString:
    function: Address
    function_name: str
    site: Address
    stack_offset: int
    byte_length: int
    encoding: str
    text: str
    text_truncated: bool
    terminated: bool
    writes: tuple[Address, ...]

    def render(self) -> str:
        """The text quoted and escaped as a C string literal; UTF-16 text gets an L prefix."""
        body = json.dumps(self.text)
        return ("L" if self.encoding == "utf16le" else "") + body + ("..." if self.text_truncated else "")


@dataclass(frozen=True)
class StackStringsReport:
    schema_version: int
    program_id: str | None
    revision: int
    language_id: str
    compiler_spec_id: str
    function: Address | None
    function_name: str | None
    minimum_length: int
    function_limit: int
    functions_scanned: int
    functions_skipped: int
    functions_partial: int
    stack_writes: int
    truncated: bool
    strings: tuple[StackString, ...]
    # The validated JSON document, for services that forward it unchanged.
    document: dict[str, Any] = field(repr=False, compare=False)


def _fail(message: str) -> None:
    raise StackStringsReportError(message)


def _get(obj: Any, key: str, kind: type | tuple[type, ...], where: str) -> Any:
    if not isinstance(obj, dict) or key not in obj:
        _fail(f"{where}: missing {key}")
    value = obj[key]
    # bool is an int subclass; a boolean never stands for a number here.
    if kind is not bool and isinstance(value, bool) or not isinstance(value, kind):
        _fail(f"{where}: {key} has the wrong type")
    return value


def _int(obj: Any, key: str, where: str, minimum: int = _INT64[0], maximum: int = _INT64[1]) -> int:
    value = _get(obj, key, int, where)
    if not minimum <= value <= maximum:
        _fail(f"{where}: {key} is out of range")
    return value


def _name(obj: Any, key: str, where: str) -> str:
    value = _get(obj, key, str, where)
    if not value or len(value) > 1024 or any(ord(ch) < 32 or 127 <= ord(ch) < 160 for ch in value):
        _fail(f"{where}: {key} must be nonempty printable text")
    return value


def _keys(obj: Any, expected: set[str], where: str) -> None:
    if not isinstance(obj, dict):
        _fail(f"{where} must be an object")
    if set(obj) != expected:
        _fail(f"{where}: unexpected or missing fields {sorted(set(obj) ^ expected)}")


def _address(obj: Any, where: str) -> Address:
    space = _name(obj, "address_space", where)
    offset = _get(obj, "address", str, where)
    if _HEX.fullmatch(offset) is None:
        _fail(f"{where}: address must be bare lowercase hex")
    return Address(space, int(offset, 16))


def _function(obj: Any, where: str) -> tuple[Address, str]:
    _keys(obj, {"address_space", "address", "name"}, where)
    return _address(obj, where), _name(obj, "name", where)


_STRING_KEYS = {"function", "address_space", "address", "stack_offset", "byte_length", "encoding", "text",
                "text_truncated", "terminated", "writes"}


def _string(obj: Any, minimum: int, where: str) -> StackString:
    _keys(obj, _STRING_KEYS, where)
    function, function_name = _function(obj["function"], f"{where} function")
    site = _address(obj, where)
    offset = _int(obj, "stack_offset", where)
    length = _int(obj, "byte_length", where, 1, 1 << 20)
    encoding = _get(obj, "encoding", str, where)
    if encoding not in ENCODINGS:
        _fail(f"{where}: unsupported encoding")
    text = _get(obj, "text", str, where)
    if len(text) > MAX_TEXT or _TEXT.fullmatch(text) is None:
        _fail(f"{where}: text must be 1 to {MAX_TEXT} printable ASCII, tab, newline or CR characters")
    truncated = _get(obj, "text_truncated", bool, where)
    unit = 2 if encoding == "utf16le" else 1
    characters = length // unit
    if length % unit or characters < minimum or (characters != len(text) if not truncated else
                                                 len(text) != MAX_TEXT or characters <= MAX_TEXT):
        _fail(f"{where}: byte_length does not match the text and encoding")
    if offset > _INT64[1] - (length - 1):
        _fail(f"{where}: the string runs past the largest stack offset")
    terminated = _get(obj, "terminated", bool, where)
    raw_writes = _get(obj, "writes", list, where)
    if not raw_writes or len(raw_writes) > length + 2:
        _fail(f"{where}: writes must cite 1 to byte_length + 2 instructions")
    writes = []
    for index, item in enumerate(raw_writes):
        _keys(item, {"address_space", "address"}, f"{where} write {index}")
        writes.append(_address(item, f"{where} write {index}"))
    ascending = all(a.offset < b.offset for a, b in zip(writes, writes[1:]) if a.space == b.space)
    if not ascending or len(set(writes)) != len(writes) or writes[0] != site:
        _fail(f"{where}: writes must be unique, in address order, starting at the string's address")
    return StackString(function, function_name, site, offset, length, encoding, text, truncated, terminated,
                       tuple(writes))


_REPORT_KEYS = {"schema_version", "analysis_mode", "revision", "program_id", "language_id", "compiler_spec_id",
                "function", "minimum_length", "function_limit", "functions_scanned", "functions_skipped",
                "functions_partial", "stack_writes", "truncated", "strings"}


def parse_stack_strings_report(document: Any) -> StackStringsReport:
    """Validate a decoded report and return typed values. Raises StackStringsReportError."""
    where = "report"
    _keys(document, _REPORT_KEYS, where)
    if _get(document, "schema_version", int, where) != SCHEMA_VERSION:
        _fail("unsupported schema_version")
    if _get(document, "analysis_mode", str, where) != ANALYSIS_MODE:
        _fail("unsupported analysis_mode")
    program_id = document["program_id"]
    if program_id is not None and (not isinstance(program_id, str) or _PROGRAM_ID.fullmatch(program_id) is None):
        _fail("report: program_id must be null or sha256:<64 lowercase hex>")
    function, function_name = (None, None) if document["function"] is None else \
        _function(document["function"], "function")
    minimum = _int(document, "minimum_length", where, 1, 64)
    limit = _int(document, "function_limit", where, 1, MAX_FUNCTIONS)
    scanned = _int(document, "functions_scanned", where, 0, limit)
    skipped = _int(document, "functions_skipped", where, 0, 1 << 31)
    partial = _int(document, "functions_partial", where, 0, scanned)
    writes = _int(document, "stack_writes", where, 0, 1 << 40)
    truncated = _get(document, "truncated", bool, where)
    raw_strings = _get(document, "strings", list, where)
    if len(raw_strings) > MAX_STRINGS:
        _fail("report: too many strings")
    strings = tuple(_string(item, minimum, f"string {index}") for index, item in enumerate(raw_strings))
    if function is not None and (scanned != 1 or skipped or any(item.function != function for item in strings)):
        _fail("report: a one-function report must scan that function only")
    if strings and not writes:
        _fail("report: strings need stack writes")
    return StackStringsReport(
        SCHEMA_VERSION, program_id, _int(document, "revision", where),
        _name(document, "language_id", where), _name(document, "compiler_spec_id", where),
        function, function_name, minimum, limit, scanned, skipped, partial, writes, truncated, strings,
        dict(document),
    )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise StackStringsReportError("duplicate JSON property")
        result[key] = value
    return result


def _no_constant(token: str) -> None:
    raise StackStringsReportError(f"invalid JSON constant {token}")


def _bounded_int(token: str) -> int:
    if len(token.lstrip("-")) > 20:
        raise StackStringsReportError("oversized integer in stack-string report")
    return int(token)


def decode_stack_strings_report(data: bytes | str) -> StackStringsReport:
    """Decode strict JSON (no duplicate keys, NaN or huge integers) and validate it."""
    raw = data.encode("utf-8") if isinstance(data, str) else data
    if len(raw) > MAX_REPORT_BYTES:
        raise StackStringsReportError("stack-string report exceeds 16 MiB")
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                              parse_constant=_no_constant, parse_int=_bounded_int)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as cause:
        raise StackStringsReportError(f"invalid stack-string report JSON: {cause}") from None
    return parse_stack_strings_report(document)


def load_stack_strings_report(path: str | Path) -> StackStringsReport:
    file = Path(path)
    if not file.is_file():
        raise StackStringsReportError("expected a regular stack-string report file")
    with file.open("rb") as stream:
        data = stream.read(MAX_REPORT_BYTES + 1)
    return decode_stack_strings_report(data)


def _clean(text: str) -> str:
    return "".join(ch if ch.isprintable() else "?" for ch in text)


def _offset(value: int) -> str:
    return f"-0x{-value:x}" if value < 0 else f"0x{value:x}"


def explain_stack_strings(report: StackStringsReport) -> list[str]:
    """One line per string: address of its first store, function, stack offset and text."""
    count = report.functions_scanned
    scope = _clean(report.function_name) if report.function_name is not None else \
        f"{count} function{'' if count == 1 else 's'}"
    lines = [f"Stack strings in {scope}: {len(report.strings)}"
             + (" (truncated)" if report.truncated else "")]
    for item in report.strings:
        lines.append(f"{item.site}  {_clean(item.function_name)}  stack {_offset(item.stack_offset)}  "
                     f"{item.render()}" + ("" if item.terminated else "  (no terminator)"))
    return lines
