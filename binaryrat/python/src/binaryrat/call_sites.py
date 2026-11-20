"""Typed, versioned call-site reports.

Reports come from ``BinaryRatCallSites.java`` or ``ProgramView.call_sites``; both use the
Java ``binaryrat.CallSites`` service. Each site is one call to the selected function (or to a
thunk of it), shown as the caller's decompiled C statement with the argument values the
decompiler proved constant. Parsing is strict: every field is typed and bounded, statuses and
argument kinds carry exactly the fields they promise, and the counts agree with the sites.

Apache-2.0; Copyright 2026 YurilLAB.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
import json
from pathlib import Path
import re
from typing import Any

from .models import Address

SCHEMA_VERSION = 1
ANALYSIS_MODE = "read_only_call_sites"
MAX_REPORT_BYTES = 8 * 1024 * 1024
MAX_SITES = 1024
MAX_CALLERS = 256
MAX_TIMEOUT_SECONDS = 600
MAX_REFERENCES = 100_000
MAX_ARGUMENTS = 64
MAX_STATEMENT = 1024
MAX_STRING = 120
STATUSES = ("decompiled", "no_function", "unsupported_caller", "decompile_failed",
            "not_in_decompilation", "caller_limit")
KINDS = ("constant", "address", "unknown")
STRING_SOURCES = ("defined_data", "memory_scan")
# Statuses whose caller the service decompiled (successfully or not).
_DECOMPILE_ATTEMPTED = ("decompiled", "decompile_failed", "not_in_decompilation")
_INT64 = (-(1 << 63), (1 << 63) - 1)
_HEX = re.compile(r"[0-9a-f]{1,16}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_PROGRAM_ID = re.compile(r"sha256:[0-9a-f]{64}")


class CallSitesReportError(ValueError):
    """A call-site report is malformed, inconsistent or unsupported."""


@dataclass(frozen=True, slots=True)
class CallArgument:
    index: int
    size: int
    kind: str
    value: int | None
    signed: int | None
    variable: str | None
    symbol: str | None
    string: str | None
    string_source: str | None

    def render(self) -> str:
        """The argument as a C call shows it: 7, -1, 0x401000, a string, &symbol or a name."""
        if self.kind == "unknown":
            return self.variable or "?"
        if self.kind == "address":
            if self.string is not None:
                return self.string
            return f"&{self.symbol}" if self.symbol is not None else f"0x{self.value:x}"
        if self.signed is not None and -0x10000 < self.signed < 0x10000:
            return str(self.signed)
        return f"0x{self.value:x}"


@dataclass(frozen=True, slots=True)
class CallTarget:
    address: Address
    name: str | None
    thunk: bool


@dataclass(frozen=True, slots=True)
class CallSite:
    site: Address
    target: Address
    caller: Address | None
    caller_name: str | None
    status: str
    reason: str | None
    operation: str | None
    statement: str | None
    arguments: tuple[CallArgument, ...]
    arguments_truncated: bool
    instruction_sha256: str | None


@dataclass(frozen=True)
class CallSitesReport:
    schema_version: int
    program_id: str | None
    revision: int
    language_id: str
    compiler_spec_id: str
    function: Address
    function_name: str
    root_function: Address
    root_name: str
    targets: tuple[CallTarget, ...]
    timeout_seconds: int
    site_limit: int
    caller_limit: int
    references_scanned: int
    call_references: int
    other_references: int
    truncated: bool
    decompiled_callers: int
    sites: tuple[CallSite, ...]
    # The validated JSON document, for services that forward it unchanged.
    document: dict[str, Any] = field(repr=False, compare=False)

    def callers(self) -> tuple[Address, ...]:
        """Distinct callers in order of their first call site."""
        seen: dict[Address, None] = {}
        for site in self.sites:
            if site.caller is not None:
                seen.setdefault(site.caller, None)
        return tuple(seen)


def _fail(message: str) -> None:
    raise CallSitesReportError(message)


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


def _printable(value: str) -> bool:
    return not any(ord(ch) < 32 or 127 <= ord(ch) < 160 for ch in value)


def _text(obj: Any, key: str, where: str, *, optional: bool = False, limit: int = 4096) -> str | None:
    if optional and isinstance(obj, dict) and key in obj and obj[key] is None:
        return None
    value = _get(obj, key, str, where)
    if not value or len(value) > limit or not _printable(value):
        _fail(f"{where}: {key} must be nonempty printable text of at most {limit} characters")
    return value


def _null(obj: Any, key: str, where: str) -> None:
    if not isinstance(obj, dict) or key not in obj or obj[key] is not None:
        _fail(f"{where}: {key} must be null")


def _address(obj: Any, prefix: str, where: str) -> Address:
    space = _text(obj, f"{prefix}address_space", where, limit=64)
    offset = _get(obj, f"{prefix}address", str, where)
    if _HEX.fullmatch(offset) is None:
        _fail(f"{where}: {prefix}address must be bare lowercase hex")
    return Address(space, int(offset, 16))


def _keys(obj: Any, expected: set[str], where: str) -> None:
    if not isinstance(obj, dict):
        _fail(f"{where} must be an object")
    if set(obj) != expected:
        _fail(f"{where}: unexpected or missing fields {sorted(set(obj) ^ expected)}")


def _named_function(obj: Any, where: str) -> tuple[Address, str]:
    _keys(obj, {"address_space", "address", "name"}, where)
    return _address(obj, "", where), _text(obj, "name", where, limit=MAX_STATEMENT)


_ARGUMENT_KEYS = {"index", "size", "kind", "value", "signed", "variable", "symbol", "string",
                  "string_source"}


def _argument(obj: Any, index: int, where: str) -> CallArgument:
    _keys(obj, _ARGUMENT_KEYS, where)
    if _int(obj, "index", where, 0, MAX_ARGUMENTS - 1) != index:
        _fail(f"{where}: arguments must be numbered in order")
    size = _int(obj, "size", where, 1, 1 << 16)
    kind = _get(obj, "kind", str, where)
    if kind not in KINDS:
        _fail(f"{where}: unsupported argument kind")
    if kind == "unknown":
        for key in ("value", "signed", "symbol", "string", "string_source"):
            _null(obj, key, where)
        variable = _text(obj, "variable", where, optional=True, limit=MAX_STATEMENT)
        return CallArgument(index, size, kind, None, None, variable, None, None, None)
    _null(obj, "variable", where)
    raw = _get(obj, "value", str, where)
    if _HEX.fullmatch(raw) is None:
        _fail(f"{where}: value must be bare lowercase hex")
    value = int(raw, 16)
    if size < 8 and value >> (8 * size):
        _fail(f"{where}: value does not fit the argument size")
    if size <= 8:
        signed = _int(obj, "signed", where)
        bits = 8 * size
        if signed != (value - (1 << bits) if value >> (bits - 1) else value):
            _fail(f"{where}: signed does not match value")
    else:
        _null(obj, "signed", where)
        signed = None
    if kind == "constant":
        for key in ("symbol", "string", "string_source"):
            _null(obj, key, where)
        return CallArgument(index, size, kind, value, signed, None, None, None, None)
    if size > 8:
        _fail(f"{where}: an address must fit 64 bits")
    symbol = _text(obj, "symbol", where, optional=True, limit=MAX_STATEMENT)
    string = _text(obj, "string", where, optional=True, limit=MAX_STRING)
    source = obj.get("string_source")
    if (string is None) != (source is None) or source is not None and source not in STRING_SOURCES:
        _fail(f"{where}: string_source must name the source of a string, and only then")
    return CallArgument(index, size, kind, value, signed, None, symbol, string, source)


_SITE_KEYS = {"address_space", "address", "target_address_space", "target_address", "caller",
              "status", "reason", "operation", "statement", "arguments", "arguments_truncated",
              "instruction_sha256"}


def _site(obj: Any, where: str) -> CallSite:
    _keys(obj, _SITE_KEYS, where)
    site = _address(obj, "", where)
    target = _address(obj, "target_", where)
    status = _get(obj, "status", str, where)
    if status not in STATUSES:
        _fail(f"{where}: unsupported status")
    if obj["caller"] is None:
        caller, caller_name = None, None
    else:
        caller, caller_name = _named_function(obj["caller"], f"{where} caller")
    if (caller is None) != (status == "no_function"):
        _fail(f"{where}: only a call outside every function has no caller")
    digest = obj["instruction_sha256"]
    if digest is not None and (not isinstance(digest, str) or _SHA256.fullmatch(digest) is None):
        _fail(f"{where}: instruction_sha256 must be null or 64 lowercase hex digits")
    truncated = _get(obj, "arguments_truncated", bool, where)
    raw_arguments = _get(obj, "arguments", list, where)
    if len(raw_arguments) > MAX_ARGUMENTS:
        _fail(f"{where}: too many arguments")
    if status != "decompiled":
        _text(obj, "reason", where, limit=MAX_STATEMENT)
        for key in ("operation", "statement"):
            _null(obj, key, where)
        if raw_arguments or truncated:
            _fail(f"{where}: only a decompiled call has arguments")
        return CallSite(site, target, caller, caller_name, status, obj["reason"], None, None, (),
                        False, digest)
    _null(obj, "reason", where)
    operation = _get(obj, "operation", str, where)
    if operation not in ("CALL", "CALLIND"):
        _fail(f"{where}: operation must be CALL or CALLIND")
    statement = _text(obj, "statement", where, optional=True, limit=MAX_STATEMENT)
    if truncated and len(raw_arguments) != MAX_ARGUMENTS:
        _fail(f"{where}: arguments are truncated only at the argument limit")
    arguments = tuple(_argument(item, index, f"{where} argument {index}")
                      for index, item in enumerate(raw_arguments))
    return CallSite(site, target, caller, caller_name, status, None, operation, statement, arguments,
                    truncated, digest)


_REPORT_KEYS = {"schema_version", "analysis_mode", "function", "root_function", "revision",
                "program_id", "language_id", "compiler_spec_id", "targets", "timeout_seconds",
                "site_limit", "caller_limit", "references_scanned", "call_references",
                "other_references", "truncated", "decompiled_callers", "sites"}


def parse_call_sites_report(document: Mapping[str, Any]) -> CallSitesReport:
    """Validate a decoded report and return typed values. Raises CallSitesReportError."""
    where = "report"
    _keys(document, _REPORT_KEYS, where)
    if _get(document, "schema_version", int, where) != SCHEMA_VERSION:
        _fail("unsupported schema_version")
    if _get(document, "analysis_mode", str, where) != ANALYSIS_MODE:
        _fail("unsupported analysis_mode")
    program_id = document["program_id"]
    if program_id is not None and (not isinstance(program_id, str) or
                                   _PROGRAM_ID.fullmatch(program_id) is None):
        _fail("report: program_id must be null or sha256:<64 lowercase hex>")
    function, function_name = _named_function(document["function"], "function")
    root, root_name = _named_function(document["root_function"], "root_function")
    targets = []
    for index, item in enumerate(_get(document, "targets", list, where)):
        here = f"target {index}"
        _keys(item, {"address_space", "address", "name", "thunk"}, here)
        targets.append(CallTarget(_address(item, "", here),
                                  _text(item, "name", here, optional=True, limit=MAX_STATEMENT),
                                  _get(item, "thunk", bool, here)))
    roots = [target for target in targets if not target.thunk]
    if len(roots) != 1 or roots[0].address != root or targets[0] != roots[0]:
        _fail("report: targets must start with the root function, then its thunks")
    if len({target.address for target in targets}) != len(targets):
        _fail("report: duplicate target")
    if function not in {target.address for target in targets}:
        _fail("report: the selected function must be the root or one of its thunks")
    site_limit = _int(document, "site_limit", where, 1, MAX_SITES)
    caller_limit = _int(document, "caller_limit", where, 1, MAX_CALLERS)
    scanned = _int(document, "references_scanned", where, 0, MAX_REFERENCES)
    call_references = _int(document, "call_references", where, 0, MAX_REFERENCES)
    other = _int(document, "other_references", where, 0, MAX_REFERENCES)
    truncated = _get(document, "truncated", bool, where)
    decompiled_callers = _int(document, "decompiled_callers", where, 0, caller_limit)
    if call_references + other > scanned:
        _fail("report: more references than were scanned")
    raw_sites = _get(document, "sites", list, where)
    if len(raw_sites) > site_limit:
        _fail("report: more sites than the site limit")
    sites = tuple(_site(item, f"site {index}") for index, item in enumerate(raw_sites))
    if len(sites) > call_references:
        _fail("report: more sites than call references")
    if len(sites) < call_references and not truncated:
        _fail("report: a shortened site list must be marked truncated")
    if len({site.site for site in sites}) != len(sites):
        _fail("report: duplicate call site")
    target_addresses = {target.address for target in targets}
    if any(site.target not in target_addresses for site in sites):
        _fail("report: a site reaches an address that is not a target")
    attempted = {site.caller for site in sites if site.status in _DECOMPILE_ATTEMPTED}
    if len(attempted) != decompiled_callers:
        _fail("report: decompiled_callers does not match the sites")
    if any(site.status == "caller_limit" for site in sites) and decompiled_callers != caller_limit:
        _fail("report: callers were skipped before the caller limit was reached")
    return CallSitesReport(
        SCHEMA_VERSION, program_id, _int(document, "revision", where),
        _text(document, "language_id", where, limit=256),
        _text(document, "compiler_spec_id", where, limit=256),
        function, function_name, root, root_name, tuple(targets),
        _int(document, "timeout_seconds", where, 1, MAX_TIMEOUT_SECONDS),
        site_limit, caller_limit, scanned, call_references, other, truncated, decompiled_callers, sites,
        dict(document),
    )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise CallSitesReportError("duplicate JSON property")
        result[key] = value
    return result


def _no_constant(token: str) -> None:
    raise CallSitesReportError(f"invalid JSON constant {token}")


def _bounded_int(token: str) -> int:
    if len(token.lstrip("-")) > 20:
        raise CallSitesReportError("oversized integer in call-site report")
    return int(token)


def decode_call_sites_report(data: bytes | str) -> CallSitesReport:
    """Decode strict JSON (no duplicate keys, NaN or huge integers) and validate it."""
    raw = data.encode("utf-8") if isinstance(data, str) else data
    if len(raw) > MAX_REPORT_BYTES:
        raise CallSitesReportError("call-site report exceeds 8 MiB")
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                              parse_constant=_no_constant, parse_int=_bounded_int)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as cause:
        raise CallSitesReportError(f"invalid call-site report JSON: {cause}") from None
    return parse_call_sites_report(document)


def load_call_sites_report(path: str | Path) -> CallSitesReport:
    file = Path(path)
    if not file.is_file():
        raise CallSitesReportError("expected a regular call-site report file")
    with file.open("rb") as stream:
        data = stream.read(MAX_REPORT_BYTES + 1)
    return decode_call_sites_report(data)


def _clean(text: str) -> str:
    return "".join(ch if ch.isprintable() else "?" for ch in text)


def explain_call_sites(report: CallSitesReport) -> list[str]:
    """One line per call: address, caller and statement, then the arguments with known values."""
    callers = len(report.callers())
    lines = [f"Calls to {_clean(report.root_name)} at {report.root_function}: {len(report.sites)} "
             f"{'site' if len(report.sites) == 1 else 'sites'} in {callers} "
             f"{'caller' if callers == 1 else 'callers'}"
             + (f" (truncated; {report.call_references} call references)" if report.truncated else "")]
    for site in report.sites:
        caller = _clean(site.caller_name) if site.caller_name is not None else "(no function)"
        text = site.statement if site.statement is not None else f"[{site.status}] {site.reason}"
        lines.append(f"{site.site}  {caller}  {_clean(text or '')}")
        known = [f"arg{argument.index} = {_clean(argument.render())}" for argument in site.arguments
                 if argument.kind != "unknown"]
        if known:
            lines.append("    " + ", ".join(known))
    return lines
