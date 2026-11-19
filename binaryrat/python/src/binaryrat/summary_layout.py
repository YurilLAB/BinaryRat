"""Typed, versioned summary layout reports.

Reports come from ``BinaryRatSolveLayouts.java``, ``ProgramView.solve_layout`` or the
``binaryrat-live`` service; all three use the Java ``binaryrat.SummaryLayouts`` service.
Parsing is strict: every reached state must be a valid step of a call path, every
derived access must match its summary, and every field must cite derived evidence.
Strengths are uncalibrated support counts, never probabilities.

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
ANALYSIS_MODE = "read_only_summary_layout_evidence"
SCORE_KIND = "uncalibrated_evidence_strength"
MAX_REPORT_BYTES = 8 * 1024 * 1024
_INT64 = (-(1 << 63), (1 << 63) - 1)
_HEX = re.compile(r"[0-9a-f]{1,16}")
_VIEWS = ("integer", "floating_point")


class SummaryReportError(ValueError):
    """A summary layout report is malformed, inconsistent or unsupported."""


@dataclass(frozen=True, slots=True)
class SummaryAccess:
    offset: int
    width: int
    evidence_id: str
    site: Address
    pcode_order: int
    operation: str
    storage_view: str | None


@dataclass(frozen=True, slots=True)
class ParameterSummary:
    id: str
    function: Address
    function_name: str
    parameter_index: int
    parameter_storage: str | None
    call_refusal: str | None
    accesses: tuple[SummaryAccess, ...]


@dataclass(frozen=True, slots=True)
class CallEdge:
    """The callee's parameter equals the caller's parameter plus ``offset``."""

    caller: str
    callee: str
    offset: int
    evidence_id: str
    site: Address
    argument_index: int


@dataclass(frozen=True, slots=True)
class RefusedCall:
    caller: str
    site: Address
    callee: Address
    argument_index: int
    offset: int
    reason: str


@dataclass(frozen=True, slots=True)
class CallComponent:
    """Mutually recursive summaries; inconsistent ones had their internal edges withheld."""

    summaries: tuple[str, ...]
    consistent: bool
    withheld_edges: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class ReachedState:
    summary: str
    offset: int
    hops: int
    edge: int | None
    parent: int | None


@dataclass(frozen=True, slots=True)
class DerivedAccess:
    state: int
    access: int
    offset: int
    width: int
    evidence_id: str
    storage_view: str | None


@dataclass(frozen=True, slots=True)
class SolvedField:
    offset: int
    width: int
    evidence_ids: tuple[str, ...]
    evidence_strength: float
    overlaps_other_fields: bool


@dataclass(frozen=True, slots=True)
class UnionView:
    kind: str
    width: int
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class UnionCandidate:
    offset: int
    views: tuple[UnionView, ...]
    evidence_strength: float


@dataclass(frozen=True)
class SummaryLayoutReport:
    schema_version: int
    program_id: str
    revision: int
    language_id: str
    compiler_spec_id: str
    function: Address
    function_name: str
    parameter_index: int
    object_id: str
    complete: bool
    withheld_components: tuple[int, ...]
    overflowed: int
    summaries: tuple[ParameterSummary, ...]
    edges: tuple[CallEdge, ...]
    refused_calls: tuple[RefusedCall, ...]
    components: tuple[CallComponent, ...]
    states: tuple[ReachedState, ...]
    derived: tuple[DerivedAccess, ...]
    fields: tuple[SolvedField, ...]
    union_candidates: tuple[UnionCandidate, ...]
    minimum_extent: int
    # The validated JSON document, for services that forward it unchanged.
    document: dict[str, Any] = field(repr=False, compare=False)

    def summary(self, summary_id: str) -> ParameterSummary:
        for summary in self.summaries:
            if summary.id == summary_id:
                return summary
        raise KeyError(summary_id)

    def call_path(self, state: int) -> tuple[CallEdge, ...]:
        """The shortest recorded call path from the root to a reached state."""
        if not 0 <= state < len(self.states):
            raise IndexError(state)
        path = []
        current = self.states[state]
        while current.parent is not None:
            path.append(self.edges[current.edge])
            current = self.states[current.parent]
        return tuple(reversed(path))

    def evidence_for(self, offset: int, width: int) -> tuple[tuple[DerivedAccess, tuple[CallEdge, ...]], ...]:
        """Derived accesses at one field, each with the call path that reached it."""
        return tuple((row, self.call_path(row.state)) for row in self.derived
                     if row.offset == offset and row.width == width)


def _fail(message: str) -> None:
    raise SummaryReportError(message)


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


def _text(obj: Any, key: str, where: str, *, optional: bool = False) -> str | None:
    if optional and isinstance(obj, dict) and obj.get(key) is None:
        return None
    value = _get(obj, key, str, where)
    if not value or len(value) > 4096 or any(ord(ch) < 32 for ch in value):
        _fail(f"{where}: {key} must be nonempty printable text")
    return value


def _list(obj: Any, key: str, where: str, limit: int = 65_536) -> list:
    value = _get(obj, key, list, where)
    if len(value) > limit:
        _fail(f"{where}: {key} has too many entries")
    return value


def _address(obj: Any, prefix: str, where: str) -> Address:
    space = _text(obj, f"{prefix}address_space", where)
    offset = _get(obj, f"{prefix}address", str, where)
    if _HEX.fullmatch(offset) is None:
        _fail(f"{where}: {prefix}address must be bare lowercase hex")
    return Address(space, int(offset, 16))


def _view(obj: Any, where: str) -> str | None:
    if "storage_view" not in obj:
        return None
    view = _get(obj, "storage_view", str, where)
    if view not in _VIEWS:
        _fail(f"{where}: unsupported storage_view")
    return view


def _strength(obj: Any, where: str) -> float:
    value = _get(obj, "evidence_strength", (int, float), where)
    if not 0 <= value < 1:
        _fail(f"{where}: evidence_strength must be in [0, 1)")
    return float(value)


def parse_summary_report(document: Mapping[str, Any]) -> SummaryLayoutReport:
    """Validate a decoded report and return typed values. Raises SummaryReportError."""
    if not isinstance(document, dict):
        _fail("report must be a JSON object")
    where = "report"
    if _get(document, "schema_version", int, where) != SCHEMA_VERSION:
        _fail("unsupported schema_version")
    if (_get(document, "analysis_mode", str, where) != ANALYSIS_MODE or
            _get(document, "score_kind", str, where) != SCORE_KIND or
            _get(document, "assumption", str, where) != "analyst_selected_object_start"):
        _fail("not a summary layout evidence report")
    program_id = _text(document, "program_id", where)
    if re.fullmatch(r"sha256:[0-9a-f]{64}", program_id) is None:
        _fail("program_id must be sha256:<64 lowercase hex>")
    target = _get(document, "function", dict, where)
    function = _address(target, "", "function")
    parameter = _int(document, "parameter_index", where, 0, 1 << 16)
    root_id = f"{program_id}/{function.space}/{function.offset:x}/param/{parameter}"
    if _text(document, "object_id", where) != root_id:
        _fail("object_id does not name the selected parameter")

    summaries: list[ParameterSummary] = []
    by_id: dict[str, ParameterSummary] = {}
    evidence_owner: dict[str, str] = {}
    for index, item in enumerate(_list(document, "summaries", where, 256)):
        place = f"summaries[{index}]"
        summary_id = _text(item, "id", place)
        if summary_id in by_id:
            _fail(f"{place}: duplicate summary id")
        entry = _address(item, "function_", place)
        index_value = _int(item, "parameter_index", place, 0, 1 << 16)
        if summary_id != f"{program_id}/{entry.space}/{entry.offset:x}/param/{index_value}":
            _fail(f"{place}: id does not name its function parameter")
        accesses = []
        for number, row in enumerate(_list(item, "accesses", place, 4096)):
            spot = f"{place}.accesses[{number}]"
            evidence = _text(row, "evidence_id", spot)
            if not evidence.startswith(summary_id + "/") or evidence in evidence_owner:
                _fail(f"{spot}: evidence_id is foreign or repeated")
            evidence_owner[evidence] = summary_id
            accesses.append(SummaryAccess(_int(row, "offset", spot), _int(row, "width", spot, 1, 1 << 20),
                                          evidence, _address(row, "", spot),
                                          _int(row, "pcode_order", spot, 0, (1 << 32) - 1),
                                          _text(row, "operation", spot), _view(row, spot)))
        summary = ParameterSummary(summary_id, entry, _text(item, "function_name", place), index_value,
                                   _text(item, "parameter_storage", place, optional=True),
                                   _text(item, "call_refusal", place, optional=True), tuple(accesses))
        by_id[summary_id] = summary
        summaries.append(summary)
    if root_id not in by_id:
        _fail("the root summary is missing")

    edges = []
    for index, item in enumerate(_list(document, "edges", where, 1024)):
        place = f"edges[{index}]"
        caller, callee = _text(item, "caller", place), _text(item, "callee", place)
        if caller not in by_id or callee not in by_id:
            _fail(f"{place}: names an unknown summary")
        evidence = _text(item, "evidence_id", place)
        if not evidence.startswith(caller + "/call/"):
            _fail(f"{place}: evidence_id does not belong to the caller")
        callee_address = _address(item, "callee_", place)
        if by_id[callee].function != callee_address:
            _fail(f"{place}: callee address does not match the callee summary")
        argument = _int(item, "argument_index", place, 0, 1 << 16)
        if by_id[callee].parameter_index != argument:
            _fail(f"{place}: argument_index does not name the callee parameter")
        edges.append(CallEdge(caller, callee, _int(item, "offset", place), evidence,
                              _address(item, "", place), argument))

    refused = []
    for index, item in enumerate(_list(document, "refused_calls", where, 1024)):
        place = f"refused_calls[{index}]"
        caller = _text(item, "caller", place)
        if caller not in by_id:
            _fail(f"{place}: names an unknown caller")
        refused.append(RefusedCall(caller, _address(item, "", place), _address(item, "callee_", place),
                                   _int(item, "argument_index", place, 0, 1 << 16), _int(item, "offset", place),
                                   _text(item, "reason", place)))

    components = []
    for index, item in enumerate(_list(document, "components", where, 256)):
        place = f"components[{index}]"
        members = tuple(_get(item, "summaries", list, place))
        if not members or any(member not in by_id for member in members) or len(set(members)) != len(members):
            _fail(f"{place}: summaries must be distinct known ids")
        withheld = tuple(_get(item, "withheld_edges", list, place))
        consistent = _get(item, "consistent", bool, place)
        if any(type(edge) is not int or not 0 <= edge < len(edges) for edge in withheld) or (
                consistent and withheld):
            _fail(f"{place}: withheld_edges are invalid")
        components.append(CallComponent(members, consistent, withheld))
    withheld_edges = {edge for component in components for edge in component.withheld_edges}

    solution = _get(document, "solution", dict, where)
    if (_get(solution, "status", str, "solution") != "solved" or
            _get(solution, "summary", str, "solution") != root_id or
            _get(solution, "object_id", str, "solution") != root_id):
        _fail("solution does not describe a solved root")
    states = []
    seen_states: set[tuple[str, int]] = set()
    for index, item in enumerate(_list(solution, "states", "solution", 4096)):
        place = f"states[{index}]"
        summary_id = _text(item, "summary", place)
        offset, hops = _int(item, "offset", place), _int(item, "hops", place, 0, 4096)
        edge, parent = item.get("edge"), item.get("parent")
        if summary_id not in by_id or (summary_id, offset) in seen_states:
            _fail(f"{place}: unknown or repeated state")
        seen_states.add((summary_id, offset))
        if index == 0:
            if (summary_id, offset, hops, edge, parent) != (root_id, 0, 0, None, None):
                _fail("the first state must be the root")
        else:
            if (type(edge) is not int or type(parent) is not int or not 0 <= parent < index or
                    not 0 <= edge < len(edges) or edge in withheld_edges):
                _fail(f"{place}: invalid path step")
            step, previous = edges[edge], states[parent]
            if (step.caller != previous.summary or step.callee != summary_id or
                    previous.offset + step.offset != offset or previous.hops + 1 != hops):
                _fail(f"{place}: the recorded call does not lead to this state")
        states.append(ReachedState(summary_id, offset, hops, edge, parent))
    if not states:
        _fail("solution has no states")

    derived = []
    for index, item in enumerate(_list(solution, "derived", "solution", 4096)):
        place = f"derived[{index}]"
        state = _int(item, "state", place, 0, len(states) - 1)
        access_index = _int(item, "access", place, 0, 4095)
        accesses = by_id[states[state].summary].accesses
        if access_index >= len(accesses):
            _fail(f"{place}: access index out of range")
        access = accesses[access_index]
        row = DerivedAccess(state, access_index, _int(item, "offset", place), _int(item, "width", place, 1),
                            _text(item, "evidence_id", place), _view(item, place))
        if (row.offset != states[state].offset + access.offset or row.width != access.width or
                row.evidence_id != access.evidence_id or row.storage_view != access.storage_view):
            _fail(f"{place}: does not match its summary access")
        derived.append(row)
    cited = {(row.evidence_id, row.offset, row.width) for row in derived}

    withheld_components = tuple(_get(solution, "withheld_components", list, "solution"))
    if any(type(c) is not int or not 0 <= c < len(components) or components[c].consistent
           for c in withheld_components):
        _fail("solution names an invalid withheld component")
    overflowed = _int(solution, "overflowed", "solution", 0)
    complete = _get(solution, "complete", bool, "solution")
    if complete != (not withheld_components and overflowed == 0):
        _fail("solution completeness contradicts its withheld and overflowed counts")

    fields: list[SolvedField] = []
    candidates: list[UnionCandidate] = []
    minimum_extent = 0
    layout = solution.get("layout")
    if layout is not None:
        if _get(layout, "object_id", str, "layout") != root_id:
            _fail("layout names another object")
        for index, item in enumerate(_list(layout, "fields", "layout", 4096)):
            place = f"fields[{index}]"
            offset, width = _int(item, "offset", place, 0), _int(item, "width", place, 1)
            ids = tuple(_get(item, "evidence_ids", list, place))
            if not ids or any((evidence, offset, width) not in cited for evidence in ids):
                _fail(f"{place}: cites evidence no derived access supports")
            fields.append(SolvedField(offset, width, ids, _strength(item, place),
                                      _get(item, "overlaps_other_fields", bool, place)))
            minimum_extent = max(minimum_extent, offset + width)
        if _int(layout, "minimum_extent", "layout", 0) != minimum_extent:
            _fail("layout minimum_extent does not match its fields")
        for index, item in enumerate(_list(layout, "union_candidates", "layout", 4096)):
            place = f"union_candidates[{index}]"
            offset = _int(item, "offset", place, 0)
            views = []
            for view in _get(item, "views", list, place):
                kind = _get(view, "kind", str, place)
                if kind not in _VIEWS:
                    _fail(f"{place}: unsupported view kind")
                views.append(UnionView(kind, _int(view, "width", place, 1, 8),
                                       tuple(_get(view, "evidence_ids", list, place))))
            candidates.append(UnionCandidate(offset, tuple(views), _strength(item, place)))

    return SummaryLayoutReport(
        SCHEMA_VERSION, program_id, _int(document, "revision", where, 0),
        _text(document, "language_id", where), _text(document, "compiler_spec_id", where),
        function, _text(target, "name", "function"), parameter, root_id, complete, withheld_components,
        overflowed, tuple(summaries), tuple(edges), tuple(refused), tuple(components), tuple(states),
        tuple(derived), tuple(fields), tuple(candidates), minimum_extent, document,
    )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise SummaryReportError("duplicate JSON property")
        result[key] = value
    return result


def _no_constant(token: str) -> None:
    raise SummaryReportError(f"invalid JSON constant {token}")


def _bounded_int(token: str) -> int:
    if len(token.lstrip("-")) > 20:
        raise SummaryReportError("oversized integer in summary report")
    return int(token)


def decode_summary_report(data: bytes | str) -> SummaryLayoutReport:
    """Decode strict JSON (no duplicate keys, NaN or huge integers) and validate it."""
    raw = data.encode("utf-8") if isinstance(data, str) else data
    if len(raw) > MAX_REPORT_BYTES:
        raise SummaryReportError("summary report exceeds 8 MiB")
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                              parse_constant=_no_constant, parse_int=_bounded_int)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as cause:
        raise SummaryReportError(f"invalid summary report JSON: {cause}") from None
    return parse_summary_report(document)


def load_summary_report(path: str | Path) -> SummaryLayoutReport:
    file = Path(path)
    if not file.is_file():
        raise SummaryReportError("expected a regular summary report file")
    with file.open("rb") as stream:
        data = stream.read(MAX_REPORT_BYTES + 1)
    return decode_summary_report(data)


def _clean(text: str) -> str:
    return "".join(ch if ch.isprintable() else "?" for ch in text)


def explain_summary(report: SummaryLayoutReport, offset: int | None = None) -> list[str]:
    """Human-readable fields with the call path behind each piece of evidence."""
    names = {summary.id: summary.function_name for summary in report.summaries}
    lines = [f"Summary layout evidence for {_clean(report.function_name)} parameter "
             f"{report.parameter_index} ({report.program_id}, revision {report.revision})"]
    if report.complete:
        lines.append("Solution: complete")
    else:
        lines.append(f"Solution: incomplete (withheld cycles {len(report.withheld_components)}, "
                     f"overflowed paths {report.overflowed})")
    for component in report.components:
        members = ", ".join(_clean(names[member]) for member in component.summaries)
        lines.append(f"Call cycle ({'consistent' if component.consistent else 'withheld: offsets drift'}): "
                     f"{members}")
    lines.append(f"Reached {len(report.states)} function parameters through {len(report.edges)} calls; "
                 f"minimum extent {report.minimum_extent}")
    shown = [f for f in report.fields if offset is None or f.offset == offset]
    for item in shown:
        lines.append(f"  +0x{item.offset:x} width {item.width}  evidence {len(item.evidence_ids)}  "
                     f"strength {item.evidence_strength:.3f} (uncalibrated)"
                     f"{'  overlaps another field' if item.overlaps_other_fields else ''}")
        for row, path in report.evidence_for(item.offset, item.width):
            summary = report.summary(report.states[row.state].summary)
            access = summary.accesses[row.access]
            route = " -> ".join([_clean(names[path[0].caller]) if path else _clean(summary.function_name)] +
                                [f"{_clean(names[step.callee])} ({step.site}, {step.offset:+d})" for step in path])
            lines.append(f"      {access.operation} at {access.site} in {_clean(summary.function_name)}"
                         f"{' as ' + access.storage_view if access.storage_view else ''}; path: {route}")
    for candidate in report.union_candidates:
        if offset is None or candidate.offset == offset:
            kinds = ", ".join(f"{view.kind} {view.width}" for view in candidate.views)
            lines.append(f"  Shared storage at +0x{candidate.offset:x}: {kinds}")
    if offset is not None and not shown:
        lines.append(f"  No field starts at +0x{offset:x}")
    for call in report.refused_calls:
        lines.append(f"  Refused call at {call.site} to {call.callee}: {_clean(call.reason)}")
    return lines
