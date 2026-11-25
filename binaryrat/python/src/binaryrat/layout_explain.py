"""Inspect the recorded p-code behind a BinaryRat layout proposal offline.

Apache-2.0; Copyright 2026 YurilLAB.
"""

from __future__ import annotations

import argparse
import codecs
from concurrent.futures import CancelledError
import json
import re
import sys
from pathlib import Path
from typing import Any

from ._console import tolerant_output
from .live import LiveProgramError
from .summary_layout import ANALYSIS_MODE, explain_summary, parse_summary_report
from .summary_review import check_project_review, check_review, make_review, open_review

# Layout extraction bounds a report to 4,096 memory accesses. Also bound the
# serialized input before decoding strings and building the evidence index.
_MAX_BYTES = 8 * 1024 * 1024


def _unique_object(pairs: list[tuple[str, Any]]) -> dict:
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate JSON property")
        obj[key] = value
    return obj


def _invalid_constant(token: str) -> None:
    raise ValueError(f"invalid JSON constant {token}")


def _parse_integer(token: str) -> int:
    # The producer's largest integers are 64-bit. Bound conversion on Python
    # versions where decimal-to-integer conversion has no built-in limit.
    if len(token.lstrip("-")) > 20:
        raise ValueError("oversized integer in layout report")
    return int(token)


def _get(obj: dict, key: str, kind: type) -> Any:
    if not isinstance(obj, dict) or type(obj.get(key)) is not kind:
        raise ValueError(f"{key} must be a {kind.__name__}")
    return obj[key]


def _integer(obj: dict, key: str, minimum: int = 0) -> int:
    n = _get(obj, key, int)
    if n < minimum:
        raise ValueError(f"{key} must be at least {minimum}")
    return n


def _text(obj: dict, key: str) -> str:
    value = _get(obj, key, str)
    if not value:
        raise ValueError(f"{key} is empty")
    # A name can be referenced by many lines in a report. Keep its terminal
    # rendering bounded without changing the identifiers used to join records.
    if len(value) > 1024:
        value = value[:1024] + "..."
    # Render control sequences and directional overrides in names as literals.
    return value if value.isprintable() else ascii(value)[1:-1]


def _addr(obj: dict, prefix: str = "") -> str:
    address = _get(obj, prefix + "address", str)
    if not re.fullmatch(r"[0-9a-fA-F]{1,16}", address):
        raise ValueError(f"invalid {prefix}address")
    return f"{_text(obj, prefix + 'address_space')}:{address}"


def _site(obj: dict) -> str:
    return f"{_addr(obj)} (p-code {_integer(obj, 'pcode_order')})"


def _strength(obj: dict) -> str:
    n = obj.get("evidence_strength")
    if type(n) not in (int, float) or not 0 <= n <= 1:
        raise ValueError("evidence_strength must be between 0 and 1")
    return f"{n:.3g}"


def _evidence_line(row: dict) -> str:
    operation = _get(row, "operation", str)
    if operation not in ("LOAD", "STORE"):
        raise ValueError("expected a LOAD or STORE observation")
    line = f"{operation} at {_site(row)}"
    if "function_address" in row or "function_address_space" in row:
        line += " in function " + _addr(row, "function_")
    if "storage_view" in row or "typed_use" in row:
        use = _get(row, "typed_use", dict)
        if operation != "LOAD" or _get(row, "storage_view", str) not in ("integer", "floating_point"):
            raise ValueError("invalid typed use in layout observation")
        line += f", {_text(row, 'storage_view')} from {_text(use, 'operation')} at {_site(use)}"
    return line


def _citations(proposal: dict, observations: dict, object_id: str, offset: int,
               width: int, used: set[str], kind: str | None = None) -> list[str]:
    lines = []
    for eid in _get(proposal, "evidence_ids", list):
        if not isinstance(eid, str) or eid not in observations or eid in used:
            raise ValueError("missing or duplicate observation in proposal citations")
        used.add(eid)
        row = observations[eid]
        if (not _get(row, "object_start_known", bool) or row["object_id"] != object_id
                or row["offset"] != offset or row["width"] != width
                or kind is not None and row.get("storage_view") != kind):
            raise ValueError("cited observation disagrees with the proposal")
        lines.append("    " + _evidence_line(row))
    if not lines:
        raise ValueError("proposal has no supporting observations")
    return lines


def explain(report: dict, offset: int | None = None) -> list[str]:
    """Describe exact and variable access *starts* at an optional byte offset."""
    if (_get(report, "schema_version", int) != 1
            or _get(report, "analysis_mode", str) != "read_only_layout_evidence"
            or _get(report, "assumption", str) != "analyst_selected_object_start"
            or _get(report, "score_kind", str) != "uncalibrated_evidence_strength"):
        raise ValueError("expected a version-1 BinaryRat layout evidence report")
    program = _get(report, "program_id", str)
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", program):
        raise ValueError("expected a SHA-256 program identity")
    function = _get(report, "function", dict)
    entry = _addr(function)
    parameter = _integer(report, "parameter_index")
    object_id = f"{program}/{function['address_space']}/{function['address']}/param/{parameter}"
    lines = [
        f"{_text(function, 'name')} at {entry}, parameter {parameter} as object start",
        f"Program {program}, revision {_integer(report, 'revision')}",
        f"{_integer(report, 'pcode_ops')} p-code operations examined, "
        f"{_integer(report, 'unresolved_accesses')} unresolved accesses",
    ]
    if offset is not None:
        lines.append(f"Showing access starts at {offset:#x}")

    rows = _get(report, "observations", list)
    observations = {}
    for row in rows:
        eid = _get(row, "evidence_id", str)
        if not eid or eid in observations:
            raise ValueError("empty or duplicate observation ID")
        if _get(row, "object_id", str) != object_id:
            raise ValueError("observation belongs to another object")
        _get(row, "offset", int)  # Negative observations can have a rejection reason.
        _integer(row, "width", 1)
        observations[eid] = row

    layouts = _get(report, "layouts", list)
    if len(layouts) > 1:
        raise ValueError("expected at most one layout for the selected parameter")
    field_ids: set[str] = set()
    union_ids: set[str] = set()
    matched = False
    for layout in layouts:
        if _get(layout, "object_id", str) != object_id:
            raise ValueError("layout belongs to another object")
        lines.append(f"Minimum extent {_integer(layout, 'minimum_extent')} bytes")
        for field in _get(layout, "fields", list):
            start = _integer(field, "offset")
            width = _integer(field, "width", 1)
            strength = _strength(field)
            cites = _citations(field, observations, object_id, start, width, field_ids)
            flags = [label for key, label in (
                ("overlaps_other_fields", "overlaps another field"),
                ("stride_conflict", "conflicting strides"),
                ("stride_overlaps_access", "stride overlaps access"),
            ) if _get(field, key, bool)]
            if field.get("stride") is not None:
                flags.append(f"stride {_integer(field, 'stride', 1)}")
            if offset in (None, start):
                matched = True
                lines.append(f"Field +{start:#x}, {width} bytes, uncalibrated strength {strength}"
                             + "".join(f", {flag}" for flag in flags))
                lines.extend(cites)
        if "union_candidates" not in layout:
            lines.append("This report does not record union candidates.")
        unions = _get(layout, "union_candidates", list) if "union_candidates" in layout else []
        for union in unions:
            start = _integer(union, "offset")
            strength = _strength(union)
            views = _get(union, "views", list)
            if {_text(view, "kind") for view in views} != {"integer", "floating_point"}:
                raise ValueError("union candidate needs integer and floating-point views")
            if offset in (None, start):
                matched = True
                lines.append(f"Union candidate +{start:#x}, uncalibrated strength {strength}")
            for view in views:
                kind = _text(view, "kind")
                width = _integer(view, "width", 1)
                cites = _citations(view, observations, object_id, start, width, union_ids, kind)
                if offset in (None, start):
                    lines.append(f"  {kind} view, {width} bytes")
                    lines.extend(cites)

    if "variable_accesses" not in report:
        lines.append("This report does not record variable-offset coverage.")
    else:
        variable_ids = set()
        for row in _get(report, "variable_accesses", list):
            eid = _get(row, "evidence_id", str)
            if not eid or eid in observations or eid in variable_ids:
                raise ValueError("empty or duplicate observation ID")
            variable_ids.add(eid)
            low = _integer(row, "minimum_offset")
            high = _integer(row, "maximum_offset")
            stride = _integer(row, "stride", 1)
            width = _integer(row, "width", 1)
            description = _evidence_line(row)
            if _get(row, "object_id", str) != object_id or high <= low or (high - low) % stride:
                raise ValueError("invalid variable-offset evidence")
            if offset is None or low <= offset <= high and (offset - low) % stride == 0:
                matched = True
                lines.append(f"Possible access starts +{low:#x} to +{high:#x}, stride {stride}, "
                             f"width {width} bytes")
                lines.append("    " + description)
    rejected_indices = set()
    for rejected in _get(report, "rejected", list):
        index = _integer(rejected, "observation_index")
        if index >= len(rows) or index in rejected_indices:
            raise ValueError("invalid or duplicate rejected observation index")
        rejected_indices.add(index)
        row = rows[index]
        if row["evidence_id"] in field_ids or row["evidence_id"] in union_ids:
            raise ValueError("rejected observation also cited as proposal evidence")
        reason = _text(rejected, "reason")
        description = _evidence_line(row)
        if offset in (None, row["offset"]):
            matched = True
            lines.append(f"Rejected observation at offset {row['offset']:#x}, {reason}")
            lines.append("    " + description)
    if not matched:
        lines.append("No matching field, union candidate, variable access or rejected observation.")

    if "follow_depth" in report or "forwarded_calls" in report:
        depth = _integer(report, "follow_depth")
        calls = _get(report, "forwarded_calls", list)
        if depth > 4 or len(calls) > 128 or depth == 0 and calls:
            raise ValueError("forwarded calls exceed report limits")
        lines.append(f"Report-wide forwarding depth {depth}, {len(calls)} recorded call sites")
        for call in calls:
            caller = _addr(call, "caller_") if depth > 1 else entry
            hop = _integer(call, "hop", 1) if depth > 1 else 1
            if hop > depth:
                raise ValueError("call hop exceeds follow depth")
            lines.append(f"  Hop {hop}: {caller} calls {_addr(call, 'callee_')} parameter "
                         f"{_integer(call, 'callee_parameter_index')} at {_site(call)}")
    else:
        lines.append("This report does not record call forwarding.")
    return lines


def _read_document(path: Path) -> Any:
    if not path.is_file():
        raise ValueError("expected a regular layout report file")
    with path.open("rb") as stream:
        data = stream.read(_MAX_BYTES + 1)
    if len(data) > _MAX_BYTES:
        raise ValueError("layout report exceeds 8 MiB")
    # Windows PowerShell file redirection can transcode JSON to BOM-marked UTF-16.
    encoding = "utf-16" if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)) else "utf-8-sig"
    return json.loads(data.decode(encoding), object_pairs_hook=_unique_object,
                      parse_constant=_invalid_constant, parse_int=_parse_integer)


def main(argv: list[str] | None = None) -> int:
    tolerant_output()
    parser = argparse.ArgumentParser(prog="binaryrat-explain",
                                     description="Inspect the recorded p-code behind a layout proposal.")
    parser.add_argument("report", type=Path,
                        help="BinaryRat layout report or portable summary review")
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--offset", type=lambda value: int(value, 0),
                        help="show proposals and possible accesses starting at this byte offset (decimal or 0x hex)")
    action.add_argument("--make-review", action="store_true",
                        help="print a portable JSON review of this interprocedural summary report")
    action.add_argument("--check-review", type=Path, metavar="FRESH_REPORT",
                        help="compare this portable review with a supplied summary report offline")
    action.add_argument("--check-project", nargs=2, metavar=("PROJECT.gpr", "/PROGRAM"),
                        help="rerun summary recovery on the saved Program and compare with this review")
    parser.add_argument("--install-dir", type=Path, help="Ghidra installation for --check-project")
    args = parser.parse_args(argv)
    if args.install_dir is not None and args.check_project is None:
        parser.error("--install-dir requires --check-project")
    try:
        report = _read_document(args.report)
        if args.make_review:
            print(make_review(parse_summary_report(report)))
            return 0
        if args.check_review is not None or args.check_project is not None:
            captured = open_review(report)
            if args.check_project is not None:
                result = check_project_review(captured, *args.check_project, install_dir=args.install_dir)
            else:
                fresh = parse_summary_report(_read_document(args.check_review))
                result = check_review(captured, fresh)
            print(json.dumps(result))
            return 0 if result["status"] == "matched" else 1
        if isinstance(report, dict) and "review_format" in report:
            lines = explain_summary(open_review(report), args.offset)
        elif isinstance(report, dict) and report.get("analysis_mode") == ANALYSIS_MODE:
            lines = explain_summary(parse_summary_report(report), args.offset)
        else:
            lines = explain(report, args.offset)
        for line in lines:
            print(line)
    except (CancelledError, KeyboardInterrupt):
        return 130
    except (LiveProgramError, TypeError, ValueError, OSError, RecursionError) as error:
        print(f"binaryrat-explain: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
