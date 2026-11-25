"""Portable read-only reviews of version-1 interprocedural layout reports.

Digests cover compact, sorted-key, ASCII-escaped Python JSON with finite numbers.
Array order is preserved. Only the top-level revision is excluded during
cross-session comparison. The full capture checksum includes that revision.

Apache-2.0; Copyright 2026 YurilLAB.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
import re
from typing import Any

from .summary_layout import MAX_REPORT_BYTES, SummaryLayoutReport, parse_summary_report
from .live import open_program

REVIEW_FORMAT = "binaryrat.summary-review/1"
_DIGEST = re.compile(r"[0-9a-f]{64}")
_ADDRESS = re.compile(r"[0-9a-f]{1,16}")


def _write_canonical(value: Any, write: Callable[[bytes], object], limit: int = MAX_REPORT_BYTES) -> None:
    encoder = json.JSONEncoder(ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)
    size = 0
    for part in encoder.iterencode(value):
        size += len(part)
        if size > limit:
            raise ValueError("canonical summary review exceeds 8 MiB")
        write(part.encode("ascii"))


def _digest(value: Any) -> str:
    digest = sha256()
    _write_canonical(value, digest.update)
    return digest.hexdigest()


def _witness_rows(document: dict) -> Iterator[tuple[str, dict | None]]:
    for summary in document["summaries"]:
        for access in summary["accesses"]:
            yield "field access", access
            if "storage_view" in access:
                yield "typed consumer", access.get("typed_use")
    for label, key in (("forwarded call", "edges"), ("refused call", "refused_calls"),
                       ("variable access", "variable_accesses")):
        rows = document.get(key)
        if rows is None and key == "variable_accesses" and key not in document:
            yield "variable access inventory", None
            continue
        if not isinstance(rows, list) or len(rows) > 4096:
            raise ValueError(f"invalid {label} inventory")
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError(f"invalid {label} witness")
            yield label, row


def _witness_gap(report: SummaryLayoutReport) -> str | None:
    """Check hash syntax and consistency even if another witness is missing."""
    hashes = {}
    summaries = {summary.id for summary in report.summaries}
    access_ids = {access.evidence_id for summary in report.summaries for access in summary.accesses}
    gap = None
    for label, row in _witness_rows(report.document):
        if row is None:
            gap = gap or f"missing {label} record"
            continue
        space, address, order = row.get("address_space"), row.get("address"), row.get("pcode_order")
        if (not isinstance(space, str) or not space or len(space) > 4096 or
                not isinstance(address, str) or not _ADDRESS.fullmatch(address) or
                type(order) is not int or not 0 <= order < (1 << 32)):
            raise ValueError(f"invalid instruction location or p-code order for {label}")
        location = f"{space}/{int(address, 16):x}/{order}"
        if label in ("forwarded call", "refused call"):
            expected = f"{row['caller']}/call/{location}/arg/{row['argument_index']}"
            if row.get("evidence_id") != expected:
                raise ValueError(f"{label} citation does not identify the recorded instruction and argument")
        if label == "variable access":
            owner = row.get("summary")
            keys = ("minimum_offset", "maximum_offset", "stride", "width")
            low, high, stride, width = (row.get(key) for key in keys)
            if (not isinstance(owner, str) or owner not in summaries
                    or row.get("operation") not in ("LOAD", "STORE")
                    or any(type(n) is not int for n in (low, high, stride, width))
                    or not (0 <= low < high and 0 < stride and 0 < width and high + width <= (1 << 20))
                    or (high - low) % stride):
                raise ValueError("invalid variable access context or bounded range")
            evidence_id = row.get("evidence_id")
            if evidence_id != f"{owner}/{location}" or evidence_id in access_ids:
                raise ValueError("variable access citation is foreign or repeated")
            access_ids.add(evidence_id)
        if "instruction_sha256" not in row:
            gap = gap or f"missing instruction bytes digest for {label} at {space}:{address}"
            continue
        digest = row["instruction_sha256"]
        if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
            raise ValueError(f"invalid instruction bytes digest for {label}")
        if hashes.setdefault((space, int(address, 16)), digest) != digest:
            raise ValueError("conflicting instruction bytes digests at the same location")
    limit = report.document.get("summary_limit")
    if "summary_limit" not in report.document:
        gap = gap or "missing recovery summary limit"
    elif type(limit) is not int or not 1 <= limit <= 256:
        raise ValueError("invalid recovery summary limit")
    if not report.fields:
        gap = gap or "no recovered fields to check"
    if not report.complete:
        gap = gap or "incomplete summary solution"
    return gap


def make_review(report: SummaryLayoutReport) -> str:
    """Return an ASCII JSON envelope suitable for sending to another analyst."""
    _witness_gap(report)
    document = report.document
    envelope = {"review_format": REVIEW_FORMAT, "capture_sha256": _digest(document),
                "proposal_sha256": _digest(document["solution"].get("layout")), "report": document}
    # Include room for the newline printed by the CLI, including a Windows CRLF.
    with BytesIO() as stream:
        _write_canonical(envelope, stream.write, MAX_REPORT_BYTES - 2)
        return stream.getvalue().decode("ascii")


def open_review(envelope: dict) -> SummaryLayoutReport:
    if not isinstance(envelope, dict) or envelope.get("review_format") != REVIEW_FORMAT:
        raise ValueError("expected a version-1 BinaryRat summary review")
    if set(envelope) != {"review_format", "capture_sha256", "proposal_sha256", "report"}:
        raise ValueError("invalid portable review envelope")
    report = parse_summary_report(envelope["report"])
    if (_digest(report.document) != envelope["capture_sha256"] or
            _digest(report.document["solution"].get("layout")) != envelope["proposal_sha256"]):
        raise ValueError("portable review checksum does not match its embedded capture or proposal")
    _witness_gap(report)
    return report


def check_review(captured: SummaryLayoutReport, fresh: SummaryLayoutReport) -> dict:
    """Compare supplied captures. Their origin and freshness are caller-provided."""
    captured_gap, fresh_gap = _witness_gap(captured), _witness_gap(fresh)
    if (captured.object_id, captured.language_id, captured.compiler_spec_id) != (
            fresh.object_id, fresh.language_id, fresh.compiler_spec_id):
        status, reason = "incompatible", "different executable, target, language or compiler specification"
    elif captured_gap or fresh_gap:
        status = "unverifiable"
        reason = f"capture: {captured_gap}" if captured_gap else f"destination: {fresh_gap}"
    elif captured.document["summary_limit"] != fresh.document["summary_limit"]:
        status, reason = "incompatible", "different recovery summary limits"
    elif _digest(captured.document["solution"].get("layout")) != _digest(fresh.document["solution"].get("layout")):
        status, reason = "changed", "recorded layout proposal differs"
    elif _digest({k: v for k, v in captured.document.items() if k != "revision"}) != _digest(
            {k: v for k, v in fresh.document.items() if k != "revision"}):
        status, reason = "changed", "recorded evidence or report context differs"
    else:
        status, reason = "matched", "recorded proposal, instruction witnesses and report context match"
    return {"status": status, "reason": reason, "captured_revision": captured.revision,
            "fresh_revision": fresh.revision, "verification": "supplied_report"}


def check_project_review(captured: SummaryLayoutReport, project: Path | str, program: str,
                         install_dir: Path | str | None = None) -> dict:
    """Regenerate the selected proposal from a saved, read-only Program in this process."""
    result = {"status": "unverifiable", "captured_revision": captured.revision,
              "fresh_revision": None, "verification": "project_preflight"}
    gap = _witness_gap(captured)
    if gap:
        return result | {"reason": f"capture: {gap}"}
    with open_program(project, program, install_dir=install_dir) as view:
        info = view.info
        result["fresh_revision"] = info.revision
        if info.executable_sha256 is None or not _DIGEST.fullmatch(info.executable_sha256.lower()):
            return result | {"reason": "destination Program has no executable SHA-256"}
        if (captured.program_id, captured.language_id, captured.compiler_spec_id) != (
                "sha256:" + info.executable_sha256.lower(), info.language_id, info.compiler_spec_id):
            return result | {"status": "incompatible",
                             "reason": "different executable, language or compiler specification"}
        try:
            target = view.function_at(captured.function)
        except ValueError:
            # The destination may not have the capture's overlay or address range.
            target = None
        if target is None or target.external or target.thunk:
            return result | {"reason": "target function unavailable at its recorded entry"}
        fresh = view.solve_layout(captured.function, captured.parameter_index,
                                  max_summaries=captured.document["summary_limit"])
        return check_review(captured, fresh) | {"verification": "saved_program"}
