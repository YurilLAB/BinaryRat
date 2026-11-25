"""Typed summary layout reports: strict validation, provenance and the explain CLI.

Apache-2.0; Copyright 2026 YurilLAB.
"""

import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path

from binaryrat import Address, SummaryReportError, decode_summary_report, parse_summary_report
from binaryrat.layout_explain import main as explain_main
from binaryrat.summary_layout import MAX_REPORT_BYTES, explain_summary

PROGRAM = "sha256:" + "ab" * 32


def summary_id(entry: int, parameter: int = 0) -> str:
    return f"{PROGRAM}/ram/{entry:x}/param/{parameter}"


def access(owner: str, offset: int, site: int, width: int = 4, view: str | None = None) -> dict:
    row = dict(offset=offset, width=width, evidence_id=f"{owner}/ram/{site:x}/0", address_space="ram",
               address=f"{site:x}", pcode_order=0, operation="LOAD")
    if view:
        row["storage_view"] = view
    return row


def report() -> dict:
    """root(0x1000) -> leaf(0x2000) at +24; walk(0x3000) calls itself with the same pointer."""
    root, leaf, walk = summary_id(0x1000), summary_id(0x2000), summary_id(0x3000)
    summaries = [
        dict(id=root, function_address_space="ram", function_address="1000", function_name="root",
             parameter_index=0, parameter_storage="register:00000038", call_refusal=None,
             accesses=[access(root, 0, 0x1004)]),
        dict(id=leaf, function_address_space="ram", function_address="2000", function_name="leaf",
             parameter_index=0, parameter_storage="register:00000038", call_refusal=None,
             accesses=[access(leaf, -8, 0x2004, view="integer")]),
        dict(id=walk, function_address_space="ram", function_address="3000", function_name="walk",
             parameter_index=0, parameter_storage="register:00000038", call_refusal=None,
             accesses=[access(walk, 4, 0x3004, view="floating_point")]),
    ]

    def edge(caller, callee, callee_address, offset, site):
        return dict(caller=caller, callee=callee, offset=offset, evidence_id=f"{caller}/call/ram/{site:x}/1/arg/0",
                    address_space="ram", address=f"{site:x}", pcode_order=1, callee_address_space="ram",
                    callee_address=callee_address, argument_index=0, argument_value_storage="register:00000000")

    edges = [edge(root, leaf, "2000", 24, 0x1008), edge(root, walk, "3000", 12, 0x100c),
             edge(walk, walk, "3000", 0, 0x3008)]
    states = [dict(summary=root, offset=0, hops=0, edge=None, parent=None),
              dict(summary=leaf, offset=24, hops=1, edge=0, parent=0),
              dict(summary=walk, offset=12, hops=1, edge=1, parent=0)]
    derived = [dict(state=0, access=0, offset=0, width=4, evidence_id=f"{root}/ram/1004/0"),
               dict(state=1, access=0, offset=16, width=4, evidence_id=f"{leaf}/ram/2004/0",
                    storage_view="integer"),
               dict(state=2, access=0, offset=16, width=4, evidence_id=f"{walk}/ram/3004/0",
                    storage_view="floating_point")]
    layout = dict(object_id=root, minimum_extent=20, has_overlaps=False, has_stride_conflicts=False,
                  has_overlapping_stride=False,
                  fields=[dict(offset=0, width=4, stride=None, evidence_ids=[derived[0]["evidence_id"]],
                               evidence_strength=0.5, overlaps_other_fields=False, stride_conflict=False,
                               stride_overlaps_access=False),
                          dict(offset=16, width=4, stride=None,
                               evidence_ids=sorted([derived[1]["evidence_id"], derived[2]["evidence_id"]]),
                               evidence_strength=2 / 3, overlaps_other_fields=False, stride_conflict=False,
                               stride_overlaps_access=False)],
                  union_candidates=[dict(offset=16, evidence_strength=2 / 3, views=[
                      dict(kind="integer", width=4, evidence_ids=[derived[1]["evidence_id"]]),
                      dict(kind="floating_point", width=4, evidence_ids=[derived[2]["evidence_id"]])])])
    return dict(
        schema_version=1, analysis_mode="read_only_summary_layout_evidence",
        assumption="analyst_selected_object_start", score_kind="uncalibrated_evidence_strength",
        function=dict(address_space="ram", address="1000", name="root"), revision=7, program_id=PROGRAM,
        language_id="x86:LE:64:default", compiler_spec_id="gcc", parameter_index=0, object_id=root,
        summary_limit=32, decompile_attempts=3, pcode_ops=40, unresolved_accesses=0,
        summaries=summaries, edges=edges, refused_calls=[dict(
            caller=root, offset=0, evidence_id=f"{root}/call/ram/1010/2/arg/1", address_space="ram",
            address="1010", pcode_order=2, callee_address_space="ram", callee_address="4000",
            argument_index=1, argument_value_storage="register:00000030",
            reason="callee is missing, external, a thunk, uninitialized or above 64 KiB")],
        variable_accesses=[], components=[dict(summaries=[walk], consistent=True, withheld_edges=[])],
        solution=dict(summary=root, object_id=root, status="solved", complete=True, withheld_components=[],
                      overflowed=0, states=states, derived=derived, layout=layout, rejected=[]),
    )


class SummaryReportTests(unittest.TestCase):
    def test_valid_report_types_and_call_paths(self):
        parsed = parse_summary_report(report())
        self.assertEqual(parsed.function, Address("ram", 0x1000))
        self.assertEqual([(f.offset, f.width) for f in parsed.fields], [(0, 4), (16, 4)])
        self.assertTrue(parsed.complete)
        self.assertEqual(parsed.minimum_extent, 20)
        self.assertEqual([edge.offset for edge in parsed.call_path(1)], [24])
        self.assertEqual(parsed.call_path(0), ())
        evidence = parsed.evidence_for(16, 4)
        self.assertEqual([path[0].callee for _, path in evidence], [summary_id(0x2000), summary_id(0x3000)])
        self.assertEqual(parsed.union_candidates[0].offset, 16)
        self.assertTrue(parsed.components[0].consistent)
        self.assertEqual(parsed.document["revision"], 7)
        with self.assertRaises(IndexError):
            parsed.call_path(3)
        lines = "\n".join(explain_summary(parsed))
        self.assertIn("path: root -> leaf (ram:1008, +24)", lines)
        self.assertIn("Shared storage at +0x10: integer 4, floating_point 4", lines)
        self.assertIn("Call cycle (consistent): walk", lines)
        self.assertIn("Refused call at ram:1010 to ram:4000", lines)
        only = explain_summary(parsed, offset=0)
        self.assertFalse(any("+0x10" in line for line in only))
        self.assertTrue(any("No field starts at +0x8" in line for line in explain_summary(parsed, offset=8)))

    def test_incomplete_report_with_withheld_cycle(self):
        document = report()
        document["components"][0] = dict(summaries=[summary_id(0x3000)], consistent=False, withheld_edges=[2])
        document["solution"].update(complete=False, withheld_components=[0])
        parsed = parse_summary_report(document)
        self.assertFalse(parsed.complete)
        self.assertIn("incomplete (withheld cycles 1", explain_summary(parsed)[1])

    def test_consumer_mnemonics_use_ghidra_spelling_and_legacy_citations_still_work(self):
        for mnemonic in ("TRUNC", "FLOAT2FLOAT", "FLOAT_LESSEQUAL"):
            document = report()
            access = document["summaries"][2]["accesses"][0]
            access["typed_use"] = dict(address_space="overlay", address="3030", pcode_order=17,
                                       operation=mnemonic)
            with self.subTest(mnemonic=mnemonic):
                parsed = parse_summary_report(document)
                self.assertIn(f"consumed by {mnemonic} at overlay:3030 (p-code 17)",
                              "\n".join(explain_summary(parsed)))
                self.assertIsNone(parsed.summaries[1].accesses[0].typed_use)

    def test_corrupted_reports_are_refused(self):
        root, leaf = summary_id(0x1000), summary_id(0x2000)

        def set_path(path, value):
            def change(document):
                target = document
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
            return change

        corruptions = {
            "wrong mode": set_path(["analysis_mode"], "read_only_layout_evidence"),
            "future schema": set_path(["schema_version"], 2),
            "boolean schema": set_path(["schema_version"], True),
            "upper-case program": set_path(["program_id"], "sha256:" + "AB" * 32),
            "object id": set_path(["object_id"], leaf),
            "duplicate summary": lambda d: d["summaries"].append(copy.deepcopy(d["summaries"][1])),
            "summary id names another parameter": set_path(["summaries", 1, "parameter_index"], 1),
            "foreign evidence": set_path(["summaries", 1, "accesses", 0, "evidence_id"], f"{root}/ram/2004/0"),
            "moved source": set_path(["summaries", 1, "accesses", 0, "address"], "2008"),
            "reordered source": set_path(["summaries", 1, "accesses", 0, "pcode_order"], 9),
            "non-string field citation": set_path(["solution", "layout", "fields", 1, "evidence_ids"], [{}]),
            "boolean offset": set_path(["summaries", 0, "accesses", 0, "offset"], False),
            "zero width": set_path(["summaries", 0, "accesses", 0, "width"], 0),
            "offset beyond int64": set_path(["summaries", 0, "accesses", 0, "offset"], 1 << 63),
            "upper-case address": set_path(["summaries", 0, "accesses", 0, "address"], "1004A"),
            "unknown view": set_path(["summaries", 1, "accesses", 0, "storage_view"], "pointer"),
            "edge to unknown summary": set_path(["edges", 0, "callee"], summary_id(0x9000)),
            "edge evidence from another caller": set_path(["edges", 0, "evidence_id"], f"{leaf}/call/ram/1/1/arg/0"),
            "edge callee address": set_path(["edges", 0, "callee_address"], "2001"),
            "edge argument index": set_path(["edges", 0, "argument_index"], 1),
            "state offset": set_path(["solution", "states", 1, "offset"], 16),
            "state hops": set_path(["solution", "states", 1, "hops"], 2),
            "state edge": set_path(["solution", "states", 1, "edge"], 1),
            "state parent ahead": set_path(["solution", "states", 1, "parent"], 2),
            "first state": set_path(["solution", "states", 0, "offset"], 8),
            "repeated state": lambda d: d["solution"]["states"].append(dict(d["solution"]["states"][1], parent=0)),
            "derived offset": set_path(["solution", "derived", 1, "offset"], 24),
            "derived view": set_path(["solution", "derived", 1, "storage_view"], "floating_point"),
            "derived access index": set_path(["solution", "derived", 1, "access"], 1),
            "field without derived evidence": set_path(["solution", "layout", "fields", 0, "offset"], 8),
            "minimum extent": set_path(["solution", "layout", "minimum_extent"], 24),
            "strength above one": set_path(["solution", "layout", "fields", 0, "evidence_strength"], 1.5),
            "complete contradiction": set_path(["solution", "complete"], False),
            "withheld names consistent component": set_path(["solution", "withheld_components"], [0]),
            "consistent component withholds": set_path(["components", 0, "withheld_edges"], [2]),
            "unsolved": set_path(["solution", "status"], "state_limit"),
            "control character": set_path(["summaries", 0, "function_name"], "ro\u0007ot"),
        }
        parse_summary_report(report())
        for name, corrupt in corruptions.items():
            document = report()
            corrupt(document)
            with self.subTest(name), self.assertRaises(SummaryReportError):
                parse_summary_report(document)

    def test_evidence_must_belong_to_its_summary(self):
        # Renamed consistently everywhere, so only the ownership check can notice.
        document = report()
        old = document["summaries"][1]["accesses"][0]["evidence_id"]
        foreign = f"{summary_id(0x1000)}/ram/2004/0"
        text = json.dumps(document).replace(old, foreign)
        with self.assertRaisesRegex(SummaryReportError, "foreign or repeated"):
            decode_summary_report(text)

    def test_withheld_edge_cannot_lead_to_a_state(self):
        document = report()
        document["components"][0] = dict(summaries=[summary_id(0x3000)], consistent=False, withheld_edges=[1])
        document["solution"].update(complete=False, withheld_components=[0])
        with self.assertRaisesRegex(SummaryReportError, "invalid path step"):
            parse_summary_report(document)

    def test_strict_json_decoding(self):
        text = json.dumps(report())
        self.assertEqual(decode_summary_report(text).revision, 7)
        for bad in (text[:-1] + ',"revision":8}', text.replace('"revision": 7', '"revision": NaN'),
                    text.replace('"revision": 7', '"revision": ' + "9" * 30), b"\xff",
                    b" " * (MAX_REPORT_BYTES + 1)):
            with self.subTest(bad=bad[:40]), self.assertRaises(SummaryReportError):
                decode_summary_report(bad)

    def test_explain_cli_reads_summary_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "summary.json"
            path.write_text(json.dumps(report()), encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(explain_main([str(path), "--offset", "0x10"]), 0)
            self.assertIn("+0x10 width 4  evidence 2", output.getvalue())
            broken = report()
            broken["solution"]["states"][1]["offset"] = 8
            path.write_text(json.dumps(broken), encoding="utf-8")
            errors = io.StringIO()
            with contextlib.redirect_stderr(errors):
                self.assertEqual(explain_main([str(path)]), 2)
            self.assertIn("does not lead to this state", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
