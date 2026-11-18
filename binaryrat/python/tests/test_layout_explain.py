"""Apache-2.0; Copyright 2026 YurilLAB."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from binaryrat.layout_explain import explain, main


PROGRAM = "sha256:" + "a" * 64
OBJECT = PROGRAM + "/ram/1000/param/0"


def observation(eid, offset, width):
    return dict(object_id=OBJECT, evidence_id=eid, offset=offset, width=width,
                object_start_known=True, address_space="ram", address="2001",
                operation="LOAD", pcode_order=1,
                function_address_space="ram", function_address="2000")


def field(offset, width, eid):
    return dict(offset=offset, width=width, evidence_ids=[eid], evidence_strength=0.5,
                overlaps_other_fields=False, stride=None, stride_conflict=False,
                stride_overlaps_access=False)


def report():
    return dict(schema_version=1, analysis_mode="read_only_layout_evidence",
                assumption="analyst_selected_object_start",
                score_kind="uncalibrated_evidence_strength", program_id=PROGRAM,
                language_id="x86:LE:64:default", compiler_spec_id="gcc",
                parameter_index=0, revision=7, pcode_ops=8, unresolved_accesses=1,
                function=dict(name="inspect", address_space="ram", address="1000"),
                observations=[observation("load", 4, 4)], variable_accesses=[],
                layouts=[dict(object_id=OBJECT, minimum_extent=8, fields=[field(4, 4, "load")],
                              union_candidates=[])], rejected=[], follow_depth=1,
                forwarded_calls=[dict(address_space="ram", address="1004", pcode_order=2,
                                      callee_address="2000", callee_address_space="ram",
                                      callee_parameter_index=0)])


class LayoutExplanationTests(unittest.TestCase):
    def test_field_points_to_its_callee_instruction_and_call_site(self):
        lines = "\n".join(explain(report(), 4))
        for expected in ("inspect at ram:1000, parameter 0", "8 p-code operations",
                         "1 unresolved", "Field +0x4, 4 bytes, uncalibrated strength 0.5",
                         "LOAD at ram:2001 (p-code 1) in function ram:2000",
                         "ram:1000 calls ram:2000 parameter 0 at ram:1004"):
            self.assertIn(expected, lines)
        self.assertIn("No matching field", "\n".join(explain(report(), 5)))

    def test_union_cites_independent_integer_and_float_uses(self):
        r = report()
        r["observations"].append(observation("float", 4, 8))
        r["layouts"][0]["fields"].append(field(4, 8, "float"))
        views = []
        for row, kind, op in zip(r["observations"], ["integer", "floating_point"],
                                 ["INT_XOR", "FLOAT_ADD"]):
            row.update(storage_view=kind, typed_use=dict(address_space="ram", address="beef",
                                                          pcode_order=5, operation=op))
            views.append(dict(kind=kind, width=row["width"], evidence_ids=[row["evidence_id"]]))
        r["layouts"][0]["union_candidates"].append(dict(offset=4, views=views, evidence_strength=2/3))
        output = "\n".join(explain(r, 4))
        self.assertIn("Union candidate +0x4, uncalibrated strength 0.667", output)
        self.assertIn("integer from INT_XOR at ram:beef", output)
        self.assertIn("floating_point from FLOAT_ADD at ram:beef", output)
        views[0]["evidence_ids"] = ["float"]
        with self.assertRaisesRegex(ValueError, "disagrees"):
            explain(r)

    def test_variable_ranges_match_starts_only_and_rejections_keep_reason(self):
        r = report()
        variable = observation("indexed", 0, 4)
        del variable["offset"]
        variable.update(minimum_offset=12, maximum_offset=28, stride=8, operation="STORE")
        r["variable_accesses"] = [variable]
        r["observations"].append(observation("before", -4, 1))
        r["rejected"] = [dict(observation_index=1, reason="negative offset")]
        for match in (12, 20, 28):
            lines = "\n".join(explain(r, match))
            self.assertIn("Possible access starts +0xc to +0x1c, stride 8, width 4", lines)
            self.assertIn("STORE at ram:2001", lines)
            self.assertNotIn("Field +", lines)
        for miss in (0, 13, 16, 29):
            self.assertIn("No matching field", "\n".join(explain(r, miss)))
        self.assertIn("Rejected observation at offset -0x4, negative offset", "\n".join(explain(r, -4)))

    def test_multihop_origin_and_legacy_absence(self):
        r = report()
        call = r["forwarded_calls"][0]
        r["follow_depth"] = 3
        call.update(caller_address_space="reg", caller_address="1001", hop=2)
        self.assertIn("Hop 2: reg:1001 calls ram:2000", "\n".join(explain(r)))
        for key in ("forwarded_calls", "follow_depth", "variable_accesses"):
            del r[key]
        del r["observations"][0]["function_address_space"], r["observations"][0]["function_address"]
        del r["layouts"][0]["union_candidates"]
        lines = "\n".join(explain(r))
        self.assertIn("does not record variable-offset coverage", lines)
        self.assertIn("does not record call forwarding", lines)
        self.assertNotIn("in function", lines)

    def test_invalid_fields_cannot_impersonate_supporting_evidence(self):
        updates = [("evidence_ids", ["unknown"]), ("evidence_ids", ["load", "load"]),
                   ("width", True), ("offset", 0), ("evidence_strength", float("nan")),
                   ("evidence_strength", 1.1)]
        for key, value in updates:
            with self.subTest(key=key, value=value):
                r = report()
                r["layouts"][0]["fields"][0][key] = value
                with self.assertRaises(ValueError):
                    explain(r)
        for key, value in (("schema_version", True), ("schema_version", 2),
                           ("score_kind", "probability"), ("layouts", [None]),
                           ("analysis_mode", "other"), ("program_id", "unrelated")):
            with self.subTest(key=key), self.assertRaises(ValueError):
                explain({**report(), key: value})

    def test_contradictory_and_duplicate_observations_are_rejected(self):
        r = report()
        r["observations"].append(observation("load", 0, 4))
        with self.assertRaisesRegex(ValueError, "duplicate observation"):
            explain(r)
        r = report()
        r["rejected"].append(dict(observation_index=0, reason="negative offset"))
        with self.assertRaisesRegex(ValueError, "also cited"):
            explain(r)
        r = report()
        r["observations"][0]["object_start_known"] = False
        with self.assertRaisesRegex(ValueError, "disagrees"):
            explain(r)

    def test_cli_rejects_corrupt_large_and_unrelated_files_without_partial_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            for data in (b"{", b'{"a":1,"a":2}', b'{"not_json":NaN}', b"9" * 5000, b"[]", b"\xff",
                         b"[" * 2000 + b"]" * 2000):
                with self.subTest(data=data[:15]):
                    path.write_bytes(data)
                    with redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()) as err:
                        self.assertEqual(main([str(path)]), 2)
                    self.assertEqual(out.getvalue(), "")
                    self.assertIn("binaryrat-explain:", err.getvalue())
            path.write_text(json.dumps(report()), encoding="utf-8")
            with patch("binaryrat.layout_explain._MAX_BYTES", 64), redirect_stderr(io.StringIO()) as err:
                self.assertEqual(main([str(path)]), 2)
            self.assertIn("exceeds", err.getvalue())
            with redirect_stdout(io.StringIO()) as out:
                self.assertEqual(main([str(path), "--offset", "0x4"]), 0)
            self.assertIn("Field +0x4", out.getvalue())
            self.assertEqual(json.loads(path.read_bytes()), report())

    def test_untrusted_terminal_controls_are_escaped(self):
        r = report()
        r["function"]["name"] = "before\n\x1b[2Jafter"
        self.assertNotIn("\x1b", "\n".join(explain(r)))
        self.assertTrue(explain(r)[0].startswith(r"before\n\x1b[2Jafter"))
