"""Portable summary handoffs and revalidation at a destination.

Apache-2.0; Copyright 2026 YurilLAB.
"""

import codecs
import copy
from contextlib import redirect_stderr, redirect_stdout
from hashlib import sha256
from io import StringIO
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from binaryrat.layout_explain import main
from binaryrat.summary_layout import parse_summary_report
from binaryrat.summary_review import check_project_review, check_review, make_review, open_review
from test_summary_layout import report
from test_summary_provenance_fuzz import generated_report


def witnessed(document):
    rows = []
    for summary in document["summaries"]:
        for access in summary["accesses"]:
            rows.append(access)
            if "storage_view" in access:
                if "typed_use" not in access:
                    use = int(access["address"], 16) + 0x80
                    access["typed_use"] = dict(address_space=access["address_space"], address=f"{use:x}",
                                               pcode_order=3, operation="INT_XOR" if
                                               access["storage_view"] == "integer" else "FLOAT_ADD")
                rows.append(access["typed_use"])
    rows.extend(document["edges"] + document["refused_calls"] + document["variable_accesses"])
    for row in rows:
        row["instruction_sha256"] = sha256(f"{row['address_space']}:{row['address']}".encode()).hexdigest()
    return document


def compare(captured, fresh):
    return check_review(parse_summary_report(captured), parse_summary_report(fresh))["status"]


def cli(*args):
    output, errors = StringIO(), StringIO()
    with redirect_stdout(output), redirect_stderr(errors):
        status = main([str(a) for a in args])
    return status, output.getvalue(), errors.getvalue()


class SummaryReviewTests(unittest.TestCase):
    def test_cli_round_trip_survives_reopen_and_json_object_reordering(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "source.json")
            bundle = Path(directory, "review.json")
            fresh = Path(directory, "destination.json")
            document = witnessed(report())
            document["function"]["name"] = "résumé"
            source.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
            status, encoded, errors = cli(source, "--make-review")
            self.assertEqual((status, errors), (0, ""))
            self.assertTrue(encoded.isascii())
            bundle.write_text(encoded, encoding="utf-8")
            status, output, errors = cli(bundle, "--offset", "0x10")
            self.assertEqual((status, output, errors), cli(source, "--offset", "0x10"))
            self.assertIn("FLOAT_ADD", output)
            document["revision"] = 0
            fresh.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")
            status, output, errors = cli(bundle, "--check-review", fresh)
            self.assertEqual((status, errors), (0, ""))
            result = json.loads(output)
            self.assertEqual((result["status"], result["captured_revision"], result["fresh_revision"]),
                             ("matched", 7, 0))
            self.assertEqual(result["verification"], "supplied_report")
            self.assertEqual(bundle.read_text(encoding="utf-8"), encoded)

    def test_envelope_integrity_covers_session_revision_and_proposal(self):
        envelope = json.loads(make_review(parse_summary_report(witnessed(report()))))
        def rev(item):
            item["report"]["revision"] += 1
        for change in (rev, lambda x: x.update(capture_sha256="0" * 64),
                       lambda x: x.update(proposal_sha256="a" * 64),
                       lambda x: x.update(review_format=True), lambda x: x.update(extra={"v": 1})):
            with self.subTest(change=change):
                damaged = copy.deepcopy(envelope)
                change(damaged)
                with self.assertRaises(ValueError):
                    open_review(damaged)

    def test_check_review_accepts_a_second_handoff_and_preserves_comparison_results(self):
        with tempfile.TemporaryDirectory() as directory:
            first, raw, second = (Path(directory, name) for name in ("first", "raw", "second"))
            original = witnessed(report())
            first.write_text(make_review(parse_summary_report(original)), encoding="ascii")
            for expected, edit in (
                    ("matched", lambda d: d.update(revision=8)),
                    ("changed", lambda d: d["edges"][0].update(argument_value_storage="register:00000010")),
                    ("unverifiable", lambda d: d["edges"][0].pop("instruction_sha256")),
                    ("incompatible", lambda d: d.update(language_id="AARCH64:LE:64:v8A"))):
                with self.subTest(expected=expected):
                    changed = copy.deepcopy(original)
                    edit(changed)
                    raw.write_text(json.dumps(changed), encoding="utf-8")
                    second.write_text(make_review(parse_summary_report(changed)), encoding="utf-16")
                    reference = cli(first, "--check-review", raw)
                    rc, output, err = cli(first, "--check-review", second)
                    self.assertEqual((rc, output, err), reference)
                    self.assertEqual(rc, 0 if expected == "matched" else 1)
                    result = json.loads(output)
                    self.assertEqual((result["status"], result["verification"]), (expected, "supplied_report"))

    def test_check_review_validates_both_handoffs_before_classifying_a_difference(self):
        original = witnessed(report())
        with tempfile.TemporaryDirectory() as directory:
            good, bad = (Path(directory, name) for name in ("good", "bad"))
            good.write_text(make_review(parse_summary_report(original)), encoding="ascii")
            changed = copy.deepcopy(original)
            changed["language_id"] = "AARCH64:LE:64:v8A"
            envelope = json.loads(make_review(parse_summary_report(changed)))
            for key, invalid in (("capture_sha256", "0" * 64), ("proposal_sha256", "f" * 64),
                                 ("review_format", "unknown")):
                bad.write_text(json.dumps(envelope | {key: invalid}), encoding="utf-8")
                for first, second in ((good, bad), (bad, good)):
                    with self.subTest(key=key, damaged_input=1 if first == bad else 2):
                        rc, output, err = cli(first, "--check-review", second)
                        self.assertEqual((rc, output), (2, ""))
                        self.assertIn("version-1" if key == "review_format" else "checksum", err)

    def test_powershell_encoded_review_round_trip_and_strict_byte_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "report.json")
            bundle = Path(directory, "redirected.json")
            document = witnessed(report())
            document["function"]["name"] = "résumé🐀"
            source.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
            status, output, errors = cli(source, "--make-review")
            self.assertEqual((status, errors), (0, ""))
            redirected = output.rstrip("\n") + "\r\n"
            for bom, encoding in ((b"", "utf-8"), (codecs.BOM_UTF8, "utf-8"),
                                  (codecs.BOM_UTF16_LE, "utf-16-le"),
                                  (codecs.BOM_UTF16_BE, "utf-16-be")):
                with self.subTest(encoding=encoding, bom=bom):
                    bundle.write_bytes(bom + redirected.encode(encoding))
                    status, result, errors = cli(bundle, "--check-review", source)
                    self.assertEqual((status, errors), (0, ""))
                    self.assertEqual(json.loads(result)["status"], "matched")
            valid = codecs.BOM_UTF16_LE + redirected.encode("utf-16-le")
            for bad in (valid[:-1], valid + b"\x00\xd8", codecs.BOM_UTF8 + b"\xc3",
                        redirected.encode("utf-16-le")):
                bundle.write_bytes(bad)
                status, result, errors = cli(bundle, "--check-review", source)
                self.assertEqual((status, result), (2, ""))
                self.assertIn("binaryrat-explain", errors)
            bundle.write_bytes(valid)
            with patch("binaryrat.layout_explain._MAX_BYTES", len(valid) - 1):
                status, result, errors = cli(bundle, "--check-review", source)
            self.assertEqual((status, result), (2, ""))
            self.assertIn("exceeds 8 MiB", errors)

    def test_context_includes_nested_revisions_call_sites_and_summary_limit(self):
        baseline = witnessed(report())
        baseline["producer_metadata"] = {"revision": 1}
        for change, expected in (
                (lambda d: d["producer_metadata"].update(revision=2), "changed"),
                (lambda d: d["solution"]["layout"]["fields"][0].update(evidence_strength=.51), "changed"),
                (lambda d: d["summaries"][0].update(parameter_storage="register:00000000"), "changed"),
                (lambda d: d["edges"][0].update(argument_value_storage="register:00000010"), "changed"),
                (lambda d: d["refused_calls"][0].update(instruction_sha256="f" * 64), "changed"),
                (lambda d: d.update(summary_limit=12), "incompatible"),
                (lambda d: d.update(compiler_spec_id="windows"), "incompatible"),
                (lambda d: d.update(language_id="AARCH64:LE:64:v8A"), "incompatible")):
            dest = copy.deepcopy(baseline)
            change(dest)
            with self.subTest(expected=expected, change=change):
                self.assertEqual(compare(baseline, dest), expected)
        dest = json.loads(json.dumps(baseline).replace(baseline["program_id"], "sha256:" + "cd" * 32))
        self.assertEqual(compare(baseline, dest), "incompatible")
        dest = json.loads(json.dumps(baseline).replace("/ram/", "/overlay/").replace('"ram"', '"overlay"'))
        self.assertEqual(compare(baseline, dest), "incompatible")

    def test_missing_context_or_witness_cannot_match_even_with_identical_revisions(self):
        baseline = witnessed(report())
        for change in (lambda d: d["edges"][0].pop("instruction_sha256"),
                       lambda d: d["refused_calls"][0].pop("instruction_sha256"),
                       lambda d: d["summaries"][0]["accesses"][0].pop("instruction_sha256"),
                       lambda d: d["summaries"][1]["accesses"][0]["typed_use"].pop("instruction_sha256"),
                       lambda d: d["summaries"][1]["accesses"][0].pop("typed_use"),
                       lambda d: d.pop("variable_accesses"), lambda d: d.pop("summary_limit"),
                       lambda d: d["solution"].update(layout=None)):
            dest = copy.deepcopy(baseline)
            change(dest)
            self.assertEqual(compare(dest, dest), "unverifiable")
            self.assertEqual(compare(baseline, dest), "unverifiable")
            self.assertEqual(compare(dest, baseline), "unverifiable")

    def test_malformed_digest_and_conflicting_bytes_at_one_address_fail(self):
        baseline = witnessed(report())
        for digest in (False, None, "ab", "A" * 64, []):
            bad = copy.deepcopy(baseline)
            bad["summaries"][0]["accesses"][0]["instruction_sha256"] = digest
            with self.subTest(digest=digest), self.assertRaisesRegex(ValueError, "invalid instruction"):
                make_review(parse_summary_report(bad))
        # Repeated instruction locations can occur in call/refusal records with different arguments.
        bad = copy.deepcopy(baseline)
        bad["refused_calls"][0]["address"] = bad["edges"][0]["address"]
        bad["refused_calls"][0]["evidence_id"] = bad["refused_calls"][0]["evidence_id"].replace(
            "/1010/", f"/{bad['edges'][0]['address']}/")
        with self.assertRaisesRegex(ValueError, "conflicting instruction bytes"):
            compare(bad, bad)

    def test_variable_and_call_context_must_belong_to_the_observed_operation(self):
        doc = witnessed(report())
        owner = doc["summaries"][0]["id"]
        doc["variable_accesses"].append(dict(
            summary=owner, evidence_id=f"{owner}/ram/1050/1", address_space="ram", address="1050",
            pcode_order=1, operation="STORE", minimum_offset=4, maximum_offset=12, stride=4, width=2,
            instruction_sha256="a" * 64))
        self.assertEqual(compare(doc, doc), "matched")
        for key, value in (("summary", {}), ("minimum_offset", 12), ("stride", 3), ("width", True),
                           ("pcode_order", 2), ("operation", "COPY")):
            bad = copy.deepcopy(doc)
            bad["variable_accesses"][0][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "variable access"):
                compare(bad, bad)
        for key in ("edges", "refused_calls"):
            bad = copy.deepcopy(doc)
            bad[key][0]["pcode_order"] += 1
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "recorded instruction"):
                compare(bad, bad)

    def test_generated_handoffs_and_single_fact_mutations(self):
        for seed in range(24):
            with self.subTest(seed=seed):
                doc, _, _ = generated_report(seed)
                doc = witnessed(doc)
                captured = open_review(json.loads(make_review(parse_summary_report(doc))))
                dest = copy.deepcopy(doc)
                dest["revision"] = seed
                self.assertEqual(check_review(captured, parse_summary_report(dest))["status"], "matched")
                consumer = dest["summaries"][1]["accesses"][0]["typed_use"]
                consumer["pcode_order"] += 1
                self.assertEqual(check_review(captured, parse_summary_report(dest))["status"], "changed")
                consumer.pop("instruction_sha256")
                self.assertEqual(check_review(captured, parse_summary_report(dest))["status"], "unverifiable")

    def test_cli_error_and_nonmatch_exit_codes(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle, fresh = (Path(directory, name) for name in ("bundle", "fresh"))
            original = witnessed(report())
            bundle.write_text(make_review(parse_summary_report(original)), encoding="utf-8")
            original["language_id"] = "AARCH64:LE:64:v8A"
            fresh.write_text(json.dumps(original), encoding="utf-8")
            status, text, err = cli(bundle, "--check-review", fresh)
            self.assertEqual((status, json.loads(text)["status"], err), (1, "incompatible", ""))
            for bad in (b"[]", b'{"x":1,"x":2}', b'{"a":NaN}', b"\xff", b"[" * 3000 + b"]" * 3000,
                        b" " * (8 * 1024 * 1024 + 1)):
                fresh.write_bytes(bad)
                status, text, err = cli(bundle, "--check-review", fresh)
                self.assertEqual((status, text), (2, ""))
                self.assertIn("binaryrat-explain", err)

    def test_ascii_expansion_and_nonfinite_unknown_fields_do_not_emit_partial_reviews(self):
        document = witnessed(report())
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder, "report.json")
            for value in ('"' + "é" * 1_500_000 + '"', "1e9999"):
                data = json.dumps(document)[:-1] + ',"metadata":' + value + "}"
                path.write_text(data, encoding="utf-8")
                rc, output, error = cli(path, "--make-review")
                self.assertEqual((rc, output), (2, ""))
                self.assertIn("binaryrat-explain", error)

    def test_project_preflight_refuses_missing_witnesses_and_wrong_targets_before_recovery(self):
        doc = witnessed(report())
        captured = parse_summary_report(doc)
        with patch("binaryrat.summary_review.open_program") as opener:
            missing = copy.deepcopy(doc)
            del missing["edges"][0]["instruction_sha256"]
            result = check_project_review(parse_summary_report(missing), "fixture.gpr", "/target")
            self.assertEqual((result["status"], result["fresh_revision"]), ("unverifiable", None))
            opener.assert_not_called()
            view = opener.return_value.__enter__.return_value
            view.info = SimpleNamespace(revision=23, executable_sha256="0" * 64,
                                        language_id=captured.language_id, compiler_spec_id=captured.compiler_spec_id)
            self.assertEqual(check_project_review(captured, "fixture.gpr", "/target")["status"], "incompatible")
            view.function_at.assert_not_called()
            view.info.executable_sha256 = None
            self.assertEqual(check_project_review(captured, "fixture.gpr", "/target")["status"], "unverifiable")
            view.info.executable_sha256 = captured.program_id.removeprefix("sha256:")
            for target in (None, SimpleNamespace(external=False, thunk=True)):
                view.function_at.return_value = target
                result = check_project_review(captured, "fixture.gpr", "/target")
                self.assertEqual((result["status"], result["verification"]), ("unverifiable", "project_preflight"))
            view.solve_layout.assert_not_called()
            view.function_at.return_value = SimpleNamespace(external=False, thunk=False)
            view.solve_layout.return_value = captured
            result = check_project_review(captured, "fixture.gpr", "/target")
            self.assertEqual((result["status"], result["verification"]), ("matched", "saved_program"))
            view.solve_layout.assert_called_once_with(captured.function, captured.parameter_index,
                                                     max_summaries=doc["summary_limit"])

        with tempfile.TemporaryDirectory() as folder:
            handoff = Path(folder, "handoff")
            handoff.write_text(make_review(captured), encoding="ascii")
            rc, output, err = cli(handoff, "--check-project", Path(folder, "missing.gpr"), "/target")
            self.assertEqual((rc, output), (2, ""))
            self.assertIn("missing.gpr", err)


if __name__ == "__main__":
    unittest.main()
