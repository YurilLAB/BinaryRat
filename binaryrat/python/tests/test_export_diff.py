"""Tests for the read-only export comparison CLI. Apache-2.0; Copyright 2026 YurilLAB."""

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import random
import tempfile
import unittest

from binaryrat.export_diff import compare_exports, main
from binaryrat.exports import ExportError


PROGRAM = "sha256:" + "ab" * 32


def row(address="10", **overrides):
    return dict({
        "schema_version": 1, "program_id": PROGRAM, "revision": 5, "address_space": "ram",
        "address": address, "name": "parse", "body_sha256": "cd" * 32,
        "body_ranges": [["10", "1e"], ["20", "2e"]], "prototype": "void parse(void)",
        "c": "void parse(void) {}\n", "completed": True, "timed_out": False, "cancelled": False,
        "failed_to_start": False, "error": "",
    }, **overrides)


class ExportDiffTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.before, self.after = (Path(temp.name) / name for name in ("before.jsonl", "after.jsonl"))

    @staticmethod
    def write(path, rows):
        path.write_text("".join(json.dumps(record) + "\n" for record in rows), encoding="utf-8")

    def cli(self, *options):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = main([str(self.before), str(self.after), *options])
        return status, stdout.getvalue(), stderr.getvalue()

    def test_revision_order_address_format_and_range_order_do_not_change_a_function(self):
        first = [row(), row(address="fffffffffffffff0", address_space="overlay")]
        self.write(self.before, first)
        self.write(self.after, [dict(item, revision=97, address="0X" + item["address"].upper(),
                                     program_id="sha256:" + PROGRAM[7:].upper(),
                                     body_sha256=item["body_sha256"].upper(),
                                     body_ranges=list(reversed(item["body_ranges"])))
                                for item in reversed(first)])
        status, out, err = self.cli("--json")
        report = json.loads(out)
        self.assertEqual((status, err), (0, ""))
        self.assertEqual(report, {"schema_version": 1, "program_id": PROGRAM, "changes": [],
                                  "counts": {"unchanged": 2, "added": 0, "removed": 0, "changed": 0}})

    def test_changed_fields_added_and_removed_in_numeric_space_order(self):
        baseline = [row("f"), row("ff"), row("1", address_space="rom"), row("ff", address_space="io")]
        current = [row("10", name="new"), row("ff", address_space="io"),
                   row("f", name="renamed", body_sha256="aa" * 32, body_ranges=[["0f", "21"]],
                       prototype="void renamed(void)", c=" changed\n", completed=False,
                       timed_out=True, cancelled=True, failed_to_start=True, error="aborted")]
        self.write(self.before, baseline)
        self.write(self.after, current)
        report = compare_exports(self.before, self.after)
        self.assertEqual(report["counts"], {"added": 1, "removed": 2, "changed": 1, "unchanged": 1})
        self.assertEqual([(c["kind"], c["address_space"], c["address"]) for c in report["changes"]],
                         [("changed", "ram", "f"), ("added", "ram", "10"), ("removed", "ram", "ff"),
                          ("removed", "rom", "1")])
        first = report["changes"][0]
        self.assertEqual((first["before_name"], first["after_name"]), ("parse", "renamed"))
        self.assertEqual(first["fields"], ["name", "body_sha256", "body_ranges", "prototype", "c",
                                           "completed", "timed_out", "cancelled", "failed_to_start", "error"])
        self.assertIsNone(report["changes"][1]["before_name"])
        self.assertIsNone(report["changes"][2]["after_name"])
        status, text, err = self.cli()
        self.assertEqual((status, err), (1, ""))
        self.assertIn('changed ram:f "parse" -> "renamed"', text)

    def test_rejects_ambiguous_inputs_without_a_partial_report(self):
        self.write(self.before, [row()])
        invalid = [
            ([], "empty export"),
            ([row(program_id="name:tool")], "SHA-256"),
            ([row(program_id="sha256:" + "af" * 32)], "program_id mismatch"),
            ([row(), row("20", program_id="sha256:" + "ff" * 32)], "program_id mismatch"),
            ([row(), row(program_id="sha256:" + PROGRAM[7:].upper())], "program_id mismatch"),
            ([row(), row("20", revision=6)], "mixed revisions"),
            ([row(), row("00010")], "duplicate"),
            ([row("10000000000000000")], "64-bit"),
            ([row(body_ranges=[["10", "10000000000000000"]])], "64-bit"),
        ]
        for records, message in invalid:
            with self.subTest(message=message, records=len(records)):
                self.write(self.after, records)
                code, out, err = self.cli("--json")
                self.assertEqual((code, out), (2, ""))
                self.assertIn(message, err)
        self.write(self.before, [])
        self.write(self.after, [row()])
        self.assertIn("empty export", self.cli()[2])

    def test_malformed_truncated_oversized_and_unreadable_input(self):
        self.write(self.before, [row()])
        self.assertEqual(self.cli()[0], 2)
        good = (json.dumps(row()) + "\n").encode("utf-8")
        for suffix, message in ((b'{"name":', "line 2"), (b'\xff', "line 2"),
                                (b"[" * 4000 + b"]" * 4000, "binaryrat-diff:"),
                                (b" " * (1024 * 1024 + 1), "record limit")):
            with self.subTest(message=message):
                self.after.write_bytes(good + suffix)
                code, out, err = self.cli("--json", "--max-record-mib", "1")
                self.assertEqual((code, out), (2, ""))
                self.assertIn(message, err)
        self.after.write_bytes(good.rstrip(b"\n"))
        self.assertEqual(self.cli()[0], 0)
        self.assertEqual(self.cli("--max-record-mib", "0")[0], 2)

    def test_record_limit_includes_the_line_ending(self):
        raw = json.dumps(row()).encode("utf-8")
        self.before.write_bytes(raw + b"\n")
        padding = b" " * (1024 * 1024 - len(raw) - 1)
        self.after.write_bytes(raw + padding + b"\n")
        self.assertEqual(self.cli("--max-record-mib", "1")[0], 0)
        self.after.write_bytes(raw + padding + b"\r\n")
        self.assertEqual(self.cli("--max-record-mib", "1")[0], 2)
        with self.assertRaises(ValueError):
            compare_exports(self.before, self.after, max_record_mib=True)

    def test_large_c_change_report_omits_bodies_and_escapes_terminal_controls(self):
        body = "/* x */" * 200000
        names = {"name": "routine\x1b[31m\udfff", "address_space": "mem\n"}
        self.write(self.before, [row(c=body, **names)])
        self.write(self.after, [row(c=body + "\n", **names)])
        for path in (self.before, self.after):
            self.assertGreater(path.stat().st_size, 1024 * 1024)
        status, out, err = self.cli()
        self.assertEqual((status, err), (1, ""))
        self.assertIn('changed mem\\n:10 "routine\\u001b[31m\\udfff" (c)', out)
        self.assertLess(len(out), 1024)
        self.assertNotIn("\x1b", out)
        with self.assertRaisesRegex(ExportError, "record limit"):
            compare_exports(self.before, self.after, max_record_mib=1)

    def test_seeded_comparison_matches_independent_record_differences(self):
        # Compare missing entries, renames, signature, diagnostic and C edits to a simple oracle.
        rng = random.Random(20261118)
        for _ in range(35):
            old, new, expected = [], [], {}
            for address in range(24):
                key = f"{address:x}"
                base = row(key)
                present = rng.choice(("both", "left", "right"))
                if present != "right":
                    old.append(base)
                if present != "left":
                    edited = dict(base, revision=10)
                    for attr in ("name", "prototype", "c", "error"):
                        if rng.random() < 0.2:
                            edited[attr] += " change"
                    new.append(edited)
                if present != "both":
                    expected[key] = ("removed" if present == "left" else "added", set())
                else:
                    changed = {field for field in base if field != "revision" and base[field] != edited[field]}
                    if changed:
                        expected[key] = ("changed", changed)
            rng.shuffle(old)
            rng.shuffle(new)
            self.write(self.before, old)
            self.write(self.after, new)
            inputs = [hashlib.sha256(path.read_bytes()).digest() for path in (self.before, self.after)]
            report = compare_exports(self.before, self.after)
            self.assertEqual({c["address"]: (c["kind"], set(c["fields"])) for c in report["changes"]},
                             expected)
            self.assertEqual(inputs, [hashlib.sha256(path.read_bytes()).digest()
                                      for path in (self.before, self.after)])
