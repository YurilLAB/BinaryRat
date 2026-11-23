"""Tests for the read-only export comparison CLI. Apache-2.0; Copyright 2026 YurilLAB."""

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import random
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from binaryrat import export_diff
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

    def test_text_a_redirected_stream_cannot_encode_is_escaped_not_fatal(self):
        # Windows redirects in the ANSI code page; a CJK string literal must not end the output.
        self.write(self.before, [row()])
        self.write(self.after, [row(c='void parse(void) { puts("\u65e5\u672c\ud83d"); }\n')])
        source = Path(__file__).resolve().parents[1] / "src"
        for options, expected in (("--patch",), 1), ((), 1):
            with self.subTest(options=options):
                done = subprocess.run(
                    [sys.executable, "-m", "binaryrat.export_diff", str(self.before), str(self.after), *options],
                    capture_output=True, timeout=60,
                    env=os.environ | {"PYTHONIOENCODING": "cp1252", "PYTHONPATH": str(source)})
                self.assertEqual((done.returncode, done.stderr), (expected, b""))
                self.assertIn(b"changed ram:10", done.stdout)
                if options:
                    self.assertIn(b'puts("\\u65e5\\u672c\\ud83d")', done.stdout)

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

    def test_patch_diffs_changed_prototype_c_and_error_only(self):
        self.write(self.before, [row("10", c="int f(void)\n{\n  return 1;\n}\n"), row("20"), row("30")])
        self.write(self.after, [
            row("10", c="int f(void)\n{\n  return 2;\n}\n", prototype="int f(void)"),
            row("20", name="renamed"), row("30", error="timed out", completed=False),
        ])
        report = compare_exports(self.before, self.after, patch_context=0)
        changes = {change["address"]: change for change in report["changes"]}
        self.assertNotIn("patch", changes["20"], "a rename alone has no text diff")
        self.assertEqual(changes["10"]["patch"].splitlines(), [
            "--- before ram:10 parse", "+++ after ram:10 parse", "@@ -1 +1 @@",
            "-/* prototype: void parse(void) */", "+/* prototype: int f(void) */",
            "@@ -4 +4 @@", "-  return 1;", "+  return 2;"])
        self.assertIn("+/* error: timed out */", changes["30"]["patch"].splitlines())
        self.assertNotIn("patch", compare_exports(self.before, self.after)["changes"][0])
        status, out, err = self.cli("--patch", "--json")
        self.assertEqual((status, err), (1, ""))
        # The default three context lines join both edits into one hunk.
        self.assertEqual(json.loads(out)["changes"][0]["patch"].count("@@"), 2)
        status, out, err = self.cli("--patch", "--context", "1")
        self.assertEqual((status, err), (1, ""))
        lines = out.splitlines()
        self.assertEqual(lines[2], 'changed ram:10 "parse" (prototype, c)')
        self.assertEqual(lines[3:5], ["--- before ram:10 parse", "+++ after ram:10 parse"])
        self.assertIn("+  return 2;", lines)
        self.assertIn('changed ram:20 "parse" -> "renamed" (name)', lines)

    def test_patch_escapes_terminal_controls_and_checks_its_arguments(self):
        self.write(self.before, [row(c="x\n")])
        self.write(self.after, [row(c="x\x1b[2J\ty\n")])
        status, out, err = self.cli("--patch")
        self.assertEqual((status, err), (1, ""))
        self.assertNotIn("\x1b", out)
        self.assertIn("+x\\x1b[2J\\ty", out.splitlines())
        for options in (("--context", "2"), ("--patch", "--context", "-1")):
            with self.subTest(options=options):
                with redirect_stderr(io.StringIO()):
                    try:
                        code = main([str(self.before), str(self.after), *options])
                    except SystemExit as exit:
                        code = exit.code
                self.assertEqual(code, 2)
        with self.assertRaises(ValueError):
            compare_exports(self.before, self.after, patch_context=True)

    def test_patch_refuses_an_export_replaced_between_passes(self):
        before = [row(c="a\n"), row("20")]
        after = [row(c="b\n"), row("20")]
        changed = "the export changed"
        cases = [
            (self.before, [row("20")], changed),
            (self.after, [row("20")], changed),
            (self.before, [row(c="edited again\n"), row("20")], changed),
            (self.before, [dict(record, revision=6) for record in before], changed),
            (self.after, [dict(record, program_id="sha256:" + "ef" * 32) for record in after],
             "program_id mismatch"),
            (self.after, [row(c="b\n"), row("20", name="changed unselected function")], changed),
            (self.before, [row(), row("0010", revision=6)], "mixed revisions"),
            (self.after, [row(), row("0010")], "duplicate function identity"),
            (self.after, [row(), row("20", revision=6)], "mixed revisions"),
            (self.after, [row(), row("20", body_ranges=[["10", "10000000000000000"]])],
             "64-bit Ghidra offset"),
        ]
        replacement = self.before.with_suffix(".next")
        make_patches = export_diff._patches
        for path, records, message in cases:
            with self.subTest(path=path.name, records=records):
                self.write(self.before, before)
                self.write(self.after, after)
                self.write(replacement, records)

                def replace(*args):
                    replacement.replace(path)
                    return make_patches(*args)

                with patch.object(export_diff, "_patches", side_effect=replace):
                    status, out, err = self.cli("--patch", "--json", "--function", "ram:10")
                self.assertEqual((status, out), (2, ""))
                self.assertIn(f"{path}:", err)
                self.assertIn(message, err)

    def test_cli_reports_a_selected_function_repeated_across_revisions_on_reread(self):
        self.write(self.before, [row(c="a\n")])
        self.write(self.after, [row(c="b\n")])
        replacement = self.after.with_suffix(".next")
        self.write(replacement, [row(c="b\n"), row("0x0010", revision=6, c="c\n")])
        # Swap the file at the second open in the CLI process to avoid a timing race in the test.
        program = """\
from pathlib import Path
import runpy
import sys
from unittest.mock import patch

replacement = Path(sys.argv.pop(1))
after = Path(sys.argv[2])
original_open = Path.open
opens = 0

def open_with_replacement(path, *args, **kwargs):
    global opens
    if path == after:
        opens += 1
        if opens == 2:
            replacement.replace(after)
    return original_open(path, *args, **kwargs)

with patch.object(Path, "open", open_with_replacement):
    runpy.run_module("binaryrat.export_diff", run_name="__main__", alter_sys=True)
"""
        done = subprocess.run(
            [sys.executable, "-c", program, str(replacement), str(self.before), str(self.after),
             "--patch", "--json", "--function", "ram:10"],
            capture_output=True, timeout=60)
        self.assertEqual((done.returncode, done.stdout), (2, b""))
        self.assertIn(b"mixed revisions", done.stderr)
        self.assertNotIn(b"Traceback", done.stderr)

    def test_patch_keeps_both_names_when_a_function_is_renamed(self):
        self.write(self.before, [row(c="before\n", name="old_name")])
        self.write(self.after, [row(c="after\n", name="new_name")])
        report = compare_exports(self.before, self.after, patch_context=0)
        self.assertEqual(report["changes"][0]["patch"].splitlines()[:2],
                         ["--- before ram:10 old_name", "+++ after ram:10 new_name"])

    def test_patch_shows_raw_digests_when_only_line_endings_change(self):
        for before, after in (("a\nb\n", "a\r\nb\r\n"), ("a\n", "a"), ("a\r\nb\n", "a\nb\r\n")):
            with self.subTest(before=before, after=after):
                self.write(self.before, [row(c=before, error=before)])
                self.write(self.after, [row(c=after, error=after)])
                status, out, err = self.cli("--patch", "--json")
                self.assertEqual((status, err), (1, ""))
                change = json.loads(out)["changes"][0]
                self.assertEqual(change["fields"], ["c", "error"])
                for label in ("C text", "Error text"):
                    for sign, value in (("-", before), ("+", after)):
                        digest = hashlib.sha256(value.encode()).hexdigest()
                        self.assertIn(f"{sign}/* {label} raw SHA-256: {digest} */", change["patch"])

    def test_function_selection_distinguishes_overlays_and_counts_selected_entries(self):
        self.write(self.before, [row("10"), row("10", address_space="overlay"),
                                 row("20"), row("30"), row("40")])
        self.write(self.after, [row("10", c="changed main"),
                                row("10", c="changed overlay", address_space="overlay"),
                                row("30"), row("40", c="unselected change"), row("50")])
        status, out, err = self.cli(
            "--json", "--patch", "--function", "overlay:0X0010", "--function", "overlay:10",
            "--function", "ram:20", "--function", "ram:30", "--function", "ram:50",
        )
        self.assertEqual((status, err), (1, ""))
        report = json.loads(out)
        self.assertEqual(report["counts"], {"added": 1, "removed": 1, "changed": 1, "unchanged": 1})
        self.assertEqual([(c["address_space"], c["address"], c["kind"]) for c in report["changes"]],
                         [("overlay", "10", "changed"), ("ram", "20", "removed"),
                          ("ram", "50", "added")])
        self.assertIn("+changed overlay", report["changes"][0]["patch"])
        self.assertEqual(self.cli("--function", "ram:30")[0], 0)

    def test_function_selection_rejects_missing_entries_and_validates_both_files(self):
        self.write(self.before, [row("10")])
        self.write(self.after, [row("10")])
        status, out, err = self.cli("--function", "ram:10", "--function", "overlay:10")
        self.assertEqual((status, out), (2, ""))
        self.assertIn("overlay:10", err)
        for malformed in ("10", ":10", "ram:-1", "ram:10000000000000000"):
            with self.subTest(malformed=malformed):
                with self.assertRaises(SystemExit) as raised:
                    self.cli("--function", malformed)
                self.assertEqual(raised.exception.code, 2)
        for bad in (row("20", revision=6), row("10000000000000000"), row("0010")):
            with self.subTest(bad=bad):
                self.write(self.after, [row("10"), bad])
                status, out, err = self.cli("--function", "ram:10")
                self.assertEqual((status, out), (2, ""))
                self.assertTrue(err)

    @staticmethod
    def apply_patch(before, patch):
        """Independent unified-diff applier: context and removals must match exactly."""
        lines = patch.splitlines()
        result, cursor, index = [], 0, 2
        while index < len(lines):
            header = re.fullmatch(r"@@ -(\d+)(?:,(\d+))? \+\d+(?:,\d+)? @@", lines[index])
            assert header is not None, lines[index]
            start = int(header[1]) - (0 if header[2] == "0" else 1)
            result += before[cursor:start]
            cursor, index = start, index + 1
            while index < len(lines) and not lines[index].startswith("@@ "):
                tag, text = lines[index][:1], lines[index][1:]
                if tag in " -":
                    assert before[cursor] == text, (before[cursor], text)
                    cursor += 1
                if tag in " +":
                    result.append(text)
                index += 1
        return result + before[cursor:]

    def test_seeded_patch_fuzz_rebuilds_every_changed_text(self):
        # Random C-like bodies with inserted, deleted, replaced and reordered lines,
        # unusual characters, empty bodies and error transitions, at varied context sizes.
        rng = random.Random(20261120)
        alphabet = ["  x = y;", "{", "}", "return 0;", "", "\t/* tab */", "if (a) {", "  b++;",
                    "s = \"\x1b[2J\";", "\u00e9t\u00e9 \U0001f400", "--- not a header", "@@ -1 +1 @@ text"]
        for case in range(120):
            old, new = [], []
            for index in range(rng.randrange(1, 12)):
                lines = [rng.choice(alphabet) for _ in range(rng.randrange(0, 25))]
                edited = list(lines)
                for _ in range(rng.randrange(0, 5)):
                    action = rng.randrange(4)
                    position = rng.randrange(len(edited) + 1)
                    if action == 0:
                        edited.insert(position, rng.choice(alphabet))
                    elif edited and action == 1:
                        del edited[min(position, len(edited) - 1)]
                    elif edited and action == 2:
                        edited[min(position, len(edited) - 1)] = rng.choice(alphabet) + " changed"
                    elif len(edited) > 1:
                        rng.shuffle(edited)
                base = row(f"{index * 16 + 16:x}", c="\n".join(lines) + ("\n" if lines else ""))
                after = dict(base, c="\n".join(edited) + ("\n" if edited else ""))
                if rng.random() < 0.15:
                    after.update(c="", completed=False, timed_out=True, error="timed out\nsecond line")
                if rng.random() < 0.15:
                    after["prototype"] = "int parse(char *text)"
                old.append(base)
                new.append(after)
            self.write(self.before, old)
            self.write(self.after, new)
            context = rng.choice((0, 1, 3, 7))
            report = compare_exports(self.before, self.after, patch_context=context)
            by_address = {record["address"]: record for record in new}
            originals = {record["address"]: record for record in old}

            def text(record):
                lines = [f"/* prototype: {record['prototype']} */"]
                lines += [f"/* error: {line} */" for line in record["error"].splitlines()]
                return lines + record["c"].splitlines()

            patched = 0
            for change in report["changes"]:
                key = change["address"]
                self.assertEqual(change["kind"], "changed")
                self.assertEqual("patch" in change, bool({"prototype", "c", "error"} & set(change["fields"])))
                if "patch" in change:
                    patched += 1
                    with self.subTest(case=case, address=key, context=context):
                        self.assertEqual(self.apply_patch(text(originals[key]), change["patch"]),
                                         text(by_address[key]))
            unchanged = sum(text(a) == text(b) for a, b in zip(old, new))
            self.assertEqual(patched + unchanged, len(old))
