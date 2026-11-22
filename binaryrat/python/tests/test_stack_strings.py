"""Strict stack-string report parsing, rendering and CLI argument checks.

Apache-2.0; Copyright 2026 YurilLAB.
"""

from __future__ import annotations

import copy
import io
import json
import random
import unittest
from contextlib import redirect_stderr

from binaryrat import Address
from binaryrat.decompile_cli import main as decompile_main
from binaryrat.stack_strings import (
    MAX_TEXT,
    StackStringsReportError,
    decode_stack_strings_report,
    explain_stack_strings,
    parse_stack_strings_report,
)


def _function(offset: int, name: str) -> dict:
    return {"address_space": "ram", "address": f"{offset:x}", "name": name}


def _string(function: dict, site: int, offset: int, text: str, encoding: str = "ascii", terminated: bool = True,
            writes: tuple[int, ...] | None = None) -> dict:
    return {"function": function, "address_space": "ram", "address": f"{site:x}", "stack_offset": offset,
            "byte_length": len(text) * (2 if encoding == "utf16le" else 1), "encoding": encoding, "text": text,
            "text_truncated": False, "terminated": terminated,
            "writes": [{"address_space": "ram", "address": f"{address:x}"} for address in (writes or (site,))]}


def _report() -> dict:
    """The shape BinaryRatStackStringsProof produces on its disposable x86-64 Program."""
    builder, brancher = _function(0x1000, "builder"), _function(0x1200, "brancher")
    return {
        "schema_version": 1, "analysis_mode": "read_only_stack_strings", "revision": 9,
        "program_id": None, "language_id": "x86:LE:64:default", "compiler_spec_id": "gcc", "function": None,
        "minimum_length": 4, "function_limit": 10000, "functions_scanned": 3, "functions_skipped": 1,
        "functions_partial": 0, "stack_writes": 31, "truncated": False,
        "strings": [
            _string(builder, 0x100b, -16, "hello", writes=(0x100b, 0x1012)),
            _string(builder, 0x1036, -48, "wide", "utf16le"),
            _string(builder, 0x104b, -64, "abcdXXXX", terminated=False, writes=(0x104b, 0x1052)),
            _string(builder, 0x1065, -32, "C:\\Temp\tx\n"),
            _string(brancher, 0x1209, -24, "AAAA", terminated=False),
        ],
    }


class StackStringsReportTests(unittest.TestCase):
    def test_valid_report_decodes_and_renders(self):
        report = decode_stack_strings_report(json.dumps(_report()))
        self.assertIsNone(report.function)
        self.assertEqual([item.text for item in report.strings], ["hello", "wide", "abcdXXXX", "C:\\Temp\tx\n", "AAAA"])
        hello, wide = report.strings[0], report.strings[1]
        self.assertEqual((hello.function, hello.stack_offset, hello.writes),
                         (Address("ram", 0x1000), -16, (Address("ram", 0x100b), Address("ram", 0x1012))))
        self.assertEqual([item.render() for item in report.strings[:4]],
                         ['"hello"', 'L"wide"', '"abcdXXXX"', '"C:\\\\Temp\\tx\\n"'])
        self.assertEqual(report.document, _report())
        lines = explain_stack_strings(report)
        self.assertEqual(lines[0], "Stack strings in 3 functions: 5")
        self.assertIn('ram:100b  builder  stack -0x10  "hello"', lines)
        self.assertIn('ram:1209  brancher  stack -0x18  "AAAA"  (no terminator)', lines)

    def test_one_function_report(self):
        document = _report()
        document["function"] = _function(0x1200, "brancher")
        document["functions_scanned"], document["functions_skipped"] = 1, 0
        document["strings"] = document["strings"][-1:]
        report = parse_stack_strings_report(document)
        self.assertEqual((report.function, report.function_name), (Address("ram", 0x1200), "brancher"))
        self.assertEqual(explain_stack_strings(report)[0], "Stack strings in brancher: 1")
        document["strings"] = _report()["strings"]
        with self.assertRaisesRegex(StackStringsReportError, "one-function"):
            parse_stack_strings_report(document)

    def test_name_at_unicode_character_limit(self):
        document = _report()
        name = "a" * 1023 + "\U0001f400"
        document["strings"][0]["function"]["name"] = name
        report = decode_stack_strings_report(json.dumps(document))
        self.assertEqual(report.strings[0].function_name, name)
        output = json.dumps(report.document, ensure_ascii=False).encode("utf-8")
        self.assertEqual(decode_stack_strings_report(output), report)
        for invalid in (name + "z", "a" * 1023 + "\ud83d", "a" * 1023 + "\udc00"):
            with self.subTest(invalid=ascii(invalid[-2:])):
                document["strings"][0]["function"]["name"] = invalid
                with self.assertRaisesRegex(StackStringsReportError, "nonempty printable text"):
                    decode_stack_strings_report(json.dumps(document))
        with self.assertRaisesRegex(StackStringsReportError, "invalid stack-string report JSON"):
            decode_stack_strings_report(json.dumps(document, ensure_ascii=False))

    def test_overlay_spaces_sharing_an_offset_stay_apart(self):
        # BinaryRatStackStringsProof's overlay banks: bankA::1000 and bankB::1000 beside ram:1000.
        def banked(space: str, text: str) -> dict:
            item = _string({"address_space": space, "address": "1000", "name": "banked_" + text}, 0x1004, -24, text)
            item["address_space"] = item["writes"][0]["address_space"] = space
            return item

        document = _report()
        document["strings"] += [banked("bankA", "north"), banked("bankB", "south")]
        report = parse_stack_strings_report(document)
        builder, north, south = report.strings[0], report.strings[-2], report.strings[-1]
        self.assertEqual([item.function for item in (builder, north, south)],
                         [Address("ram", 0x1000), Address("bankA", 0x1000), Address("bankB", 0x1000)])
        self.assertEqual(len({item.function for item in (builder, north, south)}), 3)
        self.assertEqual((north.site, north.writes), (Address("bankA", 0x1004), (Address("bankA", 0x1004),)))
        lines = explain_stack_strings(report)
        self.assertIn('bankA:1004  banked_north  stack -0x18  "north"', lines)
        self.assertIn('bankB:1004  banked_south  stack -0x18  "south"', lines)

        # A one-function report for bankA::1000 must not accept a string from ram:1000.
        one = _report()
        one["function"] = {"address_space": "bankA", "address": "1000", "name": "banked_north"}
        one["functions_scanned"], one["functions_skipped"] = 1, 0
        one["strings"] = [banked("bankA", "north")]
        self.assertEqual(parse_stack_strings_report(one).function, Address("bankA", 0x1000))
        one["strings"].append(_report()["strings"][0])
        with self.assertRaisesRegex(StackStringsReportError, "one-function"):
            parse_stack_strings_report(one)

    def test_truncated_text(self):
        document = _report()
        item = document["strings"][0]
        item.update(text="a" * MAX_TEXT, byte_length=MAX_TEXT + 5, text_truncated=True)
        report = parse_stack_strings_report(document)
        self.assertTrue(report.strings[0].render().endswith('"...'))
        item["byte_length"] = MAX_TEXT
        with self.assertRaises(StackStringsReportError):
            parse_stack_strings_report(document)

    def test_each_invariant_is_enforced(self):
        def mutate(path, value):
            document = _report()
            target = document
            for key in path[:-1]:
                target = target[key]
            if value is _DELETE:
                del target[path[-1]]
            else:
                target[path[-1]] = value
            return document

        cases = {
            "schema": mutate(("schema_version",), 2),
            "mode": mutate(("analysis_mode",), "read_only_call_sites"),
            "program id": mutate(("program_id",), "sha256:abc"),
            "extra field": mutate(("extra",), 1),
            "missing field": mutate(("strings",), _DELETE),
            "minimum 0": mutate(("minimum_length",), 0),
            "minimum 65": mutate(("minimum_length",), 65),
            "scanned over limit": mutate(("functions_scanned",), 10001),
            "partial over scanned": mutate(("functions_partial",), 4),
            "bool as int": mutate(("revision",), False),
            "strings without writes": mutate(("stack_writes",), 0),
            "encoding": mutate(("strings", 0, "encoding"), "utf8"),
            "length mismatch": mutate(("strings", 0, "byte_length"), 6),
            "odd UTF-16 length": mutate(("strings", 1, "byte_length"), 7),
            "shorter than minimum": mutate(("strings", 0, "text"), "hel"),
            "control text": mutate(("strings", 0, "text"), "he\x01lo"),
            "non-ASCII text": mutate(("strings", 0, "text"), "h\u00e9llo"),
            "empty text": mutate(("strings", 0, "text"), ""),
            "no writes": mutate(("strings", 0, "writes"), []),
            "site not first write": mutate(("strings", 0, "address"), "1012"),
            "writes out of order": mutate(("strings", 0, "writes"),
                                          [{"address_space": "ram", "address": "1012"},
                                           {"address_space": "ram", "address": "100b"}]),
            "duplicate write": mutate(("strings", 0, "writes"),
                                      [{"address_space": "ram", "address": "100b"}] * 2),
            "offset overflow": mutate(("strings", 0, "stack_offset"), (1 << 63) - 2),
            "uppercase address": mutate(("strings", 0, "address"), "100B"),
            "function name control": mutate(("strings", 0, "function", "name"), "bu\nilder"),
            "terminated not bool": mutate(("strings", 0, "terminated"), 1),
        }
        for name, document in cases.items():
            with self.subTest(name), self.assertRaises(StackStringsReportError):
                parse_stack_strings_report(document)

    def test_strict_json(self):
        text = json.dumps(_report())
        for bad in ('{"schema_version": 1, "schema_version": 1}', text.replace('"revision": 9', '"revision": NaN'),
                    text.replace('"revision": 9', '"revision": ' + "9" * 30), "{", b"\xfe"):
            with self.subTest(bad=str(bad)[:40]), self.assertRaises(StackStringsReportError):
                decode_stack_strings_report(bad)

    def test_seeded_mutation_fuzz_only_raises_report_errors(self):
        """Random edits either decode to a consistent report or raise StackStringsReportError."""
        values = [None, True, False, 0, -1, 3, 1 << 70, "", "x", "ram", "100b", "zz", [], {}, [1], {"a": 1},
                  "ascii", "utf16le", "hello", "\x00", "a" * 2000, -(1 << 63)]
        for seed in range(60):
            generator = random.Random(seed)
            for _ in range(40):
                document = _report()
                for _ in range(generator.randint(1, 4)):
                    _mutate(document, generator, values)
                try:
                    report = decode_stack_strings_report(json.dumps(document))
                except StackStringsReportError:
                    continue
                except Exception as unexpected:  # pragma: no cover - the failure being searched for
                    self.fail(f"seed {seed}: {type(unexpected).__name__}: {unexpected}")
                for item in report.strings:
                    unit = 2 if item.encoding == "utf16le" else 1
                    self.assertTrue(item.text_truncated or item.byte_length == unit * len(item.text))
                    self.assertGreaterEqual(item.byte_length // unit, report.minimum_length)
                    self.assertEqual(item.writes[0], item.site)
                    self.assertIsInstance(item.render(), str)


_DELETE = object()


def _mutate(node, generator: random.Random, values: list) -> None:
    path = []
    while isinstance(node, (dict, list)) and node and generator.random() < 0.8:
        key = generator.choice(list(node)) if isinstance(node, dict) else generator.randrange(len(node))
        path.append((node, key))
        node = node[key]
    if not path:
        return
    parent, key = path[-1]
    action = generator.random()
    if action < 0.15 and isinstance(parent, dict):
        del parent[key]
    elif action < 0.25 and isinstance(parent, list):
        parent.append(copy.deepcopy(parent[key]))
    else:
        parent[key] = copy.deepcopy(generator.choice(values))


class StackStringsCliTests(unittest.TestCase):
    def run_cli(self, *argv: str) -> int:
        with redirect_stderr(io.StringIO()):
            try:
                return decompile_main(list(argv))
            except SystemExit as stop:
                return stop.code

    def test_options_are_checked_before_opening_a_program(self):
        base = ("missing.gpr", "/program")
        self.assertEqual(self.run_cli(*base, "--stack-strings", "--list"), 2)
        self.assertEqual(self.run_cli(*base, "main", "--stack-strings", "--call-sites"), 2)
        self.assertEqual(self.run_cli(*base, "main", "--min-length", "5"), 2)
        self.assertEqual(self.run_cli(*base, "--list", "--max-functions", "5"), 2)
        self.assertEqual(self.run_cli(*base, "main", "--stack-strings", "--max-functions", "5"), 2)
        for bad in ("0", "65", "x"):
            with self.subTest(bad=bad):
                self.assertEqual(self.run_cli(*base, "--stack-strings", "--min-length", bad), 2)
        self.assertEqual(self.run_cli(*base, "--stack-strings", "--max-functions", "200001"), 2)
        # Without FUNCTION, --stack-strings passes argument checks and fails on the missing project.
        errors = io.StringIO()
        with redirect_stderr(errors):
            code = decompile_main([*base, "--stack-strings", "--backend", "stock"])
        self.assertEqual(code, 2)
        self.assertNotIn("usage:", errors.getvalue())
        self.assertIn("binaryrat-decompile:", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
