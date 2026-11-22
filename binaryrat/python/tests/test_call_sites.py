"""Strict call-site report parsing, rendering and CLI argument checks.

Apache-2.0; Copyright 2026 YurilLAB.
"""

from __future__ import annotations

import copy
import io
import json
import random
import unittest
from contextlib import redirect_stderr
from unittest.mock import patch

from binaryrat import Address
from binaryrat.call_sites import (
    MAX_ARGUMENTS,
    CallSitesReportError,
    decode_call_sites_report,
    explain_call_sites,
    parse_call_sites_report,
)
from binaryrat.decompile_cli import main as decompile_main


def _function(offset: int, name: str) -> dict:
    return {"address_space": "ram", "address": f"{offset:x}", "name": name}


def _argument(index: int, kind: str, value: int | None = None, size: int = 4, **extra) -> dict:
    item = {"index": index, "size": size, "kind": kind, "value": None, "signed": None, "variable": None,
            "symbol": None, "string": None, "string_source": None}
    if value is not None:
        bits = 8 * size
        item["value"] = f"{value:x}"
        item["signed"] = value - (1 << bits) if value >> (bits - 1) else value
    item.update(extra)
    return item


def _site(offset: int, status: str, caller: dict | None, reason: str | None = None,
          statement: str | None = None, arguments: list | None = None, target: int = 0x1080) -> dict:
    decompiled = status == "decompiled"
    return {"address_space": "ram", "address": f"{offset:x}", "target_address_space": "ram",
            "target_address": f"{target:x}", "caller": caller, "status": status,
            "reason": None if decompiled else reason, "operation": "CALL" if decompiled else None,
            "statement": statement, "arguments": arguments or [], "arguments_truncated": False,
            "instruction_sha256": "ab" * 32}


def _report() -> dict:
    """The shape BinaryRatCallSitesProof produces on its disposable x86-64 Program."""
    caller, callee = _function(0x1000, "caller"), _function(0x1080, "callee")
    return {
        "schema_version": 1, "analysis_mode": "read_only_call_sites",
        "function": callee, "root_function": copy.deepcopy(callee), "revision": 7,
        "program_id": "sha256:" + "0" * 64, "language_id": "x86:LE:64:default", "compiler_spec_id": "gcc",
        "targets": [{"address_space": "ram", "address": "1080", "name": "callee", "thunk": False},
                    {"address_space": "ram", "address": "10c0", "name": "callee", "thunk": True}],
        "timeout_seconds": 60, "site_limit": 64, "caller_limit": 32, "references_scanned": 11,
        "call_references": 5, "other_references": 2, "truncated": False, "decompiled_callers": 2,
        "sites": [
            _site(0x1000, "not_in_decompilation", caller, "the decompiler emitted no call at this address"),
            _site(0x100a, "decompiled", caller, statement='callee(7,"hello")', arguments=[
                _argument(0, "constant", 7),
                _argument(1, "address", 0x3000, size=8, string='"hello"', string_source="defined_data")]),
            _site(0x1019, "decompiled", caller, statement='a = callee(-1,"raw text")', target=0x10c0,
                  arguments=[_argument(0, "constant", 0xFFFFFFFF),
                             _argument(1, "address", 0x3010, size=8, symbol="raw_label",
                                       string='"raw text"', string_source="memory_scan")]),
            _site(0x1086, "decompiled", callee, statement="iVar1 = callee(a + -1,s)", arguments=[
                _argument(0, "unknown"), _argument(1, "unknown", size=8, variable="s")]),
            _site(0x1140, "no_function", None, "the call is not inside a defined function"),
        ],
    }


def _encode(document: dict) -> str:
    return json.dumps(document)


class CallSitesReportTests(unittest.TestCase):
    def test_long_overlay_address_space_keeps_its_identity(self):
        document = _report()
        space = "bank_" + "x" * 65
        for field in ("function", "root_function"):
            document[field]["address_space"] = space
        for target in document["targets"]:
            target["address_space"] = space
        for site in document["sites"]:
            site["address_space"] = site["target_address_space"] = space
            if site["caller"] is not None:
                site["caller"]["address_space"] = space
        report = decode_call_sites_report(_encode(document))
        self.assertEqual(report.root_function, Address(space, 0x1080))
        self.assertEqual(report.sites[1].site, Address(space, 0x100A))
        self.assertEqual(report.sites[1].target, report.root_function)
        self.assertEqual(report.sites[1].caller, Address(space, 0x1000))

    def test_utf8_byte_budget_and_invalid_unicode(self):
        document = _report()
        argument = document["sites"][1]["arguments"][1]
        argument["string"] = '"café🐀"'
        text = json.dumps(document, ensure_ascii=False)
        raw = text.encode("utf-8")
        for payload in (text, raw):
            with patch("binaryrat.call_sites.MAX_REPORT_BYTES", len(raw)):
                self.assertEqual(decode_call_sites_report(payload).document, document)
            with patch("binaryrat.call_sites.MAX_REPORT_BYTES", len(raw) - 1):
                with self.assertRaisesRegex(CallSitesReportError, "exceeds 8 MiB"):
                    decode_call_sites_report(payload)

        argument["string"] = '"\ud800"'
        with self.assertRaisesRegex(CallSitesReportError, "invalid call-site report JSON"):
            decode_call_sites_report(json.dumps(document, ensure_ascii=False))
        with self.assertRaisesRegex(CallSitesReportError, "printable text"):
            decode_call_sites_report(json.dumps(document))

    def test_valid_report_decodes_and_renders(self):
        report = decode_call_sites_report(_encode(_report()))
        self.assertEqual((report.root_function, report.root_name), (Address("ram", 0x1080), "callee"))
        self.assertEqual([site.status for site in report.sites],
                         ["not_in_decompilation", "decompiled", "decompiled", "decompiled", "no_function"])
        self.assertEqual(report.callers(), (Address("ram", 0x1000), Address("ram", 0x1080)))
        first, second, recursive = report.sites[1], report.sites[2], report.sites[3]
        self.assertEqual([argument.render() for argument in first.arguments], ["7", '"hello"'])
        self.assertEqual([argument.render() for argument in second.arguments], ["-1", '"raw text"'])
        self.assertEqual([argument.render() for argument in recursive.arguments], ["?", "s"])
        self.assertEqual((second.arguments[0].value, second.arguments[0].signed), (0xFFFFFFFF, -1))
        self.assertEqual(report.document, _report())
        lines = explain_call_sites(report)
        self.assertEqual(lines[0], "Calls to callee at ram:1080: 5 sites in 2 callers")
        self.assertIn('ram:100a  caller  callee(7,"hello")', lines)
        self.assertIn('    arg0 = 7, arg1 = "hello"', lines)
        self.assertIn("ram:1140  (no function)  [no_function] the call is not inside a defined function", lines)

    def test_rendering_of_large_values_symbols_and_wide_constants(self):
        document = _report()
        document["sites"][1]["arguments"] = [
            _argument(0, "constant", 0x401000, size=8),
            _argument(1, "address", 0x3000, size=8, symbol="table"),
            _argument(2, "address", 0x3008, size=8),
            _argument(3, "constant", 0x8000, size=2),
            _argument(4, "constant", 5, size=16) | {"signed": None},
        ]
        rendered = [argument.render() for argument in decode_call_sites_report(_encode(document)).sites[1].arguments]
        self.assertEqual(rendered, ["0x401000", "&table", "0x3008", "-32768", "0x5"])

    def test_truncation_limits_and_callers_must_agree(self):
        document = _report()
        document["call_references"] = 9
        with self.assertRaisesRegex(CallSitesReportError, "truncated"):
            parse_call_sites_report(document)
        document["truncated"] = True
        self.assertTrue(parse_call_sites_report(document).truncated)
        limited = _report()
        limited["caller_limit"] = limited["decompiled_callers"] = 1
        limited["sites"][3] = _site(0x1086, "caller_limit", _function(0x1080, "callee"),
                                    "the caller decompile limit of 1 was reached")
        limited["sites"] = limited["sites"][:2] + limited["sites"][3:]
        limited["call_references"] = 4
        limited["sites"][0]["status"] = "decompile_failed"
        limited["sites"][0]["reason"] = "decompiler failed: timeout"
        limited["sites"][1] = _site(0x100a, "decompile_failed", _function(0x1000, "caller"),
                                    "decompiler failed: timeout")
        self.assertEqual([site.status for site in parse_call_sites_report(limited).sites],
                         ["decompile_failed", "decompile_failed", "caller_limit", "no_function"])
        limited["decompiled_callers"] = 0
        with self.assertRaisesRegex(CallSitesReportError, "decompiled_callers"):
            parse_call_sites_report(limited)

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
            "mode": mutate(("analysis_mode",), "other"),
            "program id": mutate(("program_id",), "sha256:XYZ"),
            "extra field": mutate(("extra",), 1),
            "missing field": mutate(("sites",), _DELETE),
            "bool as int": mutate(("revision",), True),
            "site limit": mutate(("site_limit",), 0),
            "caller limit": mutate(("caller_limit",), 257),
            "timeout": mutate(("timeout_seconds",), 601),
            "too few scanned": mutate(("references_scanned",), 3),
            "unknown status": mutate(("sites", 0, "status"), "maybe"),
            "caller missing": mutate(("sites", 1, "caller"), None),
            "caller on orphan": mutate(("sites", 4, "caller"), _function(0x1000, "caller")),
            "reason on decompiled": mutate(("sites", 1, "reason"), "why"),
            "no reason": mutate(("sites", 0, "reason"), None),
            "statement on failure": mutate(("sites", 0, "statement"), "x()"),
            "operation": mutate(("sites", 1, "operation"), "BRANCH"),
            "arguments on failure": mutate(("sites", 0, "arguments"), [_argument(0, "unknown")]),
            "argument order": mutate(("sites", 1, "arguments", 0, "index"), 1),
            "argument kind": mutate(("sites", 1, "arguments", 0, "kind"), "float"),
            "value too wide": mutate(("sites", 1, "arguments", 0, "value"), "1ffffffff"),
            "uppercase hex": mutate(("sites", 1, "arguments", 1, "value"), "3A00"),
            "signed mismatch": mutate(("sites", 1, "arguments", 0, "signed"), -7),
            "unknown with value": mutate(("sites", 3, "arguments", 0, "value"), "7"),
            "constant with string": mutate(("sites", 1, "arguments", 0, "string"), '"x"'),
            "string without source": mutate(("sites", 1, "arguments", 1, "string_source"), None),
            "unknown source": mutate(("sites", 1, "arguments", 1, "string_source"), "guess"),
            "variable on constant": mutate(("sites", 1, "arguments", 0, "variable"), "x"),
            "long string": mutate(("sites", 1, "arguments", 1, "string"), '"' + "a" * 200 + '"'),
            "control text": mutate(("sites", 1, "statement"), "callee(\n)"),
            "c1 control text": mutate(("sites", 1, "statement"), "callee(\x85)"),
            "empty statement": mutate(("sites", 1, "statement"), ""),
            "long statement": mutate(("sites", 1, "statement"), "x" * 1025),
            "truncated arguments": mutate(("sites", 1, "arguments_truncated"), True),
            "digest": mutate(("sites", 1, "instruction_sha256"), "AB" * 32),
            "target not listed": mutate(("sites", 1, "target_address"), "2000"),
            "address prefix": mutate(("sites", 1, "address"), "0x100a"),
            "two roots": mutate(("targets", 1, "thunk"), False),
            "root not first": mutate(("targets",), list(reversed(_report()["targets"]))),
            "selected not target": mutate(("function",), _function(0x2000, "other")),
        }
        duplicate = _report()
        duplicate["sites"].append(copy.deepcopy(duplicate["sites"][1]))
        duplicate["call_references"] = 6
        cases["duplicate site"] = duplicate
        over = _report()
        over["site_limit"] = 4
        cases["over the site limit"] = over
        for name, document in cases.items():
            with self.subTest(name), self.assertRaises(CallSitesReportError):
                parse_call_sites_report(document)

    def test_strict_json(self):
        text = _encode(_report())
        for bad in ('{"schema_version": 1, "schema_version": 1}', text.replace('"revision": 7', '"revision": NaN'),
                    text.replace('"revision": 7', '"revision": ' + "9" * 30), "[", b"\xff"):
            with self.subTest(bad=str(bad)[:40]), self.assertRaises(CallSitesReportError):
                decode_call_sites_report(bad)
        with self.assertRaises(CallSitesReportError):
            decode_call_sites_report(b" " * (8 * 1024 * 1024 + 1))

    def test_argument_limit_is_exact(self):
        document = _report()
        document["sites"][1]["arguments"] = [_argument(index, "constant", index) for index in range(MAX_ARGUMENTS)]
        document["sites"][1]["arguments_truncated"] = True
        self.assertTrue(parse_call_sites_report(document).sites[1].arguments_truncated)
        document["sites"][1]["arguments"].append(_argument(MAX_ARGUMENTS, "constant", 1))
        with self.assertRaises(CallSitesReportError):
            parse_call_sites_report(document)

    def test_seeded_mutation_fuzz_only_raises_report_errors(self):
        """Random edits either decode to a consistent report or raise CallSitesReportError."""
        values = [None, True, False, 0, -1, 1 << 70, "", "x", "ram", "1080", "zz", [], {}, [1], {"a": 1},
                  "decompiled", "constant", "address", "unknown", "CALL", '"s"', "a" * 2000]
        for seed in range(60):
            generator = random.Random(seed)
            for _ in range(40):
                document = _report()
                for _ in range(generator.randint(1, 4)):
                    _mutate(document, generator, values)
                try:
                    report = decode_call_sites_report(json.dumps(document))
                except CallSitesReportError:
                    continue
                except Exception as unexpected:  # pragma: no cover - the failure being searched for
                    self.fail(f"seed {seed}: {type(unexpected).__name__}: {unexpected}")
                self.assertLessEqual(len(report.sites), report.site_limit)
                self.assertTrue(len(report.sites) == report.call_references or report.truncated)
                for site in report.sites:
                    self.assertEqual(site.caller is None, site.status == "no_function")
                    if site.status != "decompiled":
                        self.assertEqual((site.statement, site.arguments), (None, ()))
                    for argument in site.arguments:
                        self.assertIsInstance(argument.render(), str)


_DELETE = object()


def _mutate(node, generator: random.Random, values: list) -> None:
    """Replace, delete or duplicate one randomly chosen value somewhere in the document."""
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


class CallSitesCliTests(unittest.TestCase):
    def run_cli(self, *argv: str) -> int:
        with redirect_stderr(io.StringIO()):
            try:
                return decompile_main(list(argv))
            except SystemExit as stop:
                return stop.code

    def test_options_are_checked_before_opening_a_program(self):
        base = ("missing.gpr", "/program")
        self.assertEqual(self.run_cli(*base, "--list", "--call-sites"), 2)
        self.assertEqual(self.run_cli(*base, "main", "--max-sites", "5"), 2)
        self.assertEqual(self.run_cli(*base, "main", "--max-callers", "5"), 2)
        for bad in ("0", "1025", "x", "-3", "1.5"):
            with self.subTest(bad=bad):
                self.assertEqual(self.run_cli(*base, "main", "--call-sites", "--max-sites", bad), 2)
        self.assertEqual(self.run_cli(*base, "main", "--call-sites", "--max-callers", "257"), 2)


if __name__ == "__main__":
    unittest.main()
