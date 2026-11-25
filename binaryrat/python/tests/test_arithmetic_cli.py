"""Register arithmetic command output and exit statuses. Apache-2.0; Copyright 2026 YurilLAB."""

from concurrent.futures import CancelledError
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from binaryrat.arithmetic import ArithmeticRefusal, build_expression
from binaryrat.arithmetic_cli import main
from binaryrat.live import InstructionPcode, PcodeListing, PcodeOperation, PcodeVarnode, ProgramInfo
from binaryrat.models import Address


_BASE = ["arith.gpr", "/add", "overlay:1004", "overlay:1004", "RAX"]
_REG = PcodeVarnode(Address("register", 0), 8)


class View:
    info = ProgramInfo("add", "/add", "ab" * 32, "x86:LE:64:default", "gcc", Address("ram", 0), 12)

    def __init__(self):
        self.calls = []

    def register_name(self, storage):
        return "RAX" if storage == _REG else None

    def explain_arithmetic(self, start, end, register):
        self.calls.append((start, end, register))
        immediate = PcodeVarnode(Address("const", (1 << 64) - 1), 8)
        op = PcodeOperation("INT_ADD", start, 3, _REG, (_REG, immediate), 2)
        listing = PcodeListing((op,), 1)
        instruction = InstructionPcode(start, 3, 3, "ADD", self.info.revision, listing, listing)
        return build_expression([instruction], _REG)


class ArithmeticCommandTests(unittest.TestCase):
    def setUp(self):
        self.view = View()
        self.active = False

        @contextmanager
        def opened(*args, **kwargs):
            self.assertEqual(kwargs["backend"], "stock")
            self.active = True
            try:
                yield self.view
            finally:
                self.active = False

        patcher = patch("binaryrat.arithmetic_cli.open_program", side_effect=opened)
        self.enter = patcher.start()
        self.addCleanup(patcher.stop)

    def invoke(self, args):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            code = main(args)
        return code, output.getvalue(), errors.getvalue()

    def test_json_preserves_evidence_and_uint64_values(self):
        code, output, errors = self.invoke([*_BASE, "--json"])
        self.assertEqual((code, errors), (0, ""))
        report = json.loads(output)
        self.assertEqual((report["program"], report["sha256"], report["revision"], report["language_id"],
                          report["compiler_spec_id"], report["status"]),
                         ("/add", "ab" * 32, 12, "x86:LE:64:default", "gcc", "explained"))
        self.assertEqual(self.view.calls, [(Address("overlay", 0x1004), Address("overlay", 0x1004), "RAX")])
        selection, = report["selections"]
        self.assertEqual((selection["start"], selection["end"]), ("overlay:1004", "overlay:1004"))
        expr = selection["expression"]
        target = expr["nodes"][expr["root"]]
        self.assertEqual((target["op"], target["bits"], target["site"], target["sequence"]),
                         ("INT_ADD", 64, "overlay:1004", 3))
        left, right = [expr["nodes"][index] for index in target["args"]]
        self.assertEqual((left["register_name"], left["register"], right["value"]),
                         ("RAX", "register:0", "0xffffffffffffffff"))
        code, output, errors = self.invoke(_BASE)
        self.assertEqual((code, errors), (0, ""))
        self.assertIn("INT_ADD(", output)
        self.assertIn("input RAX register:0", output)
        self.assertIn("overlay:1004, p-code 3", output)
        self.assertIn("register:0 (64 bits)", output)

    def test_compares_inside_one_view_and_releases_it_before_proof(self):
        for status, code in (("proved", 0), ("different", 1), ("unknown", 3), ("unavailable", 3)):
            with self.subTest(status=status):
                def checked(left, right, *, timeout_ms):
                    self.assertFalse(self.active)
                    self.assertEqual(timeout_ms, 10)
                    return SimpleNamespace(status=status, reason="test result", solver_version="test",
                                           witness=((_REG, 0),), left_value=1, right_value=2)

                self.enter.reset_mock()
                self.view.calls.clear()
                with patch("binaryrat.arithmetic_cli.prove_equivalence", side_effect=checked):
                    result, output, errors = self.invoke([*_BASE, "--compare", "0x0", "0", "RAX",
                                                          "--timeout-ms", "10", "--json"])
                self.enter.assert_called_once()
                self.assertEqual(self.view.calls[-1], (Address("ram", 0), Address("ram", 0), "RAX"))
                self.assertEqual((result, errors), (code, ""))
                report = json.loads(output)
                self.assertEqual((len(report["selections"]), report["status"]), (2, status))
                if status == "different":
                    self.assertEqual((report["left_value"], report["right_value"]), ("0x1", "0x2"))
                    self.assertEqual(report["witness"], [{"register": "register:0", "register_name": "RAX",
                                                          "bits": 64, "value": "0x0"}])
                else:
                    self.assertNotIn("witness", report)

    def test_refusal_is_distinct_from_missing_input_and_never_starts_a_proof(self):
        with patch.object(self.view, "explain_arithmetic", side_effect=ArithmeticRefusal("control transfer")), \
                patch("binaryrat.arithmetic_cli.prove_equivalence") as proof:
            code, output, errors = self.invoke([*_BASE, "--compare", "10", "11", "RAX", "--json"])
        self.assertEqual((code, errors), (3, ""))
        self.assertEqual(json.loads(output)["status"], "unsupported")
        self.assertIn("control transfer", json.loads(output)["reason"])
        proof.assert_not_called()
        with patch.object(self.view, "explain_arithmetic", side_effect=CancelledError):
            self.assertEqual(self.invoke(_BASE), (130, "", ""))

    def test_subprocess_input_errors_have_no_partial_stdout(self):
        with TemporaryDirectory() as temp:
            missing = str(Path(temp) / "absent.gpr")
            for args, message in (([missing, "/add", "0", "0", "RAX"], "absent.gpr"),
                                  ([missing, "/add", "expr(x)", "0", "RAX"], "instruction address"),
                                  ([*_BASE, "--compare", "1", "0x10000000000000000", "RAX"], "address"),
                                  ([*_BASE, "--timeout-ms", "1"], "--timeout-ms requires")):
                with self.subTest(args=args):
                    result = subprocess.run([sys.executable, "-m", "binaryrat.arithmetic_cli", *args],
                                            text=True, capture_output=True, timeout=20)
                    self.assertEqual((result.returncode, result.stdout), (2, ""))
                    self.assertIn(message, result.stderr)
                    self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
