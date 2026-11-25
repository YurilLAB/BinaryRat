"""Decision, replay and budget checks for arithmetic proofs. Apache-2.0; Copyright 2026 YurilLAB."""
import os
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import subprocess
import unittest
from unittest.mock import patch

from binaryrat.arithmetic import ArithmeticExpression, ExpressionNode
from binaryrat.arithmetic_proof import _installed_solver, _model_values, prove_equivalence
from binaryrat.live import PcodeVarnode
from binaryrat.models import Address


def register(offset, size):
    return PcodeVarnode(Address("register", offset), size)


def node(op, size, *args, value=None, reg=None):
    return ExpressionNode(op=op, size=size, args=args, value=value, register=reg, site=None, sequence=None)


def expression(*nodes):
    return ArithmeticExpression(nodes=tuple(nodes), root=len(nodes) - 1, target=register(0x100, nodes[-1].size))


def literal(value, size=1):
    return expression(node("CONSTANT", size, value=value))


def add_constant(amount, size):
    return expression(node("INPUT", size, reg=register(0, size)), node("CONSTANT", size, value=amount),
                      node("INT_ADD", size, 0, 1))


class ProofBoundaryTests(unittest.TestCase):
    def test_windows_runtime_path_belongs_to_wheel_and_is_private_to_solver(self):
        with TemporaryDirectory(prefix="proof wheel ") as temporary:
            root = Path(temporary).resolve()
            files = [Path("data/bin/z3.exe"), Path("z3/lib/msvcp140.dll"), Path("data/bin/z3")]
            for item in files:
                (root / item).parent.mkdir(parents=True, exist_ok=True)
                (root / item).touch()
            dist = SimpleNamespace(files=files, version="4.13.0.0", locate_file=root.joinpath)
            with patch("binaryrat.arithmetic_proof.metadata.distribution", return_value=dist), \
                 patch.dict(os.environ, {"PATH": "parent-toolchain", "BINARYRAT_PARENT": "kept"}):
                for platform, name in (("win32", "z3.exe"), ("linux", "z3")):
                    with self.subTest(platform=platform), patch("sys.platform", platform), \
                         patch("binaryrat.arithmetic_proof.subprocess.run",
                               return_value=subprocess.CompletedProcess([], 0, b"unsat\n", b"")) as run:
                        result = prove_equivalence(literal(1), literal(1))
                        self.assertEqual(result.status, "proved")
                        command, = run.call_args.args
                        self.assertEqual(command[0], str(root / "data/bin" / name))
                        child = run.call_args.kwargs["env"]
                        if platform == "win32":
                            self.assertEqual(child["PATH"], str(root / "z3/lib") + os.pathsep + "parent-toolchain")
                            self.assertEqual(child["BINARYRAT_PARENT"], "kept")
                        else:
                            self.assertIsNone(child)
                        self.assertEqual(os.environ["PATH"], "parent-toolchain")

    def test_missing_backend(self):
        with patch("binaryrat.arithmetic_proof._installed_solver", return_value=None):
            result = prove_equivalence(literal(4), literal(4))
        self.assertEqual(result.status, "unavailable")
        self.assertIsNone(result.solver_version)

    def test_unsupported_solver_version_never_starts(self):
        with patch("binaryrat.arithmetic_proof._installed_solver", return_value=(Path("z3"), "5.0", None)), \
             patch("binaryrat.arithmetic_proof._query", side_effect=AssertionError("launched solver")):
            result = prove_equivalence(literal(0), literal(0))
        self.assertEqual(result.status, "unavailable")
        self.assertIn("4.13.0.0", result.reason)
        self.assertEqual(result.solver_version, "5.0")

    def test_physical_register_map_must_agree(self):
        value = add_constant(4, 8)
        left = replace(value, language_id="x86:LE:64:default")
        arm = replace(value, language_id="AARCH64:LE:64:v8A")
        with patch("binaryrat.arithmetic_proof._installed_solver", side_effect=AssertionError("launched solver")):
            for right in (arm, value):
                with self.subTest(language=right.language_id):
                    self.assertEqual(prove_equivalence(left, right).status, "unknown")

    def test_declines_partial_register_aliases_across_expressions(self):
        left = expression(node("INPUT", 2, reg=register(0, 2)))
        right = expression(node("INPUT", 1, reg=register(1, 1)), node("INT_ZEXT", 2, 0))
        with patch("binaryrat.arithmetic_proof._installed_solver", side_effect=AssertionError("launched solver")):
            result = prove_equivalence(left, right)
            self.assertEqual(result.status, "unknown")
            self.assertIn("overlap", result.reason)
            self.assertEqual(prove_equivalence(left, literal(0)).status, "unknown")

    def test_timeout_and_invalid_budget(self):
        with patch("binaryrat.arithmetic_proof._installed_solver", return_value=(Path("z3"), "4.13.0.0", None)), \
             patch("binaryrat.arithmetic_proof.subprocess.run", side_effect=subprocess.TimeoutExpired("z3", 1)):
            self.assertEqual(prove_equivalence(literal(0), literal(1)).status, "unknown")
        for value in (0, 10_001, True, 1.5):
            with self.subTest(timeout_ms=value), self.assertRaises(ValueError):
                prove_equivalence(literal(0), literal(1), timeout_ms=value)

    def test_sat_requires_validated_counterexample_and_outputs(self):
        left, right = add_constant(1, 1), add_constant(2, 1)
        invalid = (
            ["unknown"],
            ["sat", "((r0 #x00) (a2 #x01))"],
            ["sat", "((r0 #x00) (a2 #x11) (b2 #x02))"],
            ["sat", "((r0 #x00) (a2 #x01) (b2 #x01))"],
        )
        for response in invalid:
            with self.subTest(response=response), \
                 patch("binaryrat.arithmetic_proof._installed_solver", return_value=(Path("z3"), "4.13.0.0", None)), \
                 patch("binaryrat.arithmetic_proof._query", side_effect=[["sat"], response]):
                result = prove_equivalence(left, right)
                self.assertEqual(result.status, "unknown")
                self.assertEqual(result.witness, ())

    def test_model_needs_exact_width_unique_known_names_and_complete_input(self):
        for response in ("((r0 #x1234))", "((r0 #x03) (r0 #x04))", "((r1 #xFF))",
                         "((r0 #x00)) garbage", "(r0 #x01)", "()", "((r0 #xzz))"):
            with self.subTest(response=response), self.assertRaises(ValueError):
                _model_values([response], {"r0": 1})
        self.assertEqual(_model_values(["((r1 #x0102)", " (r0 #xff))"], {"r0": 1, "r1": 2}),
                         {"r0": 255, "r1": 258})


class RealZ3Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        installed = _installed_solver()
        if installed is None or installed[1] != "4.13.0.0":
            if os.getenv("BINARYRAT_REQUIRE_Z3") == "1":
                raise AssertionError("required proof checks need the binaryrat[proof] extra")
            raise unittest.SkipTest("install binaryrat[proof] to run the native Z3 checks")

    def test_wraparound_identity_and_wrong_constant(self):
        for size in (1, 2, 4, 8):
            with self.subTest(size=size):
                x = node("INPUT", size, reg=register(0, size))
                left = expression(x, node("CONSTANT", size, value=9), node("INT_ADD", size, 0, 1),
                                  node("CONSTANT", size, value=5), node("INT_SUB", size, 2, 3))
                self.assertEqual(prove_equivalence(left, add_constant(4, size), timeout_ms=5000).status, "proved")
                result = prove_equivalence(left, add_constant(5, size), timeout_ms=5000)
                self.assertEqual(result.status, "different", result.reason)
                self.assertEqual(left.evaluate(dict(result.witness)), result.left_value)
                self.assertNotEqual(result.left_value, result.right_value)

    def test_disjoint_inputs_can_differ_and_identical_inputs_are_shared(self):
        x = expression(node("INPUT", 4, reg=register(0, 4)))
        y = expression(node("INPUT", 4, reg=register(4, 4)))
        self.assertEqual(prove_equivalence(x, x, timeout_ms=5000).status, "proved")
        result = prove_equivalence(x, y, timeout_ms=5000)
        self.assertEqual(result.status, "different", result.reason)
        self.assertEqual([reg for reg, _ in result.witness], [register(0, 4), register(4, 4)])
        self.assertEqual(result.left_value, x.evaluate(dict(result.witness)))
        self.assertEqual(result.right_value, y.evaluate(dict(result.witness)))
        self.assertNotEqual(result.left_value, result.right_value)

    def test_operations_against_constants(self):
        cases = (("INT_ADD", 255, 3, 2), ("INT_SUB", 0, 1, 255), ("INT_AND", 3, 5, 1),
                 ("INT_OR", 3, 5, 7), ("INT_XOR", 3, 5, 6), ("COPY", 129, None, 129),
                 ("INT_NEGATE", 129, None, 126), ("INT_2COMP", 129, None, 127),
                 ("INT_ZEXT", 255, None, 255), ("INT_SEXT", 255, None, 65535))
        for op, a, b, expected in cases:
            with self.subTest(op=op):
                size = 2 if op in ("INT_ZEXT", "INT_SEXT") else 1
                nodes = [node("CONSTANT", 1, value=a)]
                if b is not None:
                    nodes.append(node("CONSTANT", 1, value=b))
                left = expression(*nodes, node(op, size, *range(len(nodes))))
                result = prove_equivalence(left, literal(expected, size), timeout_ms=5000)
                self.assertEqual(result.status, "proved", result.reason)
        result = prove_equivalence(literal(1), literal(2), timeout_ms=5000)
        self.assertEqual((result.status, result.witness, result.left_value, result.right_value),
                         ("different", (), 1, 2))


if __name__ == "__main__":
    unittest.main()
