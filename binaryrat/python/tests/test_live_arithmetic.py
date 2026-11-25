"""Selected arithmetic explanations on real x86-64 and AArch64 Listings.

Apache-2.0; Copyright 2026 YurilLAB.
"""

from contextlib import ExitStack
import json
import os
from pathlib import Path
from random import Random
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from binaryrat import Address, PcodeVarnode, StaleProgramError, open_program


_INSTALL = os.environ.get("BINARYRAT_GHIDRA_INSTALL_DIR")
_MASK = (1 << 64) - 1


def _ram(offset):
    return Address("ram", offset)


def _register(view, name):
    reg = view._program.getLanguage().getRegister(name)
    return PcodeVarnode(Address("register", int(reg.getAddress().getOffset())), reg.getNumBytes())


@unittest.skipUnless(_INSTALL or os.environ.get("BINARYRAT_REQUIRE_SHARED_SERVICE") == "1",
                     "set BINARYRAT_GHIDRA_INSTALL_DIR for live arithmetic checks")
class LiveArithmeticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import pyghidra

        if not _INSTALL:
            raise AssertionError("required arithmetic checks need BINARYRAT_GHIDRA_INSTALL_DIR")
        pyghidra.start(install_dir=Path(_INSTALL).resolve())
        from ghidra.app.util.opinion import BinaryLoader
        from ghidra.program.flatapi import FlatProgramAPI
        from java.lang import Object

        directory = TemporaryDirectory(prefix="binaryrat-arithmetic-")
        cls.addClassCleanup(directory.cleanup)
        cls.marker = Path(directory.name) / "arithmetic.gpr"
        # LLVM MC 19.1.7: MOV RAX,RCX; ADD RAX,RDX; SUB RAX,9; XOR RAX,R8;
        # AND RAX,RDX; OR RAX,7; RET. x86 ADD also writes arithmetic flags.
        x86 = bytearray.fromhex("4889c8 4801d0 4883e809 4c31c0 4821d0 4883c807 c3")
        x86.extend(bytes(32 - len(x86)))
        # AL is a partial write to RAX. The second snippet contains an unrelated load.
        x86.extend(bytes.fromhex("b001 4883c001 c3 4d8b0a 4883c001 c3"))
        x86.extend(bytes(64 - len(x86)))
        x86.extend(bytes.fromhex("4889d1 4889ca") * 16 + bytes.fromhex("4889c8 c3"))
        x86.extend(bytes(192 - len(x86)))
        x86.extend(bytes.fromhex("4889c8 4801d0 c3"))
        x86.extend(bytes(208 - len(x86)) + bytes.fromhex("00c8 c3"))  # ADD AL,CL; RET
        # x0 = x1+x2; x0 -= 9; x0 ^= x3; x0 &= x2; x0 |= 7; ret
        arm = bytes.fromhex("2000028b 002400d1 000003ca 0000028a 000840b2 c0035fd6")
        # (x1+9)-5, x1+4, and x1+5; each snippet ends with its own return.
        arm += bytes.fromhex("20240091 001400d1 c0035fd6 20100091 c0035fd6 20140091 c0035fd6")
        arm += bytes.fromhex("2000020b c0035fd6")  # ADD W0,W1,W2; RET
        with ExitStack() as opened:
            project = pyghidra.open_project(cls.marker.parent, cls.marker.stem, create=True)
            opened.callback(project.close)
            for name, language, image, entries in (
                ("x86", "x86:LE:64:default", bytes(x86), (0, 32, 39, 64, 192, 208)),
                ("arm", "AARCH64:LE:64:v8A", arm, (0, 24, 36, 44, 52)),
            ):
                source = cls.marker.parent / (name + ".bin")
                source.write_bytes(image)
                with ExitStack() as imported:
                    loaded = (pyghidra.program_loader().source(str(source)).name(name)
                              .loaders(BinaryLoader.class_).language(language).project(project)
                              .projectFolderPath("/").load())
                    imported.callback(loaded.close)
                    consumer = Object()
                    program = loaded.getPrimaryDomainObject(consumer)
                    imported.callback(program.release, consumer)
                    api = FlatProgramAPI(program)
                    with pyghidra.transaction(program, "Decode arithmetic examples"):
                        for offset in entries:
                            if not api.disassemble(program.getMinAddress().add(offset)):
                                raise AssertionError(f"could not disassemble {name} at {offset}")
                        if name == "x86":
                            instruction = api.getInstructionAt(program.getMinAddress().add(192))
                            instruction.setFallThrough(program.getMinAddress().add(198))
                    loaded.save(pyghidra.task_monitor())

    def test_expressions_match_independent_modular_arithmetic(self):
        rng = Random(0xB17A2)
        samples = [(0, 0, 0), (_MASK, 1, 1 << 63), (1 << 63, 1 << 63, _MASK),
                   (0, _MASK, 0), (0x80000000, 0x80000000, 7)]
        samples.extend(tuple(rng.getrandbits(64) for _ in range(3)) for _ in range(64))
        for name, dest, inputs, writers in (
            ("x86", "RAX", ("RCX", "RDX", "R8"), (0, 3, 6, 10, 13, 16)),
            ("arm", "x0", ("x1", "x2", "x3"), (0, 4, 8, 12, 16)),
        ):
            with self.subTest(isa=name), open_program(self.marker, "/" + name) as view:
                revision = view._program.getModificationNumber()
                expr = view.explain_arithmetic(_ram(0), _ram(writers[-1]), dest)
                keys = [_register(view, reg) for reg in inputs]
                self.assertEqual(expr.target, _register(view, dest))
                self.assertEqual({n.register for n in expr.nodes if n.op == "INPUT"}, set(keys))
                sources = {n.site for n in expr.nodes if n.site is not None}
                self.assertEqual(sources, {_ram(start) for start in writers})
                for a, b, c in samples:
                    expected = ((((a + b - 9) & _MASK) ^ c) & b) | 7
                    self.assertEqual(expr.evaluate(dict(zip(keys, (a, b, c)))), expected)
                self.assertEqual(view._program.getModificationNumber(), revision)

    def test_whole_range_boundaries_and_unsupported_effects(self):
        from binaryrat.arithmetic import ArithmeticRefusal

        with open_program(self.marker, "/x86") as view:
            for start, end, name in ((1, 3, "RAX"), (0, 4, "RAX"), (6, 3, "RAX"),
                                     (21, 24, "RAX"), (0, 3, "missing_register")):
                with self.subTest(start=start, end=end, name=name), self.assertRaises(ValueError):
                    view.explain_arithmetic(_ram(start), _ram(end), name)
            for start, end in ((0, 20), (32, 34), (39, 42), (192, 195), (64, 160)):
                with self.subTest(start=start, end=end), self.assertRaises(ArithmeticRefusal):
                    view.explain_arithmetic(_ram(start), _ram(end), "RAX")
            with self.assertRaises(ArithmeticRefusal):
                view.explain_arithmetic(_ram(0), _ram(3), "RIP")

    def test_concrete_pcode_replay_agrees_on_selected_register(self):
        from ghidra.app.emulator import EmulatorHelper
        from ghidra.util.task import TaskMonitor
        from java.math import BigInteger

        for name, dest, inputs, instructions in (
            ("x86", "RAX", ("RCX", "RDX", "R8"), 6),
            ("arm", "x0", ("x1", "x2", "x3"), 5),
        ):
            with self.subTest(isa=name), open_program(self.marker, "/" + name) as view:
                expr = view.explain_arithmetic(_ram(0), _ram(16), dest)
                with ExitStack() as cleanup:
                    emu = EmulatorHelper(view._program)
                    cleanup.callback(emu.dispose)
                    for values in ((_MASK, 1, 1 << 63), (0x123456785a, 0xabcdef04044, 0xfffffffe)):
                        emu.writeRegister(emu.getPCRegister(), BigInteger.ZERO)
                        for reg, value in zip(inputs, values):
                            emu.writeRegister(reg, BigInteger(str(value)))
                        for _ in range(instructions):
                            self.assertTrue(emu.step(TaskMonitor.DUMMY), str(emu.getLastError()))
                        self.assertEqual(emu.getExecutionAddress().getOffset(), 20)
                        bindings = {_register(view, reg): value for reg, value in zip(inputs, values)}
                        self.assertEqual(int(str(emu.readRegister(dest))) & _MASK, expr.evaluate(bindings))

    def test_narrow_add_and_register_alias_names(self):
        with open_program(self.marker, "/x86") as view:
            instruction = _ram(208)
            expr = view.explain_arithmetic(instruction, instruction, "AL")
            al, cl = _register(view, "AL"), _register(view, "CL")
            for a in range(256):
                for b in range(256):
                    self.assertEqual(expr.evaluate({al: a, cl: b}), (a + b) & 255)
            for width, name in ((8, "RAX"), (4, "EAX"), (3, None)):
                self.assertEqual(view.register_name(PcodeVarnode(al.address, width)), name)
            self.assertIsNone(view.register_name(PcodeVarnode(Address("const", 0), 8)))
            with self.assertRaises(ValueError):
                view.register_name(PcodeVarnode(al.address, 0))
        with open_program(self.marker, "/arm") as view:
            instruction = _ram(52)
            expr = view.explain_arithmetic(instruction, instruction, "x0")
            w1, w2 = _register(view, "w1"), _register(view, "w2")
            for left, right in ((0xffffffff, 1), (0x7fffffff, 1), (0xffffffff, 0xffffffff)):
                self.assertEqual(expr.evaluate({w1: left, w2: right}), (left + right) & 0xffffffff)

    def test_optional_proof_uses_actual_selected_ranges(self):
        from binaryrat.arithmetic_proof import prove_equivalence

        with open_program(self.marker, "/arm") as view:
            two_ops = view.explain_arithmetic(_ram(24), _ram(28), "x0")
            plus_four = view.explain_arithmetic(_ram(36), _ram(36), "x0")
            plus_five = view.explain_arithmetic(_ram(44), _ram(44), "x0")
            x1 = _register(view, "x1")
        proof = prove_equivalence(two_ops, plus_four, timeout_ms=5000)
        if proof.status == "unavailable" and os.environ.get("BINARYRAT_REQUIRE_Z3") != "1":
            self.assertTrue(proof.reason)
            return
        self.assertEqual(proof.status, "proved", proof.reason)
        changed = prove_equivalence(two_ops, plus_five, timeout_ms=5000)
        self.assertEqual(changed.status, "different", changed.reason)
        witness = dict(changed.witness)
        self.assertEqual(set(witness), {x1})
        self.assertEqual(changed.left_value, (witness[x1] + 4) & _MASK)
        self.assertEqual(changed.right_value, (witness[x1] + 5) & _MASK)

    def test_saved_range_from_cli(self):
        result = subprocess.run([sys.executable, "-m", "binaryrat.arithmetic_cli", str(self.marker),
                                 "/x86", "ram:0", "ram:10", "RAX", "--install-dir", _INSTALL, "--json"],
                                capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr)
        capture = json.loads(result.stdout)
        self.assertEqual(capture["status"], "explained")
        expression = capture["selections"][0]["expression"]
        root = expression["nodes"][expression["root"]]
        self.assertEqual((root["op"], root["site"], root["bits"]), ("INT_OR", "ram:10", 64))
        self.assertEqual({n["register_name"] for n in expression["nodes"] if n["op"] == "INPUT"},
                         {"RCX", "RDX", "R8"})

    def test_program_edit_during_capture_discards_expression(self):
        import pyghidra
        from binaryrat.live import _lift_instruction

        # The second selection ordinarily produces an alias refusal. A concurrent edit
        # takes precedence even when the expression builder cannot publish a result.
        for start, end in ((0, 16), (32, 34)):
            with self.subTest(start=start), open_program(self.marker, "/x86") as view:
                def edit_after_last_lift(*args):
                    instruction = _lift_instruction(*args)
                    if instruction.address == _ram(end):
                        with pyghidra.transaction(view._program, "Rename in memory during review"):
                            view._program.setName("changed")
                    return instruction

                with patch("binaryrat.live._lift_instruction", side_effect=edit_after_last_lift), \
                        self.assertRaises(StaleProgramError):
                    view.explain_arithmetic(_ram(start), _ram(end), "RAX")
        with open_program(self.marker, "/x86") as reopened:
            self.assertEqual(reopened.info.name, "x86.bin")
