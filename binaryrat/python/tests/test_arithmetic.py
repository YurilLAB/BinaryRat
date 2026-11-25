"""Fixed-width semantic and budget checks for detached p-code. Apache-2.0; Copyright 2026 YurilLAB."""

from dataclasses import replace
from random import Random
import unittest

from binaryrat.arithmetic import (
    ArithmeticExpression, ArithmeticRefusal, ExpressionNode, MAX_NODES, build_expression,
)
from binaryrat.live import InstructionPcode, PcodeListing, PcodeOperation, PcodeVarnode
from binaryrat.models import Address


def var(space, offset, size=4):
    return PcodeVarnode(Address(space, offset), size)


def instruction(offset, *steps):
    site = Address("ram", offset)
    ops = [PcodeOperation(op, site, i, output, tuple(inputs), len(inputs))
           for i, (op, output, *inputs) in enumerate(steps)]
    listing = PcodeListing(tuple(ops), len(ops))
    return InstructionPcode(site, 1, 1, "fixture", 42, listing, listing)


class ArithmeticTests(unittest.TestCase):
    def test_shifted_sum_shows_sources_and_register_input_once(self):
        x, y = var("register", 0), var("register", 8)
        flag, tmp = var("register", 16, 1), var("unique", 0)
        code = (
            instruction(0, ("INT_SCARRY", flag, x, y), ("INT_ADD", tmp, x, x), ("COPY", y, tmp)),
            instruction(1, ("INT_SUB", y, y, var("const", 5))),
        )
        expr = build_expression(code, y)
        self.assertEqual([n.op for n in expr.nodes], ["INPUT", "INT_ADD", "COPY", "CONSTANT", "INT_SUB"])
        self.assertEqual([(n.site.offset, n.sequence) for n in expr.nodes if n.site is not None],
                         [(0, 1), (0, 2), (1, 0)])
        self.assertEqual(expr.nodes[1].args, (0, 0))
        for value in (0, 1, 0x7fffffff, 0x80000001, 0xffffffff):
            self.assertEqual(expr.evaluate({x: value}), (2 * value - 5) % (1 << 32))
        for invalid in (-1, 1 << 32, True, 2.5):
            with self.subTest(value=invalid), self.assertRaises(ValueError):
                expr.evaluate({x: invalid})
        with self.assertRaisesRegex(ValueError, "Missing input"):
            expr.evaluate({})
        # The output of an unsupported flag producer can be skipped only off the selected slice.
        with self.assertRaisesRegex(ArithmeticRefusal, "INT_SCARRY at ram:0 p-code 0"):
            build_expression(code, flag)

    def test_extensions_complements_and_constant_widths(self):
        for width in range(1, 8):
            bits = width * 8
            x = var("register", 0, width)
            dest = var("register", 16, width + 1)
            for op in ("INT_ZEXT", "INT_SEXT"):
                expr = build_expression([instruction(0, (op, dest, x))], dest)
                for value in (0, 1, (1 << (bits - 1)) - 1, 1 << (bits - 1), (1 << bits) - 1):
                    signed = int.from_bytes(value.to_bytes(width, "little"), "little", signed=True)
                    expected = value if op == "INT_ZEXT" else signed % (1 << (bits + 8))
                    self.assertEqual(expr.evaluate({x: value}), expected)
        for op, expected in (("INT_2COMP", 1), ("INT_NEGATE", 0)):
            dest = var("register", 16, 1)
            expr = build_expression([instruction(0, (op, dest, var("const", (1 << 64) - 1, 1)))], dest)
            self.assertEqual(expr.evaluate({}), expected)
            self.assertEqual(expr.nodes[0].value, 255)

    def test_range_and_instruction_local_temporaries(self):
        reg, tmp = var("register", 0), var("unique", 0)
        first = instruction(100, ("COPY", tmp, reg))
        read = instruction(101, ("COPY", reg, tmp))
        with self.assertRaisesRegex(ArithmeticRefusal, "instruction-local"):
            build_expression([first, read], reg)
        valid = instruction(101, ("COPY", tmp, var("const", 8)), ("COPY", reg, tmp))
        self.assertEqual(build_expression([first, valid], reg).evaluate({}), 8)
        for problem in (replace(valid, revision=3), replace(valid, parsed_length=2),
                        replace(valid, address=Address("other", 101)), replace(valid, length=0),
                        replace(valid, address=Address("ram", 103))):
            with self.subTest(problem=problem), self.assertRaises(ArithmeticRefusal):
                build_expression([first, problem], reg)
        # An empty effective listing is allowed for an instruction with no semantics.
        self.assertEqual(build_expression([valid, instruction(102)], reg).evaluate({}), 8)
        with self.assertRaisesRegex(ArithmeticRefusal, "no writer"):
            build_expression([instruction(0)], reg)

    def test_memory_control_and_unknown_effects_anywhere(self):
        reg = var("register", 0)
        for mnemonic in ("LOAD", "STORE", "CALL", "RETURN", "BRANCH", "CBRANCH", "CALLOTHER",
                         "BRANCHIND", "INDIRECT", "UNIMPLEMENTED", "FUTURE_OPCODE"):
            block = instruction(0, ("COPY", reg, var("const", 1)), (mnemonic, reg, reg))
            with self.subTest(mnemonic=mnemonic), self.assertRaisesRegex(ArithmeticRefusal, "effect"):
                build_expression([block], reg)
        for bad in (("COPY", var("ram", 0), reg), ("COPY", var("unique", 1), var("overlay", 15)),
                    ("COPY", var("const", 14), reg), ("INT_ADD", reg, reg, None),
                    ("COPY", None, reg)):
            with self.subTest(step=bad), self.assertRaisesRegex(ArithmeticRefusal, "space"):
                build_expression([instruction(0, ("COPY", reg, reg), bad)], reg)
        # Only the effective listing is used.
        clean = instruction(0, ("COPY", reg, var("const", 5)))
        raw = instruction(0, ("COPY", reg, var("const", 7)))
        self.assertEqual(build_expression([replace(clean, raw=raw.raw)], reg).evaluate({}), 5)

    def test_aliases_and_overwritten_values(self):
        full, part, middle = var("register", 0), var("register", 0, 2), var("register", 1, 2)
        dest = var("register", 16)
        with self.assertRaisesRegex(ArithmeticRefusal, "overlapping write"):
            build_expression([instruction(0, ("COPY", full, var("const", 9)),
                                           ("COPY", part, var("const", 4, 2)))], full)
        with self.assertRaisesRegex(ArithmeticRefusal, "overlapping write"):
            build_expression([instruction(0, ("COPY", full, var("const", 9)),
                                           ("INT_ZEXT", dest, middle))], dest)
        with self.assertRaisesRegex(ArithmeticRefusal, "Overlapping input"):
            build_expression([instruction(0, ("INT_ZEXT", dest, middle), ("INT_ADD", dest, full, dest))], dest)
        # A newer complete definition kills the irrelevant partial write and unknown pure producer.
        good = instruction(0, ("INT_MULT", full, full, full), ("COPY", part, var("const", 4, 2)),
                           ("COPY", full, var("const", 7)), ("INT_ADD", dest, full, full))
        self.assertEqual(build_expression([good], dest).evaluate({}), 14)
        # Half-open byte intervals: a neighbouring write does not alias the selected value.
        neighbour = var("register", 4, 8)
        self.assertEqual(build_expression([instruction(0, ("COPY", full, var("const", 5)),
                                                      ("COPY", neighbour, var("const", 3, 8)))], full).evaluate({}), 5)

    def test_refuses_truncation_inconsistent_metadata_and_invalid_shapes(self):
        target = var("register", 0)
        ins = instruction(0, ("COPY", target, var("const", 1)))
        op = ins.effective.operations[0]
        for listing in (PcodeListing((op,), 2), PcodeListing((replace(op, input_count=2),), 1),
                        PcodeListing((op, op), 2), PcodeListing((replace(op, site=Address("ram", 3)),), 1)):
            with self.subTest(listing=listing), self.assertRaises(ArithmeticRefusal):
                build_expression([replace(ins, effective=listing)], target)
        for step in (("INT_ZEXT", target, var("const", 1)), ("INT_SEXT", target, var("const", 1, 8)),
                     ("INT_ADD", target, target, var("register", 8, 1)), ("INT_SUB", target, target)):
            with self.subTest(step=step), self.assertRaisesRegex(ArithmeticRefusal, "widths"):
                build_expression([instruction(0, step)], target)
        for bad in (var("register", (1 << 64) - 1), var("register", 0, 9), var("unique", 0)):
            with self.subTest(bad=bad), self.assertRaises(ArithmeticRefusal):
                build_expression([ins], bad)

    def test_limits_apply_including_off_slice_operations(self):
        reg = var("register", 0)
        copy = ("COPY", reg, reg)
        seq = [instruction(i, *([copy] * 32)) for i in range(7)]
        expr = build_expression(seq + [instruction(7, *([copy] * 31))], reg)
        self.assertEqual(len(expr.nodes), MAX_NODES)
        self.assertEqual(expr.evaluate({reg: 7}), 7)
        with self.assertRaisesRegex(ArithmeticRefusal, "nodes"):
            build_expression(seq + [instruction(7, *([copy] * 32))], reg)
        with self.assertRaisesRegex(ArithmeticRefusal, "operation limit"):
            build_expression(seq + [instruction(7, *([copy] * 33))], reg)
        with self.assertRaisesRegex(ArithmeticRefusal, "contiguous instructions"):
            build_expression([instruction(i, copy) for i in range(33)], reg)

    def test_hand_built_expressions_validate_their_topology_and_constants(self):
        target = var("register", 0)
        value = ExpressionNode("CONSTANT", 4, value=2)
        for nodes, root in (((value, value), 1), ((value, ExpressionNode("COPY", 4, (2,))), 1),
                            ((replace(value, size=10),), 0), ((replace(value, value=1 << 32),), 0),
                            ((ExpressionNode("NEW_OPCODE", 4, ()),), 0), ((value,), 2)):
            with self.subTest(nodes=nodes, root=root), self.assertRaises(ArithmeticRefusal):
                ArithmeticExpression(nodes, root, target)
        self.assertEqual(ArithmeticExpression((value,), 0, target).evaluate({}), 2)

    def test_language_identity_is_retained_for_proof_and_rejects_invalid_metadata(self):
        target = var("register", 8)
        code = [instruction(0, ("COPY", target, var("const", 42)))]
        for lang in ("x86:LE:64:default", "AARCH64:LE:64:v8A", None):
            self.assertEqual(build_expression(code, target, language_id=lang).language_id, lang)
        for invalid in ("", "a" * 257, "two lines\nhere", "tab\there", "\u0085", 1):
            with self.subTest(lang=invalid), self.assertRaisesRegex(ArithmeticRefusal, "language ID"):
                build_expression(code, target, language_id=invalid)

    def test_seeded_straight_line_register_programs_match_concrete_reference(self):
        # Maps mutable registers to independent Python integer results while generating the
        # sequence. Each input has a distinct byte range, and multiple ops may rewrite it.
        rng = Random(0xB17A)
        for case in range(256):
            size = rng.randrange(1, 9)
            registers = [var("register", 8 * i, size) for i in range(4)]
            inputs = {reg: rng.getrandbits(size * 8) for reg in registers}
            expected = dict(inputs)
            code = []
            for site in range(rng.randint(1, 8)):
                steps = []
                for _ in range(rng.randint(1, 4)):
                    dest, left, right = rng.choices(registers, k=3)
                    op = rng.choice(("INT_ADD", "INT_SUB", "INT_AND", "INT_XOR", "INT_OR"))
                    right_value = expected[right]
                    if rng.randrange(2):
                        right_value = rng.getrandbits(size * 8)
                        right = var("const", right_value, size)
                    x = expected[left]
                    values = {"INT_ADD": x + right_value, "INT_SUB": x - right_value,
                              "INT_AND": x & right_value, "INT_OR": x | right_value, "INT_XOR": x ^ right_value}
                    expected[dest] = values[op] % (1 << (8 * size))
                    steps.append((op, dest, left, right))
                code.append(instruction(site, *steps))
            with self.subTest(seed=0xB17A, case=case):
                expr = build_expression(code, dest)
                self.assertEqual(expr.evaluate(inputs), expected[dest])


if __name__ == "__main__":
    unittest.main()
