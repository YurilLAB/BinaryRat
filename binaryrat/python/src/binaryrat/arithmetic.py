"""Bounded fixed-width expressions over a straight-line range of effective Listing p-code.

Apache-2.0; Copyright 2026 YurilLAB.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from operator import add, and_, invert, neg, or_, sub, xor

from .live import InstructionPcode, PcodeOperation, PcodeVarnode
from .models import Address


MAX_INSTRUCTIONS = 32
MAX_OPERATIONS = 256
MAX_NODES = 256
_ADDRESS_LIMIT = 1 << 64
_BINARY = {"INT_ADD": add, "INT_SUB": sub, "INT_AND": and_, "INT_OR": or_, "INT_XOR": xor}
_UNARY = {"INT_NEGATE": invert, "INT_2COMP": neg}
_EXTENSIONS = {"INT_ZEXT", "INT_SEXT"}
_SUPPORTED = set(_BINARY) | set(_UNARY) | _EXTENSIONS | {"COPY"}
# Pure flag and intermediate calculations often accompany a SLEIGH register write.
# Only an operation whose result is outside the selected slice may be skipped.
_PURE = _SUPPORTED | {
    "INT_EQUAL", "INT_NOTEQUAL", "INT_SLESS", "INT_SLESSEQUAL", "INT_LESS", "INT_LESSEQUAL",
    "INT_CARRY", "INT_SCARRY", "INT_SBORROW", "INT_LEFT", "INT_RIGHT", "INT_SRIGHT", "INT_MULT",
    "BOOL_NEGATE", "BOOL_XOR", "BOOL_AND", "BOOL_OR", "PIECE", "SUBPIECE", "POPCOUNT", "LZCOUNT",
}


class ArithmeticRefusal(ArithmeticError):
    """The selected result cannot be explained within the supported semantics or budgets."""


def _mask(size: int) -> int:
    return (1 << (size * 8)) - 1


def _overlap(a: PcodeVarnode, b: PcodeVarnode) -> bool:
    return (a.address.space == b.address.space and a.address.offset < b.address.offset + b.size and
            b.address.offset < a.address.offset + a.size)


def _check_storage(node: PcodeVarnode, spaces: tuple[str, ...]) -> None:
    if (not isinstance(node, PcodeVarnode) or not isinstance(node.address, Address) or
            node.address.space not in spaces):
        raise ArithmeticRefusal("Unsupported p-code storage space")
    if (type(node.size) is not int or not 1 <= node.size <= 8 or
            node.address.offset >= _ADDRESS_LIMIT or
            (node.address.space != "const" and node.address.offset + node.size > _ADDRESS_LIMIT)):
        raise ArithmeticRefusal("Expected a 1–8 byte value in the 64-bit address space")


def _check_shape(op: str, size: int, input_sizes: tuple[int, ...]) -> None:
    if op not in _SUPPORTED:
        raise ArithmeticRefusal(f"Unsupported arithmetic producer {op}")
    if op in _EXTENSIONS:
        valid = len(input_sizes) == 1 and input_sizes[0] < size
    else:
        valid = input_sizes == (size,) * (2 if op in _BINARY else 1)
    if not valid:
        raise ArithmeticRefusal(f"Invalid operand count or widths for {op}")


@dataclass(frozen=True, slots=True)
class ExpressionNode:
    """Indices in args refer to earlier nodes. Size is the result width in bytes."""

    op: str
    size: int
    args: tuple[int, ...] = ()
    value: int | None = None
    register: PcodeVarnode | None = None
    site: Address | None = None
    sequence: int | None = None


@dataclass(frozen=True, slots=True)
class ArithmeticExpression:
    """A dependency DAG in evaluation order. INPUT values are registers at range entry."""

    nodes: tuple[ExpressionNode, ...]
    root: int
    target: PcodeVarnode
    language_id: str | None = None

    def __post_init__(self) -> None:
        if self.language_id is not None and (
                not isinstance(self.language_id, str) or not 1 <= len(self.language_id) <= 256 or
                any(not "!" <= char <= "~" for char in self.language_id)):
            raise ArithmeticRefusal("Expected a printable Ghidra language ID")
        _check_storage(self.target, ("register",))
        if (not isinstance(self.nodes, tuple) or not 1 <= len(self.nodes) <= MAX_NODES or
                type(self.root) is not int or self.root != len(self.nodes) - 1):
            raise ArithmeticRefusal("Invalid expression size or root")
        used = {self.root}
        inputs: set[PcodeVarnode] = set()
        for index, node in enumerate(self.nodes):
            if (not isinstance(node, ExpressionNode) or not isinstance(node.op, str) or
                    type(node.size) is not int or not 1 <= node.size <= 8 or
                    not isinstance(node.args, tuple) or len(node.args) > 2 or
                    any(type(i) is not int or not 0 <= i < index for i in node.args)):
                raise ArithmeticRefusal("Invalid expression node or dependency order")
            if node.op in ("CONSTANT", "INPUT"):
                if node.args or node.site is not None or node.sequence is not None:
                    raise ArithmeticRefusal("An expression leaf cannot have a producer or operands")
                if node.op == "CONSTANT":
                    if (node.register is not None or type(node.value) is not int or
                            not 0 <= node.value <= _mask(node.size)):
                        raise ArithmeticRefusal("Constant does not fit its declared width")
                else:
                    _check_storage(node.register, ("register",))
                    if node.value is not None or node.register.size != node.size:
                        raise ArithmeticRefusal("Invalid input register width or value")
                    if any(reg != node.register and _overlap(reg, node.register) for reg in inputs):
                        raise ArithmeticRefusal("Overlapping input register ranges require alias modeling")
                    inputs.add(node.register)
            else:
                if node.register is not None or node.value is not None:
                    raise ArithmeticRefusal("A produced value cannot also be an expression leaf")
                if (node.site is not None or node.sequence is not None) and (
                        not isinstance(node.site, Address) or node.site.offset >= _ADDRESS_LIMIT or
                        type(node.sequence) is not int or not 0 <= node.sequence < 1 << 32):
                    raise ArithmeticRefusal("Invalid producing p-code location")
                _check_shape(node.op, node.size, tuple(self.nodes[i].size for i in node.args))
                used.update(node.args)
        if len(used) != len(self.nodes) or self.target.size != self.nodes[self.root].size:
            raise ArithmeticRefusal("Expression contains unused nodes or has an inconsistent target width")

    def evaluate(self, bindings: Mapping[PcodeVarnode, int]) -> int:
        """Evaluate with unsigned register values at entry; every operation wraps at its width."""
        values = []
        for node in self.nodes:
            if node.op == "INPUT":
                if node.register not in bindings:
                    raise ValueError(f"Missing input register {node.register}")
                value = bindings[node.register]
                if type(value) is not int or not 0 <= value <= _mask(node.size):
                    raise ValueError(f"Input register requires an unsigned {node.size * 8}-bit value")
            elif node.op == "CONSTANT":
                value = node.value
            elif node.op in _BINARY:
                left, right = node.args
                value = _BINARY[node.op](values[left], values[right])
            else:
                first, = node.args
                value = values[first]
                if node.op in _UNARY:
                    value = _UNARY[node.op](value)
                elif node.op == "INT_SEXT":
                    source_bits = self.nodes[first].size * 8
                    if value & (1 << (source_bits - 1)):
                        value -= 1 << source_bits
                # COPY and zero extension preserve the unsigned input value.
            values.append(value & _mask(node.size))
        return values[self.root]


def _operations(instructions: Sequence[InstructionPcode]) -> list[PcodeOperation]:
    if not 1 <= len(instructions) <= MAX_INSTRUCTIONS:
        raise ArithmeticRefusal(f"Select between 1 and {MAX_INSTRUCTIONS} contiguous instructions")
    ops = []
    start = instructions[0]
    next_offset = start.address.offset
    for ins in instructions:
        if (type(ins.revision) is not int or ins.revision != start.revision or
                ins.address.space != start.address.space or type(ins.parsed_length) is not int or
                ins.address.offset != next_offset or type(ins.length) is not int or
                ins.length <= 0 or ins.length != ins.parsed_length):
            raise ArithmeticRefusal("Expected contiguous instructions of original length in one revision")
        next_offset += ins.length
        if next_offset > _ADDRESS_LIMIT:
            raise ArithmeticRefusal("Instruction range wraps the address space")
        listing = ins.effective
        if (type(listing.operation_count) is not int or listing.operation_count != len(listing.operations) or
                len(ops) + len(listing.operations) > MAX_OPERATIONS):
            raise ArithmeticRefusal("Truncated listing or range exceeds the p-code operation limit")
        orders = set()
        for op in listing.operations:
            if (op.site != ins.address or type(op.sequence) is not int or
                    not 0 <= op.sequence < (1 << 32) or op.sequence in orders):
                raise ArithmeticRefusal("Ambiguous instruction or p-code sequence in the selection")
            orders.add(op.sequence)
            if not isinstance(op.mnemonic, str) or op.mnemonic not in _PURE:
                raise ArithmeticRefusal(f"Unsupported instruction effect {op.mnemonic} at {op.site}")
            if type(op.input_count) is not int or op.input_count != len(op.inputs) or len(op.inputs) > 8:
                raise ArithmeticRefusal("Truncated p-code operands")
            _check_storage(op.output, ("register", "unique"))
            for node in op.inputs:
                _check_storage(node, ("register", "unique", "const"))
            ops.append(op)
    return ops


def _source(ops: list[PcodeOperation], before: int, operand: PcodeVarnode,
            instruction: Address) -> int | PcodeVarnode:
    if operand.address.space == "const":
        return operand
    temporary = operand.address.space == "unique"
    for i in range(before - 1, -1, -1):
        producer = ops[i]
        if temporary and producer.site != instruction:
            break
        if producer.output == operand:
            return i
        if _overlap(producer.output, operand):
            raise ArithmeticRefusal(f"Partial or overlapping write at {producer.site} p-code {producer.sequence}")
    if temporary:
        raise ArithmeticRefusal(f"Unique temporary at {instruction} has no instruction-local definition")
    return operand


def build_expression(instructions: Sequence[InstructionPcode], target: PcodeVarnode, *,
                     language_id: str | None = None) -> ArithmeticExpression:
    """Explain the selected register at range exit assuming ordinary straight-line execution.

    The caller supplies a byte-addressed instruction range with Listing fall-through checked.
    All effective p-code is checked for side effects. Only definitions that contribute to the
    result appear in the expression. Registers used before a write become explicit inputs.
    """
    _check_storage(target, ("register",))
    ops = _operations(instructions)
    root = _source(ops, len(ops), target, instructions[-1].address)
    if not isinstance(root, int):
        raise ArithmeticRefusal("The selected register has no writer in this range")
    needed = {root}
    dependencies = {}
    for i in range(root, -1, -1):
        if i not in needed:
            continue
        op = ops[i]
        try:
            _check_shape(op.mnemonic, op.output.size, tuple(v.size for v in op.inputs))
        except ArithmeticRefusal as exc:
            raise ArithmeticRefusal(f"{exc} at {op.site} p-code {op.sequence}") from exc
        sources = tuple(_source(ops, i, v, op.site) for v in op.inputs)
        dependencies[i] = sources
        needed.update(source for source in sources if isinstance(source, int))

    nodes: list[ExpressionNode] = []
    leaves: dict[ExpressionNode, int] = {}
    produced: dict[int, int] = {}
    for i in reversed(dependencies):
        args = []
        for source in dependencies[i]:
            if isinstance(source, int):
                args.append(produced[source])
                continue
            if source.address.space == "const":
                leaf = ExpressionNode("CONSTANT", source.size, value=source.address.offset & _mask(source.size))
            else:
                leaf = ExpressionNode("INPUT", source.size, register=source)
            if leaf not in leaves:
                leaves[leaf] = len(nodes)
                nodes.append(leaf)
            args.append(leaves[leaf])
        op = ops[i]
        produced[i] = len(nodes)
        nodes.append(ExpressionNode(op.mnemonic, op.output.size, tuple(args), site=op.site, sequence=op.sequence))
        if len(nodes) > MAX_NODES:
            raise ArithmeticRefusal(f"Expression exceeds {MAX_NODES} nodes")
    return ArithmeticExpression(tuple(nodes), produced[root], target, language_id)
