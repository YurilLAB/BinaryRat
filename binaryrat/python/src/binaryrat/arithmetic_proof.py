"""Check equality of two finite bit-vector expressions with an optional isolated Z3 process.

Copyright 2026 YurilLAB. SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

from dataclasses import dataclass
from importlib import metadata
import os
from pathlib import Path
import re
import subprocess
import sys
from time import monotonic
from typing import Literal

from .arithmetic import ArithmeticExpression
from .live import PcodeVarnode


_SOLVER_MEMORY_MIB = 96
_SUPPORTED_VERSION = "4.13.0.0"
_BINARY = {"INT_ADD": "bvadd", "INT_SUB": "bvsub", "INT_AND": "bvand",
           "INT_OR": "bvor", "INT_XOR": "bvxor"}
_UNARY = {"INT_NEGATE": "bvnot", "INT_2COMP": "bvneg"}
_EXTENSION = {"INT_ZEXT": "zero_extend", "INT_SEXT": "sign_extend"}
_STATUS = Literal["proved", "different", "unknown", "unavailable"]


@dataclass(frozen=True, slots=True)
class ArithmeticProof:
    """Equality of the selected output under shared physical register inputs."""

    status: _STATUS
    reason: str
    solver_version: str | None = None
    witness: tuple[tuple[PcodeVarnode, int], ...] = ()
    left_value: int | None = None
    right_value: int | None = None


def _installed_solver() -> tuple[Path, str, Path | None] | None:
    # Windows wheels install under data/bin, which can differ from Python's Scripts.
    # Locate the executable owned by the optional distribution in this interpreter.
    try:
        dist = metadata.distribution("z3-solver")
    except metadata.PackageNotFoundError:
        return None
    windows = sys.platform == "win32"
    name = "z3.exe" if windows else "z3"
    files = dist.files or ()
    dll_dir = None
    if windows:
        for item in files:
            if item.as_posix().lower() == "z3/lib/msvcp140.dll":
                runtime = Path(dist.locate_file(item)).resolve()
                if runtime.is_file():
                    dll_dir = runtime.parent
                break
    for item in files:
        if item.name == name:
            path = Path(dist.locate_file(item)).resolve()
            if path.is_file():
                return path, dist.version, dll_dir
    return None


def _definitions(expr: ArithmeticExpression, prefix: str, registers: dict[PcodeVarnode, str]) -> list[str]:
    definitions = []
    for index, node in enumerate(expr.nodes):
        args = [f"{prefix}{arg}" for arg in node.args]
        bits = node.size * 8
        if node.op == "INPUT":
            term = registers[node.register]
        elif node.op == "CONSTANT":
            term = f"(_ bv{node.value} {bits})"
        elif node.op == "COPY":
            term = args[0]
        elif node.op in _BINARY:
            term = f"({_BINARY[node.op]} {args[0]} {args[1]})"
        elif node.op in _UNARY:
            term = f"({_UNARY[node.op]} {args[0]})"
        elif node.op in _EXTENSION:
            extra = bits - expr.nodes[node.args[0]].size * 8
            term = f"((_ {_EXTENSION[node.op]} {extra}) {args[0]})"
        else:
            raise ValueError("unsupported arithmetic proof operation")
        definitions.append(f"(define-fun {prefix}{index} () (_ BitVec {bits}) {term})")
    return definitions


def _query(path: Path, commands: str, deadline: float, dll_dir: Path | None) -> list[str]:
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise TimeoutError
    env = None
    if dll_dir is not None:
        # Windows wheels keep the executable and its MSVC runtime in different directories.
        env = os.environ.copy()
        inherited = env.get("PATH", "")
        env["PATH"] = str(dll_dir) + (os.pathsep + inherited if inherited else "")
    result = subprocess.run([str(path), "-in", "-smt2", f"-memory:{_SOLVER_MEMORY_MIB}",
                             f"-t:{max(1, int(remaining * 1000))}"],
                            input=commands.encode("ascii"), capture_output=True,
                            cwd=path.parent, env=env, timeout=remaining)
    if monotonic() > deadline:
        raise TimeoutError
    if result.returncode or result.stderr.strip():
        raise ValueError("Z3 stopped before returning a result within the solver budget")
    try:
        return result.stdout.decode("ascii").strip().splitlines()
    except UnicodeDecodeError:
        raise ValueError("unexpected Z3 output encoding") from None


def _model_values(lines: list[str], widths: dict[str, int]) -> dict[str, int]:
    # All variables and output symbols are generated locally. At whole-byte widths
    # Z3 writes exact-width hexadecimal literals for these bit-vector values.
    text = " ".join(lines).strip()
    if not text.startswith("(") or not text.endswith(")"):
        raise ValueError("Z3 returned an incomplete counterexample")
    text = text[1:-1].strip()
    values: dict[str, int] = {}
    for match in re.finditer(r"\(([a-z][0-9]+)\s+#x([0-9a-fA-F]+)\)|([^\s]+)", text):
        name, literal, other = match.groups()
        if other or name not in widths or name in values or len(literal) != 2 * widths[name]:
            raise ValueError("Z3 returned an invalid counterexample binding")
        values[name] = int(literal, 16)
    if values.keys() != widths.keys():
        raise ValueError("Z3 omitted a counterexample binding")
    return values


def prove_equivalence(left: ArithmeticExpression, right: ArithmeticExpression, *,
                      timeout_ms: int = 1000) -> ArithmeticProof:
    """Compare two selected register results in the same language/register map.

    Equally sized inputs at the same register offset share a bit vector. Distinct
    overlapping inputs are refused. Only UNSAT for disequality proves equality.
    A differing result includes input values replayed through both concrete evaluators.
    The solver uses up to 96 MiB under Z3's memory limit. The wall deadline covers
    both the decision and optional witness queries. No Program or JVM is needed.
    """
    if type(timeout_ms) is not int or not 1 <= timeout_ms <= 10_000:
        raise ValueError("timeout_ms must be an integer between 1 and 10000")
    if not isinstance(left, ArithmeticExpression) or not isinstance(right, ArithmeticExpression):
        raise TypeError("expected two arithmetic expressions")
    if left.language_id != right.language_id:
        return ArithmeticProof("unknown", "the expressions belong to different or unbound register maps")
    if left.target.size != right.target.size:
        return ArithmeticProof("unknown", "selected results have different widths")
    inputs = {node.register for expr in (left, right) for node in expr.nodes if node.op == "INPUT"}
    ordered = sorted(inputs, key=lambda reg: (reg.address.offset, reg.size))
    for previous, current in zip(ordered, ordered[1:]):
        if previous.address.offset + previous.size > current.address.offset:
            return ArithmeticProof("unknown", "input registers overlap at different widths or offsets")
    installed = _installed_solver()
    if installed is None:
        return ArithmeticProof("unavailable", "install the binaryrat[proof] extra for Z3")
    executable, version, dll_dir = installed
    if version != _SUPPORTED_VERSION:
        return ArithmeticProof("unavailable", f"this proof backend requires z3-solver {_SUPPORTED_VERSION}", version)
    registers = {reg: f"r{index}" for index, reg in enumerate(ordered)}
    statements = ["(set-logic QF_BV)"]
    for reg, symbol in registers.items():
        statements.append(f"(declare-const {symbol} (_ BitVec {reg.size * 8}))")
    lroot, rroot = f"a{left.root}", f"b{right.root}"
    deadline = monotonic() + timeout_ms / 1000
    try:
        statements.extend(_definitions(left, "a", registers))
        statements.extend(_definitions(right, "b", registers))
        statements.extend([f"(assert (distinct {lroot} {rroot}))", "(check-sat)"])
        query = "\n".join(statements) + "\n"
        status = _query(executable, query, deadline, dll_dir)
        if status == ["unsat"]:
            return ArithmeticProof("proved", "disequality is unsatisfiable for these input registers", version)
        if status != ["sat"]:
            return ArithmeticProof("unknown", "Z3 did not decide disequality", version)
        widths = {symbol: reg.size for reg, symbol in registers.items()}
        widths.update({lroot: left.target.size, rroot: right.target.size})
        model = _query(executable, query + f"(get-value ({' '.join(widths)}))\n", deadline, dll_dir)
        if not model or model[0] != "sat":
            return ArithmeticProof("unknown", "Z3 did not return a counterexample", version)
        values = _model_values(model[1:], widths)
        witness = {reg: values[symbol] for reg, symbol in registers.items()}
        lvalue, rvalue = left.evaluate(witness), right.evaluate(witness)
        if lvalue == rvalue or (lvalue, rvalue) != (values[lroot], values[rroot]):
            return ArithmeticProof("unknown", "the counterexample failed concrete replay", version)
        return ArithmeticProof("different", "the input values reproduce different results", version,
                               tuple(witness.items()), lvalue, rvalue)
    except (TimeoutError, subprocess.TimeoutExpired):
        return ArithmeticProof("unknown", "the proof exceeded its wall-clock deadline", version)
    except OSError:
        return ArithmeticProof("unavailable", "the installed Z3 executable could not start", version)
    except ValueError as error:
        return ArithmeticProof("unknown", str(error), version)
