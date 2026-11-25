"""Explain a register value over an inclusive range of Listing instructions.

Apache-2.0; Copyright 2026 YurilLAB.
"""

from __future__ import annotations

import argparse
from concurrent.futures import CancelledError
import json
import sys
from typing import Sequence

from ._console import tolerant_output
from .arithmetic import ArithmeticExpression, ArithmeticRefusal
from .arithmetic_proof import prove_equivalence
from .decompile_cli import _ENTRY, _shown
from .live import LiveProgramError, ProgramView, open_program
from .models import Address


_MODEL = ("The result is the selected register after the listed instructions execute in order "
          "with Listing overrides. Inputs are register values on entry. Each operation uses its "
          "recorded bit width. A comparison starts both ranges with the same input storage values "
          "and compares only their selected outputs.")


def _address_arg(value: str) -> tuple[str | None, int]:
    match = _ENTRY.fullmatch(value)
    if match is None or not value.isprintable():
        raise ValueError(f"expected [SPACE:][0x]HEX instruction address, got {value!r}")
    return match["space"], int(match["offset"], 16)


def _expression_record(view: ProgramView, expression: ArithmeticExpression) -> dict:
    nodes = []
    for node in expression.nodes:
        row = {"op": node.op, "bits": node.size * 8, "args": list(node.args)}
        if node.register is not None:
            row["register"] = str(node.register.address)
            row["register_name"] = view.register_name(node.register)
        if node.value is not None:
            row["value"] = hex(node.value)
        if node.site is not None:
            row.update(site=str(node.site), sequence=node.sequence)
        nodes.append(row)
    return {"target": str(expression.target.address), "bits": expression.target.size * 8,
            "nodes": nodes, "root": expression.root}


def _capture(view: ProgramView, selections) -> tuple[dict, list[ArithmeticExpression]]:
    info = view.info
    report = {"schema_version": 1, "program": info.path, "sha256": info.executable_sha256,
              "revision": info.revision, "language_id": info.language_id,
              "compiler_spec_id": info.compiler_spec_id, "model": _MODEL, "selections": [],
              "status": "explained"}
    expressions = []
    for (start_space, first), (end_space, last), register in selections:
        start = Address(start_space or info.image_base.space, first)
        end = Address(end_space or info.image_base.space, last)
        selection = {"start": str(start), "end": str(end), "register": register}
        report["selections"].append(selection)
        try:
            expression = view.explain_arithmetic(start, end, register)
        except ArithmeticRefusal as cause:
            report.update(status="unsupported", reason=str(cause))
            break
        expressions.append(expression)
        selection["expression"] = _expression_record(view, expression)
    return report, expressions


def _render(report: dict) -> None:
    print(f"{_shown(report['program'])}  revision {report['revision']}  "
          f"{_shown(report['language_id'])}  {_shown(report['compiler_spec_id'])}")
    print(f"Executable SHA-256 {_shown(report['sha256'] or 'unavailable')}")
    print(report["model"])
    for selection in report["selections"]:
        print(f"{_shown(selection['register'])} from {_shown(selection['start'])} through "
              f"{_shown(selection['end'])}")
        if "expression" not in selection:
            continue
        expr = selection["expression"]
        for index, row in enumerate(expr["nodes"]):
            if row["op"] == "INPUT":
                name = _shown(row["register_name"]) + " " if row["register_name"] else ""
                term = f"input {name}{_shown(row['register'])}"
            elif row["op"] == "CONSTANT":
                term = row["value"]
            else:
                args = ", ".join(f"t{arg}" for arg in row["args"])
                term = f"{row['op']}({args})  [{_shown(row['site'])}, p-code {row['sequence']}]"
            print(f"  t{index} ({row['bits']} bits) = {term}")
        print(f"  Result t{expr['root']} in {_shown(expr['target'])} ({expr['bits']} bits)")
    if report["status"] != "explained":
        print(f"{report['status']}  {_shown(report['reason'])}")
    if report["status"] == "different":
        for item in report["witness"]:
            name = _shown(item["register_name"]) + " " if item["register_name"] else ""
            print(f"  Input {name}{_shown(item['register'])} ({item['bits']} bits) = {item['value']}")
        print(f"  Selected results {report['left_value']} and {report['right_value']}")


def main(argv: Sequence[str] | None = None) -> int:
    tolerant_output()
    parser = argparse.ArgumentParser(
        prog="binaryrat-arithmetic", description=__doc__.splitlines()[0],
        epilog="START and END are exact instruction starts in [SPACE:][0x]HEX form. "
               "Bare hexadecimal addresses use the image-base space. Exit 0 for an explanation "
               "or a proof, 1 for a difference, 2 for an error, 3 for unsupported semantics or "
               "an inconclusive or unavailable proof, and 130 for cancellation.")
    parser.add_argument("project_file", metavar="PROJECT.gpr")
    parser.add_argument("program_path", metavar="/PROGRAM")
    parser.add_argument("start", metavar="START")
    parser.add_argument("end", metavar="END")
    parser.add_argument("register", metavar="REGISTER")
    parser.add_argument("--compare", nargs=3, metavar=("START", "END", "REGISTER"),
                        help="check equality with a second selection in the same Program")
    parser.add_argument("--timeout-ms", type=int, help="solver time budget with --compare (1–10000 ms)")
    parser.add_argument("--install-dir", metavar="GHIDRA_DIR")
    parser.add_argument("--json", action="store_true", help="write the expression and evidence as JSON")
    args = parser.parse_args(argv)
    if args.timeout_ms is not None and (args.compare is None or not 1 <= args.timeout_ms <= 10_000):
        parser.error("--timeout-ms requires --compare and a value from 1 to 10000")
    try:
        selections = [(_address_arg(args.start), _address_arg(args.end), args.register)]
        if args.compare is not None:
            first, last, register = args.compare
            selections.append((_address_arg(first), _address_arg(last), register))
        with open_program(args.project_file, args.program_path, install_dir=args.install_dir,
                          backend="stock", max_heap_mb=1024) as view:
            report, expressions = _capture(view, selections)
        if len(expressions) == 2:
            proof = prove_equivalence(*expressions, timeout_ms=args.timeout_ms or 1000)
            report.update(status=proof.status, reason=proof.reason, solver_version=proof.solver_version)
            if proof.status == "different":
                names = {(row["register"], row["bits"]): row["register_name"]
                         for selection in report["selections"] for row in selection["expression"]["nodes"]
                         if row["op"] == "INPUT"}
                report.update(witness=[{"register": str(reg.address), "bits": reg.size * 8,
                                        "register_name": names[str(reg.address), reg.size * 8],
                                        "value": hex(value)} for reg, value in proof.witness],
                              left_value=hex(proof.left_value), right_value=hex(proof.right_value))
        if args.json:
            print(json.dumps(report, ensure_ascii=True))
        else:
            _render(report)
        return {"explained": 0, "proved": 0, "different": 1, "unknown": 3,
                "unsupported": 3, "unavailable": 3}[report["status"]]
    except (CancelledError, KeyboardInterrupt):
        return 130
    except (LiveProgramError, OSError, ValueError, TypeError) as cause:
        print(f"binaryrat-arithmetic: {_shown(str(cause))}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
