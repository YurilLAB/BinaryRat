#!/usr/bin/env python3
"""Verify the combined output of Ghidra's native decompiler test harness.

SPDX-License-Identifier: Apache-2.0
Copyright 2026 YurilLAB. New BinaryRat tooling.
"""

import argparse
from collections.abc import Iterable
from pathlib import Path
import re


UNIT_TOTAL = re.compile(r"([0-9]+)/([0-9]+) tests passed\.")
DATA_APPLIED = "Total tests applied"
DATA_PASSED = "Total passing tests"
FAILURE_PREFIXES = (
    "fail:", "FAIL -- ", "Error parsing ", "Error executing ",
    "Error: Did not apply tests in ", "Execution failed for ", "No output for ",
)


def verify_log(lines: Iterable[str]) -> tuple[int, int]:
    """Return the unit and data test counts, raising ValueError on an incomplete or failed run."""
    unit_count = None
    data_counts: dict[str, int] = {}
    failure_list = False
    for raw in lines:
        line = raw.strip()
        # testfunction.cc records failed fixtures even when their tests never enter the totals.
        if line == "fail" or line.startswith(FAILURE_PREFIXES):
            raise ValueError(f"upstream test failure: {line}")
        if line.startswith("Failures:"):
            failure_list = True
        if unit := UNIT_TOTAL.fullmatch(line):
            if unit_count is not None:
                raise ValueError("duplicate unit-test summary")
            passed, total = map(int, unit.groups())
            if passed == 0 or passed != total:
                raise ValueError(f"invalid unit-test result: {line}")
            unit_count = total
        name, _, count = (part.strip() for part in line.partition("="))
        if name in (DATA_APPLIED, DATA_PASSED):
            if name in data_counts or not re.fullmatch(r"[0-9]+", count):
                raise ValueError(f"invalid or duplicate data-test summary: {line}")
            data_counts[name] = int(count)

    if failure_list:
        raise ValueError("upstream test failure list present")
    if unit_count is None or len(data_counts) != 2:
        raise ValueError("missing unit or data test summary")
    applied, passed = data_counts[DATA_APPLIED], data_counts[DATA_PASSED]
    if applied == 0 or applied != passed:
        raise ValueError(f"invalid data-test result: {passed}/{applied} tests passed")
    return unit_count, applied


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    args = parser.parse_args()
    try:
        with args.log.open(encoding="utf-8") as stream:
            units, data = verify_log(stream)
    except (OSError, ValueError) as error:
        parser.exit(1, f"{args.log}: {error}\n")
    print(f"Verified {units} upstream unit tests and {data} data tests.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
