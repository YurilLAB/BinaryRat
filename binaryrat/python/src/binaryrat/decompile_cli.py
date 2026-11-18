"""Run one BinaryRat decompilation against a saved Ghidra Program.

Apache-2.0; Copyright 2026 YurilLAB.
"""

from __future__ import annotations

import argparse
from concurrent.futures import CancelledError
from dataclasses import asdict
import json
import re
import sys
from typing import Sequence

from .live import LiveProgramError, open_program
from .models import Address

_ENTRY = re.compile(r"(?:(?P<space>[^:\s]+):)?(?:0[xX])?(?P<offset>[0-9a-fA-F]{1,16})")


def _parse_entry(value: str) -> tuple[str | None, int]:
    match = _ENTRY.fullmatch(value)
    if match is None:
        raise argparse.ArgumentTypeError("entry must be [SPACE:] followed by a 64-bit hexadecimal offset")
    return match["space"], int(match["offset"], 16)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("project_file", metavar="PROJECT.gpr")
    parser.add_argument("program_path", metavar="/PROGRAM")
    parser.add_argument("entry", type=_parse_entry, metavar="[SPACE:]HEX",
                        help="function entry, using the program's image-base space by default")
    parser.add_argument("--install-dir", metavar="GHIDRA_DIR")
    parser.add_argument("--backend", choices=("auto", "scheduled", "stock"), default="scheduled",
                        help="choose the Ghidra backend (default: scheduled)")
    parser.add_argument("--timeout-seconds", type=int, default=30)
    parser.add_argument("--max-heap-mb", type=int, default=1024)
    parser.add_argument("--json", action="store_true", help="emit result and status as JSON")
    args = parser.parse_args(argv)
    space, offset = args.entry
    try:
        with open_program(
            args.project_file, args.program_path, install_dir=args.install_dir,
            max_heap_mb=args.max_heap_mb, backend=args.backend,
        ) as view:
            run = view.decompile_with_metrics(
                Address(space or view.info.image_base.space, offset), timeout_seconds=args.timeout_seconds,
            )
    except (CancelledError, KeyboardInterrupt):
        return 130
    except (LiveProgramError, LookupError, OSError, TypeError, ValueError) as cause:
        print(f"binaryrat-decompile: {cause}", file=sys.stderr)
        return 2

    result = run.result
    if args.json:
        print(json.dumps(asdict(result) | {"backend": run.backend, "cache_status": run.cache_status}))
    elif result.successful:
        print(result.c, end="" if result.c.endswith("\n") else "\n")
    else:
        print(f"binaryrat-decompile: {result.error or 'decompilation did not complete'}", file=sys.stderr)
    return 0 if result.successful else 1


if __name__ == "__main__":
    raise SystemExit(main())
