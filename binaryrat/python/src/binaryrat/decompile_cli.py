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

from .live import LiveProgramError, ProgramFunction, ProgramView, open_program
from .models import Address

_ENTRY = re.compile(r"(?:(?P<space>[^:\s]+):)?(?P<prefix>0[xX])?(?P<offset>[0-9a-fA-F]{1,16})")
# A leading digit or a single-colon space prefix means an address; "ns::f" stays a name.
_ADDRESS_LIKE = re.compile(r"[0-9]|[^:\s]+:(?!:)")
_NAME_PREFIX = "name:"
_SHOWN_MATCHES = 8


def _parse_function(value: str) -> tuple[str, object]:
    """Return ("name", NAME) or ("address", (SPACE | None, OFFSET, BARE_TOKEN | None))."""
    if value.startswith(_NAME_PREFIX):
        name = value[len(_NAME_PREFIX):]
        if not name or not name.isprintable():
            raise argparse.ArgumentTypeError("name: needs a printable function name")
        return "name", name
    # Ghidra symbol names never contain whitespace; use name: for anything unusual.
    if not value or not value.isprintable() or any(character.isspace() for character in value):
        raise argparse.ArgumentTypeError("function must be an address or a name without spaces")
    match = _ENTRY.fullmatch(value)
    if match is None:
        if _ADDRESS_LIKE.match(value):
            raise argparse.ArgumentTypeError(
                "address must be [SPACE:][0x] followed by up to 16 hexadecimal digits")
        return "name", value
    bare = match["space"] is None and match["prefix"] is None
    return "address", (match["space"], int(match["offset"], 16), value if bare else None)


def _shown(text: str) -> str:
    # Names come from the binary. Render control sequences literally on terminals.
    return text if text.isprintable() else ascii(text)[1:-1]


def _resolve(view: ProgramView, query: tuple[str, object]) -> ProgramFunction:
    kind, value = query
    if kind == "name":
        page = view.functions_named(value, limit=_SHOWN_MATCHES + 1)
        if not page.items:
            raise LookupError(f'no function named "{_shown(value)}"; '
                              f"search with --list --match {_shown(value)}")
        if len(page.items) > 1:
            more = "+" if page.truncated or len(page.items) > _SHOWN_MATCHES else ""
            entries = ", ".join(str(f.entry) for f in page.items[:_SHOWN_MATCHES])
            raise LookupError(f'{min(len(page.items), _SHOWN_MATCHES)}{more} functions are named '
                              f'"{_shown(value)}" ({entries}); pass an entry address instead')
        return page.items[0]
    space, offset, bare = value
    address = Address(space or view.info.image_base.space, offset)
    function = view.function_containing(address)
    if function is None:
        # A bare token such as "add" may have been meant as a function name.
        hint = f"; for a function named {bare} use name:{bare}" if bare and bare[0].isalpha() else ""
        raise LookupError(f"no function contains {address}{hint}")
    if function.entry != address:
        print(f"binaryrat-decompile: {address} is inside {_shown(function.qualified_name)} "
              f"at {function.entry}", file=sys.stderr)
    return function


def _list(view: ProgramView, match: str | None, as_json: bool) -> int:
    needle = match.casefold() if match is not None else None
    offset: int | None = 0
    shown = 0
    while offset is not None:
        page = view.functions(offset=offset, limit=1000)
        for function in page.items:
            if needle is not None and needle not in function.qualified_name.casefold():
                continue
            shown += 1
            if as_json:
                print(json.dumps(asdict(function), ensure_ascii=True))
                continue
            line = f"{function.entry}  {_shown(function.signature)}"
            if function.qualified_name != function.name:
                line += f"  [{_shown(function.qualified_name)}]"
            print(line)
        if page.truncated:
            print("binaryrat-decompile: the listing stops after 100,000 functions", file=sys.stderr)
        offset = page.next_offset
    return 0 if shown else 1


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="binaryrat-decompile",
        description=__doc__.splitlines()[0],
        epilog="FUNCTION is an entry or any address inside a function ([SPACE:][0x]HEX, using the "
               "image-base space by default), or a function name (ns::f for a qualified name). "
               "Use name:NAME for a name that is also valid hexadecimal, such as name:add. "
               "Exit 0 for C output, 1 for an incomplete decompilation or an empty listing, "
               "2 for invalid input or an unavailable backend, 130 when interrupted.",
    )
    parser.add_argument("project_file", metavar="PROJECT.gpr")
    parser.add_argument("program_path", metavar="/PROGRAM")
    parser.add_argument("function", type=_parse_function, nargs="?", metavar="FUNCTION",
                        help="function to decompile: address or name")
    parser.add_argument("--list", action="store_true",
                        help="list the program's functions (entry and signature) instead of decompiling")
    parser.add_argument("--match", metavar="TEXT",
                        help="with --list, keep functions whose qualified name contains TEXT (any case)")
    parser.add_argument("--install-dir", metavar="GHIDRA_DIR")
    parser.add_argument("--backend", choices=("auto", "scheduled", "stock"), default="scheduled",
                        help="choose the Ghidra backend (default: scheduled)")
    parser.add_argument("--timeout-seconds", type=int, default=30)
    parser.add_argument("--max-heap-mb", type=int, default=1024)
    parser.add_argument("--json", action="store_true",
                        help="emit the result and status as JSON, or one JSON object per listed function")
    args = parser.parse_args(argv)
    if args.list == (args.function is not None):
        parser.error("give either FUNCTION or --list")
    if args.match is not None and not args.list:
        parser.error("--match only applies to --list")
    # Listing never decompiles, so it does not need the extension's scheduled backend.
    backend = "stock" if args.list else args.backend
    try:
        with open_program(
            args.project_file, args.program_path, install_dir=args.install_dir,
            max_heap_mb=args.max_heap_mb, backend=backend,
        ) as view:
            if args.list:
                return _list(view, args.match, args.json)
            function = _resolve(view, args.function)
            run = view.decompile_with_metrics(function.entry, timeout_seconds=args.timeout_seconds)
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
