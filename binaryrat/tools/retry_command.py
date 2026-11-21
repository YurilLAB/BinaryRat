#!/usr/bin/env python3
"""Run a network setup command again after a failure, with growing waits.

Only for steps whose failures are download failures, such as fetching the
Gradle distribution. Never wrap a test or verifier: a retried test hides a flake.

    python binaryrat/tools/retry_command.py [--attempts N] -- COMMAND [ARGS...]

SPDX-License-Identifier: Apache-2.0
Copyright 2026 YurilLAB. New BinaryRat tooling.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time
from typing import Callable, Sequence


def run(command: Sequence[str], *, attempts: int = 3, first_delay: float = 10.0,
        runner: Callable = subprocess.run, sleep: Callable[[float], None] = time.sleep) -> int:
    """Return the exit code of the first successful run, or of the last attempt."""
    if attempts < 1:
        raise ValueError("attempts must be at least 1")
    if not command:
        raise ValueError("no command given")
    code = 1
    for attempt in range(1, attempts + 1):
        code = runner(list(command)).returncode
        if code == 0:
            return 0
        if attempt < attempts:
            delay = first_delay * 3 ** (attempt - 1)
            print(f"attempt {attempt}/{attempts} exited with {code}; retrying in {delay:g} s",
                  file=sys.stderr, flush=True)
            sleep(delay)
    return code


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("give the command after --")
    return run(command, attempts=args.attempts)


if __name__ == "__main__":
    sys.exit(main())
