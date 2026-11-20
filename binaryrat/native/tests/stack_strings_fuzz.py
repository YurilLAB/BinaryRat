#!/usr/bin/env python3
# Copyright 2026 YurilLAB
# SPDX-License-Identifier: Apache-2.0
"""Seeded model check of `strings.stack` through a real `serve` process.

Random groups of constant stack writes (overlapping and rewritten slots, equal
orders, ASCII and UTF-16LE text, control bytes, gaps, signed 64-bit extremes)
are assembled by the engine and by an independent Python oracle that replays
the writes into a byte map and scans each contiguous run. Every recovered
string must match exactly: offset, length, encoding, text, terminator and the
orders of the writes behind it. Each case is also sent with its writes
shuffled; with distinct orders the answer must not change. Malformed requests
must fail with invalid_request and leave the process usable.

Example: python stack_strings_fuzz.py --engine build/binaryrat-engine --seed 7 --cases 500
"""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import queue
import random
import subprocess
import sys
import tempfile
import threading
from typing import Any, Callable

DEFAULT_SEEDS = (0, 1, 20261120)
INT64_MIN, INT64_MAX = -(1 << 63), (1 << 63) - 1
PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}
REQUIRED_COVERAGE = ("ascii string", "utf16 string", "terminated", "unterminated", "rewritten text",
                     "equal orders", "extreme offset", "several runs", "minimum length 1",
                     "empty group", "refused malformed request")


class Failure(Exception):
    pass


class Engine:
    def __init__(self, executable: Path, root: Path, timeout: float):
        self.timeout = timeout
        self.process = subprocess.Popen([str(executable), "serve", "--cache", str(root)],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, text=True, encoding="utf-8")
        self.lines: queue.Queue[str | None] = queue.Queue()
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()
        self.counter = 0

    def _read(self) -> None:
        for line in self.process.stdout:
            self.lines.put(line)
        self.lines.put(None)

    def call(self, request: dict[str, Any]) -> dict[str, Any]:
        self.counter += 1
        request = dict(request, id=str(self.counter))
        self.process.stdin.write(json.dumps(request) + "\n")
        self.process.stdin.flush()
        try:
            line = self.lines.get(timeout=self.timeout)
        except queue.Empty:
            raise Failure("engine did not answer in time") from None
        if line is None:
            raise Failure("engine exited")
        response = json.loads(line)
        if response.get("id") != request["id"] or response.get("protocol_version") != 1:
            raise Failure(f"mismatched response: {response}")
        return response

    def close(self) -> None:
        try:
            self.process.stdin.close()
            self.process.wait(timeout=10)
        finally:
            if self.process.poll() is None:
                self.process.kill()
                self.process.wait()


# ---------------------------------------------------------------- oracle

def oracle_group(writes: list[dict[str, Any]], minimum: int) -> list[dict[str, Any]]:
    """Replay writes (ascending order, ties in input order) and scan every contiguous run."""
    cells: dict[int, tuple[int, int]] = {}
    for _, write in sorted(enumerate(writes), key=lambda pair: (pair[1]["order"], pair[0])):
        for position, value in enumerate(bytes.fromhex(write["bytes"])):
            cells[write["offset"] + position] = (value, write["order"])
    runs: list[tuple[int, list[tuple[int, int]]]] = []
    for offset in sorted(cells):
        if runs and runs[-1][0] + len(runs[-1][1]) == offset:
            runs[-1][1].append(cells[offset])
        else:
            runs.append((offset, [cells[offset]]))
    found = []
    for start, run in runs:
        values = bytes(value for value, _ in run)
        position = 0
        while position < len(values):
            wide = 0
            while (position + 2 * wide + 1 < len(values) and values[position + 2 * wide] in PRINTABLE
                   and values[position + 2 * wide + 1] == 0):
                wide += 1
            narrow = 0
            while position + narrow < len(values) and values[position + narrow] in PRINTABLE:
                narrow += 1
            if wide >= minimum:
                end = position + 2 * wide
                terminated = values[end:end + 2] == b"\0\0"
                text, encoding, length = values[position:end:2].decode("ascii"), "utf16le", 2 * wide
                consumed = end + (2 if terminated else 0)
            elif narrow >= minimum:
                end = position + narrow
                terminated = values[end:end + 1] == b"\0"
                text, encoding, length = values[position:end].decode("ascii"), "ascii", narrow
                consumed = end + (1 if terminated else 0)
            else:
                position += 1
                continue
            found.append({"offset": start + position, "byte_length": length, "encoding": encoding,
                          "text": text, "terminated": terminated,
                          "orders": sorted({order for _, order in run[position:consumed]})})
            position = consumed
    return found


def expect(expected: Any, actual: Any, label: str) -> None:
    if expected != actual:
        raise Failure(f"{label}: expected {json.dumps(expected)}, engine gave {json.dumps(actual)}")


def check(request: dict[str, Any], result: dict[str, Any], seen: Counter) -> None:
    minimum = request.get("minimum_length", 4)
    expect(minimum, result["minimum_length"], "minimum_length")
    expect([group["id"] for group in request["groups"]], [group["id"] for group in result["groups"]], "group ids")
    for group, answer in zip(request["groups"], result["groups"]):
        model = oracle_group(group["writes"], minimum)
        expect(model, answer["strings"], f"group {group['id']}")
        if not group["writes"]:
            seen["empty group"] += 1
        if len({write["order"] for write in group["writes"]}) < len(group["writes"]):
            seen["equal orders"] += 1
        if any(abs(write["offset"]) > 1 << 62 for write in group["writes"]):
            seen["extreme offset"] += 1
        if len(model) > 1 and any(b["offset"] > a["offset"] + a["byte_length"] + 1
                                  for a, b in zip(model, model[1:])):
            seen["several runs"] += 1
        for text in model:
            seen[f"{'utf16' if text['encoding'] == 'utf16le' else 'ascii'} string"] += 1
            seen["terminated" if text["terminated"] else "unterminated"] += 1
            if len(text["orders"]) > 1:
                seen["rewritten text"] += 1
    if minimum == 1 and any(model for model in result["groups"]):
        seen["minimum length 1"] += 1


# ---------------------------------------------------------------- generator

def chunk(rng: random.Random) -> bytes:
    kind = rng.random()
    if kind < 0.35:
        return bytes(rng.choice(b"abcdefghijklmnopqrstuvwxyzABC0123 _./%\t\n\r") for _ in range(rng.randint(1, 12)))
    if kind < 0.55:
        units = bytes(rng.choice(b"WideStrng09 ") for _ in range(rng.randint(1, 8)))
        return b"".join(bytes((unit, 0)) for unit in units)
    if kind < 0.75:
        return b"\0" * rng.randint(1, 4)
    if kind < 0.85:
        return bytes(rng.choice((0x01, 0x07, 0x1B, 0x7F, 0x80, 0xFF)) for _ in range(rng.randint(1, 3)))
    return bytes(rng.randrange(256) for _ in range(rng.randint(1, 8)))


def generate(rng: random.Random) -> dict[str, Any]:
    groups = []
    for index in range(rng.randint(1, 4)):
        base = rng.choice((0, -0x40, 0x1000, INT64_MAX - 200, INT64_MIN))
        writes = []
        for _ in range(rng.choice((0, rng.randint(1, 8), rng.randint(5, 40)))):
            data = b"".join(chunk(rng) for _ in range(rng.randint(1, 3)))[:rng.choice((4, 8, 16, 64))]
            offset = base + rng.randint(0, 120)
            if offset > INT64_MAX - (len(data) - 1):
                offset = INT64_MAX - (len(data) - 1)
            writes.append({"offset": offset, "bytes": data.hex(), "order": rng.randint(0, 30)})
        groups.append({"id": f"g{index}", "writes": writes})
    request: dict[str, Any] = {"op": "strings.stack", "groups": groups}
    if rng.random() < 0.6:
        request["minimum_length"] = rng.choice((1, 1, 2, 3, 4, 5, 8, 64))
    return request


def shuffled(request: dict[str, Any], rng: random.Random) -> dict[str, Any]:
    other = json.loads(json.dumps(request))
    for group in other["groups"]:
        rng.shuffle(group["writes"])
    return other


def prelude() -> list[dict[str, Any]]:
    """Fixed cases a compiler emits: pieces of one string, a rewrite, UTF-16, a split."""
    def group(name: str, *writes: tuple[int, bytes, int]) -> dict[str, Any]:
        return {"id": name, "writes": [{"offset": o, "bytes": b.hex(), "order": r} for o, b, r in writes]}
    return [
        {"op": "strings.stack", "groups": [group("pieces", (-0x20, b"hell", 1), (-0x1C, b"o\0", 2))]},
        {"op": "strings.stack", "groups": [group("rewrite", (0, b"XXXXXXXX", 1), (0, b"abcd", 2))]},
        {"op": "strings.stack", "groups": [group("wide", (8, "wide\0".encode("utf-16-le"), 1))]},
        {"op": "strings.stack", "groups": [group("split", (0, b"abcd", 1), (5, b"efgh", 2)), group("empty")],
         "minimum_length": 1},
        {"op": "strings.stack", "groups": [group("top", (INT64_MAX - 3, b"tail", 1)),
                                           group("bottom", (INT64_MIN, b"head\0", 1))]},
        {"op": "strings.stack", "groups": [group("ties", (0, b"aaaa", 5), (0, b"bbbb", 5))]},
    ]


def _first_write(request: dict[str, Any]) -> dict[str, Any]:
    for group in request["groups"]:
        if group["writes"]:
            return group["writes"][0]
    request["groups"].append({"id": "added", "writes": [{"offset": 0, "bytes": "41", "order": 0}]})
    return request["groups"][-1]["writes"][0]


INVALID_MUTATIONS: list[tuple[str, Callable[[dict[str, Any]], None]]] = [
    ("uppercase hex", lambda r: _first_write(r).update(bytes="4A")),
    ("odd hex", lambda r: _first_write(r).update(bytes="414")),
    ("empty bytes", lambda r: _first_write(r).update(bytes="")),
    ("65 bytes", lambda r: _first_write(r).update(bytes="41" * 65)),
    ("not hex", lambda r: _first_write(r).update(bytes="zz")),
    ("bytes not text", lambda r: _first_write(r).update(bytes=[65])),
    ("range overflow", lambda r: _first_write(r).update(offset=INT64_MAX, bytes="4142")),
    ("offset above int64", lambda r: _first_write(r).update(offset=1 << 63)),
    ("negative order", lambda r: _first_write(r).update(order=-1)),
    ("order as text", lambda r: _first_write(r).update(order="1")),
    ("missing offset", lambda r: _first_write(r).pop("offset")),
    ("duplicate group", lambda r: r["groups"].append(dict(r["groups"][0]))),
    ("empty group id", lambda r: r["groups"][0].update(id="")),
    ("missing writes", lambda r: r["groups"][0].pop("writes")),
    ("groups not array", lambda r: r.update(groups={})),
    ("minimum 0", lambda r: r.update(minimum_length=0)),
    ("minimum 65", lambda r: r.update(minimum_length=65)),
    ("minimum negative", lambda r: r.update(minimum_length=-1)),
    ("minimum fraction", lambda r: r.update(minimum_length=2.5)),
]


def run_seed(engine: Engine, seed: int, cases: int, seen: Counter) -> int:
    rng = random.Random(seed)
    checked = 0
    pending = prelude() + [None] * cases
    for index, request in enumerate(pending):
        if request is None:
            request = generate(rng)
        context = f"seed {seed} case {index}"
        try:
            response = engine.call(request)
            if not response["ok"]:
                raise Failure(f"valid request failed: {response}")
            check(request, response["result"], seen)
            other = shuffled(request, rng)
            again = engine.call(other)
            if not again["ok"]:
                raise Failure(f"shuffled request failed: {again}")
            check(other, again["result"], seen)
            if all(len({w["order"] for w in g["writes"]}) == len(g["writes"]) for g in request["groups"]):
                expect(response["result"], again["result"], "order independence")
            if rng.random() < 0.3:
                name, mutate = rng.choice(INVALID_MUTATIONS)
                broken = json.loads(json.dumps(request))
                mutate(broken)
                answer = engine.call(broken)
                if answer["ok"] or answer["error"]["code"] != "invalid_request":
                    raise Failure(f"malformed request ({name}) was not refused: {answer}")
                if not engine.call({"op": "ping"})["ok"]:
                    raise Failure("engine unusable after a refused request")
                seen["refused malformed request"] += 1
        except Failure as failure:
            raise Failure(f"{context}: {failure}\nrequest: {json.dumps(request)}") from None
        checked += 1
    return checked


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--engine", type=Path, required=True)
    parser.add_argument("--seed", type=int, action="append", help="repeat for several reproducible seeds")
    parser.add_argument("--cases", type=int, default=400, help="random requests per seed, after fixed cases")
    parser.add_argument("--timeout", type=float, default=30.0, help="seconds to wait for one response")
    args = parser.parse_args()
    if not 1 <= args.cases <= 100_000 or not 0 < args.timeout <= 600:
        parser.error("cases must be 1..100000 and timeout 0..600 seconds")
    seeds = args.seed or list(DEFAULT_SEEDS)
    total = 0
    seen: Counter = Counter()
    for seed in seeds:
        with tempfile.TemporaryDirectory() as root:
            engine = Engine(args.engine.resolve(), Path(root), args.timeout)
            try:
                total += run_seed(engine, seed, args.cases, seen)
            except Failure as failure:
                print(f"strings.stack model check failed: {failure}", file=sys.stderr)
                return 1
            finally:
                engine.close()
    missing = [name for name in REQUIRED_COVERAGE if not seen[name]]
    if missing and args.cases * len(seeds) >= 600:
        # A generator change that stops reaching an edge case must not pass quietly.
        print(f"strings.stack model check never reached: {', '.join(missing)}", file=sys.stderr)
        return 1
    print(json.dumps(dict(status="passed", seeds=seeds, cases=total, coverage=dict(sorted(seen.items())))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
