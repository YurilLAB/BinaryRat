#!/usr/bin/env python3
# Copyright 2026 YurilLAB
# SPDX-License-Identifier: Apache-2.0
"""Seeded robustness check of the `serve` wire contract through a real process.

Valid requests for every operation are damaged two ways: structurally (a field
replaced by a value of another type or range, removed, or nested deeper) and as
bytes (truncation, inserted control and non-UTF-8 bytes, repeated or removed
slices). Whatever arrives, the engine must keep running, answer each line once
and in order with a well-formed reply that carries the request's ID (null when
the line had no usable one), write valid UTF-8, and still give the same answers
to unchanged requests. Only `sched.acquire` may answer later; every such request
must be answered by the time the engine exits, and the exit must be clean.

Example: python protocol_fuzz.py --engine build/binaryrat-engine --seed 7 --cases 2000
"""

from __future__ import annotations

import argparse
from collections import Counter
import copy
import json
from pathlib import Path
import queue
import random
import subprocess
import sys
import tempfile
import threading
from typing import Any

DEFAULT_SEEDS = (0, 1, 20261121)
MAXIMUM_DEPTH = 64
MAXIMUM_LINE = 16 * 1024 * 1024
ERROR_CODES = ("invalid_request", "operation_failed")
# A process ID no system assigns: Windows IDs are multiples of four and Linux ones stay below 2^22.
# The scheduler may stop an attached process, so no request here ever names one that could exist.
SAFE_PIDS = (0, 0x7FFFFFF1, (1 << 32) + 5, 1 << 63, (1 << 64) - 1, 1 << 64, -1)
REQUIRED_COVERAGE = ("accepted", "refused", "null id", "invalid utf-8", "nested too deeply",
                     "deepest accepted", "late acquire answer", "scheduler event", "oversized line")

KEY_LIVE = {"schema_version": 2, "ghidra_version": "12.2", "kind": "decompile", "program_id": "sha256:p",
            "address_space": "ram", "address": "401000", "options_digest": "d"}
KEY_FIXED = {"schema_version": 1, "ghidra_version": "12.2", "program_id": "p", "revision": 3,
             "address_space": "ram", "address": "401000", "body_sha256": "b", "options_digest": "d"}
VALUE = {"output": {"c": "int f(void)\n{\n  return 1;\n}\n", "completed": True}, "reads": ["l:ram:401"],
         "always_verify": False}
CANARIES = [
    {"op": "ping"},
    {"op": "types.recover", "observations": [
        {"object_id": "o", "offset": 0, "width": 4, "evidence_id": "e1", "object_start_known": True},
        {"object_id": "o", "offset": 8, "width": 8, "evidence_id": "e2", "object_start_known": True,
         "storage_view": "floating_point", "stride": 16}], "maximum_extent": 4096},
    {"op": "types.solve", "summaries": [
        {"id": "f", "accesses": [{"offset": 0, "width": 4, "evidence_id": "a"}]},
        {"id": "g", "accesses": [{"offset": -8, "width": 8, "evidence_id": "b", "storage_view": "integer"}]}],
     "edges": [{"caller": "f", "callee": "g", "offset": 16, "evidence_id": "c"}],
     "roots": [{"summary": "f", "object_id": "o"}], "maximum_states": 64, "maximum_derived": 64},
    {"op": "strings.stack", "minimum_length": 4, "groups": [{"id": "g", "writes": [
        {"offset": -32, "bytes": "68656c6c", "order": 1}, {"offset": -28, "bytes": "6f00", "order": 2}]}]},
]
CACHE = [
    {"op": "cache.put", "key": KEY_LIVE, "value": VALUE, "dependencies": ["l:ram:401"], "as_of": 0},
    {"op": "cache.put", "key": KEY_FIXED, "value": VALUE, "dependencies": []},
    {"op": "cache.get", "key": KEY_LIVE},
    {"op": "cache.get", "key": KEY_FIXED},
    {"op": "cache.changed", "dependencies": ["l:ram:401", "s:other"]},
    {"op": "cache.changed", "all": True},
    {"op": "cache.invalidate", "dependencies": ["l:ram:401"]},
    {"op": "cache.confirm", "key": KEY_LIVE, "seq": 0, "generation": 0},
    {"op": "cache.evict", "key": KEY_LIVE},
    {"op": "cache.stats"},
]
CONFIGURE = {"op": "sched.configure", "cpu_workers": 2, "worker_cap": 2, "ram_bytes": 1 << 30,
             "jvm_reserve_bytes": 0, "other_reserve_bytes": 0, "worker_bytes": 1 << 20, "max_pending": 8,
             "memory_poll_ms": 50, "kill_grace_ms": 0}
LEASES = ("L0", "L1", "L2", "L3", "L4")
INTERESTING: list[Any] = [
    None, True, False, 0, 1, -1, 2, 64, 65, 255, 4096, 65536, 65537, (1 << 31) - 1, 1 << 31, 1 << 32,
    (1 << 53) + 1, (1 << 63) - 1, 1 << 63, (1 << 64) - 1, 1 << 64, -(1 << 63), -(1 << 63) - 1, 1 << 200,
    0.5, -0.0, 1e308, "", "x", "ping", "12.2", "integer", "\x00", "a\tb\r", "é中\U0001f600",
    "\\", "\"", "x" * 4096, [], {}, [[]], [1, "a", None], {"a": {"b": []}}, ["L0"] * 300,
]


class Failure(Exception):
    pass


def depth(value: Any) -> int:
    if isinstance(value, dict):
        return 1 + max(map(depth, value.values()), default=0)
    if isinstance(value, list):
        return 1 + max(map(depth, value), default=0)
    return 0


def nested(levels: int, rng: random.Random) -> Any:
    value: Any = rng.choice((1, "x", None))
    for _ in range(levels):
        value = [value] if rng.random() < 0.5 else {"n": value}
    return value


class Engine:
    def __init__(self, executable: Path, root: Path, timeout: float):
        self.timeout = timeout
        self.process = subprocess.Popen([str(executable), "serve", "--cache", str(root)],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL)
        self.lines: queue.Queue[bytes | None] = queue.Queue()
        threading.Thread(target=self._read, daemon=True).start()
        self.counter = 0
        self.pending: set[str] = set()
        self.last = b""
        self.configured = False

    def _read(self) -> None:
        for line in self.process.stdout:
            self.lines.put(line)
        self.lines.put(None)

    def token(self, rng: random.Random, kind: str = "r") -> str:
        self.counter += 1
        return f"{kind}{self.counter:07d}-{rng.getrandbits(40):010x}"

    def _line(self) -> dict[str, Any] | None:
        try:
            raw = self.lines.get(timeout=self.timeout)
        except queue.Empty:
            raise Failure("engine did not answer in time") from None
        if raw is None:
            return None
        if not raw.endswith(b"\n") or raw.endswith(b"\r\n"):
            raise Failure(f"reply is not one LF-terminated line: {raw[-40:]!r}")
        try:
            message = json.loads(raw.decode("utf-8", "strict"))
        except ValueError as error:
            raise Failure(f"reply is not UTF-8 JSON ({error}): {raw[:200]!r}") from None
        if not isinstance(message, dict) or message.get("protocol_version") != 1:
            raise Failure(f"reply is not a protocol 1 object: {message}")
        return message

    def _own(self, message: dict[str, Any], seen: Counter) -> bool:
        """Consumes a scheduler event or the late answer to an earlier sched.acquire."""
        if "event" in message:
            if not self.configured or message["event"] not in ("lease.stop", "lease.killed"):
                raise Failure(f"unexpected event: {message}")
            if message["event"] == "lease.killed":
                raise Failure(f"the engine killed a process: {message}")
            seen["scheduler event"] += 1
            return False
        if message.get("id") in self.pending:
            self.pending.discard(message["id"])
            check_shape(message)
            seen["late acquire answer"] += 1
            return False
        return True

    def exchange(self, line: bytes, rng: random.Random, seen: Counter) -> list[dict[str, Any]]:
        """Sends one line and a ping; returns the answers that arrived before the ping's."""
        sentinel = self.token(rng, "s")
        self.last = line
        self.process.stdin.write(line + b"\n" + json.dumps({"id": sentinel, "op": "ping"}).encode() + b"\n")
        self.process.stdin.flush()
        answers = []
        while True:
            message = self._line()
            if message is None:
                raise Failure(f"engine exited with {self.process.wait(timeout=10)}")
            if message.get("id") == sentinel:
                if message.get("ok") is not True:
                    raise Failure(f"ping failed after the request: {message}")
                return answers
            if self._own(message, seen):
                answers.append(message)

    def close(self, seen: Counter) -> None:
        self.process.stdin.close()
        while (message := self._line()) is not None:
            if self._own(message, seen):
                raise Failure(f"answer to no request at shutdown: {message}")
        code = self.process.wait(timeout=30)
        if code != 0:
            raise Failure(f"engine exited with {code} after end of input")
        if self.pending:
            raise Failure(f"sched.acquire requests never answered: {sorted(self.pending)}")

    def kill(self) -> None:
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait()


def check_shape(message: dict[str, Any]) -> None:
    if type(message.get("ok")) is not bool or "id" not in message:
        raise Failure(f"reply without ok or id: {message}")
    if message["ok"]:
        if "result" not in message or "error" in message:
            raise Failure(f"malformed success: {message}")
    else:
        error = message.get("error")
        if (not isinstance(error, dict) or error.get("code") not in ERROR_CODES or
                not isinstance(error.get("message"), str) or "result" in message):
            raise Failure(f"malformed error: {message}")


def slots(value: Any, found: list[tuple[Any, Any]]) -> list[tuple[Any, Any]]:
    children = value.items() if isinstance(value, dict) else enumerate(value) if isinstance(value, list) else ()
    for key, child in list(children):
        found.append((value, key))
        slots(child, found)
    return found


def damage(request: dict[str, Any], rng: random.Random) -> None:
    """One structural change; the result is still JSON both parsers read the same way."""
    container, key = rng.choice(slots(request, []))
    kind = rng.random()
    if key == "pid":
        container[key] = rng.choice(SAFE_PIDS + (None, "4", [], 0.5))
    elif kind < 0.55:
        container[key] = copy.deepcopy(rng.choice(INTERESTING))
    elif kind < 0.7:
        del container[key]
    elif kind < 0.8:
        # Deeper text than Python can build as a value is sent by the fixed cases.
        container[key] = nested(rng.choice((1, 3, 30, 60, 61, 62, 63, 64, 65, 200, 400)), rng)
    elif kind < 0.9 and isinstance(container, dict):
        container[rng.choice(("extra", "protocol_version", "all", "revision", "stride"))] = \
            copy.deepcopy(rng.choice(INTERESTING))
    else:
        container[key] = [copy.deepcopy(container[key])] * rng.choice((2, 17))


def corrupt(line: bytes, rng: random.Random) -> bytes:
    data = bytearray(line)
    for _ in range(rng.randint(1, 3)):
        kind, at = rng.randrange(7), rng.randrange(len(data) + 1)
        if kind == 0:
            del data[at:]
        elif kind == 1:
            data[at:at] = bytes(rng.choice(b"\x00\x1a\x1b\x7f\x80\xc3\xed\xa0\xff\"\\{}[],:0-e. \t\r")
                                for _ in range(rng.randint(1, 4)))
        elif kind == 2 and data:
            data[min(at, len(data) - 1)] ^= 1 << rng.randrange(8)
        elif kind == 3:
            del data[at:at + rng.randint(1, 12)]
        elif kind == 4:
            data[at:at] = data[at:at + rng.randint(1, 40)]
        elif kind == 5:
            data = bytearray(rng.choice((b"\xef\xbb\xbf", b"\xff\xfe", b"[", b" ")) + bytes(data))
        else:
            data = bytearray(rng.randbytes(rng.randint(0, 60)))
    return bytes(data).replace(b"\n", b"\x0b")


def run_case(engine: Engine, request: dict[str, Any], line: bytes, exact: bool, rng: random.Random,
             seen: Counter) -> list[dict[str, Any]]:
    answers = engine.exchange(line, rng, seen)
    usable = isinstance(request.get("id"), str)
    too_deep = exact and depth(request) > MAXIMUM_DEPTH
    deferred = (exact and usable and not too_deep and request.get("op") == "sched.acquire" and not answers)
    if deferred:
        engine.pending.add(request["id"])
        return answers
    if len(answers) != 1:
        raise Failure(f"expected one answer, got {len(answers)}: {answers}")
    answer = answers[0]
    check_shape(answer)
    if exact:
        expected = request["id"] if usable and not too_deep else None
        if answer["id"] != expected:
            raise Failure(f"answer ID {answer['id']!r}, expected {expected!r}")
        if too_deep:
            if answer["ok"] or answer["error"]["code"] != "invalid_request":
                raise Failure(f"request nested {depth(request)} deep was not refused: {answer}")
            seen["nested too deeply"] += 1
        elif usable and depth(request) == MAXIMUM_DEPTH:
            seen["deepest accepted"] += 1
    elif answer["id"] is not None and answer["id"] != request.get("id"):
        try:
            readable = json.loads(line)
        except ValueError:
            readable = None
        if not isinstance(readable, dict) or readable.get("id") != answer["id"]:
            raise Failure(f"answer ID {answer['id']!r} was not in the request")
    seen["null id" if answer["id"] is None else "accepted" if answer["ok"] else "refused"] += 1
    return answers


def prelude(engine: Engine, rng: random.Random, seen: Counter) -> None:
    """Fixed lines, each of which once ended or could end the engine."""
    def refused(line: bytes, label: str) -> None:
        answers = engine.exchange(line, rng, seen)
        if len(answers) != 1 or answers[0]["ok"] or answers[0]["id"] is not None or \
                answers[0]["error"]["code"] != "invalid_request":
            raise Failure(f"{label}: expected one invalid_request with a null ID, got {answers}")
        check_shape(answers[0])
        seen[label] += 1

    for raw in (b"\xff", b'{"id":"\xff","op":"ping"}', b'{"id":"1","op":"\xc3\x28"}', b"\xed\xa0\x80"):
        refused(raw, "invalid utf-8")
    for raw in (b"", b" \t\r", b"\x00", b'{"id":"1","op":"pi\x1ang"}', b"\x1a", b"null", b"[]", b'"ping"',
                b'{"id":"1","op":"ping"} x', b'{"id":"\\ud800","op":"ping"}', b"\xff\xfe{\x00}\x00"):
        refused(raw, "malformed line")
    put = dict(CACHE[0], id="deep")
    for levels in (2000, 200_000):
        text = json.dumps(dict(put, value=0)).replace('"value": 0', '"value": ' + "[" * levels + "]" * levels)
        refused(text.encode(), "nested too deeply")
        refused(("{\"a\":" * levels + "1" + "}" * levels).encode(), "nested too deeply")
    refused(b"[" * 200_000, "nested too deeply")
    refused(b" " * (MAXIMUM_LINE + 1), "oversized line")
    for raw in (b'{"id":"crlf","op":"ping"}\r', b'\xef\xbb\xbf{"id":"bom","op":"ping"}',
                b'{"id":"brackets","op":"ping","note":"' + b"[{" * 5000 + b'"}',
                b'{"id":"escaped","op":"ping","note":"\\"' + b"[" * 100 + b'"}'):
        answers = engine.exchange(raw, rng, seen)
        if len(answers) != 1 or answers[0].get("ok") is not True:
            raise Failure(f"valid line was refused: {raw[:60]!r} -> {answers}")
        seen["accepted"] += 1


def run_seed(executable: Path, seed: int, cases: int, timeout: float, scheduler: bool, fixed: bool,
             seen: Counter) -> int:
    """One engine process. With `scheduler`, leases come and go under a fixed configuration that
    never stops a process; without it, `sched.configure` itself is damaged and nothing is attached."""
    rng = random.Random(f"{seed}/{scheduler}")
    templates = CANARIES + CACHE + [{"op": "sched.stats"}, {"op": "sched.cancel", "lease": "L0"},
                                    {"op": "sched.release", "lease": "L0"},
                                    {"op": "sched.acquire", "lease": "L0", "timeout_ms": 20, "reserve_bytes": 0}]
    templates += [{"op": "sched.attach", "lease": "L0", "pid": SAFE_PIDS[1]}] if scheduler else [CONFIGURE] * 3
    with tempfile.TemporaryDirectory() as root:
        engine = Engine(executable, Path(root), timeout)
        request: dict[str, Any] = {}
        try:
            if fixed:
                prelude(engine, rng, seen)
            if scheduler:
                request = dict(CONFIGURE, id=engine.token(rng))
                line = json.dumps(request).encode()
                if run_case(engine, request, line, True, rng, seen)[0].get("ok") is not True:
                    raise Failure("the fixed scheduler configuration was refused")
            engine.configured = True
            baseline: dict[int, Any] = {}
            for index in range(cases):
                if index % 50 == 0:
                    for number, canary in enumerate(CANARIES):
                        request = dict(canary, id=engine.token(rng))
                        line = json.dumps(request).encode()
                        answer = run_case(engine, request, line, True, rng, seen)[0]
                        if answer.get("ok") is not True or baseline.setdefault(number, answer["result"]) != \
                                answer["result"]:
                            raise Failure(f"unchanged request answered differently: {answer}")
                request = copy.deepcopy(rng.choice(templates))
                if "lease" in request:
                    request["lease"] = rng.choice(LEASES)
                    if request["op"] == "sched.acquire":
                        request["timeout_ms"] = rng.choice((0, 1, 20, 200))
                request["id"] = engine.token(rng)
                mode = rng.random()
                if mode < 0.15:
                    exact = True
                elif mode < 0.65 or request["op"] in ("sched.acquire", "sched.attach"):
                    exact = True
                    for _ in range(rng.choice((1, 1, 2))):
                        damage(request, rng)
                else:
                    exact = False
                if request.get("op") == "sched.acquire" and isinstance(request.get("id"), str):
                    # Its answer may come much later, so its ID must not match another request's.
                    request["id"] = engine.token(rng)
                line = json.dumps(request, ensure_ascii=rng.random() < 0.5, allow_nan=False).encode()
                if not exact:
                    line = corrupt(line, rng)
                run_case(engine, request, line, exact, rng, seen)
            engine.close(seen)
        except Failure as failure:
            line = engine.last
            shown = line if len(line) <= 600 else line[:300] + b" ... " + line[-300:]
            raise Failure(f"seed {seed} scheduler={scheduler} request {engine.counter}: {failure}\n"
                          f"line: {shown!r}") from None
        finally:
            engine.kill()
    return cases


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--engine", type=Path, required=True)
    parser.add_argument("--seed", type=int, action="append", help="repeat for several reproducible seeds")
    parser.add_argument("--cases", type=int, default=400, help="damaged requests per seed and session kind")
    parser.add_argument("--timeout", type=float, default=30.0, help="seconds to wait for one response")
    args = parser.parse_args()
    if not 1 <= args.cases <= 100_000 or not 0 < args.timeout <= 600:
        parser.error("cases must be 1..100000 and timeout 0..600 seconds")
    seeds = args.seed or list(DEFAULT_SEEDS)
    seen: Counter = Counter()
    total = 0
    for seed in seeds:
        for scheduler in (False, True):
            try:
                total += run_seed(args.engine.resolve(), seed, args.cases, args.timeout, scheduler,
                                  seed == seeds[0], seen)
            except Failure as failure:
                print(f"protocol robustness check failed: {failure}", file=sys.stderr)
                return 1
    missing = [name for name in REQUIRED_COVERAGE if not seen[name]]
    if missing and args.cases * len(seeds) >= 1200:
        # A generator change that stops reaching an edge case must not pass quietly.
        print(f"protocol robustness check never reached: {', '.join(missing)}", file=sys.stderr)
        return 1
    print(json.dumps(dict(status="passed", seeds=seeds, cases=total, coverage=dict(sorted(seen.items())))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
