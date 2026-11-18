#!/usr/bin/env python3
# Copyright 2026 YurilLAB
# SPDX-License-Identifier: Apache-2.0
"""Seeded stateful property checks of the live cache over valid local JSONL.

Only synthetic fixture identities and metadata are used. This is a correctness
test of normal cache operations, not a binary, parser or security fuzzer. The
reference model retains complete change history; it independently derives which
entries may be trusted, including the engine's conservative journal cutoff.

Example: python live_cache_fuzz.py --engine build/binaryrat/binaryrat-engine \
    --seed 0 --seed 42 --steps 400
"""

from __future__ import annotations

import argparse
from collections import Counter, deque
from dataclasses import dataclass
import json
import math
from pathlib import Path
import queue
import random
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any


JOURNAL_LIMIT = 4096  # LiveCache's default, used by the JSONL session.
DEFAULT_SEEDS = (0, 1, 20261118)


@dataclass
class Entry:
    value: dict[str, Any]
    dependencies: frozenset[str]
    checked_at: int | None
    write: int
    generation: int | None = None


@dataclass(frozen=True)
class Check:
    key: int
    seq: int
    generation: int
    write: int | None


class Peer:
    """One actual engine process; all requests are small, ordinary cache calls."""

    def __init__(self, engine: Path, root: Path, deadline: float):
        self.deadline = deadline
        self.stderr = tempfile.TemporaryFile(mode="w+b")
        self.process = subprocess.Popen(
            [str(engine), "serve", "--cache", str(root)], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=self.stderr, text=True,
            encoding="utf-8", bufsize=1,
        )
        self.responses: queue.Queue[Any] = queue.Queue(maxsize=4)
        self.request_id = 0
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self) -> None:
        try:
            assert self.process.stdout is not None
            for line in self.process.stdout:
                self.responses.put(json.loads(line))
            self.responses.put(EOFError("engine closed stdout"))
        except Exception as error:
            self.responses.put(error)

    def call(self, op: str, **fields: Any) -> dict[str, Any]:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise AssertionError("seed exceeded its time budget")
        self.request_id += 1
        request = dict(id=f"f{self.request_id}", protocol_version=1, op=op, **fields)
        assert self.process.stdin is not None
        self.process.stdin.write(json.dumps(request, allow_nan=False) + "\n")
        self.process.stdin.flush()
        try:
            response = self.responses.get(timeout=min(5.0, remaining))
        except queue.Empty as error:
            raise AssertionError(f"engine response deadline exceeded for {op}") from error
        if isinstance(response, Exception):
            raise AssertionError(str(response)) from response
        if not isinstance(response, dict) or response.get("id") != request["id"]:
            raise AssertionError(f"unexpected response: {response!r}")
        if type(response.get("protocol_version")) is not int or response["protocol_version"] != 1:
            raise AssertionError(f"bad protocol version: {response!r}")
        if response.get("ok") is not True or not isinstance(response.get("result"), dict):
            raise AssertionError(f"valid operation failed: {response!r}")
        return response["result"]

    def close(self) -> None:
        try:
            if self.process.stdin is not None and not self.process.stdin.closed:
                self.process.stdin.close()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
                raise AssertionError("engine did not stop after EOF")
            if self.process.returncode:
                self.stderr.seek(0)
                detail = self.stderr.read(4096).decode("utf-8", errors="replace")
                raise AssertionError(f"engine exited {self.process.returncode}: {detail}")
        finally:
            if self.process.poll() is None:
                self.process.kill()
                self.process.wait(timeout=3)
            if self.process.stdout is not None:
                self.process.stdout.close()
            self.reader.join(timeout=1)
            self.stderr.close()


class Run:
    def __init__(self, engine: Path, root: Path, seed: int, seconds: float):
        self.engine, self.root, self.seed = engine, root, seed
        self.rng = random.Random(seed)
        self.deadline = time.monotonic() + seconds
        self.peer = Peer(engine, root, self.deadline)
        self.entries: dict[int, Entry] = {}
        self.history: list[frozenset[str] | None] = []
        self.last_unknown = 0
        self.hits = self.unverified_hits = self.misses = self.removed = 0
        self.writes = self.requests = self.restarts = 0
        self.operations: Counter[str] = Counter()
        self.saved: list[Check] = []
        self.trace: deque[dict[str, Any]] = deque(maxlen=12)
        self.step: int | str = "initialization"
        self.active: dict[str, Any] = {}
        self.keys = [dict(schema_version=2, ghidra_version="12.2", kind="decompile",
                          program_id=f"fixture:seed:{seed}",
                          address_space="ram" if key < 6 else "fixture-overlay",
                          address=f"{0x1000 + (key % 6) * 16:x}",
                          options_digest="fixture-options-v1") for key in range(12)]
        self.dependencies = [f"fixture:type:{index}" for index in range(8)]

    @property
    def seq(self) -> int:
        return len(self.history)

    def trusted(self, entry: Entry) -> bool:
        return entry.checked_at is not None and entry.checked_at >= self.last_unknown

    def call(self, op: str, **fields: Any) -> dict[str, Any]:
        self.active = dict(op=op, **fields)
        self.requests += 1
        self.operations[op] += 1
        result = self.peer.call(op, **fields)
        self.trace.append(dict(step=self.step, request=self.active, result=result))
        return result

    def expect(self, actual: Any, expected: Any, label: str) -> None:
        if actual != expected:
            raise AssertionError(f"{label}: expected {expected!r}, got {actual!r}")

    def get(self, key: int) -> Check:
        # A key's object-field order is not part of its identity.
        pairs = list(self.keys[key].items())
        self.rng.shuffle(pairs)
        result = self.call("cache.get", key=dict(pairs))
        entry = self.entries.get(key)
        expected = dict(hit=entry is not None, verified=bool(entry and self.trusted(entry)),
                        value=entry.value if entry else None, seq=self.seq)
        for field, value in expected.items():
            self.expect(result.get(field), value, f"get[{key}].{field}")
        generation = result.get("generation")
        if type(generation) is not int or generation < 0:
            raise AssertionError(f"invalid generation {generation!r}")
        if entry:
            if entry.generation is not None:
                self.expect(generation, entry.generation, "generation changed without a write")
            entry.generation = generation
            self.hits += 1
            self.unverified_hits += not self.trusted(entry)
        else:
            self.misses += 1
        check = Check(key, self.seq, generation, entry.write if entry else None)
        self.saved.append(check)
        return check

    def affected(self, as_of: int, dependencies: frozenset[str]) -> bool:
        # The complete reference history makes dependency reach explicit. The
        # production engine must also distrust work older than its retained log.
        if as_of < max(0, self.seq - JOURNAL_LIMIT):
            return True
        return any(change is None or bool(change & dependencies)
                   for change in self.history[as_of:])

    def put(self, key: int, dependencies: list[str], as_of: int | None = None) -> None:
        previous = self.entries.get(key)
        self.writes += 1
        value = dict(fixture="synthetic-metadata", key=key, write=self.writes,
                     content_digest=f"fixture-content-{self.writes}")
        fields: dict[str, Any] = dict(key=self.keys[key], value=value, dependencies=dependencies)
        if as_of is not None:
            fields["as_of"] = as_of
        self.expect(self.call("cache.put", **fields), {"stored": True}, "put result")
        deps = frozenset(dependencies)
        checked = self.seq if as_of is None or not self.affected(as_of, deps) else None
        self.entries[key] = Entry(value, deps, checked, self.writes)
        found = self.get(key)
        if previous and previous.generation == found.generation:
            raise AssertionError("overwriting an entry did not change its generation")

    def changed(self, dependencies: list[str] | None) -> None:
        if dependencies is None:
            result = self.call("cache.changed", all=True)
            self.history.append(None)
            self.last_unknown = self.seq
            removed = 0
        else:
            # cache.invalidate and cache.changed must have the same dependency semantics.
            op = self.rng.choice(("cache.changed", "cache.invalidate"))
            result = self.call(op, dependencies=dependencies)
            touched = frozenset(dependencies)
            self.history.append(touched)
            victims = [key for key, entry in self.entries.items() if entry.dependencies & touched]
            removed = len(victims)
            for key in victims:
                del self.entries[key]
        self.removed += removed
        self.expect(result, dict(removed=removed, seq=self.seq), "change result")

    def confirm(self, check: Check) -> None:
        entry = self.entries.get(check.key)
        expected = entry is not None and entry.write == check.write
        result = self.call("cache.confirm", key=self.keys[check.key],
                           seq=check.seq, generation=check.generation)
        self.expect(result, dict(confirmed=expected), "confirm result")
        if expected:
            assert entry is not None
            entry.checked_at = max(entry.checked_at or 0, check.seq)

    def evict(self, key: int) -> None:
        expected = key in self.entries
        self.expect(self.call("cache.evict", key=self.keys[key]), dict(removed=expected), "evict result")
        self.entries.pop(key, None)
        self.removed += expected

    def stats(self) -> None:
        expected = dict(entries=len(self.entries), verified=sum(map(self.trusted, self.entries.values())),
                        dependencies=len(set().union(*(entry.dependencies for entry in self.entries.values()))),
                        journal=min(self.seq, JOURNAL_LIMIT), seq=self.seq, hits=self.hits,
                        unverified_hits=self.unverified_hits, misses=self.misses, removed=self.removed)
        self.expect(self.call("cache.stats"), expected, "stats")

    def audit(self) -> None:
        for key in range(len(self.keys)):
            self.get(key)
        self.stats()

    def restart(self) -> None:
        self.step = f"{self.step}/restart"
        self.peer.close()
        self.peer = Peer(self.engine, self.root, self.deadline)
        self.restarts += 1
        self.history.clear()
        self.last_unknown = 0
        self.saved.clear()  # Lookup tokens belong to a session, not the disk store.
        self.hits = self.unverified_hits = self.misses = self.removed = 0
        for entry in self.entries.values():
            entry.checked_at = None
            entry.generation = None
        self.audit()

    def prelude(self) -> None:
        """Guarantee difficult transitions even for a very short random run."""
        self.step = "prelude/replay"
        self.put(0, [self.dependencies[0], self.dependencies[0]])
        old = self.get(0)
        self.put(0, [self.dependencies[1]])
        self.confirm(old)  # A prior generation cannot confirm a rewritten value.
        self.changed([self.dependencies[0]])  # Replaced dependencies must be unindexed.
        current = self.get(0)
        self.changed(None)
        self.confirm(current)  # A replay before an unknown change cannot restore trust.
        self.get(0)
        self.confirm(self.get(0))
        self.get(0)
        start = self.seq
        self.changed([self.dependencies[2]])
        self.put(1, [self.dependencies[3]], as_of=start)  # Unrelated change is safe.
        self.put(2, [self.dependencies[2]], as_of=start)  # Affected work stays unverified.
        self.restart()
        self.step = "prelude/journal-rollover"
        for _ in range(JOURNAL_LIMIT + 1):
            self.changed([])
        self.put(3, [], as_of=0)  # Forgotten history cannot establish trust.
        self.audit()

    def random_steps(self, count: int) -> None:
        for index in range(count):
            self.step = index
            choice, key = self.rng.randrange(100), self.rng.randrange(len(self.keys))
            if choice < 28:
                deps = self.rng.choices(self.dependencies, k=self.rng.randrange(5))
                as_of = None if self.rng.randrange(3) == 0 else self.rng.randrange(self.seq + 1)
                self.put(key, deps, as_of)
            elif choice < 48:
                self.get(key)
            elif choice < 65:
                self.changed(self.rng.choices(self.dependencies, k=self.rng.randrange(4)))
            elif choice < 73:
                self.changed(None)
            elif choice < 82:
                if self.saved:
                    self.confirm(self.rng.choice(self.saved))
                else:
                    self.confirm(self.get(key))
            elif choice < 88:
                self.evict(key)
            elif choice < 92:
                self.restart()
            else:
                self.stats()
            if index % 32 == 0:
                self.audit()
            else:
                self.stats()
        self.audit()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", type=Path, required=True)
    parser.add_argument("--seed", type=int, action="append", help="repeat for multiple reproducible seeds")
    parser.add_argument("--steps", type=int, default=400, help="random operations per seed, after fixed edge cases")
    parser.add_argument("--timeout", type=float, default=30.0, help="maximum seconds per seed")
    args = parser.parse_args()
    if not 1 <= args.steps <= 100_000:
        parser.error("steps must be in 1..100000")
    if not math.isfinite(args.timeout) or not 0 < args.timeout <= 600:
        parser.error("timeout must be finite and in (0,600]")
    seeds = args.seed if args.seed is not None else list(DEFAULT_SEEDS)
    if len(seeds) > 32:
        parser.error("at most 32 seeds may be supplied")
    engine = args.engine.resolve()
    if not engine.is_file():
        parser.error("engine must name the local native executable")
    reports = []
    for seed in seeds:
        started = time.monotonic()
        with tempfile.TemporaryDirectory(prefix="binaryrat-live-cache-") as directory:
            run = None
            try:
                run = Run(engine, Path(directory), seed, args.timeout)
                run.prelude()
                run.random_steps(args.steps)
                run.peer.close()
                reports.append(dict(seed=seed, steps=args.steps, requests=run.requests,
                                    restarts=run.restarts, operations=dict(run.operations),
                                    seconds=round(time.monotonic() - started, 6)))
            except Exception as error:
                failure = dict(status="failed", seed=seed,
                               operation_index=run.step if run else "startup", error=str(error))
                if run:
                    failure.update(request=run.active, recent_operations=list(run.trace))
                    try:
                        run.peer.close()
                    except Exception:
                        pass
                print(json.dumps(failure, indent=2), file=sys.stderr)
                return 1
    print(json.dumps(dict(status="passed", test="live-cache-model", synthetic_metadata_only=True,
                         journal_limit=JOURNAL_LIMIT, runs=reports), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
