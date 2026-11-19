#!/usr/bin/env python3
# Copyright 2026 YurilLAB
# SPDX-License-Identifier: Apache-2.0
"""Seeded model check of `types.solve` through a real `serve` process.

Random call graphs of parameter summaries (cycles, self calls, parallel and
duplicate edges, interior pointers, signed 64-bit extremes) are solved by the
engine and by an independent Python oracle:

- components from Floyd-Warshall reachability, consistency from enumerating
  every simple cycle and the members' positions;
- reached states from a fixed-point closure, hops from a separate search;
- layouts from a re-implementation of the aggregation rules.

The engine's provenance (edge and parent of every state) is checked to be a
valid shortest path, and each case is re-solved with summaries, accesses and
edges shuffled, which must give the same facts. Malformed requests must fail
with invalid_request and leave the process usable.

Example: python types_solve_fuzz.py --engine build/binaryrat-engine --seed 7 --cases 500
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict, deque
import json
from pathlib import Path
import queue
import random
import subprocess
import sys
import tempfile
import threading
from typing import Any

INT64_MAX = (1 << 63) - 1
INT64_MIN = -(1 << 63)
UINT64_MAX = (1 << 64) - 1
DEFAULT_SEEDS = (0, 1, 20261119)
DEFAULT_STATES = 4096
DEFAULT_DERIVED = 16384
DEFAULT_EXTENT = 1 << 32
INTEGER_WIDTHS = {1, 2, 4, 8}
FLOAT_WIDTHS = {4, 8}


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
        self.process.stdin.write(json.dumps(request, ensure_ascii=False) + "\n")
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

def fits(value: int) -> bool:
    return INT64_MIN <= value <= INT64_MAX


def canonical_edges(request: dict[str, Any]) -> list[int]:
    """Indices of unique edges; equal tuples keep their lowest index."""
    seen: dict[tuple, int] = {}
    for index, edge in enumerate(request["edges"]):
        seen.setdefault((edge["caller"], edge["callee"], edge["offset"], edge["evidence_id"]), index)
    return sorted(seen.values())


def components(request: dict[str, Any]) -> list[dict[str, Any]]:
    ids = [s["id"] for s in request["summaries"]]
    reach = {a: {b: a == b for b in ids} for a in ids}
    for edge in request["edges"]:
        reach[edge["caller"]][edge["callee"]] = True
    for k in ids:
        for i in ids:
            if reach[i][k]:
                for j in ids:
                    if reach[k][j]:
                        reach[i][j] = True
    groups: list[list[str]] = []
    placed: set[str] = set()
    for node in sorted(ids):
        if node in placed:
            continue
        group = sorted(other for other in ids if reach[node][other] and reach[other][node])
        placed.update(group)
        groups.append(group)
    result = []
    for group in sorted(groups):
        members = set(group)
        internal = [i for i, e in enumerate(request["edges"])
                    if e["caller"] in members and e["callee"] in members]
        if len(group) == 1 and not internal:
            continue
        result.append(dict(summaries=group, consistent=consistent(request, group, internal),
                           internal=internal))
    return result


def consistent(request: dict[str, Any], group: list[str], internal: list[int]) -> bool:
    edges = [request["edges"][i] for i in internal]
    # Every simple cycle (parallel edges distinct) must sum to zero.
    outgoing = defaultdict(list)
    for edge in edges:
        outgoing[edge["caller"]].append(edge)
    order = {node: index for index, node in enumerate(group)}

    def cycles_from(start: str) -> bool:
        stack = [(start, 0, {start})]
        while stack:
            node, total, visited = stack.pop()
            for edge in outgoing[node]:
                target = edge["callee"]
                if target == start:
                    if total + edge["offset"] != 0:
                        return False
                elif target not in visited and order[target] > order[start]:
                    stack.append((target, total + edge["offset"], visited | {target}))
        return True

    if not all(cycles_from(node) for node in group):
        return False
    # Positions relative to the smallest member must fit a signed 64-bit value.
    position = {group[0]: 0}
    pending = deque([group[0]])
    while pending:
        node = pending.popleft()
        for edge in outgoing[node]:
            if edge["callee"] not in position:
                position[edge["callee"]] = position[node] + edge["offset"]
                pending.append(edge["callee"])
    return all(fits(value) for value in position.values())


def reject_reason(object_id: str, offset: int, width: int, evidence: str, extent: int) -> str | None:
    if not object_id:
        return "empty object ID"
    if not evidence:
        return "empty evidence ID"
    if offset < 0:
        return "negative offset"
    if width == 0:
        return "zero access width"
    if offset + width > UINT64_MAX:
        return "offset plus width overflows"
    if offset + width > extent:
        return "object extent exceeds configured limit"
    return None


def layout(object_id: str, rows: list[tuple[int, int, str, str | None]], extent: int):
    fields: dict[tuple[int, int], dict[str, Any]] = {}
    for offset, width, evidence, view in rows:
        if reject_reason(object_id, offset, width, evidence, extent):
            continue
        field = fields.setdefault((offset, width), dict(ids=set(), views=defaultdict(set)))
        field["ids"].add(evidence)
        supported = (view == "integer" and width in INTEGER_WIDTHS) or \
                    (view == "floating_point" and width in FLOAT_WIDTHS)
        if supported:
            field["views"][view].add(evidence)
    if not fields:
        return None
    out_fields = []
    union_views: dict[int, list[tuple[str, int, list[str]]]] = defaultdict(list)
    for (offset, width) in sorted(fields):
        field = fields[(offset, width)]
        count = len(field["ids"])
        out_fields.append(dict(offset=offset, width=width, stride=None,
                               evidence_ids=sorted(field["ids"]), evidence_strength=count / (count + 1.0),
                               overlaps_other_fields=False, stride_conflict=False,
                               stride_overlaps_access=False))
        for kind in ("integer", "floating_point"):
            if field["views"].get(kind):
                union_views[offset].append((kind, width, sorted(field["views"][kind])))
    candidates = []
    for offset in sorted(union_views):
        views = union_views[offset]
        occurrences = defaultdict(int)
        for _, _, ids in views:
            for evidence in ids:
                occurrences[evidence] += 1
        kept = [(kind, width, [i for i in ids if occurrences[i] == 1]) for kind, width, ids in views]
        kept = [view for view in kept if view[2]]
        kinds = {view[0] for view in kept}
        if {"integer", "floating_point"} <= kinds:
            count = sum(len(view[2]) for view in kept)
            candidates.append(dict(offset=offset, evidence_strength=count / (count + 1.0),
                                   views=[dict(kind=k, width=w, evidence_ids=i) for k, w, i in kept]))
    earlier_end = 0
    has_overlaps = False
    for index, field in enumerate(out_fields):
        end = field["offset"] + field["width"]
        later = index + 1 < len(out_fields) and out_fields[index + 1]["offset"] < end
        field["overlaps_other_fields"] = field["offset"] < earlier_end or later
        has_overlaps |= field["overlaps_other_fields"]
        earlier_end = max(earlier_end, end)
    return dict(object_id=object_id, fields=out_fields, union_candidates=candidates,
                minimum_extent=max(f["offset"] + f["width"] for f in out_fields),
                has_overlaps=has_overlaps, has_stride_conflicts=False, has_overlapping_stride=False)


def oracle_root(request: dict[str, Any], comps: list[dict[str, Any]], root: dict[str, str]):
    states_limit = request.get("maximum_states", DEFAULT_STATES)
    derived_limit = request.get("maximum_derived", DEFAULT_DERIVED)
    extent = request.get("maximum_extent", DEFAULT_EXTENT)
    withheld = {}
    for index, comp in enumerate(comps):
        if not comp["consistent"]:
            for edge in comp["internal"]:
                withheld[edge] = index
    usable = [i for i in canonical_edges(request) if i not in withheld]
    edges = request["edges"]
    summaries = {s["id"]: s for s in request["summaries"]}

    # Fixed-point closure over (summary, offset); offsets beyond int64 are dropped.
    states = {(root["summary"], 0)}
    changed = True
    while changed and len(states) <= states_limit:
        changed = False
        for summary, offset in list(states):
            for index in usable:
                edge = edges[index]
                target = (edge["callee"], offset + edge["offset"])
                if edge["caller"] == summary and fits(target[1]) and target not in states:
                    states.add(target)
                    changed = True
    if len(states) > states_limit:
        return dict(status="state_limit")
    distance = {(root["summary"], 0): 0}
    frontier = deque([(root["summary"], 0)])
    while frontier:
        summary, offset = frontier.popleft()
        for index in usable:
            edge = edges[index]
            target = (edge["callee"], offset + edge["offset"])
            if edge["caller"] == summary and fits(target[1]) and target not in distance:
                distance[target] = distance[(summary, offset)] + 1
                frontier.append(target)
    assert set(distance) == states
    overflowed = 0
    touched = set()
    for summary, offset in states:
        for index in canonical_edges(request):
            edge = edges[index]
            if edge["caller"] != summary:
                continue
            if index in withheld:
                touched.add(withheld[index])
            elif not fits(offset + edge["offset"]):
                overflowed += 1
    derived = []
    for summary, offset in states:
        for access in summaries[summary]["accesses"]:
            total = offset + access["offset"]
            if not fits(total):
                overflowed += 1
                continue
            derived.append((summary, offset, access["offset"], access["width"],
                            access["evidence_id"], access.get("storage_view"), total))
    if len(derived) > derived_limit:
        return dict(status="derived_limit")
    rows = [(d[6], d[3], d[4], d[5]) for d in derived]
    return dict(status="solved", states={s: distance[s] for s in states}, derived=sorted(derived, key=repr),
                overflowed=overflowed, withheld=sorted(touched),
                complete=not touched and overflowed == 0,
                layout=layout(root["object_id"], rows, extent))


# ---------------------------------------------------------------- comparison

def check(request: dict[str, Any], result: dict[str, Any], seen: Counter) -> None:
    comps = components(request)
    for comp in comps:
        seen["consistent component" if comp["consistent"] else "inconsistent component"] += 1
    actual = result["components"]
    expect([dict(summaries=c["summaries"], consistent=c["consistent"],
                 withheld_edges=[] if c["consistent"] else c["internal"]) for c in comps],
           actual, "components")
    expect(len(request["roots"]), len(result["roots"]), "root count")
    for root, answer in zip(request["roots"], result["roots"]):
        model = oracle_root(request, comps, root)
        expect(model["status"], answer["status"], "root status")
        seen["root " + model["status"]] += 1
        expect((root["summary"], root["object_id"]), (answer["summary"], answer["object_id"]), "root echo")
        if model["status"] != "solved":
            expect(([], [], None, False), (answer["states"], answer["derived"], answer["layout"],
                                            answer["complete"]), "limited root output")
            continue
        states = answer["states"]
        expect(model["states"], {(s["summary"], s["offset"]): s["hops"] for s in states}, "states and hops")
        expect(len(model["states"]), len(states), "duplicate states")
        expect((None, None, 0), (states[0]["edge"], states[0]["parent"], states[0]["hops"]), "root state")
        expect((root["summary"], 0), (states[0]["summary"], states[0]["offset"]), "root state identity")
        canonical = set(canonical_edges(request))
        for index, state in enumerate(states[1:], start=1):
            if state["edge"] not in canonical:
                raise Failure(f"state {index} names a duplicate edge instead of the lowest index: {state}")
            parent = states[state["parent"]]
            edge = request["edges"][state["edge"]]
            if not (state["parent"] < index and edge["caller"] == parent["summary"] and
                    edge["callee"] == state["summary"] and
                    parent["offset"] + edge["offset"] == state["offset"] and
                    parent["hops"] + 1 == state["hops"]):
                raise Failure(f"state {index} provenance is not a valid path step: {state}")
        summaries = {s["id"]: s for s in request["summaries"]}
        engine_derived = []
        for row in answer["derived"]:
            state = states[row["state"]]
            access = summaries[state["summary"]]["accesses"][row["access"]]
            expect((access["offset"] + state["offset"], access["width"], access["evidence_id"],
                    access.get("storage_view")),
                   (row["offset"], row["width"], row["evidence_id"], row.get("storage_view")), "derived row")
            engine_derived.append((state["summary"], state["offset"], access["offset"], access["width"],
                                   access["evidence_id"], access.get("storage_view"), row["offset"]))
        expect(model["derived"], sorted(engine_derived, key=repr), "derived accesses")
        expect((model["overflowed"], model["withheld"], model["complete"]),
               (answer["overflowed"], answer["withheld_components"], answer["complete"]), "completeness")
        expect(model["layout"], answer["layout"], "layout")
        seen["withheld root"] += bool(model["withheld"])
        seen["overflowed root"] += bool(model["overflowed"])
        seen["union candidate"] += bool(model["layout"] and model["layout"]["union_candidates"])
        seen["overlapping fields"] += bool(model["layout"] and model["layout"]["has_overlaps"])
        seen["state reached twice by offset"] += len({s for s, _ in model["states"]}) < len(model["states"])
        seen["hops above 2"] += max(model["states"].values()) > 2
        extent = request.get("maximum_extent", DEFAULT_EXTENT)
        rejected = []
        for index, row in enumerate(answer["derived"]):
            reason = reject_reason(root["object_id"], row["offset"], row["width"], row["evidence_id"], extent)
            if reason:
                rejected.append(dict(derived_index=index, reason=reason))
                seen["rejected: " + reason] += 1
        expect(rejected, answer["rejected"], "rejections")


def expect(expected: Any, actual: Any, label: str) -> None:
    if expected != actual:
        raise Failure(f"{label}: expected {json.dumps(expected, default=str)[:2000]}\n"
                      f"actual {json.dumps(actual, default=str)[:2000]}")


def normalized(request: dict[str, Any], result: dict[str, Any]) -> Any:
    """Facts that must not depend on input order."""
    def edge(index):
        e = request["edges"][index]
        return (e["caller"], e["callee"], e["offset"], e["evidence_id"])
    comps = [(c["summaries"], c["consistent"], sorted(edge(i) for i in c["withheld_edges"]))
             for c in result["components"]]
    roots = []
    for answer in result["roots"]:
        states = sorted((s["summary"], s["offset"], s["hops"]) for s in answer["states"])
        derived = sorted((answer["states"][d["state"]]["summary"], d["offset"], d["width"], d["evidence_id"],
                          d.get("storage_view", "")) for d in answer["derived"])
        roots.append((answer["status"], states, derived, answer["layout"], answer["overflowed"],
                      answer["withheld_components"], len(answer["rejected"])))
    return comps, roots


# ---------------------------------------------------------------- generation

def generate(rng: random.Random) -> dict[str, Any]:
    alphabet = ["a", "b", "B", "z", "_", "0", "é", "日"]
    count = rng.randint(1, 7)
    ids: list[str] = []
    while len(ids) < count:
        candidate = "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 3)))
        if candidate not in ids:
            ids.append(candidate)
    huge = rng.random() < 0.1

    def offset(scale: int) -> int:
        if huge and rng.random() < 0.3:
            return rng.choice([INT64_MAX, INT64_MIN, INT64_MAX - 7, INT64_MIN + 8, 1 << 62, -(1 << 62)])
        return rng.randint(-3, 5) * scale

    shared_evidence = [f"shared{i}" for i in range(3)]
    summaries = []
    for summary_id in ids:
        accesses = []
        for item in range(rng.randint(0, 4)):
            width = rng.choice([1, 2, 4, 8, 8, 4, 0, 16]) if rng.random() < 0.95 else UINT64_MAX
            access = dict(offset=offset(4), width=width,
                          evidence_id=rng.choice(shared_evidence + [f"{summary_id}#{item}"] * 3 + [""]))
            view = rng.choice([None, None, "integer", "floating_point"])
            if view:
                access["storage_view"] = view
            accesses.append(access)
        summaries.append(dict(id=summary_id, accesses=accesses))
    # "random" makes most cycles drift; "positions" derives offsets from node
    # positions so cycles sum to zero unless an edge is perturbed; "chain" adds depth.
    mode = rng.choice(["random", "positions", "positions", "chain"])
    position = {summary_id: rng.randint(-2, 4) * 8 for summary_id in ids}
    pairs = [(rng.choice(ids), rng.choice(ids)) for _ in range(rng.randint(0, 3 * count))]
    if mode == "chain":
        pairs = [(ids[i], ids[i + 1]) for i in range(count - 1)] + pairs[:2]
    edges = []
    for caller, callee in pairs:
        if mode == "random" or rng.random() < 0.1:
            delta = offset(8)
        else:
            delta = position[callee] - position[caller]
        edge = dict(caller=caller, callee=callee, offset=delta, evidence_id=rng.choice(["s0", "s1", "s2"]))
        edges.append(edge)
        if rng.random() < 0.1:
            edges.append(dict(edge))
    roots = [dict(summary=rng.choice(ids), object_id=rng.choice(["obj", "other", ""]))
             for _ in range(rng.randint(1, 3))]
    request = dict(op="types.solve", summaries=summaries, edges=edges, roots=roots)
    if rng.random() < 0.3:
        request["maximum_states"] = rng.randint(0, 12)
    if rng.random() < 0.3:
        request["maximum_derived"] = rng.randint(0, 12)
    if rng.random() < 0.3:
        request["maximum_extent"] = rng.choice([0, 8, 24, 64, UINT64_MAX])
    return request


def shuffled(request: dict[str, Any], rng: random.Random) -> dict[str, Any]:
    copy = json.loads(json.dumps(request))
    rng.shuffle(copy["summaries"])
    for summary in copy["summaries"]:
        rng.shuffle(summary["accesses"])
    rng.shuffle(copy["edges"])
    return copy


INVALID_MUTATIONS = [
    ("unknown callee", lambda r: r["edges"].append(dict(caller=r["summaries"][0]["id"], callee="\u0000missing",
                                                         offset=0, evidence_id="x"))),
    ("duplicate summary", lambda r: r["summaries"].append(dict(r["summaries"][0]))),
    ("empty summary id", lambda r: r["summaries"].append(dict(id="", accesses=[]))),
    ("float offset", lambda r: r["edges"].append(dict(caller=r["summaries"][0]["id"],
                                                       callee=r["summaries"][0]["id"], offset=1.5,
                                                       evidence_id="x"))),
    ("offset beyond int64", lambda r: r["summaries"][0]["accesses"].append(
        dict(offset=INT64_MAX + 1, width=1, evidence_id="x"))),
    ("negative width", lambda r: r["summaries"][0]["accesses"].append(dict(offset=0, width=-1, evidence_id="x"))),
    ("bad view", lambda r: r["summaries"][0]["accesses"].append(
        dict(offset=0, width=4, evidence_id="x", storage_view="pointer"))),
    ("no roots", lambda r: r.__setitem__("roots", [])),
    ("too many roots", lambda r: r.__setitem__("roots", [dict(r["roots"][0])] * 17)),
    ("unknown root", lambda r: r["roots"].append(dict(summary="\u0000missing", object_id="o"))),
    ("state limit too large", lambda r: r.__setitem__("maximum_states", 65537)),
    ("derived limit negative", lambda r: r.__setitem__("maximum_derived", -1)),
    ("edges not array", lambda r: r.__setitem__("edges", {})),
    ("accesses missing", lambda r: r["summaries"][0].pop("accesses")),
    ("id not string", lambda r: r["summaries"][0].__setitem__("id", 7)),
    ("evidence not string", lambda r: r["edges"].append(dict(caller=r["summaries"][0]["id"],
                                                            callee=r["summaries"][0]["id"], offset=0,
                                                            evidence_id=None))),
]


def prelude() -> list[dict[str, Any]]:
    def summary(name, *accesses):
        return dict(id=name, accesses=[dict(offset=o, width=w, evidence_id=e) for o, w, e in accesses])

    def edge(caller, callee, offset, evidence="site"):
        return dict(caller=caller, callee=callee, offset=offset, evidence_id=evidence)

    cases = [
        # container_of through a callee, plus a consistent mutual recursion
        dict(summaries=[summary("r", (0, 8, "r")), summary("a", (-8, 4, "a")), summary("b", (0, 4, "b"))],
             edges=[edge("r", "a", 16), edge("a", "b", 8), edge("b", "a", -8)],
             roots=[dict(summary="r", object_id="o")]),
        # list walk: a nonzero self call
        dict(summaries=[summary("w", (0, 8, "next"))], edges=[edge("w", "w", 16)],
             roots=[dict(summary="w", object_id="o")]),
        # int64 extremes along a path and on an access
        dict(summaries=[summary("r"), summary("x", (1, 1, "over"), (-1, 1, "fits"))],
             edges=[edge("r", "x", INT64_MAX)], roots=[dict(summary="r", object_id="o")],
             maximum_extent=UINT64_MAX),
        # a zero-sum cycle whose positions leave the int64 range
        dict(summaries=[summary("a", (0, 1, "a")), summary("b"), summary("c")],
             edges=[edge("a", "b", INT64_MAX), edge("b", "c", 1), edge("c", "a", INT64_MIN)],
             roots=[dict(summary="a", object_id="o")]),
        # exact limits
        dict(summaries=[summary("a", (0, 1, "a")), summary("b", (0, 1, "b"))], edges=[edge("a", "b", 1)],
             roots=[dict(summary="a", object_id="o")], maximum_states=2, maximum_derived=2),
        dict(summaries=[summary("a", (0, 1, "a")), summary("b", (0, 1, "b"))], edges=[edge("a", "b", 1)],
             roots=[dict(summary="a", object_id="o")], maximum_states=1),
        dict(summaries=[summary("a", (0, 1, "a")), summary("b", (0, 1, "b"))], edges=[edge("a", "b", 1)],
             roots=[dict(summary="a", object_id="o")], maximum_derived=1),
    ]
    for case in cases:
        case["op"] = "types.solve"
    return cases


REQUIRED_COVERAGE = (
    "consistent component", "inconsistent component", "root solved", "root state_limit",
    "root derived_limit", "withheld root", "overflowed root", "union candidate", "overlapping fields",
    "state reached twice by offset", "hops above 2", "rejected: negative offset",
    "rejected: object extent exceeds configured limit", "rejected: empty evidence ID",
    "rejected: empty object ID", "rejected: zero access width", "rejected: offset plus width overflows",
    "refused malformed request",
)


def run_seed(engine: Engine, seed: int, cases: int, seen: Counter) -> int:
    rng = random.Random(seed)
    checked = 0
    pending = prelude() + [None] * cases
    for index, request in enumerate(pending):
        if request is None:
            request = generate(rng)
        context = f"seed {seed} case {index}"
        response = engine.call(request)
        try:
            if not response["ok"]:
                raise Failure(f"valid request failed: {response}")
            check(request, response["result"], seen)
            other = shuffled(request, rng)
            again = engine.call(other)
            if not again["ok"]:
                raise Failure(f"shuffled request failed: {again}")
            expect(normalized(request, response["result"]), normalized(other, again["result"]),
                   "order independence")
            if request["summaries"] and rng.random() < 0.25:
                name, mutate = rng.choice(INVALID_MUTATIONS)
                broken = json.loads(json.dumps(request))
                mutate(broken)
                answer = engine.call(broken)
                if answer["ok"] or answer["error"]["code"] != "invalid_request":
                    raise Failure(f"malformed request ({name}) was not refused: {answer}")
                if not engine.call(dict(op="ping"))["ok"]:
                    raise Failure("engine unusable after a refused request")
                seen["refused malformed request"] += 1
        except Failure as failure:
            raise Failure(f"{context}: {failure}\nrequest: {json.dumps(request, ensure_ascii=False)}") from None
        checked += 1
    return checked


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--engine", type=Path, required=True)
    parser.add_argument("--seed", type=int, action="append", help="repeat for several reproducible seeds")
    parser.add_argument("--cases", type=int, default=300, help="random graphs per seed, after fixed cases")
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
                print(f"types.solve model check failed: {failure}", file=sys.stderr)
                return 1
            finally:
                engine.close()
    missing = [name for name in REQUIRED_COVERAGE if not seen[name]]
    if missing and args.cases * len(seeds) >= 600:
        # A generator change that stops reaching an edge case must not pass quietly.
        print(f"types.solve model check never reached: {', '.join(missing)}", file=sys.stderr)
        return 1
    print(json.dumps(dict(status="passed", seeds=seeds, cases=total, coverage=dict(sorted(seen.items())))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
