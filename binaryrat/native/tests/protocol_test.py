# Copyright 2026 YurilLAB
# SPDX-License-Identifier: Apache-2.0
"""Exercise the actual C++ process, persistence, validation, and recovery."""
from collections import Counter, defaultdict
import json
from pathlib import Path
import queue
import random
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ENGINE = sys.argv.pop(1)


class ProtocolTests(unittest.TestCase):
    def test_unicode_cache_directory(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root) / "\u042e\u0440\u0438\u0439_\u65e5\u672c\u8a9e"
            response = self.run_requests(directory, [dict(id="unicode", op="ping")])[0]
            self.assertTrue(response["ok"])
            self.assertTrue(directory.is_dir())

    def test_cache_ownership_is_released_when_process_is_killed(self):
        with tempfile.TemporaryDirectory() as root:
            owner = subprocess.Popen([ENGINE, "serve", "--cache", root], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, text=True)
            try:
                owner.stdin.write('{"id":"ready","op":"ping"}\n')
                owner.stdin.flush()
                self.assertTrue(json.loads(owner.stdout.readline())["ok"])
                other = subprocess.run([ENGINE, "serve", "--cache", root], input="",
                                       text=True, capture_output=True, timeout=5)
                self.assertNotEqual(other.returncode, 0)
                owner.kill()
                owner.wait(timeout=5)
                self.assertTrue(self.run_requests(root, [dict(id="restart", op="ping")])[0]["ok"])
            finally:
                if owner.poll() is None:
                    owner.kill()
                    owner.wait()
                owner.stdin.close()
                owner.stdout.close()

    def run_requests(self, root, requests):
        run = subprocess.run([ENGINE, "serve", "--cache", str(root)],
                             input="".join(json.dumps(r) + "\n" for r in requests),
                             text=True, capture_output=True, timeout=15, check=True)
        responses = [json.loads(line) for line in run.stdout.splitlines()]
        self.assertEqual(len(responses), len(requests))
        return responses

    def test_persistent_cache_and_dependency_invalidation(self):
        key = dict(schema_version=1, ghidra_version="12.2", program_id="program",
                   revision=1, address_space="ram", address="1000",
                   body_sha256="a" * 64, options_digest="b" * 64)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            responses = self.run_requests(root, [dict(id="put", op="cache.put", key=key,
                value={"c": "int f(void) { return 1; }"}, dependencies=["callee:2000"])])
            self.assertTrue(responses[0]["ok"])
            responses = self.run_requests(root, [dict(id="get", op="cache.get", key=key),
                dict(id="unrelated", op="cache.invalidate", dependencies=["type:other"]),
                dict(id="invalidate", op="cache.invalidate", dependencies=["callee:2000"]),
                dict(id="miss", op="cache.get", key=key)])
            self.assertTrue(responses[0]["result"]["hit"])
            self.assertEqual(responses[1]["result"]["removed"], 0)
            self.assertEqual(responses[2]["result"]["removed"], 1)
            self.assertFalse(responses[3]["result"]["hit"])

    def test_recovers_after_invalid_requests(self):
        with tempfile.TemporaryDirectory() as root:
            responses = self.run_requests(root, [dict(id="bad", op="missing"),
                dict(id="version", op="ping", protocol_version=1.0), dict(id="ok", op="ping")])
        self.assertFalse(responses[0]["ok"])
        self.assertFalse(responses[1]["ok"])
        self.assertEqual(responses[2]["id"], "ok")
        self.assertEqual(responses[2]["result"]["name"], "BinaryRat")

    def test_layout_proposals_and_unknown_origin_abstention(self):
        observations = [dict(object_id="object", offset=8, width=4, stride=None,
                             evidence_id="load:1000", object_start_known=True),
                        dict(object_id="unknown", offset=0, width=8,
                             evidence_id="load:2000", object_start_known=False)]
        with tempfile.TemporaryDirectory() as root:
            response = self.run_requests(root, [dict(id="types", op="types.recover",
                                                    observations=observations)])[0]
        self.assertTrue(response["ok"], response)
        result = response["result"]
        self.assertEqual(result["layouts"][0]["minimum_extent"], 12)
        self.assertEqual(result["layouts"][0]["fields"][0]["offset"], 8)
        self.assertEqual(len(result["rejected"]), 1)
        self.assertEqual(result["score_kind"], "uncalibrated_evidence_strength")

    def test_summary_solver_response_shape_and_refusals(self):
        request = dict(id="solve", op="types.solve",
                       summaries=[dict(id="a", accesses=[dict(offset=0, width=4, evidence_id="a:0",
                                                              storage_view="floating_point")]),
                                  dict(id="b", accesses=[dict(offset=4, width=4, evidence_id="b:4")])],
                       edges=[dict(caller="a", callee="b", offset=8, evidence_id="call"),
                              dict(caller="b", callee="a", offset=-8, evidence_id="back")],
                       roots=[dict(summary="a", object_id="obj")])
        refusals = [dict(request, id="no-roots", roots=[]),
                    dict(request, id="unknown", edges=[dict(caller="a", callee="zz", offset=0,
                                                            evidence_id="x")]),
                    dict(request, id="limit", maximum_states=65537),
                    dict(request, id="roots", roots=[dict(summary="a", object_id="obj")] * 17),
                    dict(request, id="after", op="ping")]
        with tempfile.TemporaryDirectory() as root:
            responses = self.run_requests(root, [request] + refusals)
        result = responses[0]["result"]
        self.assertEqual(sorted(result), ["components", "roots", "score_kind"])
        self.assertEqual(result["components"], [dict(summaries=["a", "b"], consistent=True,
                                                     withheld_edges=[])])
        solved = result["roots"][0]
        self.assertEqual(sorted(solved), ["complete", "derived", "layout", "object_id", "overflowed",
                                          "rejected", "states", "status", "summary",
                                          "withheld_components"])
        self.assertEqual(solved["states"], [
            dict(summary="a", offset=0, hops=0, edge=None, parent=None),
            dict(summary="b", offset=8, hops=1, edge=0, parent=0)])
        self.assertEqual(solved["derived"][0], dict(state=0, access=0, offset=0, width=4,
                                                    evidence_id="a:0", storage_view="floating_point"))
        self.assertEqual([(f["offset"], f["evidence_ids"]) for f in solved["layout"]["fields"]],
                         [(0, ["a:0"]), (12, ["b:4"])])
        for response in responses[1:5]:
            self.assertFalse(response["ok"])
            self.assertEqual(response["error"]["code"], "invalid_request")
        self.assertTrue(responses[5]["ok"])

    def test_stack_strings_response_shape_and_refusals(self):
        writes = [dict(offset=-32, bytes="58585858", order=1), dict(offset=-32, bytes="68656c6c", order=2),
                  dict(offset=-28, bytes="6f00", order=3), dict(offset=-8, bytes="41004200430044000000", order=4)]
        request = dict(id="strings", op="strings.stack", groups=[dict(id="f", writes=writes),
                                                                  dict(id="empty", writes=[])])
        refusals = [dict(request, id="duplicate", groups=[dict(id="f", writes=[])] * 2),
                    dict(request, id="upper", groups=[dict(id="f", writes=[dict(offset=0, bytes="4A", order=0)])]),
                    dict(request, id="wide", groups=[dict(id="f", writes=[dict(offset=0, bytes="41" * 65, order=0)])]),
                    dict(request, id="overflow", groups=[dict(id="f", writes=[
                        dict(offset=2**63 - 1, bytes="4142", order=0)])]),
                    dict(request, id="minimum", minimum_length=65),
                    dict(request, id="after", op="ping")]
        with tempfile.TemporaryDirectory() as root:
            responses = self.run_requests(root, [request, dict(request, id="short", minimum_length=1)] + refusals)
        result = responses[0]["result"]
        self.assertEqual(sorted(result), ["groups", "minimum_length"])
        self.assertEqual(result["minimum_length"], 4)
        self.assertEqual(result["groups"], [
            dict(id="f", strings=[
                dict(offset=-32, byte_length=5, encoding="ascii", text="hello", terminated=True, orders=[2, 3]),
                dict(offset=-8, byte_length=8, encoding="utf16le", text="ABCD", terminated=True, orders=[4])]),
            dict(id="empty", strings=[])])
        self.assertEqual(responses[1]["result"]["minimum_length"], 1)
        for response in responses[2:7]:
            self.assertFalse(response["ok"])
            self.assertEqual(response["error"]["code"], "invalid_request")
        self.assertTrue(responses[7]["ok"])
        self.assertIn("stack-strings", responses[7]["result"]["capabilities"])

    def test_numeric_overflow_is_rejected_at_protocol_boundary(self):
        observation = dict(object_id="object", offset=2**63, width=4,
                           evidence_id="x", object_start_known=True)
        with tempfile.TemporaryDirectory() as root:
            response = self.run_requests(root, [dict(id="overflow", op="types.recover",
                                                    observations=[observation])])[0]
        self.assertFalse(response["ok"])

    def test_union_candidates_retain_typed_access_provenance(self):
        access = dict(object_id="object", offset=12, object_start_known=True)
        integer = dict(access, width=4, evidence_id="int-load", storage_view="integer")
        floating = dict(access, width=8, evidence_id="float-load", storage_view="floating_point")
        with tempfile.TemporaryDirectory() as root:
            response, invalid = self.run_requests(root, [
                dict(id="typed", op="types.recover", observations=[floating, integer]),
                dict(id="invalid", op="types.recover",
                     observations=[dict(integer, storage_view="unknown")]),
            ])
        self.assertTrue(response["ok"], response)
        candidate, = response["result"]["layouts"][0]["union_candidates"]
        self.assertEqual(candidate["offset"], 12)
        self.assertEqual(candidate["views"], [
            dict(kind="integer", width=4, evidence_ids=["int-load"]),
            dict(kind="floating_point", width=8, evidence_ids=["float-load"]),
        ])
        self.assertFalse(invalid["ok"])

    def test_seeded_union_candidate_aggregation(self):
        randomizer = random.Random(0xB17A7)
        requests = []
        expected = []
        supported = {"integer": (1, 2, 4, 8), "floating_point": (4, 8)}
        for index in range(320):
            observations = []
            slots = defaultdict(lambda: defaultdict(set))
            for _ in range(randomizer.randrange(1, 33)):
                obj = randomizer.choice(("a", "b", ""))
                offset = randomizer.choice((-1, 0, 2, 8, 32))
                width = randomizer.choice((0, 1, 2, 4, 8, 16))
                identity = randomizer.choice(("", "a", "b", "c", f"unique-{len(observations)}"))
                kind = randomizer.choice(tuple(supported))
                known = randomizer.randrange(5) != 0
                stride = randomizer.choice((None, None, None, 0, 8))
                observations.append(dict(object_id=obj, offset=offset, width=width, evidence_id=identity,
                                         storage_view=kind, object_start_known=known, stride=stride))
                if (obj and identity and known and stride is None and
                        0 <= offset <= 32 - width and width in supported[kind]):
                    slots[obj, offset][kind, width].add(identity)
            candidates = []
            for (obj, offset), alternatives in sorted(slots.items()):
                counts = Counter(identity for identities in alternatives.values() for identity in identities)
                views = [(kind, width, sorted(identity for identity in identities if counts[identity] == 1))
                         for (kind, width), identities in alternatives.items()]
                views = sorted((view for view in views if view[2]))
                if {kind for kind, _, _ in views} == set(supported):
                    candidates.append((obj, offset, views))
            expected.append(candidates)
            randomizer.shuffle(observations)
            requests.append(dict(id=str(index), op="types.recover", maximum_extent=32,
                                 observations=observations))
        self.assertTrue(any(expected), "fixture generated no candidate cases")
        with tempfile.TemporaryDirectory() as root:
            responses = self.run_requests(root, requests)
        for response, candidates in zip(responses, expected, strict=True):
            self.assertTrue(response["ok"], response)
            actual = [(layout["object_id"], candidate["offset"],
                       sorted((view["kind"], view["width"], view["evidence_ids"])
                              for view in candidate["views"]))
                      for layout in response["result"]["layouts"]
                      for candidate in layout["union_candidates"]]
            self.assertEqual(actual, candidates)


class Session:
    """One live engine process; responses and events arrive in any order."""

    def __init__(self, root):
        self.process = subprocess.Popen([ENGINE, "serve", "--cache", str(root)],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        text=True, bufsize=1)
        self.lines = queue.Queue()
        self.pending = []
        self.counter = 0
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for line in self.process.stdout:
            self.lines.put(json.loads(line))
        self.lines.put(None)

    def send(self, op, **fields):
        self.counter += 1
        request_id = f"r{self.counter}"
        self.process.stdin.write(json.dumps(dict(id=request_id, op=op, **fields)) + "\n")
        self.process.stdin.flush()
        return request_id

    def wait_for(self, predicate, timeout=10.0):
        for index, line in enumerate(self.pending):
            if predicate(line):
                return self.pending.pop(index)
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError(f"nothing matched within {timeout}s; pending={self.pending}")
            try:
                line = self.lines.get(timeout=remaining)
            except queue.Empty:
                continue
            if line is None:
                raise AssertionError("engine closed its output")
            if predicate(line):
                return line
            self.pending.append(line)

    def response(self, request_id, timeout=10.0):
        return self.wait_for(lambda line: line.get("id") == request_id, timeout)

    def call(self, op, **fields):
        response = self.response(self.send(op, **fields))
        if not response["ok"]:
            raise AssertionError(response)
        return response["result"]

    def event(self, kind, lease, timeout=10.0):
        return self.wait_for(lambda line: line.get("event") == kind and line.get("lease") == lease, timeout)

    def silent(self, request_id, seconds=0.2):
        time.sleep(seconds)
        try:
            self.response(request_id, timeout=0.01)
        except AssertionError:
            return True
        return False

    def close(self, timeout=10):
        self.process.stdin.close()
        try:
            return self.process.wait(timeout=timeout)
        finally:
            if self.process.poll() is None:
                self.process.kill()
                self.process.wait()
            self.process.stdout.close()


def child(code):
    """A helper process that prints 'ready' once its memory is in place."""
    process = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, text=True)
    if process.stdout.readline().strip() != "ready":
        process.kill()
        raise AssertionError("helper process did not start")
    return process


SLEEPER = "import time\nprint('ready', flush=True)\ntime.sleep(60)\n"
HOG = ("import time\nblock = bytearray(b'x') * (320 * 1024 * 1024)\n"
       "print('ready', flush=True)\ntime.sleep(60)\n")
MIB = 1024 * 1024


class SchedulerProtocolTests(unittest.TestCase):
    def session(self, **budget):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        session = Session(root.name)
        self.addCleanup(session.close)
        configuration = dict(cpu_workers=2, ram_bytes=4096 * MIB, worker_bytes=64 * MIB,
                             memory_poll_ms=10)
        configuration.update(budget)
        return session, session.call("sched.configure", **configuration)

    def test_budget_bounds_concurrent_leases_and_other_requests_keep_flowing(self):
        session, configured = self.session()
        self.assertEqual(configured["workers"], 2)
        first, second, third = (session.send("sched.acquire", lease=name)
                                for name in ("a", "b", "c"))
        self.assertTrue(session.response(first)["result"]["granted"])
        self.assertTrue(session.response(second)["result"]["granted"])
        self.assertTrue(session.silent(third), "a third lease must wait for a worker")
        stats = session.call("sched.stats")
        self.assertEqual((stats["running"], stats["queued"]), (2, 1))
        self.assertEqual(session.call("ping")["name"], "BinaryRat")
        released = session.call("sched.release", lease="a")
        self.assertEqual(released["status"], "completed")
        self.assertTrue(session.response(third)["result"]["granted"])
        self.assertEqual(session.call("sched.stats")["peak_running"], 2)
        self.assertFalse(session.response(session.send("sched.configure"))["ok"])
        self.assertEqual(session.close(), 0, "end of input with running leases exits cleanly")

    def test_deadline_cancel_and_queued_cancel(self):
        session, _ = self.session(cpu_workers=1)
        self.assertTrue(session.call("sched.acquire", lease="slow", timeout_ms=100)["granted"])
        self.assertEqual(session.event("lease.stop", "slow")["reason"], "timeout")
        self.assertEqual(session.call("sched.release", lease="slow")["status"], "timed_out")
        self.assertTrue(session.call("sched.acquire", lease="held")["granted"])
        waiting = session.send("sched.acquire", lease="waiting")
        self.assertTrue(session.call("sched.cancel", lease="waiting")["cancelled"])
        refused = session.response(waiting)["result"]
        self.assertEqual((refused["granted"], refused["status"]), (False, "cancelled"))
        self.assertTrue(session.call("sched.cancel", lease="held")["cancelled"])
        self.assertEqual(session.event("lease.stop", "held")["reason"], "cancelled")
        self.assertEqual(session.call("sched.release", lease="held")["status"], "cancelled")
        rejected = session.call("sched.acquire", lease="huge", reserve_bytes=8192 * MIB)
        self.assertEqual((rejected["granted"], rejected["status"]), (False, "rejected"))

    def test_attached_process_over_its_reservation_is_stopped(self):
        session, configured = self.session()
        if not configured["memory_watch"]:
            self.skipTest("no process memory queries on this platform")
        hog = child(HOG)
        try:
            self.assertTrue(session.call("sched.acquire", lease="job", reserve_bytes=128 * MIB)["granted"])
            attached = session.call("sched.attach", lease="job", pid=hog.pid)
            self.assertTrue(attached["attached"], attached)
            self.assertEqual(session.event("lease.stop", "job")["reason"], "memory")
            released = session.call("sched.release", lease="job")
            self.assertEqual(released["status"], "memory_exceeded")
            self.assertGreater(released["peak_resident_bytes"], 128 * MIB)
            self.assertFalse(released["killed"])
            self.assertIsNone(hog.poll(), "a prompt release does not kill")
        finally:
            hog.kill()
            hog.wait()
            hog.stdout.close()

    def test_holder_that_ignores_a_stop_has_its_process_killed(self):
        session, configured = self.session(kill_grace_ms=300)
        if not configured["memory_watch"]:
            self.skipTest("no process queries on this platform")
        sleeper = child(SLEEPER)
        try:
            self.assertTrue(session.call("sched.acquire", lease="stuck")["granted"])
            self.assertTrue(session.call("sched.attach", lease="stuck", pid=sleeper.pid)["attached"])
            self.assertFalse(session.call("sched.attach", lease="stuck", pid=2**31 - 2)["attached"])
            self.assertTrue(session.call("sched.cancel", lease="stuck")["cancelled"])
            session.event("lease.stop", "stuck")
            killed = session.event("lease.killed", "stuck", timeout=10)
            self.assertEqual(killed["pid"], sleeper.pid)
            self.assertIsNotNone(sleeper.wait(timeout=10), "the attached process was killed")
            released = session.call("sched.release", lease="stuck")
            self.assertEqual((released["status"], released["killed"]), ("cancelled", True))
        finally:
            if sleeper.poll() is None:
                sleeper.kill()
            sleeper.wait()
            sleeper.stdout.close()


class LiveCacheProtocolTests(unittest.TestCase):
    KEY = dict(schema_version=2, ghidra_version="12.2", kind="decompile", program_id="sha256:p",
               address_space="ram", address="401000", options_digest="o")

    def test_changes_remove_dependents_and_unknown_changes_need_verification(self):
        with tempfile.TemporaryDirectory() as root:
            session = Session(root)
            try:
                other = dict(self.KEY, address="402000")
                session.call("cache.put", key=self.KEY, value={"c": "A"}, dependencies=["l:ram:4010"])
                start = session.call("cache.get", key=other)["seq"]
                session.call("cache.changed", dependencies=["l:ram:9999"])
                session.call("cache.put", key=other, value={"c": "B"}, dependencies=["l:ram:4020"],
                             as_of=start)
                found = session.call("cache.get", key=self.KEY)
                self.assertEqual((found["hit"], found["verified"]), (True, True))
                self.assertTrue(session.call("cache.get", key=other)["verified"])
                self.assertEqual(session.call("cache.changed", dependencies=["l:ram:4010"])["removed"], 1)
                self.assertFalse(session.call("cache.get", key=self.KEY)["hit"])
                session.call("cache.changed", all=True)
                found = session.call("cache.get", key=other)
                self.assertEqual((found["hit"], found["verified"]), (True, False))
                self.assertTrue(session.call("cache.confirm", key=other, seq=found["seq"],
                                             generation=found["generation"])["confirmed"])
                self.assertTrue(session.call("cache.get", key=other)["verified"])
                stats = session.call("cache.stats")
                self.assertEqual((stats["entries"], stats["verified"]), (1, 1))
                bad = session.response(session.send("cache.put", key=dict(self.KEY, revision=1),
                                                    value={}, dependencies=[]))
                self.assertFalse(bad["ok"], "live keys must not name a revision")
                self.assertEqual(session.close(), 0)
            finally:
                if session.process.poll() is None:
                    session.close()
            session = Session(root)
            try:
                found = session.call("cache.get", key=dict(self.KEY, address="402000"))
                self.assertEqual((found["hit"], found["verified"]), (True, False),
                                 "a new session must verify entries before trusting them")
                self.assertEqual(session.call("cache.changed", dependencies=["l:ram:4020"])["removed"], 1)
            finally:
                session.close()


if __name__ == "__main__":
    unittest.main()
