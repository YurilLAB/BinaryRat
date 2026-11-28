"""Exercise a real subprocess with good and faulty JSONL peers.

Apache-2.0; Copyright 2026 YurilLAB.
"""

import json
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from binaryrat import EngineClient, EngineError, ProtocolError


PEER = r'''
import json, sys, time
for line in sys.stdin:
    row = json.loads(line)
    op = row["op"]
    if op == "malformed":
        print("not json", flush=True)
        continue
    if op == "stall":
        time.sleep(5)
    reply = {"id": row["id"], "protocol_version": 1, "ok": True,
             "result": {"op": op, "received": row}}
    if op == "wrong-id":
        reply["id"] = "some-other-request"
    if op == "future-version":
        reply["protocol_version"] = 2
    if op in ("error", "error-no-id", "error-null-id"):
        reply = {"id": row["id"], "protocol_version": 1, "ok": False,
                 "error": {"code": "bad_request", "message": "test error"}}
        if op == "error-no-id":
            del reply["id"]
        if op == "error-null-id":
            reply["id"] = None
    print(json.dumps(reply), flush=True)
'''


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.peer = Path(self.directory.name) / "peer.py"
        self.peer.write_text(textwrap.dedent(PEER), encoding="utf-8")
        self.original_popen = subprocess.Popen
        self.commands = []

        def launch(argv, **kwargs):
            self.commands.append(argv)
            return self.original_popen([sys.executable, str(self.peer)], **kwargs)

        self.patch = patch("binaryrat.client.subprocess.Popen", side_effect=launch)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self.directory.cleanup()

    def test_solve_types_sends_only_given_limits(self):
        with EngineClient("binaryrat-engine") as client:
            sent = client.solve_types([dict(id="a", accesses=[])], [], [dict(summary="a", object_id="o")],
                                      maximum_states=3)["received"]
        self.assertEqual(sent["op"], "types.solve")
        self.assertEqual(sent["roots"], [dict(summary="a", object_id="o")])
        self.assertEqual(sent["maximum_states"], 3)
        self.assertNotIn("maximum_derived", sent)
        self.assertNotIn("maximum_extent", sent)

    def test_stack_strings_sends_groups_and_only_a_given_minimum(self):
        with EngineClient("binaryrat-engine") as client:
            groups = [dict(id="f/1", writes=[dict(offset=-16, bytes="68656c6c6f00", order=1)])]
            sent = client.stack_strings(groups)["received"]
            self.assertEqual((sent["op"], sent["groups"]), ("strings.stack", groups))
            self.assertNotIn("minimum_length", sent)
            self.assertEqual(client.stack_strings(groups, minimum_length=2)["received"]["minimum_length"], 2)

    def test_persistent_process_and_precise_argument_boundaries(self):
        with EngineClient("engine with spaces", cache_dir="cache with spaces") as client:
            first = client.cache_put({"function": "ram:10"}, {"c": "return 1;"}, ["type:a"])
            second = client.cache_get({"function": "ram:10"})
            self.assertNotEqual(first["received"]["id"], second["received"]["id"])
        self.assertEqual(self.commands, [["engine with spaces", "serve", "--cache", "cache with spaces"]])
        with self.assertRaisesRegex(ProtocolError, "closed"):
            client.ping()

    def test_engine_error_does_not_poison_valid_connection(self):
        for operation in ("error", "error-null-id"):
            with self.subTest(operation=operation), EngineClient() as client:
                with self.assertRaises(EngineError) as caught:
                    client.request(operation)
                self.assertEqual(caught.exception.code, "bad_request")
                self.assertEqual(client.ping()["op"], "ping")

    def test_invalid_peers_are_rejected_and_connection_is_closed(self):
        for operation in ("malformed", "wrong-id", "future-version", "error-no-id"):
            with self.subTest(operation=operation), EngineClient() as client:
                with self.assertRaises(ProtocolError):
                    client.request(operation)
                with self.assertRaisesRegex(ProtocolError, "closed"):
                    client.ping()

    def test_deadline_terminates_stalled_peer(self):
        with EngineClient(timeout=0.1) as client:
            with self.assertRaisesRegex(ProtocolError, "timed out"):
                client.request("stall")
            self.assertIsNotNone(client._process.poll())

    def test_response_byte_limit_includes_utf8_and_line_ending(self):
        symbol = "\N{GREEK SMALL LETTER LAMDA}\N{PUSHPIN}" * 64
        row = {"id": "1", "protocol_version": 1, "ok": True, "result": symbol}
        wire = json.dumps(row, ensure_ascii=False).encode("utf-8") + b"\r\n"
        self.peer.write_text(f"import sys\nsys.stdin.buffer.readline()\n"
                             f"sys.stdout.buffer.write({wire!r}); sys.stdout.buffer.flush()\n")
        with EngineClient(max_response_bytes=len(wire)) as client:
            self.assertEqual(client.request("read"), symbol)
        with EngineClient(max_response_bytes=len(wire) - 1) as client:
            with self.assertRaisesRegex(ProtocolError, "exceeds maximum size"):
                client.request("read")

    def test_response_byte_limit_is_enforced_before_the_line_is_complete(self):
        self.peer.write_text("import sys\nsys.stdin.buffer.readline()\n"
                             "sys.stdout.buffer.write(bytes.fromhex('f09f938c') * 512)\n"
                             "sys.stdout.buffer.flush()\nsys.stdin.buffer.read()\n")
        with EngineClient(timeout=3, max_response_bytes=1024) as client:
            with self.assertRaisesRegex(ProtocolError, "exceeds maximum size"):
                client.request("read")
            self.assertIsNotNone(client._process.poll())

    def test_nonfinite_input_is_rejected_before_transmission(self):
        with EngineClient() as client:
            with self.assertRaises(ValueError):
                client.request("cache.put", key={"bad": float("nan")})
            self.assertEqual(client.ping()["op"], "ping")

    def test_deadline_also_bounds_blocking_request_transmission(self):
        self.peer.write_text("import time; time.sleep(5)\n", encoding="utf-8")
        with EngineClient(timeout=0.1) as client:
            started = time.monotonic()
            with self.assertRaisesRegex(ProtocolError, "timed out"):
                client.request("cache.put", value={"c": "x" * 1_000_000})
            self.assertLess(time.monotonic() - started, 2)

    def test_invalid_transport_limits_are_rejected(self):
        for fields in ({"timeout": float("nan")}, {"timeout": float("inf")},
                       {"max_response_bytes": 0.5}, {"max_response_bytes": True}):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                EngineClient(**fields)

    def test_request_size_limit_leaves_connection_usable(self):
        with EngineClient() as client:
            with self.assertRaisesRegex(ValueError, "16 MiB"):
                client.request("cache.put", value={"c": "x" * (16 * 1024 * 1024)})
            self.assertEqual(client.ping()["op"], "ping")


if __name__ == "__main__":
    unittest.main()
