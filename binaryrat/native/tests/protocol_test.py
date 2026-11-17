# SPDX-License-Identifier: Apache-2.0
"""Exercise the actual C++ process, persistence, validation, and recovery."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
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

    def test_numeric_overflow_is_rejected_at_protocol_boundary(self):
        observation = dict(object_id="object", offset=2**63, width=4,
                           evidence_id="x", object_start_known=True)
        with tempfile.TemporaryDirectory() as root:
            response = self.run_requests(root, [dict(id="overflow", op="types.recover",
                                                    observations=[observation])])[0]
        self.assertFalse(response["ok"])


if __name__ == "__main__":
    unittest.main()
