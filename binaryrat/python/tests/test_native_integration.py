"""Real native-client integration, enabled by BINARYRAT_ENGINE.

Apache-2.0; Copyright 2026 YurilLAB.
"""

import os
import tempfile
import unittest

from binaryrat import EngineClient


@unittest.skipUnless(os.environ.get("BINARYRAT_ENGINE"), "set BINARYRAT_ENGINE to the built native executable")
class NativeIntegrationTests(unittest.TestCase):
    def test_cache_roundtrip_invalidation_and_layout_evidence(self):
        key = dict(schema_version=1, ghidra_version="12.2", program_id="program",
                   revision=1, address_space="ram", address="1000",
                   body_sha256="a" * 64, options_digest="b" * 64)
        with tempfile.TemporaryDirectory() as directory:
            with EngineClient(os.environ["BINARYRAT_ENGINE"], cache_dir=directory) as engine:
                self.assertEqual(engine.ping()["name"], "BinaryRat")
                self.assertTrue(engine.cache_put(key, {"c": "return 0;"}, ["type:A"])["stored"])
                self.assertEqual(engine.cache_get(key), {"hit": True, "value": {"c": "return 0;"}})
            # A new client proves data survives the first native process.
            with EngineClient(os.environ["BINARYRAT_ENGINE"], cache_dir=directory) as engine:
                self.assertTrue(engine.cache_get(key)["hit"])
                self.assertEqual(engine.cache_invalidate(["type:A"])["removed"], 1)
                self.assertFalse(engine.cache_get(key)["hit"])
                recovered = engine.recover_types([
                    dict(object_id="obj", offset=0, width=8, stride=None,
                         evidence_id="load:1", object_start_known=True),
                    dict(object_id="unknown", offset=0, width=8, stride=None,
                         evidence_id="load:2", object_start_known=False),
                ])
                self.assertEqual(recovered["layouts"][0]["minimum_extent"], 8)
                self.assertEqual(recovered["rejected"][0]["observation_index"], 1)
                self.assertEqual(recovered["score_kind"], "uncalibrated_evidence_strength")


if __name__ == "__main__":
    unittest.main()
