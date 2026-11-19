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
                found = engine.cache_get(key)
                self.assertEqual((found["hit"], found["value"]), (True, {"c": "return 0;"}))
                self.assertTrue(found["verified"], "stored in this session")
            # A new client proves data survives the first native process.
            with EngineClient(os.environ["BINARYRAT_ENGINE"], cache_dir=directory) as engine:
                found = engine.cache_get(key)
                self.assertTrue(found["hit"])
                self.assertFalse(found["verified"], "earlier sessions must be verified first")
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

    def test_summary_solver_follows_offsets_and_withholds_drifting_cycles(self):
        summaries = [
            dict(id="root", accesses=[dict(offset=0, width=8, evidence_id="root:load")]),
            dict(id="callee", accesses=[dict(offset=-8, width=4, evidence_id="callee:load",
                                             storage_view="integer")]),
            dict(id="walk", accesses=[dict(offset=0, width=8, evidence_id="walk:next")]),
        ]
        edges = [dict(caller="root", callee="callee", offset=24, evidence_id="call:1"),
                 dict(caller="root", callee="walk", offset=0, evidence_id="call:2"),
                 dict(caller="walk", callee="walk", offset=16, evidence_id="call:3")]
        with tempfile.TemporaryDirectory() as directory:
            with EngineClient(os.environ["BINARYRAT_ENGINE"], cache_dir=directory) as engine:
                self.assertIn("summary-solver", engine.ping()["capabilities"])
                solved = engine.solve_types(summaries, edges, [dict(summary="root", object_id="obj")],
                                            maximum_states=8)
        self.assertEqual(solved["components"], [dict(summaries=["walk"], consistent=False,
                                                     withheld_edges=[2])])
        root = solved["roots"][0]
        self.assertEqual((root["status"], root["complete"], root["withheld_components"]),
                         ("solved", False, [0]))
        layout = root["layout"]
        self.assertEqual([(f["offset"], f["width"]) for f in layout["fields"]], [(0, 8), (16, 4)])
        self.assertEqual(layout["fields"][1]["evidence_ids"], ["callee:load"])
        callee_state = next(s for s in root["states"] if s["summary"] == "callee")
        self.assertEqual((callee_state["offset"], callee_state["edge"], callee_state["parent"]), (24, 0, 0))


if __name__ == "__main__":
    unittest.main()
