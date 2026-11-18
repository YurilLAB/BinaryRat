# Copyright 2026 YurilLAB
# SPDX-License-Identifier: Apache-2.0

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from stage_packed_calibration import FAMILY, SCORE_KIND, stage


class PackedStagingTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        root = Path(scratch.name).resolve()
        self.source = root / "types.c"
        self.binary = root / "analysis" / "types"
        self.debug = root / "oracle" / "types.debug"
        for path, content in ((self.source, b"source"), (self.binary, b"binary"),
                              (self.debug, b"debug")):
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(content)

        artifact = {
            "id": "gcc/O0/types", "format": "ELF64", "source": "types.c",
            "source_sha256": hashlib.sha256(self.source.read_bytes()).hexdigest(),
            "binary": "analysis/types", "binary_sha256": hashlib.sha256(self.binary.read_bytes()).hexdigest(),
            "debug_file": "oracle/types.debug", "debug_sha256": hashlib.sha256(self.debug.read_bytes()).hexdigest(),
        }
        self.oracle = {"kind": "struct", "name": "PackedRecord", "size": 5,
                       "members": [{"name": "sequence", "offset": 1, "width": 4}]}
        self.manifest = root / "manifest.json"
        self.write(self.manifest, {"schema_version": 1, "status": "passed",
                                   "root": str(root), "artifacts": [artifact]})
        self.report = root / "report.json"
        self.evidence = root / "fixture.layout.json"
        self.fixture = {
            "artifact": artifact["id"], "binary_sha256": artifact["binary_sha256"],
            "debug_sha256": artifact["debug_sha256"], "oracle": self.oracle,
            "evidence": self.evidence.name,
        }
        self.write_report()
        object_id = "root"
        observed, fields = [], []
        for index, (offset, width) in enumerate(((1, 4), (4, 4))):
            evidence_id = f"pc:{index}"
            observed.append({"evidence_id": evidence_id, "object_id": object_id,
                             "object_start_known": True, "operation": "LOAD",
                             "offset": offset, "width": width})
            fields.append({"evidence_ids": [evidence_id], "offset": offset, "width": width,
                           "evidence_strength": 0.5})
        self.layout = {
            "schema_version": 1, "analysis_mode": "read_only_layout_evidence",
            "assumption": "analyst_selected_object_start", "follow_depth": 0,
            "parameter_index": 0, "program_id": "sha256:" + artifact["binary_sha256"],
            "score_kind": SCORE_KIND, "function": {"name": "read_packed"},
            "observations": observed, "layouts": [{"object_id": object_id, "fields": fields}],
        }
        self.write(self.evidence, self.layout)

    @staticmethod
    def write(path, payload):
        path.write_text(json.dumps(payload), encoding="utf-8")

    def write_report(self):
        self.write(self.report, {"schema_version": 1, "fixtures": [self.fixture]})

    def stage(self):
        with patch("stage_packed_calibration.oracle_layout", return_value=self.oracle) as reader:
            result = stage(self.manifest, self.report, self.source, "holdout", "pdbutil")
            reader.assert_called_once()
            self.assertEqual(reader.call_args.args[0], self.debug)
        return result

    def test_binds_and_labels_against_reparsed_oracle(self):
        case, = self.stage()["cases"]
        self.assertEqual(case["source_family"], FAMILY)
        self.assertEqual(case["split"], "holdout")
        self.assertEqual([entry["correct"] for entry in case["proposals"]], [True, False])
        self.fixture["oracle"] = self.oracle | {"size": 17}
        self.write_report()
        with self.assertRaisesRegex(ValueError, "reproduce"):
            self.stage()

    def test_rejects_source_and_artifact_changes(self):
        self.source.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "declared corpus source"):
            self.stage()
        self.source.write_bytes(b"source")
        self.binary.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            self.stage()

    def test_rejects_tampered_scores_and_evidence_paths(self):
        self.layout["layouts"][0]["fields"][0]["evidence_strength"] = 0.9
        self.write(self.evidence, self.layout)
        with self.assertRaisesRegex(ValueError, "evidence-strength formula"):
            self.stage()
        self.fixture["evidence"] = "../fixture.layout.json"
        self.write_report()
        with self.assertRaisesRegex(ValueError, "evidence filename"):
            self.stage()


if __name__ == "__main__":
    unittest.main()
