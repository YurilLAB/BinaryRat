# SPDX-License-Identifier: Apache-2.0

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from dwarf_oracle import MAX_DEBUG_BYTES, read_dwarf_layout
from verify_type_accuracy import PROJECT, score_fields, verified_fields


class ScoringTests(unittest.TestCase):
    def test_exact_width_and_offset_measurement_includes_false_positives(self):
        oracle = {"members": [{"offset": 0, "width": 1}, {"offset": 1, "width": 4}]}
        inferred = [{"offset": 0, "width": 1}, {"offset": 1, "width": 2}]
        report = score_fields(inferred, oracle)
        self.assertEqual(report["precision"], 0.5)
        self.assertEqual(report["recall"], 0.5)
        self.assertEqual(report["missing_ranges"], [(1, 4)])
        self.assertEqual(report["extra_ranges"], [(1, 2)])

    def test_union_duplicate_ranges_count_once_and_abstention_is_visible(self):
        oracle = {"kind": "union", "members": [{"offset": 0, "width": 8}] * 3}
        report = score_fields([], oracle)
        self.assertIsNone(report["precision"])
        self.assertEqual(report["recall"], 0)
        self.assertEqual(report["missing"], 1)

    def test_malformed_range_is_rejected(self):
        oracle = {"members": [{"offset": 0, "width": 1}]}
        for offset, width in ((-1, 4), (False, 4), (0, 0), (1 << 32, 1), (1, 1 << 32)):
            with self.subTest(offset=offset, width=width), self.assertRaises(ValueError):
                score_fields([{"offset": offset, "width": width}], oracle)

    def test_fields_require_matching_pcode_evidence(self):
        artifact = {"binary_sha256": "0" * 64}
        observation = {"evidence_id": "pc:0", "object_id": "parameter0", "offset": 1, "width": 4,
                       "object_start_known": True, "operation": "LOAD"}
        field = {"offset": 1, "width": 4, "evidence_ids": ["pc:0"]}
        export = {"schema_version": 1, "program_id": "sha256:" + artifact["binary_sha256"],
                  "function": {"name": "read_packed"}, "parameter_index": 0,
                  "assumption": "analyst_selected_object_start",
                  "observations": [observation],
                  "layouts": [{"object_id": "parameter0", "fields": [field]}]}
        self.assertEqual(verified_fields(export, artifact), [field])
        for broken in (observation | {"width": 8}, observation | {"object_id": "other"},
                       observation | {"object_start_known": False}, observation | {"operation": "COPY"}):
            with self.subTest(broken=broken), self.assertRaises(ValueError):
                verified_fields(export | {"observations": [broken]}, artifact)
        with self.assertRaises(ValueError):
            verified_fields(export | {"observations": [observation, observation]}, artifact)
        with self.assertRaises(ValueError):
            verified_fields(export | {"program_id": "another binary"}, artifact)


class DwarfTests(unittest.TestCase):
    def test_oversized_input_is_rejected_before_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            debug = Path(directory) / "large.debug"
            with debug.open("wb") as stream:
                stream.truncate(MAX_DEBUG_BYTES + 1)
            with self.assertRaisesRegex(ValueError, "size"):
                read_dwarf_layout(debug, "PackedRecord")

    @unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("gcc") and
                         shutil.which("objcopy"), "requires a Linux C compiler and objcopy")
    def test_reads_packed_union_array_and_pointer_in_real_dwarf(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            original, debug = directory / "original", directory / "oracle.debug"
            fixture = PROJECT / "binaryrat/corpus/fixtures/types.c"
            subprocess.run(["gcc", "-g", "-gdwarf-4", "-O2", str(fixture), "-o", str(original)],
                           check=True, timeout=30, capture_output=True)
            subprocess.run(["objcopy", "--only-keep-debug", str(original), str(debug)],
                           check=True, timeout=30, capture_output=True)
            packed = read_dwarf_layout(debug, "PackedRecord")
            self.assertEqual(packed["size"], 5)
            self.assertEqual([(member["offset"], member["width"]) for member in packed["members"]],
                             [(0, 1), (1, 4)])
            payload = read_dwarf_layout(debug, "Payload")
            self.assertEqual(payload["kind"], "union")
            self.assertTrue(all(member["offset"] == 0 for member in payload["members"]))
            record = {member["name"]: member for member in read_dwarf_layout(debug, "Record")["members"]}
            self.assertEqual(record["next"]["width"], 8)
            self.assertEqual(record["samples"]["width"], 16)
            with self.assertRaisesRegex(ValueError, "no concrete"):
                read_dwarf_layout(debug, "UnknownLayout")


if __name__ == "__main__":
    unittest.main()
