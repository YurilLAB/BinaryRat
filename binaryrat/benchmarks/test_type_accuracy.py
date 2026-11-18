# SPDX-License-Identifier: Apache-2.0

from io import BytesIO
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bounded_io import read_limited
from dwarf_oracle import MAX_DEBUG_BYTES, read_dwarf_layout
from verify_type_accuracy import (
    PROJECT, checked_artifact_pair, digest, json_file, score_fields, verified_fields, verify_union_views,
)


class ScoringTests(unittest.TestCase):
    def test_byte_ceiling_applies_during_reads(self):
        class ShortReads(BytesIO):
            def read(self, size):
                if size > 64 * 1024:
                    raise AssertionError("reserved an entire large budget")
                return super().read(min(5000, size))

        payload = b"x" * 140_000
        self.assertEqual(read_limited(ShortReads(payload), 32 * 1024 * 1024), payload)
        with ShortReads(payload) as stream:
            self.assertEqual(read_limited(stream, 100_001), payload[:100_001])
            self.assertEqual(stream.tell(), 100_001)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "growing.json"
            path.write_text('{"x":1}', encoding="utf-8")
            stat = Path.stat

            def grow_after_stat(target, *args, **kwargs):
                result = stat(target, *args, **kwargs)
                if target == path:
                    path.write_text('{"x":"' + "x" * 4096 + '"}', encoding="utf-8")
                return result

            with patch("verify_type_accuracy.MAX_JSON_BYTES", 128), patch.object(Path, "stat", grow_after_stat):
                with self.assertRaisesRegex(ValueError, "size"):
                    json_file(path)

    def test_input_and_oracle_with_identical_contents_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            binary, debug = root / "analysis/types", root / "oracle/types.debug"
            for path in (binary, debug):
                path.parent.mkdir()
                path.write_bytes(b"the same debug-bearing input")
            artifact = {"binary": "analysis/types", "debug_file": "oracle/types.debug",
                        "binary_sha256": digest(binary), "debug_sha256": digest(debug)}
            with self.assertRaisesRegex(ValueError, "distinct content"):
                checked_artifact_pair(root, artifact)
            debug.write_bytes(b"separate debug file")
            artifact["debug_sha256"] = digest(debug)
            self.assertEqual(checked_artifact_pair(root, artifact), (binary, debug))

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
                       "address_space": "ram", "address": "1000", "pcode_order": 0,
                       "function_address_space": "ram", "function_address": "1000",
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

    def test_union_views_need_distinct_loads_linked_to_each_rooted_field(self):
        artifact = {"binary_sha256": "0" * 64}

        def make_fixture(control):
            function = "read_separate_numbers" if control else "read_overlay_number"
            fields, rows, views = [], [], []
            for index, (kind, width, operation) in enumerate(
                    [("integer", 4, "INT_XOR"), ("floating_point", 8, "FLOAT_LESS")]):
                offset = 8 * index if control else 0
                identity = f"load{index}"
                rows.append({"evidence_id": identity, "object_id": "root", "object_start_known": True,
                             "offset": offset, "width": width, "storage_view": kind, "operation": "LOAD",
                             "address_space": "ram", "address": "1000", "pcode_order": index,
                             "function_address_space": "ram", "function_address": "1000",
                             "typed_use": {"operation": operation}})
                fields.append({"offset": offset, "width": width, "evidence_ids": [identity]})
                views.append({"width": width, "kind": kind, "evidence_ids": [identity]})
            candidates = [] if control else [{"offset": 0, "views": views}]
            return ({"schema_version": 1, "program_id": "sha256:" + artifact["binary_sha256"],
                     "revision": 1, "function": {"name": function}, "parameter_index": 0,
                     "assumption": "analyst_selected_object_start", "observations": rows,
                     "layouts": [{"object_id": "root", "fields": fields, "union_candidates": candidates}]},
                    {"kind": "struct" if control else "union", "members": fields})

        control, control_oracle = make_fixture(True)
        for case in ("valid", "unsupported", "foreign_root", "same_load"):
            with self.subTest(case=case):
                export, oracle = make_fixture(False)
                layout = export["layouts"][0]
                integer, floating = layout["union_candidates"][0]["views"]
                rows = export["observations"]
                if case == "unsupported":
                    rows.append(rows[0] | {"evidence_id": "more", "pcode_order": 2})
                    layout["fields"][0]["evidence_ids"].append("more")
                    integer["evidence_ids"].append("more")
                    floating["evidence_ids"].clear()
                elif case == "foreign_root":
                    rows.append(rows[1] | {"evidence_id": "foreign", "object_id": "other", "pcode_order": 2})
                    floating["evidence_ids"] = ["foreign"]
                elif case == "same_load":
                    rows[1]["pcode_order"] = rows[0]["pcode_order"]
                if case == "valid":
                    metrics = verify_union_views(export, control, artifact, oracle, control_oracle)
                    self.assertEqual(metrics["matched"], 2)
                else:
                    with self.assertRaisesRegex((RuntimeError, ValueError), "evidence"):
                        verify_union_views(export, control, artifact, oracle, control_oracle)


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
