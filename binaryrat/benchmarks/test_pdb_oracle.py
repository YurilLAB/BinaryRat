# SPDX-License-Identifier: Apache-2.0
"""Exercise CodeView layout resolution and the bounded LLVM tool invocation."""

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml

import pdb_oracle as oracle


def aggregate(name, fields, count, size, kind="LF_STRUCTURE", *, options=None, unique=None):
    values = {"Name": name, "FieldList": fields, "MemberCount": count, "Size": size,
              "Options": options or ["None"]}
    if unique is not None:
        values["UniqueName"] = unique
    return {"Kind": kind, "Union" if kind == "LF_UNION" else "Class": values}


def field_list(*members):
    return {"Kind": "LF_FIELDLIST", "FieldList": list(members)}


def field(name, offset, kind):
    return {"Kind": "LF_MEMBER", "DataMember": {"Name": name, "FieldOffset": offset, "Type": kind}}


def continuation(index):
    return {"Kind": "LF_INDEX", "ListContinuation": {"ContinuationIndex": index}}


class LayoutTests(unittest.TestCase):
    def read(self, records, name="Record"):
        document = yaml.safe_dump({"TpiStream": {"Version": "VC80", "Records": records}}).encode()
        return self.read_document(document, name)

    def read_document(self, document, name="Record"):
        with patch.object(oracle, "_pdb_yaml", return_value=document):
            return oracle.read_pdb_layout(Path("oracle.pdb"), name)

    def test_concrete_packed_struct_disregards_forward_declaration(self):
        records = [
            aggregate("Record", 0, 0, 0, options=["ForwardReference"]),
            field_list(field("tag", 0, 0x20), field("value", 1, 0x75)),
            aggregate("Record", 0x1001, 2, 5),
        ]
        self.assertEqual(self.read(records), {
            "kind": "struct", "name": "Record", "size": 5,
            "members": [{"name": "tag", "offset": 0, "width": 1},
                        {"name": "value", "offset": 1, "width": 4}],
        })

    def test_union_retains_each_overlapping_member_and_resolves_qualifier_and_array(self):
        records = [
            {"Kind": "LF_MODIFIER", "Modifier": {"ModifiedType": 0x74}},
            {"Kind": "LF_ARRAY", "Array": {"ElementType": 0x70, "Size": 12}},
            field_list(field("id", 0, 0x1000), field("raw", 0, 0x1001), field("word", 0, 0x23)),
            aggregate("Record", 0x1002, 3, 16, "LF_UNION"),
        ]
        layout = self.read(records)
        self.assertEqual(layout["kind"], "union")
        self.assertEqual(layout["size"], 16)
        self.assertEqual([(member["offset"], member["width"]) for member in layout["members"]],
                         [(0, 4), (0, 12), (0, 8)])

    def test_class_with_continuation_pointer_enum_and_method(self):
        records = [
            {"Kind": "LF_POINTER", "Pointer": {"Attrs": 0x1000C, "ReferentType": 0x1004}},
            {"Kind": "LF_ENUM", "Enum": {"UnderlyingType": 0x21}},
            field_list(field("code", 0, 0x1001), continuation(0x1003)),
            field_list(field("link", 8, 0x1000), {"Kind": "LF_ONEMETHOD"}),
            aggregate("Record", 0x1002, 3, 16, "LF_CLASS"),
        ]
        layout = self.read(records)
        self.assertEqual(layout["kind"], "class")
        self.assertEqual(layout["members"], [{"name": "code", "offset": 0, "width": 2},
                                              {"name": "link", "offset": 8, "width": 8}])

    def test_nested_forward_reference_uses_exact_unique_name(self):
        records = [
            aggregate("Part", 0, 0, 0, options=["ForwardReference", "HasUniqueName"], unique="A"),
            aggregate("Part", 0, 0, 8, unique="A"),
            aggregate("Part", 0, 0, 4, unique="B"),
            field_list(field("part", 0, 0x1000), field("opaque", 8, 0x0603)),
            aggregate("Record", 0x1003, 2, 16),
        ]
        self.assertEqual([part["width"] for part in self.read(records)["members"]], [8, 8])
        with self.assertRaisesRegex(ValueError, "found 2"):
            self.read(records, "Part")

    def test_unmatched_forward_declaration_is_not_a_layout(self):
        records = [aggregate("Record", 0, 0, 0, options=["ForwardReference"])]
        with self.assertRaisesRegex(ValueError, "found 0"):
            self.read(records)

    def test_unsupported_storage_fields_and_bitfields_fail_closed(self):
        for kind in ("LF_BCLASS", "LF_VFUNCTAB", "LF_VBCLASS", "LF_IVBCLASS"):
            with self.subTest(kind=kind):
                with self.assertRaisesRegex(ValueError, f"instance field {kind}"):
                    self.read([field_list({"Kind": kind}), aggregate("Record", 0x1000, 1, 24)])
        records = [{"Kind": "LF_BITFIELD"}, field_list(field("bits", 0, 0x1000)),
                   aggregate("Record", 0x1001, 1, 4)]
        with self.assertRaisesRegex(ValueError, "member type LF_BITFIELD"):
            self.read(records)

    def test_inconsistent_fields_are_rejected(self):
        errors = (
            (field_list(field("value", 2, 0x74)), 1, "extent"),
            (field_list(field("value", -1, 0x74)), 1, "field offset"),
            (field_list(field("value", 0, 0x9999)), 1, "outside the TPI table"),
            (field_list(field("value", 0, 0x74), field("value", 0, 0x20)), 2, "ambiguous"),
            (field_list(field("value", 0, 0x74)), 2, "missing declared"),
            (field_list(field("value", 0, 0x74), field("extra", 0, 0x21)), 1, "exceeds"),
            (field_list(continuation(0x1000)), 1, "Cyclic CodeView field list"),
        )
        for fields, count, message in errors:
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                self.read([fields, aggregate("Record", 0x1000, count, 4)])

    def test_type_cycles_and_pointer_references_are_checked(self):
        records = [{"Kind": "LF_MODIFIER", "Modifier": {"ModifiedType": 0x1000}},
                   field_list(field("value", 0, 0x1000)), aggregate("Record", 0x1001, 1, 8)]
        with self.assertRaisesRegex(ValueError, "Cyclic or excessively deep"):
            self.read(records)
        records[0] = {"Kind": "LF_POINTER", "Pointer": {"Attrs": 0x1000C, "ReferentType": 0x1003}}
        with self.assertRaisesRegex(ValueError, "outside the TPI table"):
            self.read(records)

    def test_llvm_scalar_names_and_corrupt_yaml(self):
        document = b"""TpiStream:
  Records:
  - Kind: LF_FIELDLIST
    FieldList:
    - Kind: LF_MEMBER
      DataMember: {Name: NO, FieldOffset: 0, Type: 32}
  - Kind: LF_STRUCTURE
    Class: {Name: Off, MemberCount: 1, Options: [None], FieldList: 4096, Size: 1}
"""
        self.assertEqual(self.read_document(document, "Off")["members"],
                         [{"name": "NO", "offset": 0, "width": 1}])
        with self.assertRaisesRegex(ValueError, "duplicate CodeView YAML"):
            self.read_document(document.replace(b"Size: 1", b"Size: 1, Size: 2"), "Off")
        with self.assertRaisesRegex(ValueError, "Invalid LLVM CodeView YAML"):
            self.read_document(document[:-2], "Off")
        with self.assertRaisesRegex(ValueError, "Expected a nonempty bounded"):
            self.read_document(b"TpiStream: {Records: []}")


class ExtractionTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.pdb = self.directory / "oracle.pdb"
        self.pdb.write_bytes(oracle._PDB_MAGIC + b"fixture")

    def tool(self, source):
        (self.directory / "pdb2yaml").write_text(source, encoding="utf-8")
        real_popen = subprocess.Popen

        def run_in_fixture_directory(command, **kwargs):
            return real_popen(command, cwd=self.directory, **kwargs)

        return patch.object(oracle.subprocess, "Popen", side_effect=run_in_fixture_directory)

    def test_bad_magic_and_input_size_reject_before_invoking_tool(self):
        with patch.object(oracle, "_MAX_PDB_BYTES", len(oracle._PDB_MAGIC)):
            with self.assertRaisesRegex(ValueError, "bounded MSF 7.0 PDB"):
                oracle._pdb_yaml(self.pdb, sys.executable)
        self.pdb.write_bytes(b"not a PDB")
        with self.assertRaisesRegex(ValueError, "bounded MSF 7.0 PDB"):
            oracle._pdb_yaml(self.pdb, sys.executable)

    def test_nonzero_tool_exit_does_not_return_partial_output(self):
        with self.tool("print('partial output')\nraise SystemExit(3)\n"):
            with self.assertRaisesRegex(ValueError, "rejected.*exit 3"):
                oracle._pdb_yaml(self.pdb, sys.executable)

    def test_tool_timeout_and_output_limit(self):
        with self.tool("import time\ntime.sleep(10)\n"), patch.object(oracle, "_TOOL_TIMEOUT_SECONDS", 0.1):
            with self.assertRaisesRegex(ValueError, "timed out"):
                oracle._pdb_yaml(self.pdb, sys.executable)
        with self.tool("print('x' * 8192, flush=True)\n"), patch.object(oracle, "_MAX_YAML_BYTES", 4096):
            with self.assertRaisesRegex(ValueError, "output limit"):
                oracle._pdb_yaml(self.pdb, sys.executable)


if __name__ == "__main__":
    unittest.main()
