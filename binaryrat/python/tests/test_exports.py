"""Export identity and corruption tests. Apache-2.0; Copyright 2026 YurilLAB."""

import json
import unittest

from binaryrat import Address, ExportError, TypeProposal, parse_export


def record(**overrides):
    row = dict(
        schema_version=1, program_id="fixture", revision=7, address_space="ram",
        address="fffffffffffffff0", name="main", body_sha256="ab" * 32,
        c="int main(void) { return 0; }\n", prototype="int main(void)",
        completed=True, timed_out=False, cancelled=False, failed_to_start=False, error="",
    )
    row.update(overrides)
    return json.dumps(row)


class ExportTests(unittest.TestCase):
    def test_unsigned_offsets_and_address_spaces_survive(self):
        values = list(parse_export([record(), record(address_space="overlay")]))
        self.assertEqual(values[0].function.entry, Address("ram", 0xFFFFFFFFFFFFFFF0))
        self.assertNotEqual(values[0].function.entry, values[1].function.entry)
        self.assertTrue(values[0].successful)
        self.assertEqual(values[0].function.body_ranges, ())

    def test_errors_report_physical_line_numbers(self):
        with self.assertRaisesRegex(ExportError, "line 3:.*revision must be int"):
            list(parse_export([record(), "\n", record(revision=True)]))

    def test_duplicate_identity_is_rejected_but_new_revision_is_distinct(self):
        self.assertEqual(len(list(parse_export([record(), record(revision=8)]))), 2)
        with self.assertRaisesRegex(ExportError, "duplicate function identity"):
            list(parse_export([record(), record(c="changed output")]))

    def test_status_is_not_inferred_from_c_text(self):
        item = next(parse_export([record(completed=False, timed_out=True)]))
        self.assertFalse(item.successful)
        self.assertTrue(item.timed_out)

    def test_invalid_records_fail_instead_of_becoming_partial_functions(self):
        for fields in (
            {"schema_version": 2}, {"address": "-10"}, {"address": 16},
            {"body_sha256": "short"}, {"completed": 1}, {"revision": -1},
            {"body_ranges": [["20", "10"]]}, {"address_space": ""},
        ):
            with self.subTest(fields=fields), self.assertRaises(ExportError):
                list(parse_export([record(**fields)]))

    def test_stream_is_lazy_and_unknown_fields_are_allowed(self):
        def lines():
            yield record(future_metadata={"kind": "extension"})
            raise RuntimeError("second line was requested")
        stream = parse_export(lines())
        self.assertEqual(next(stream).function.name, "main")
        with self.assertRaisesRegex(RuntimeError, "second line"):
            next(stream)

    def test_nonfinite_or_out_of_range_proposal_confidence_is_rejected(self):
        for confidence in (float("nan"), float("inf"), -0.1, 1.1):
            with self.subTest(confidence=confidence), self.assertRaises(ValueError):
                TypeProposal("object", "struct", confidence, (), {})


if __name__ == "__main__":
    unittest.main()
