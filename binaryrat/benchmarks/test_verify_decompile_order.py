# Copyright 2026 YurilLAB
# SPDX-License-Identifier: Apache-2.0
"""Validate the decompile-order comparison and its fixture without a JVM."""

import hashlib
import unittest

import verify_decompile_order as order


def digests(fresh: dict[str, str], changed: dict[tuple[str, str], str] | None = None) -> dict:
    rows = {(phase, name): fresh[name] for phase in order.PHASES for name in order.FUNCTIONS}
    return rows | (changed or {})


FRESH = {name: hashlib.sha256(name.encode()).hexdigest() for name in order.FUNCTIONS}
OTHER = hashlib.sha256(b"renamed temporaries").hexdigest()


class DecompileOrderTests(unittest.TestCase):
    def test_fixture_entries_start_with_endbr64_and_end_with_ret(self):
        self.assertEqual(len(order.FIXTURE), 0x9a)
        for entry in (0x0, 0xf, 0x36, 0x69):
            self.assertEqual(order.FIXTURE[entry:entry + 4], bytes.fromhex("f30f1efa"))
        for end in (0xf, 0x36, 0x69, 0x9a):
            self.assertEqual(order.FIXTURE[end - 1], 0xc3)

    def test_candidate_matching_a_new_stock_process_passes(self):
        stock = digests(FRESH, {("reverse", "first16"): OTHER})
        summary = order.compare(stock, digests(FRESH))
        self.assertEqual(summary["stock_order_dependent"], ["first16"])
        self.assertEqual(summary["fresh_digests"], FRESH)

    def test_stock_without_the_order_effect_fails_the_control(self):
        with self.assertRaisesRegex(RuntimeError, "no longer depends on decompile order"):
            order.compare(digests(FRESH), digests(FRESH))

    def test_candidate_matching_only_stock_history_fails(self):
        stock = digests(FRESH, {("reverse", "first16"): OTHER})
        with self.assertRaisesRegex(RuntimeError, "reverse:first16"):
            order.compare(stock, stock)

    def test_candidate_differing_in_any_phase_fails(self):
        stock = digests(FRESH, {("forward", "first12"): OTHER})
        for phase in order.PHASES:
            for name in order.FUNCTIONS:
                with self.subTest(phase=phase, name=name):
                    with self.assertRaisesRegex(RuntimeError, f"{phase}:{name}"):
                        order.compare(stock, digests(FRESH, {(phase, name): OTHER}))


if __name__ == "__main__":
    unittest.main()
