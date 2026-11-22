# Copyright 2026 YurilLAB
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path
import random
import shutil
import subprocess
import sys
import tempfile
import unittest

from elftools.dwarf.dwarf_expr import DWARFExprParser
from elftools.dwarf.locationlists import BaseAddressEntry, LocationEntry, LocationExpr
from elftools.dwarf.structs import DWARFStructs

from dwarf_targets import (ARGUMENT_REGISTERS, _Reader, classify_range, read_dwarf_targets,
                           target_status)


def scalar(size):
    return {"kind": "scalar", "size": size}


def aggregate(size, members, kind="struct", bitfields=(), dynamic=False):
    return {"kind": kind, "name": "T", "size": size, "dynamic": dynamic,
            "members": [{"offset": offset, "name": "", "type": name} for offset, name in members],
            "bitfields": [list(item) for item in bitfields]}


TYPES = {
    "i8": scalar(1), "i16": scalar(2), "i32": scalar(4), "i64": scalar(8), "f32": scalar(4),
    "void": {"kind": "unknown", "size": None},
    "pair": aggregate(4, [(0, "i16"), (2, "i16")]),
    "words": {"kind": "array", "size": 24, "element": "i64", "count": 3},
    "pairs": {"kind": "array", "size": 8, "element": "pair", "count": 2},
    "tail": {"kind": "array", "size": None, "element": "i32", "count": None},
    "either": aggregate(4, [(0, "i32"), (0, "f32"), (0, "pair")], kind="union"),
    "base": aggregate(8, [(0, "i32"), (4, "i32")]),
    # tag, a nested pair, three words, two pairs, a union, a bit-field byte, a flexible tail
    "outer": aggregate(56, [(0, "i32"), (4, "pair"), (8, "words"), (32, "pairs"), (40, "either"),
                            (48, "tail")], bitfields=[(44, 45)]),
    "derived": aggregate(16, [(0, "base"), (8, "i64")], kind="class"),
    "virtual": aggregate(16, [(8, "i64")], kind="class", dynamic=True),
    "holder": aggregate(24, [(0, "i64"), (8, "virtual")]),
    "opaque": aggregate(None, []),
    "empty": aggregate(1, []),
    "bits": aggregate(4, [], bitfields=[(0, 4)]),
    "wide": aggregate(16, [(0, "void"), (8, "i64")]),
}


class RangeTests(unittest.TestCase):
    def verdicts(self, name, ranges):
        return [classify_range(TYPES, name, offset, width) for offset, width in ranges]

    def test_members_at_every_depth(self):
        exact = [(0, 4), (4, 4), (4, 2), (6, 2), (8, 24), (8, 8), (16, 8), (24, 8),
                 (32, 8), (32, 4), (36, 4), (32, 2), (38, 2), (40, 4), (40, 2), (42, 2)]
        self.assertEqual(self.verdicts("outer", exact), ["member"] * len(exact))

    def test_ranges_that_are_not_one_member(self):
        wrong = [(0, 8), (0, 2), (2, 2), (4, 1), (5, 2), (8, 4), (12, 8), (8, 16), (30, 4),
                 (34, 4), (46, 2), (52, 8)]
        self.assertEqual(self.verdicts("outer", wrong), ["none"] * len(wrong))

    def test_arrays_respect_their_length_and_element_grid(self):
        self.assertEqual(self.verdicts("words", [(0, 8), (16, 8), (24, 8), (4, 8), (0, 4)]),
                         ["member", "member", "none", "none", "none"])
        # A flexible array member has no declared end.
        self.assertEqual(self.verdicts("outer", [(48, 4), (52, 4), (4096, 4), (50, 4), (48, 8)]),
                         ["member", "member", "member", "none", "none"])

    def test_bitfield_and_dynamic_storage_is_not_judged(self):
        self.assertEqual(self.verdicts("outer", [(44, 1), (44, 4), (43, 2), (0, 56)]), ["bitfield"] * 4)
        self.assertEqual(self.verdicts("bits", [(0, 4), (0, 1), (3, 1)]), ["bitfield"] * 3)
        self.assertEqual(self.verdicts("holder", [(0, 8), (8, 8), (16, 8), (8, 16)]),
                         ["member", "unsupported", "unsupported", "member"])
        self.assertEqual(classify_range(TYPES, "virtual", 8, 8), "unsupported")

    def test_base_classes_and_union_alternatives(self):
        self.assertEqual(self.verdicts("derived", [(0, 8), (0, 4), (4, 4), (8, 8), (4, 8)]),
                         ["member", "member", "member", "member", "none"])
        self.assertEqual(self.verdicts("either", [(0, 4), (0, 2), (2, 2), (1, 2), (0, 8)]),
                         ["member", "member", "member", "none", "none"])

    def test_invalid_ranges_and_unknown_members(self):
        for offset, width in ((-1, 4), (0, 0), (0, -4), (True, 4), (0, 4.0), ("0", 4)):
            self.assertEqual(classify_range(TYPES, "outer", offset, width), "none")
        self.assertEqual(self.verdicts("wide", [(0, 8), (8, 8)]), ["none", "member"])

    def test_nesting_beyond_the_limit_is_unsupported(self):
        types = {"leaf": scalar(4)}
        previous = "leaf"
        for index in range(80):
            types[f"n{index}"] = aggregate(8, [(0, previous)])
            previous = f"n{index}"
        types["leaf"] = scalar(4)
        self.assertEqual(classify_range(types, previous, 0, 4), "unsupported")
        self.assertEqual(classify_range(types, "n3", 0, 4), "member")

    def test_target_status(self):
        self.assertIsNone(target_status(TYPES, "outer"))
        self.assertIsNone(target_status(TYPES, "bits"))
        self.assertIn("incomplete", target_status(TYPES, "opaque"))
        self.assertIn("virtual", target_status(TYPES, "virtual"))
        self.assertIn("no data members", target_status(TYPES, "empty"))


def random_layout(randomizer):
    """A random nested layout of structures, unions and arrays, and its root type name."""
    types = {f"s{size}": scalar(size) for size in (1, 2, 4, 8)}

    def build(depth):
        choice = randomizer.random()
        if depth >= 4 or choice < 0.35:
            return f"s{randomizer.choice((1, 2, 4, 8))}"
        name = f"t{len(types)}"
        types[name] = None
        if choice < 0.55:
            element = build(depth + 1)
            count = randomizer.randint(1, 4)
            types[name] = {"kind": "array", "size": types[element]["size"] * count,
                           "element": element, "count": count}
            return name
        union = choice > 0.9
        members, offset, size = [], 0, 0
        for _ in range(randomizer.randint(1, 4)):
            member = build(depth + 1)
            if not union:
                offset += randomizer.choice((0, 0, 0, 1, 2, 4))  # padding
            members.append((offset, member))
            size = max(size, offset + types[member]["size"])
            if not union:
                offset += types[member]["size"]
        types[name] = aggregate(size + randomizer.choice((0, 0, 4)), members,
                                "union" if union else "struct")
        return name

    root = build(0)
    while types[root]["kind"] == "scalar":
        root = build(0)
    return types, root


def subobjects(types, name, base, found):
    """Every member and array element at any depth, by plain enumeration."""
    node = types[name]
    if node["kind"] == "array":
        size = types[node["element"]]["size"]
        for index in range(node["count"]):
            found.add((base + index * size, size))
            subobjects(types, node["element"], base + index * size, found)
    elif node["kind"] != "scalar":
        for member in node["members"]:
            found.add((base + member["offset"], types[member["type"]]["size"]))
            subobjects(types, member["type"], base + member["offset"], found)
    return found


class ReferenceModelTests(unittest.TestCase):
    def test_seeded_layouts_agree_with_enumeration(self):
        checked = members = 0
        for seed in range(300):
            types, root = random_layout(random.Random(seed))
            expected = subobjects(types, root, 0, set())
            size = types[root]["size"]
            widths = sorted({1, 2, 3, 4, 6, 8, 12, 16, 24, 32, size} | {width for _, width in expected})
            for offset in range(size + 9):
                for width in widths:
                    verdict = classify_range(types, root, offset, width)
                    want = "member" if (offset, width) in expected else "none"
                    self.assertEqual(verdict, want, (seed, root, offset, width))
                    checked += 1
                    members += want == "member"
        # The generator must exercise both answers in bulk, or the check proves nothing.
        self.assertGreater(members, 2_000)
        self.assertGreater(checked - members, 50_000)


class Attribute:
    def __init__(self, value, form):
        self.value, self.form = value, form


class Die:
    """The few DIE operations the reader uses, without a compiler."""
    count = 0

    def __init__(self, tag, attributes=None, children=(), links=None):
        Die.count += 1
        self.tag, self.offset = tag, Die.count
        self.attributes = attributes or {}
        self.children, self.links = list(children), links or {}
        self.cu = {"version": 4, "address_size": 8}

    def iter_children(self):
        return iter(self.children)

    def get_DIE_from_attribute(self, name):
        return self.links[name]


class Locations:
    """Returns the location description stored as the attribute's value."""

    def attribute_has_location(self, attribute, version):
        return attribute.value is not None

    def parse_from_attribute(self, attribute, version, die=None):
        return attribute.value


def register(number):
    return bytes([0x50 + number])  # DW_OP_reg0 + number


def entry(begin, end, expression, absolute=False):
    return LocationEntry(0, 0, begin, end, expression, absolute)


def reader():
    instance = _Reader.__new__(_Reader)
    instance.registers = ARGUMENT_REGISTERS["EM_X86_64"]
    instance.locations = Locations()
    instance.ranges = None
    instance.expressions = DWARFExprParser(DWARFStructs(little_endian=True, dwarf_format=32,
                                                        address_size=8))
    instance.types, instance.functions = {}, {}
    instance.conflicts, instance.excluded, instance.subprograms = set(), {}, 0
    return instance


def parameter(name, location, target):
    pointer = Die("DW_TAG_pointer_type", links={"DW_AT_type": target} if target else {},
                  attributes={"DW_AT_type": Attribute(0, "DW_FORM_ref4")} if target else {})
    return Die("DW_TAG_formal_parameter",
               {"DW_AT_name": Attribute(name.encode(), "DW_FORM_string"),
                "DW_AT_type": Attribute(0, "DW_FORM_ref4"),
                "DW_AT_location": Attribute(location, "DW_FORM_exprloc")},
               links={"DW_AT_type": pointer})


def structure(name="record", size=8):
    member = Die("DW_TAG_member", {"DW_AT_data_member_location": Attribute(0, "DW_FORM_data1"),
                                   "DW_AT_type": Attribute(0, "DW_FORM_ref4")},
                 links={"DW_AT_type": Die("DW_TAG_base_type",
                                          {"DW_AT_byte_size": Attribute(size, "DW_FORM_data1")})})
    return Die("DW_TAG_structure_type", {"DW_AT_name": Attribute(name.encode(), "DW_FORM_string"),
                                         "DW_AT_byte_size": Attribute(size, "DW_FORM_data1")}, [member])


def subprogram(name, low, parameters):
    return Die("DW_TAG_subprogram", {"DW_AT_name": Attribute(name.encode(), "DW_FORM_string"),
                                     "DW_AT_low_pc": Attribute(low, "DW_FORM_addr")}, parameters)


class EntryLocationTests(unittest.TestCase):
    def number(self, location, start=0x1000, base=0):
        probe = parameter("p", location, None)
        return reader().entry_register(probe, start, base)

    def test_argument_register_table_is_the_system_v_order(self):
        self.assertEqual(ARGUMENT_REGISTERS["EM_X86_64"],
                         {5: "RDI", 4: "RSI", 1: "RDX", 2: "RCX", 8: "R8", 9: "R9"})

    def test_single_expression_must_be_exactly_one_register(self):
        self.assertEqual(self.number(LocationExpr(register(5))), 5)
        self.assertEqual(self.number(LocationExpr(bytes([0x90, 9]))), 9)  # DW_OP_regx 9
        self.assertIsNone(self.number(LocationExpr(bytes([0x91, 0x10]))))  # DW_OP_fbreg 16
        self.assertIsNone(self.number(LocationExpr(bytes([0x75, 0]))))  # DW_OP_breg5 0
        self.assertIsNone(self.number(LocationExpr(register(5) + bytes([0x9f]))))  # reg, stack_value
        self.assertIsNone(self.number(LocationExpr(b"")))
        self.assertIsNone(self.number(None))

    def test_only_the_range_that_starts_at_the_entry_counts(self):
        later_first = [entry(0x1010, 0x1020, register(3)), entry(0x1000, 0x1010, register(4))]
        self.assertEqual(self.number(later_first), 4)
        self.assertIsNone(self.number([entry(0x1004, 0x1020, register(5))]))
        self.assertIsNone(self.number([entry(0x0ff0, 0x1020, register(5))]))
        self.assertIsNone(self.number([entry(0x1000, 0x1000, register(5))]))
        self.assertIsNone(self.number([]))

    def test_offsets_are_relative_to_the_unit_or_a_base_entry(self):
        self.assertEqual(self.number([entry(0x10, 0x20, register(1))], base=0xff0), 1)
        self.assertIsNone(self.number([entry(0x10, 0x20, register(1))], base=0))
        self.assertEqual(self.number([BaseAddressEntry(0, 0, 0x800),
                                      entry(0x800, 0x810, register(2))], base=0x99999), 2)
        self.assertEqual(self.number([entry(0x1000, 0x1010, register(8), absolute=True)],
                                     base=0x5000), 8)

    def test_pointer_in_a_non_argument_register_is_not_a_target(self):
        instance = reader()
        instance.function(subprogram("mixed", 0x1000, [
            parameter("saved", LocationExpr(register(3)), structure()),   # RBX
            parameter("first", LocationExpr(register(5)), structure()),   # RDI
            parameter("stack", LocationExpr(bytes([0x91, 0x10])), structure()),
            parameter("plain", LocationExpr(register(4)), None),          # void * in RSI
        ]), 0)
        record = instance.functions[0x1000]
        self.assertEqual([(item["index"], item["name"], item["register"])
                          for item in record["parameters"]], [(1, "first", "RDI")])

    def test_shared_entry_register_and_duplicate_entries(self):
        instance = reader()
        instance.function(subprogram("clash", 0x2000, [
            parameter("a", LocationExpr(register(5)), structure()),
            parameter("b", LocationExpr(register(5)), structure())]), 0)
        self.assertNotIn(0x2000, instance.functions)
        self.assertEqual(instance.excluded, {"two parameters share one entry register": 1})
        # Two descriptions of one address must agree, or the address is dropped.
        instance.function(subprogram("one", 0x3000, [
            parameter("a", LocationExpr(register(5)), structure("left"))]), 0)
        instance.function(subprogram("one", 0x3000, [
            parameter("a", LocationExpr(register(5)), structure("left"))]), 0)
        self.assertEqual(instance.conflicts, set())
        instance.function(subprogram("one", 0x3000, [
            parameter("a", LocationExpr(register(5)), structure("right"))]), 0)
        self.assertEqual(instance.conflicts, {0x3000})

    def test_declarations_and_abstract_instances_have_no_entry(self):
        instance = reader()
        declared = subprogram("declared", 0x4000, [parameter("a", LocationExpr(register(5)), structure())])
        declared.attributes["DW_AT_declaration"] = Attribute(True, "DW_FORM_flag_present")
        instance.function(declared, 0)
        instance.function(Die("DW_TAG_subprogram", {}, [
            parameter("a", LocationExpr(register(5)), structure())]), 0)
        self.assertEqual((instance.functions, instance.subprograms), ({}, 0))


SOURCE = r"""
struct inner { short low; short high; };
struct outer { int tag; struct inner pair; long values[3]; unsigned flag : 3; unsigned rest : 5; };
struct listed { int count; int items[]; };
union both { int number; float real; };
struct opaque;
struct big { long a, b, c; };
#define KEEP __attribute__((noinline))

KEEP long read_outer(struct outer *item) { return item->values[1] + item->pair.high; }
KEEP int second(double scale, struct outer *item, int extra) { return item->tag + extra + (int)scale; }
KEEP int by_union(union both *value) { return value->number; }
KEEP int opaque_user(struct opaque *handle) { return handle != 0; }
KEEP long plain(long *values, void *other) { return values[0] + (other != 0); }
KEEP long seven(long a, long b, long c, long d, long e, long f, struct outer *last)
{ return a + b + c + d + e + f + last->tag; }
KEEP long by_value(struct big copy, struct outer *item) { return copy.a + item->tag; }
KEEP int flexible(struct listed *list) { return list->items[2] + list->count; }
static KEEP int pick(int unused, struct outer *item) { item->tag += 1; return item->pair.low; }
int use_pick(struct outer *item) { return pick(1, item) + pick(2, item); }
"""


@unittest.skipUnless(sys.platform == "linux" and shutil.which("gcc"), "needs Linux GCC")
class CompiledTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory()
        root = Path(cls.scratch.name)
        (root / "sample.c").write_text(SOURCE, encoding="utf-8")
        cls.library = root / "sample.so"
        subprocess.run(["gcc", "-O2", "-g", "-gdwarf-4", "-fPIC", "-fno-lto", "-shared", "-std=gnu17",
                        "sample.c", "-o", str(cls.library)], cwd=root, check=True)
        cls.symbols = subprocess.run(["nm", str(cls.library)], check=True, capture_output=True,
                                     text=True).stdout
        cls.oracle = read_dwarf_targets(cls.library)
        cls.functions = {function["name"]: function for function in cls.oracle["functions"]}

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()

    def parameter(self, function, name):
        return next(item for item in self.functions[function]["parameters"] if item["name"] == name)

    def test_registers_follow_the_entry_location_not_the_position(self):
        self.assertEqual((self.parameter("read_outer", "item")["index"],
                          self.parameter("read_outer", "item")["register"]), (0, "RDI"))
        # A double before the pointer does not use an integer register.
        self.assertEqual((self.parameter("second", "item")["index"],
                          self.parameter("second", "item")["register"]), (1, "RDI"))
        # A 24-byte structure by value goes to the stack; the pointer is still first.
        self.assertEqual(self.parameter("by_value", "item")["register"], "RDI")
        self.assertEqual(self.parameter("by_union", "value")["register"], "RDI")

    def test_removed_argument_shifts_the_register(self):
        clone = "pick.isra" in self.symbols or "pick.constprop" in self.symbols
        expected = "RDI" if clone else "RSI"
        self.assertEqual(self.parameter("pick", "item")["register"], expected)
        # The clone's debug entry lists only the parameters it still takes.
        self.assertEqual(self.parameter("pick", "item")["index"], 0 if clone else 1)

    def test_functions_without_an_aggregate_register_parameter_are_left_out(self):
        self.assertNotIn("plain", self.functions)
        self.assertNotIn("seven", self.functions)
        self.assertGreaterEqual(
            self.oracle["excluded"]["no aggregate pointer parameter in an argument register at entry"], 2)
        self.assertGreaterEqual(self.oracle["subprograms_with_code"], 10)

    def test_layouts_match_the_source(self):
        types = self.oracle["types"]
        outer = self.parameter("read_outer", "item")["type"]
        self.assertEqual((types[outer]["kind"], types[outer]["name"], types[outer]["size"]),
                         ("struct", "outer", 40))
        self.assertIsNone(target_status(types, outer))
        verdicts = {(0, 4): "member", (4, 2): "member", (6, 2): "member", (4, 4): "member",
                    (8, 8): "member", (16, 8): "member", (24, 8): "member", (8, 24): "member",
                    (0, 8): "none", (8, 4): "none", (12, 8): "none", (36, 4): "none",
                    (32, 4): "bitfield", (32, 1): "bitfield"}
        for (offset, width), expected in verdicts.items():
            self.assertEqual(classify_range(types, outer, offset, width), expected, (offset, width))
        union = self.parameter("by_union", "value")["type"]
        self.assertEqual(types[union]["kind"], "union")
        self.assertEqual(classify_range(types, union, 0, 4), "member")
        listed = self.parameter("flexible", "list")["type"]
        self.assertEqual([classify_range(types, listed, offset, 4) for offset in (0, 4, 12, 400, 6)],
                         ["member", "member", "member", "member", "none"])

    def test_incomplete_pointee_is_reported_not_guessed(self):
        handle = self.parameter("opaque_user", "handle")["type"]
        self.assertIn("incomplete", target_status(self.oracle["types"], handle))

    def test_stripped_or_foreign_files_are_refused(self):
        stripped = Path(self.scratch.name) / "stripped.so"
        subprocess.run(["strip", "--strip-all", "-o", str(stripped), str(self.library)], check=True)
        with self.assertRaises(ValueError):
            read_dwarf_targets(stripped)
        empty = Path(self.scratch.name) / "empty.debug"
        empty.write_bytes(b"")
        with self.assertRaises(ValueError):
            read_dwarf_targets(empty)


if __name__ == "__main__":
    unittest.main()
