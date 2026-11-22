# Copyright 2026 YurilLAB
# SPDX-License-Identifier: Apache-2.0
"""List the pointer parameters a DWARF file places in an argument register at function entry.

The oracle side of the family calibration. For every function with code it reads where the
compiler says each parameter lives at the entry address, so a changed or shortened signature
(IPA clones, removed arguments) cannot be mislabelled, and it records the declared layout of
every structure, union or class such a parameter points to.
"""

from collections.abc import Callable
from pathlib import Path

from elftools.dwarf.descriptions import describe_form_class
from elftools.dwarf.dwarf_expr import DWARFExprParser
from elftools.dwarf.locationlists import BaseAddressEntry, LocationEntry, LocationExpr, LocationParser
from elftools.dwarf.ranges import BaseAddressEntry as RangeBase, RangeEntry
from elftools.elf.elffile import ELFFile


AGGREGATES = {
    "DW_TAG_structure_type": "struct",
    "DW_TAG_union_type": "union",
    "DW_TAG_class_type": "class",
}
WRAPPERS = {
    "DW_TAG_typedef", "DW_TAG_const_type", "DW_TAG_volatile_type", "DW_TAG_restrict_type",
    "DW_TAG_atomic_type",
}
POINTERS = {"DW_TAG_pointer_type", "DW_TAG_reference_type", "DW_TAG_rvalue_reference_type"}
SCALARS = POINTERS | {"DW_TAG_base_type", "DW_TAG_enumeration_type", "DW_TAG_ptr_to_member_type"}
# DWARF register numbers of the integer argument registers, with Ghidra's register names.
ARGUMENT_REGISTERS = {
    "EM_X86_64": {5: "RDI", 4: "RSI", 1: "RDX", 2: "RCX", 8: "R8", 9: "R9"},
}
MAX_DEBUG_BYTES = 512 * 1024 * 1024
MAX_LAYOUT_BYTES = 1 << 32
MAX_MEMBERS = 4096
MAX_TYPE_DEPTH = 64
MAX_TYPES = 200_000
MAX_RANGE_STATES = 32_768
MAX_FUNCTIONS = 200_000
MAX_PARAMETERS = 64
MAX_EXPRESSION_BYTES = 64


class _Reader:
    def __init__(self, info, registers: dict[int, str]):
        self.info = info
        self.registers = registers
        self.locations = LocationParser(info.location_lists())
        self.ranges = info.range_lists()
        self.expressions = DWARFExprParser(info.structs)
        self.types: dict[str, dict] = {}
        self.functions: dict[int, dict] = {}
        self.conflicts: set[int] = set()
        self.excluded: dict[str, int] = {}
        self.subprograms = 0

    def exclude(self, reason: str) -> None:
        self.excluded[reason] = self.excluded.get(reason, 0) + 1

    # ---- attribute helpers -------------------------------------------------------------

    @staticmethod
    def flag(die, name: str) -> bool:
        attribute = die.attributes.get(name)
        return attribute is not None and bool(attribute.value)

    @staticmethod
    def constant(die, name: str) -> int | None:
        attribute = die.attributes.get(name)
        if (attribute is None or describe_form_class(attribute.form) != "constant" or
                type(attribute.value) is not int):
            return None
        return attribute.value

    def inherited(self, die, name: str):
        """Reads an attribute through abstract-origin and specification links."""
        for _ in range(8):
            if name in die.attributes:
                return die, die.attributes[name]
            link = next((key for key in ("DW_AT_abstract_origin", "DW_AT_specification")
                         if key in die.attributes), None)
            if link is None:
                return die, None
            die = die.get_DIE_from_attribute(link)
        return die, None

    def text(self, die, name: str) -> str:
        _, attribute = self.inherited(die, name)
        if attribute is None or not isinstance(attribute.value, bytes):
            return ""
        return attribute.value.decode("utf-8", "replace")[:256]

    def referenced(self, die, name: str = "DW_AT_type"):
        owner, attribute = self.inherited(die, name)
        return None if attribute is None else owner.get_DIE_from_attribute(name)

    def unwrap(self, die):
        for _ in range(MAX_TYPE_DEPTH):
            if die is None or die.tag not in WRAPPERS:
                return die
            die = self.referenced(die)
        return None

    # ---- declared layouts --------------------------------------------------------------

    def intern(self, die, depth: int = 0) -> str:
        die = self.unwrap(die)
        if die is None:
            return self.remember("void", {"kind": "unknown", "size": None})
        key = f"{die.offset:x}"
        if key in self.types:
            return key
        if depth >= MAX_TYPE_DEPTH or len(self.types) >= MAX_TYPES:
            raise ValueError("DWARF type nesting or type count exceeds the oracle limit")
        # Reserve the key first: a malformed self-containing type then ends in a lookup.
        self.types[key] = {"kind": "unknown", "size": None}
        self.types[key] = self.describe(die, depth)
        return key

    def remember(self, key: str, node: dict) -> str:
        if key not in self.types and len(self.types) >= MAX_TYPES:
            raise ValueError("DWARF type count exceeds the oracle limit")
        self.types.setdefault(key, node)
        return key

    def describe(self, die, depth: int) -> dict:
        if die.tag in AGGREGATES:
            return self.aggregate(die, depth)
        if die.tag == "DW_TAG_array_type":
            return self.array(die, depth)
        if die.tag in SCALARS:
            size = self.constant(die, "DW_AT_byte_size")
            if size is None and die.tag in POINTERS:
                size = die.cu["address_size"]
            return {"kind": "scalar", "size": size if size and size <= MAX_LAYOUT_BYTES else None}
        return {"kind": "unknown", "size": None}

    def array(self, die, depth: int) -> dict:
        counts = []
        flexible = False
        for child in die.iter_children():
            if child.tag != "DW_TAG_subrange_type":
                continue
            if depth + len(counts) + 1 >= MAX_TYPE_DEPTH:
                raise ValueError("DWARF array nesting exceeds the oracle limit")
            if not counts:
                flexible = ("DW_AT_count" not in child.attributes and
                            "DW_AT_upper_bound" not in child.attributes)
            length = self.constant(child, "DW_AT_count")
            if length is None:
                last = self.constant(child, "DW_AT_upper_bound")
                first = self.constant(child, "DW_AT_lower_bound") or 0
                length = None if last is None else last - first + 1
            # A missing or computed bound is a flexible or variable-length dimension.
            counts.append(length if length is not None and length >= 0 else None)
        if not counts:
            counts.append(None)
        element = self.intern(self.referenced(die), depth + len(counts))
        # C and C++ DWARF list dimensions from outermost to innermost. Model each
        # dimension so an exact row can be matched as an element of the outer array.
        for index in range(len(counts) - 1, 0, -1):
            element = self.remember(f"{die.offset:x}[{index}]",
                                    self.array_dimension(element, counts[index]))
        outer = self.array_dimension(element, counts[0])
        if flexible and self.types[element]["size"]:
            outer["flexible_tail"] = True
        return outer

    def array_dimension(self, element: str, count: int | None) -> dict:
        width = self.types[element]["size"]
        size = width * count if width is not None and count is not None else None
        if size is not None and size > MAX_LAYOUT_BYTES:
            size = None
        return {"kind": "array", "size": size, "element": element, "count": count}

    def aggregate(self, die, depth: int) -> dict:
        kind = AGGREGATES[die.tag]
        node = {"kind": kind, "name": self.text(die, "DW_AT_name"), "size": None, "members": [],
                "bitfields": [], "dynamic": False}
        size = self.constant(die, "DW_AT_byte_size")
        if self.flag(die, "DW_AT_declaration") or size is None or size > MAX_LAYOUT_BYTES:
            return node
        node["size"] = size
        last_member = None
        for child in die.iter_children():
            if child.tag not in ("DW_TAG_member", "DW_TAG_inheritance"):
                continue
            if child.tag == "DW_TAG_member" and (
                    self.flag(child, "DW_AT_declaration") or self.flag(child, "DW_AT_external")):
                continue  # static data member: no storage in the object
            if len(node["members"]) + len(node["bitfields"]) >= MAX_MEMBERS:
                node["dynamic"] = True
                break
            last_member = None
            width = self.constant(child, "DW_AT_bit_size")
            if width is not None:
                span = self.bitfield_bytes(child, width, kind, depth)
                if span is None:
                    node["dynamic"] = True
                else:
                    node["bitfields"].append(span)
                continue
            offset = self.member_offset(child, kind)
            if offset is None or self.constant(child, "DW_AT_virtuality"):
                node["dynamic"] = True  # virtual base or computed member location
                continue
            last_member = {"offset": offset, "name": self.text(child, "DW_AT_name"),
                           "type": self.intern(self.referenced(child), depth + 1)}
            node["members"].append(last_member)
        # GCC permits a flexible array's enclosing structure to sit in a union
        # or at the end of another structure. Its sizeof still excludes the tail.
        terminal = node["members"] if kind == "union" else (last_member,)
        for member in terminal:
            if member is not None and self.types[member["type"]].get("flexible_tail"):
                member["flexible_tail"] = node["flexible_tail"] = True
        return node

    def member_offset(self, member, kind: str) -> int | None:
        location = member.attributes.get("DW_AT_data_member_location")
        if location is None:
            return 0 if kind == "union" else None
        form = describe_form_class(location.form)
        if form == "constant" and type(location.value) is int and location.value >= 0:
            return location.value
        if form in ("exprloc", "block") and len(location.value) <= MAX_EXPRESSION_BYTES:
            operations = self.expressions.parse_expr(location.value)
            if len(operations) == 1 and operations[0].op_name == "DW_OP_plus_uconst":
                return operations[0].args[0]
        return None

    def bitfield_bytes(self, member, width: int, kind: str, depth: int) -> list[int] | None:
        """Bytes that hold a bit field: accesses to them are outside a byte-level oracle."""
        position = self.constant(member, "DW_AT_data_bit_offset")
        if position is not None:
            return [position // 8, (position + max(width, 1) + 7) // 8]
        offset = self.member_offset(member, kind)
        storage = self.constant(member, "DW_AT_byte_size")
        if storage is None:
            storage = self.types[self.intern(self.referenced(member), depth + 1)]["size"]
        return None if offset is None or not storage else [offset, offset + storage]

    # ---- functions ---------------------------------------------------------------------

    def entry_register(self, parameter, entry: int, unit_base: int) -> int | None:
        """The DWARF register that holds the parameter at the entry address, if it is one."""
        attribute = parameter.attributes.get("DW_AT_location")
        version = parameter.cu["version"]
        if attribute is None or not self.locations.attribute_has_location(attribute, version):
            return None
        parsed = self.locations.parse_from_attribute(attribute, version, die=parameter)
        expression = None
        if isinstance(parsed, LocationExpr):
            expression = parsed.loc_expr
        else:
            base = unit_base
            for item in parsed:
                if isinstance(item, BaseAddressEntry):
                    base = item.base_address
                elif isinstance(item, LocationEntry):
                    start = item.begin_offset + (0 if getattr(item, "is_absolute", False) else base)
                    stop = item.end_offset + (0 if getattr(item, "is_absolute", False) else base)
                    if start == entry and stop > entry:
                        expression = item.loc_expr
                        break
        if expression is None or not 0 < len(expression) <= MAX_EXPRESSION_BYTES:
            return None
        operations = self.expressions.parse_expr(expression)
        if len(operations) != 1:
            return None
        name = operations[0].op_name
        if name == "DW_OP_regx":
            return operations[0].args[0]
        if name.startswith("DW_OP_reg") and name[9:].isdigit():
            return int(name[9:])
        return None

    def entry_address(self, die, unit_base: int) -> int | None:
        """The entry of a function with code: its low PC, or the start of its first range.

        A function split into hot and cold parts lists ranges instead. A wrong guess cannot
        mislabel anything: a parameter counts only if its location starts at this address.
        """
        low = die.attributes.get("DW_AT_low_pc")
        if low is not None:
            if describe_form_class(low.form) != "address" or type(low.value) is not int:
                return None
            return low.value
        listed = die.attributes.get("DW_AT_ranges")
        if listed is None or self.ranges is None or type(listed.value) is not int:
            return None
        base = unit_base
        for item in self.ranges.get_range_list_at_offset(listed.value, cu=die.cu):
            if isinstance(item, RangeBase):
                base = item.base_address
            elif isinstance(item, RangeEntry):
                return item.begin_offset + (0 if getattr(item, "is_absolute", False) else base)
        return None

    def function(self, die, unit_base: int) -> None:
        if self.flag(die, "DW_AT_declaration"):
            return
        entry = self.entry_address(die, unit_base)
        if entry is None:
            return  # an abstract instance has no code of its own
        self.subprograms += 1
        if self.subprograms > MAX_FUNCTIONS:
            raise ValueError("DWARF function count exceeds the oracle limit")
        parameters = [child for child in die.iter_children()
                      if child.tag in ("DW_TAG_formal_parameter", "DW_TAG_GNU_formal_parameter_pack")]
        if len(parameters) > MAX_PARAMETERS or any(
                child.tag != "DW_TAG_formal_parameter" for child in parameters):
            self.exclude("parameter pack or too many parameters")
            return
        selected = []
        registers: dict[int, int] = {}
        for index, parameter in enumerate(parameters):
            number = self.entry_register(parameter, entry, unit_base)
            if number is None:
                continue
            if number in registers:
                self.exclude("two parameters share one entry register")
                return
            registers[number] = index
            pointer = self.unwrap(self.referenced(parameter))
            register = self.registers.get(number)
            if pointer is None or pointer.tag not in POINTERS or register is None:
                continue
            target = self.unwrap(self.referenced(pointer))
            if target is None or target.tag not in AGGREGATES:
                continue
            selected.append({"index": index, "name": self.text(parameter, "DW_AT_name"),
                             "register": register, "type": self.intern(target)})
        if not selected:
            self.exclude("no aggregate pointer parameter in an argument register at entry")
            return
        record = {"name": self.text(die, "DW_AT_linkage_name") or self.text(die, "DW_AT_name"),
                  "low_pc": entry, "parameters": selected}
        known = self.functions.get(entry)
        if known is None:
            self.functions[entry] = record
        elif self.signature(known) != self.signature(record):
            self.conflicts.add(entry)

    def signature(self, record: dict) -> list:
        return [(item["index"], item["register"], self.types[item["type"]]["kind"],
                 self.types[item["type"]].get("name"), self.types[item["type"]]["size"])
                for item in record["parameters"]]

    def unit(self, unit) -> None:
        top = unit.get_top_DIE()
        base = top.attributes.get("DW_AT_low_pc")
        unit_base = base.value if base is not None and type(base.value) is int else 0
        pending = [top]
        while pending:
            for child in pending.pop().iter_children():
                if child.tag == "DW_TAG_subprogram":
                    self.function(child, unit_base)
                elif child.tag == "DW_TAG_namespace":
                    pending.append(child)


def read_dwarf_targets(debug: Path) -> dict:
    """Returns functions with aggregate-pointer parameters in entry registers, and their layouts."""
    if not 0 < debug.stat().st_size <= MAX_DEBUG_BYTES:
        raise ValueError("DWARF oracle size is outside the supported range")
    with debug.open("rb") as stream:
        elf = ELFFile(stream)
        machine = elf.header["e_machine"]
        if machine not in ARGUMENT_REGISTERS or elf.elfclass != 64 or not elf.little_endian:
            raise ValueError("the target oracle supports little-endian x86-64 ELF only")
        if not elf.has_dwarf_info(strict=True):
            raise ValueError("oracle lacks a DWARF information section")
        for section in elf.iter_sections():
            if section.name.startswith(".zdebug") or (
                    section.name.startswith(".debug") and section.compressed):
                raise ValueError("the target oracle requires uncompressed DWARF")
        reader = _Reader(elf.get_dwarf_info(follow_links=False), ARGUMENT_REGISTERS[machine])
        for unit in reader.info.iter_CUs():
            reader.unit(unit)
    for address in reader.conflicts:
        del reader.functions[address]
    if reader.conflicts:
        reader.excluded["conflicting descriptions of one entry address"] = len(reader.conflicts)
    return {"architecture": "x86_64", "subprograms_with_code": reader.subprograms,
            "functions": [reader.functions[address] for address in sorted(reader.functions)],
            "excluded": dict(sorted(reader.excluded.items())), "types": reader.types}


def target_status(types: dict, type_id: str) -> str | None:
    """Why a pointee layout cannot label fields, or None when it can."""
    node = types[type_id]
    if node["size"] is None:
        return "pointee type is incomplete"
    if node["dynamic"]:
        return "pointee layout has a virtual base or computed member location"
    if not node["members"] and not node["bitfields"]:
        return "pointee type declares no data members"
    return None


class _RangeBudgetExceeded(Exception):
    pass


def classify_range(types: dict, type_id: str, offset: int, width: int) -> str:
    """Labels a byte range inside a pointee: member, none, bitfield or unsupported.

    ``member`` means the range is exactly one declared member, array element or base-class
    subobject at any nesting depth. ``bitfield`` and ``unsupported`` ranges touch storage a
    byte-level oracle cannot judge.
    """
    if type(offset) is not int or type(width) is not int or offset < 0 or width < 1:
        return "none"
    # Overlapping union views can lead to the same subobject many times.
    memo: dict[tuple[str, int, int], str] = {}
    visited = 0

    def visit(key: str, relative: int, depth: int) -> str:
        nonlocal visited
        if depth > MAX_TYPE_DEPTH:
            return "unsupported"
        state = (key, relative, depth)
        if state not in memo:
            if visited >= MAX_RANGE_STATES:
                raise _RangeBudgetExceeded
            visited += 1
            memo[state] = _inside(types, types[key], relative, width, depth, visit)
        return memo[state]

    try:
        return visit(type_id, offset, 0)
    except _RangeBudgetExceeded:
        return "unsupported"


def _inside(types: dict, node: dict, offset: int, width: int, depth: int,
            visit: Callable[[str, int, int], str]) -> str:
    if node["kind"] in ("struct", "union", "class"):
        if node["dynamic"]:
            return "unsupported"
        if any(start < offset + width and offset < stop for start, stop in node["bitfields"]):
            return "bitfield"
        verdict = "none"
        for member in node["members"]:
            child = types[member["type"]]
            relative = offset - member["offset"]
            if relative < 0:
                continue
            size = child["size"]
            if size is not None and (relative, width) == (0, size):
                return "member"
            if size is None and child["kind"] != "array":
                continue
            if size is not None and relative + width > size and not member.get("flexible_tail"):
                continue
            found = visit(member["type"], relative, depth + 1)
            if found == "member":
                return found
            if found != "none":
                verdict = found
        return verdict
    if node["kind"] == "array":
        element = types[node["element"]]
        size = element["size"]
        if size is None and element["kind"] == "array":
            return "unsupported"
        if not size:
            return "none"
        index, relative = divmod(offset, size)
        if node["count"] is not None and index >= node["count"]:
            return "none"
        if (relative, width) == (0, size):
            return "member"
        if relative + width > size:
            return "none"
        return visit(node["element"], relative, depth + 1)
    return "none"
