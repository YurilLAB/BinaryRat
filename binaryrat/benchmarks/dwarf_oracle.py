# Copyright 2026 YurilLAB
# SPDX-License-Identifier: Apache-2.0
"""Read declared byte-aligned aggregate members from a corpus DWARF file."""

from pathlib import Path

from elftools.dwarf.descriptions import describe_form_class
from elftools.dwarf.dwarf_expr import DWARFExprParser
from elftools.elf.elffile import ELFFile


AGGREGATES = {
    "DW_TAG_structure_type": "struct",
    "DW_TAG_union_type": "union",
    "DW_TAG_class_type": "class",
}
TYPE_WRAPPERS = {
    "DW_TAG_typedef", "DW_TAG_const_type", "DW_TAG_volatile_type", "DW_TAG_restrict_type",
}
MAX_DEBUG_BYTES = 64 * 1024 * 1024
MAX_LAYOUT_BYTES = 1 << 32
MAX_MEMBERS = 4096
MAX_TYPE_DEPTH = 64


def constant(die, name: str, default=None) -> int | None:
    attribute = die.attributes.get(name)
    if attribute is None:
        return default
    if describe_form_class(attribute.form) != "constant" or type(attribute.value) is not int:
        raise ValueError(f"{name} is not a constant integer")
    return attribute.value


def byte_size(die, visited: frozenset[int] = frozenset()) -> int:
    if die is None or die.offset in visited or len(visited) >= MAX_TYPE_DEPTH:
        raise ValueError("unresolved, recursive or excessively nested DWARF type size")
    width = constant(die, "DW_AT_byte_size")
    if width is None:
        if die.tag in ("DW_TAG_pointer_type", "DW_TAG_reference_type", "DW_TAG_rvalue_reference_type"):
            width = die.cu["address_size"]
        elif die.tag == "DW_TAG_array_type" or die.tag in TYPE_WRAPPERS:
            target = die.get_DIE_from_attribute("DW_AT_type")
            width = byte_size(target, visited | {die.offset})
            if die.tag == "DW_TAG_array_type":
                dimensions = 0
                for index in die.iter_children():
                    if index.tag != "DW_TAG_subrange_type" or dimensions >= MAX_TYPE_DEPTH:
                        raise ValueError("unsupported DWARF array dimension")
                    dimensions += 1
                    count = constant(index, "DW_AT_count")
                    if count is None:
                        first = constant(index, "DW_AT_lower_bound", 0)
                        last = constant(index, "DW_AT_upper_bound")
                        if last is None:
                            raise ValueError("unsized DWARF array")
                        count = last - first + 1
                    if count < 1 or count > MAX_LAYOUT_BYTES // width:
                        raise ValueError("invalid or oversized DWARF array")
                    width *= count
                if not dimensions:
                    raise ValueError("DWARF array has no dimensions")
        else:
            raise ValueError(f"DWARF type {die.tag} lacks a supported byte size")
    if not 0 < width <= MAX_LAYOUT_BYTES:
        raise ValueError("invalid DWARF byte size")
    return width


def member_offset(member, kind: str) -> int:
    location = member.attributes.get("DW_AT_data_member_location")
    if location is None and kind == "union":
        return 0
    if location is None:
        raise ValueError("non-union member lacks a data location")
    if describe_form_class(location.form) == "constant":
        return constant(member, "DW_AT_data_member_location")
    if describe_form_class(location.form) in ("exprloc", "block") and len(location.value) <= 32:
        operations = DWARFExprParser(member.dwarfinfo.structs).parse_expr(location.value)
        if len(operations) == 1 and operations[0].op_name == "DW_OP_plus_uconst":
            return operations[0].args[0]
    raise ValueError("unsupported DWARF data-member location")


def aggregate(die, name: str) -> dict:
    kind = AGGREGATES[die.tag]
    size = byte_size(die)
    members = []
    for child in die.iter_children():
        if child.tag != "DW_TAG_member":
            continue
        if "DW_AT_declaration" in child.attributes and child.attributes["DW_AT_declaration"].value:
            continue
        if any(key in child.attributes for key in ("DW_AT_bit_size", "DW_AT_data_bit_offset", "DW_AT_bit_offset")):
            raise ValueError("DWARF bit fields require a bit-level oracle")
        if len(members) >= MAX_MEMBERS:
            raise ValueError("DWARF member limit exceeded")
        offset = member_offset(child, kind)
        width = byte_size(child.get_DIE_from_attribute("DW_AT_type"))
        label = child.attributes.get("DW_AT_name")
        if offset < 0 or offset + width > size:
            raise ValueError("DWARF member exceeds its aggregate")
        members.append({"name": label.value.decode("utf-8") if label else "", "offset": offset,
                        "width": width})
    return {"kind": kind, "name": name, "size": size, "members": members}


def read_dwarf_layout(debug: Path, name: str) -> dict:
    """Return one uniquely defined layout. Duplicate equivalent definitions may occur."""
    if not 0 < debug.stat().st_size <= MAX_DEBUG_BYTES:
        raise ValueError("DWARF oracle size is outside the supported range")
    with debug.open("rb") as stream:
        elf = ELFFile(stream)
        if not elf.has_dwarf_info(strict=True):
            raise ValueError("oracle lacks a DWARF information section")
        for section in elf.iter_sections():
            if section.name.startswith(".zdebug") or (
                    section.name.startswith(".debug") and section.compressed):
                raise ValueError("the corpus reader requires uncompressed DWARF")
        info = elf.get_dwarf_info(follow_links=False)
        wanted = name.encode("utf-8")
        result = None
        for unit in info.iter_CUs():
            for die in unit.iter_DIEs():
                label = die.attributes.get("DW_AT_name")
                if die.tag not in AGGREGATES or label is None or label.value != wanted:
                    continue
                if "DW_AT_declaration" in die.attributes and die.attributes["DW_AT_declaration"].value:
                    continue
                layout = aggregate(die, name)
                if result is not None and result != layout:
                    raise ValueError(f"ambiguous DWARF layout for {name}")
                result = layout
        if result is None:
            raise ValueError(f"no concrete DWARF aggregate named {name}")
        return result
