# Copyright 2026 YurilLAB
# SPDX-License-Identifier: Apache-2.0
"""Read concrete CodeView byte layouts from a separate fixture PDB."""

from __future__ import annotations

from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import subprocess
import time
from typing import Literal, TypedDict

from bounded_io import read_limited


class Member(TypedDict):
    name: str
    offset: int
    width: int


class Layout(TypedDict):
    kind: Literal["struct", "union", "class"]
    name: str
    size: int
    members: list[Member]


_PDB_MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"
_MAX_PDB_BYTES = 128 * 1024 * 1024
_MAX_YAML_BYTES = 32 * 1024 * 1024
_TOOL_TIMEOUT_SECONDS = 30.0
_MAX_TYPE_RECORDS = 100_000
_MAX_TYPE_DEPTH = 64
_FIRST_RECORD = 0x1000
_UINT32_MAX = 0xFFFFFFFF

_AGGREGATES: dict[str, tuple[str, Literal["struct", "union", "class"]]] = {
    "LF_STRUCTURE": ("Class", "struct"),
    "LF_CLASS": ("Class", "class"),
    "LF_UNION": ("Union", "union"),
}
_NON_STORAGE_MEMBERS = {"LF_METHOD", "LF_ONEMETHOD", "LF_NESTTYPE", "LF_STMEMBER"}

# CodeView SimpleTypeKind and SimpleTypeMode are encoded in the low byte and
# bits 8–10 of a simple type index. These are target widths, never host sizeof.
_SIMPLE_WIDTHS = {
    0x08: 4,
    0x10: 1, 0x11: 2, 0x12: 4, 0x13: 8, 0x14: 16,
    0x20: 1, 0x21: 2, 0x22: 4, 0x23: 8, 0x24: 16,
    0x30: 1, 0x31: 2, 0x32: 4, 0x33: 8, 0x34: 16,
    0x40: 4, 0x41: 8, 0x42: 10, 0x43: 16, 0x44: 6, 0x45: 4, 0x46: 2,
    0x68: 1, 0x69: 1, 0x70: 1, 0x71: 2, 0x72: 2, 0x73: 2,
    0x74: 4, 0x75: 4, 0x76: 8, 0x77: 8, 0x78: 16, 0x79: 16,
    0x7A: 2, 0x7B: 4, 0x7C: 1,
}
_SIMPLE_POINTER_WIDTHS = {1: 2, 2: 4, 3: 4, 4: 4, 5: 6, 6: 8, 7: 16}


def _pdb_yaml(debug: Path, tool: Path | str) -> bytes:
    debug = debug.resolve()
    if not debug.is_file():
        raise ValueError("Expected a regular PDB file")
    with debug.open("rb") as pdb:
        if os.fstat(pdb.fileno()).st_size > _MAX_PDB_BYTES or pdb.read(len(_PDB_MAGIC)) != _PDB_MAGIC:
            raise ValueError("Expected a bounded MSF 7.0 PDB file")
    command = [str(tool), "pdb2yaml", "--tpi-stream", "--no-file-headers", str(debug)]
    # A blocking pipe read needs a separate thread on Windows. Cap the bytes
    # read and kill LLVM before joining the reader on either limit.
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as child:
        with ThreadPoolExecutor(max_workers=1) as reader:
            deadline = time.monotonic() + _TOOL_TIMEOUT_SECONDS
            assert child.stdout is not None
            try:
                data = reader.submit(read_limited, child.stdout, _MAX_YAML_BYTES + 1).result(
                    timeout=_TOOL_TIMEOUT_SECONDS)
                if len(data) > _MAX_YAML_BYTES:
                    raise ValueError("PDB type stream exceeds the output limit")
                child.wait(timeout=max(0.0, deadline - time.monotonic()))
            except (TimeoutError, subprocess.TimeoutExpired) as error:
                raise ValueError("llvm-pdbutil timed out extracting the PDB type stream") from error
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()
        if child.returncode != 0:
            raise ValueError(f"llvm-pdbutil rejected the PDB type stream (exit {child.returncode})")
        return data


def _mapping(value: object, label: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"Invalid CodeView {label}")
    return value


def _number(value: object, label: str, minimum: int = 0, maximum: int = _UINT32_MAX) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"Invalid CodeView {label}")
    return value


def _record_kind(record: dict) -> str:
    kind = record.get("Kind")
    if not isinstance(kind, str) or not kind.startswith("LF_"):
        raise ValueError("Invalid CodeView record kind")
    return kind


class _TypeStream:
    def __init__(self, document: object):
        stream = _mapping(_mapping(document, "document").get("TpiStream"), "TPI stream")
        records = stream.get("Records")
        if not isinstance(records, list) or not 1 <= len(records) <= _MAX_TYPE_RECORDS:
            raise ValueError("Expected a nonempty bounded TPI type table")
        self.records = records
        self.named: dict[str, list[int]] = {}
        for index, raw in enumerate(records, _FIRST_RECORD):
            record = _mapping(raw, "type record")
            kind = _record_kind(record)
            if kind in _AGGREGATES:
                aggregate = _mapping(record.get(_AGGREGATES[kind][0]), "aggregate")
                name = aggregate.get("Name")
                options = aggregate.get("Options")
                if not isinstance(name, str) or not isinstance(options, list) or any(
                        not isinstance(option, str) for option in options):
                    raise ValueError("Invalid CodeView aggregate identity")
                if "ForwardReference" not in options:
                    self.named.setdefault(name, []).append(index)

    def record(self, index: int) -> dict:
        position = index - _FIRST_RECORD
        if not 0 <= position < len(self.records):
            raise ValueError(f"CodeView type index 0x{index:x} is outside the TPI table")
        return self.records[position]

    def concrete_index(self, name: str, kind: str | None = None, unique: str | None = None) -> int:
        candidates = self.named.get(name, [])
        if kind is not None:
            candidates = [index for index in candidates if self.record(index)["Kind"] == kind and
                          (unique is None or self.record(index)[_AGGREGATES[kind][0]].get("UniqueName") == unique)]
        if len(candidates) != 1:
            raise ValueError(f"Expected one concrete CodeView definition for {name!r}, found {len(candidates)}")
        return candidates[0]

    def width(self, reference: object, active: frozenset[int] = frozenset()) -> int:
        index = _number(reference, "member type index")
        if index < _FIRST_RECORD:
            mode, kind = index >> 8, index & 0xFF
            if mode in _SIMPLE_POINTER_WIDTHS and (kind in _SIMPLE_WIDTHS or kind == 0x03):
                return _SIMPLE_POINTER_WIDTHS[mode]
            if mode == 0 and kind in _SIMPLE_WIDTHS:
                return _SIMPLE_WIDTHS[kind]
            raise ValueError(f"Unsupported simple CodeView type 0x{index:x}")
        if index in active or len(active) >= _MAX_TYPE_DEPTH:
            raise ValueError("Cyclic or excessively deep CodeView member type")
        active = active | {index}
        record = self.record(index)
        kind = record["Kind"]
        if kind in _AGGREGATES:
            key = _AGGREGATES[kind][0]
            aggregate = record[key]
            if "ForwardReference" in aggregate["Options"]:
                unique = aggregate.get("UniqueName")
                if unique is not None and not isinstance(unique, str):
                    raise ValueError("Invalid CodeView aggregate unique name")
                concrete = self.concrete_index(aggregate["Name"], kind, unique or None)
                aggregate = self.record(concrete)[key]
            return _number(aggregate.get("Size"), "aggregate size", 1)
        if kind == "LF_ARRAY":
            array = _mapping(record.get("Array"), "array")
            size = _number(array.get("Size"), "array size", 1)
            if size % self.width(array.get("ElementType"), active):
                raise ValueError("CodeView array size conflicts with its element width")
            return size
        if kind == "LF_MODIFIER":
            return self.width(_mapping(record.get("Modifier"), "modifier").get("ModifiedType"), active)
        if kind == "LF_ENUM":
            return self.width(_mapping(record.get("Enum"), "enum").get("UnderlyingType"), active)
        if kind == "LF_POINTER":
            pointer = _mapping(record.get("Pointer"), "pointer")
            attrs = _number(pointer.get("Attrs"), "pointer attributes")
            referent = _number(pointer.get("ReferentType"), "pointer referent index")
            if referent >= _FIRST_RECORD:
                self.record(referent)
            # PointerRecord::getSize uses these exact CodeView bit positions.
            return _number((attrs >> 13) & 0xFF, "pointer width", 1)
        raise ValueError(f"Unsupported CodeView member type {kind}")

    def field_records(self, first: int) -> Iterator[dict]:
        visited = set()
        index = first
        while index:
            if index in visited:
                raise ValueError("Cyclic CodeView field list")
            visited.add(index)
            record = self.record(index)
            fields = record.get("FieldList")
            if record["Kind"] != "LF_FIELDLIST" or not isinstance(fields, list):
                raise ValueError("Type does not reference a valid CodeView field list")
            index = 0
            for ordinal, field in enumerate(fields):
                field = _mapping(field, "field record")
                if _record_kind(field) == "LF_INDEX":
                    if ordinal != len(fields) - 1:
                        raise ValueError("CodeView continuation must end its field list")
                    continuation = _mapping(field.get("ListContinuation"), "field list continuation")
                    index = _number(continuation.get("ContinuationIndex"), "continuation index", _FIRST_RECORD)
                else:
                    yield field

    def layout(self, name: str) -> Layout:
        record = self.record(self.concrete_index(name))
        key, kind = _AGGREGATES[record["Kind"]]
        aggregate = record[key]
        size = _number(aggregate.get("Size"), "aggregate size", 1)
        count = _number(aggregate.get("MemberCount"), "member count", maximum=0xFFFF)
        fields = _number(aggregate.get("FieldList"), "field list index")
        if (fields == 0) != (count == 0):
            raise ValueError("CodeView aggregate member count conflicts with its field list")
        members: list[Member] = []
        names: set[str] = set()
        record_count = 0
        for field in self.field_records(fields):
            field_kind = field["Kind"]
            if field_kind == "LF_METHOD":
                # Each overload contributes a member to the aggregate's count.
                group = _mapping(field.get("OverloadedMethod"), "overloaded method")
                overloads = _number(group.get("NumOverloads"), "overload count", 1, 0xFFFF)
                index = _number(group.get("MethodList"), "method list index", _FIRST_RECORD)
                method_list = self.record(index)
                if method_list["Kind"] != "LF_METHODLIST":
                    raise ValueError("CodeView overloaded method does not reference a method list")
                methods = _mapping(method_list.get("MethodOverloadList"), "method list").get("Methods")
                if not isinstance(methods, list) or len(methods) != overloads:
                    raise ValueError("CodeView overload count conflicts with its method list")
                record_count += overloads
            else:
                record_count += 1
            if record_count > count:
                raise ValueError("CodeView field list exceeds its declared member count")
            if field_kind in _NON_STORAGE_MEMBERS:
                continue
            if field_kind != "LF_MEMBER":
                raise ValueError(f"Unsupported CodeView instance field {field_kind}")
            member = _mapping(field.get("DataMember"), "data member")
            member_name = member.get("Name")
            if not isinstance(member_name, str) or not member_name or member_name in names:
                raise ValueError("CodeView data member name is empty or ambiguous")
            offset = _number(member.get("FieldOffset"), "field offset")
            width = self.width(member.get("Type"))
            if offset + width > size or (kind == "union" and offset != 0):
                raise ValueError("CodeView field extent conflicts with the aggregate layout")
            names.add(member_name)
            members.append({"name": member_name, "offset": offset, "width": width})
        if record_count != count:
            raise ValueError("CodeView field list is missing declared members")
        return {"kind": kind, "name": name, "size": size, "members": members}


def read_pdb_layout(debug: Path, name: str, tool: Path | str = "llvm-pdbutil") -> Layout:
    """Resolve one named, concrete aggregate in a separate compiler PDB.

    LLVM decodes the TPI stream. This reader resolves byte widths from CodeView
    types and rejects ambiguous names, inheritance/vtable fields, and bitfields
    whose layout cannot be expressed by the byte-member schema.
    """
    import yaml

    class StrictLoader(getattr(yaml, "CSafeLoader", yaml.SafeLoader)):
        def construct_mapping(self, node, deep=False):
            result = {}
            for key, value in node.value:
                name = self.construct_object(key, deep=deep)
                if not isinstance(name, str) or name in result:
                    raise ValueError("Invalid or duplicate CodeView YAML field name")
                result[name] = self.construct_object(value, deep=deep)
            return result

    # CodeView's plain scalar names can be valid C/C++ identifiers such as
    # Off or NO. Do not apply YAML 1.1 implicit boolean/null conversions to
    # them. TPI indices, offsets, and sizes remain integers.
    StrictLoader.yaml_implicit_resolvers = {
        key: [(tag, pattern) for tag, pattern in resolvers
              if tag == "tag:yaml.org,2002:int"]
        for key, resolvers in StrictLoader.yaml_implicit_resolvers.items()
    }
    if not isinstance(name, str) or not name.strip():
        raise ValueError("Expected a concrete CodeView type name")
    try:
        document = yaml.load(_pdb_yaml(debug, tool), Loader=StrictLoader)
    except (yaml.YAMLError, UnicodeError) as error:
        raise ValueError("Invalid LLVM CodeView YAML output") from error
    return _TypeStream(document).layout(name)
