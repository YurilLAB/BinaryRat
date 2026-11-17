"""Python value objects; these are BinaryRat APIs, not Ghidra APIs.

Apache-2.0; Copyright 2026 YurilLAB.
"""

from dataclasses import dataclass
import math
from typing import Any, Mapping


@dataclass(frozen=True, slots=True, order=True)
class Address:
    """An unsigned offset together with its Ghidra address-space name."""

    space: str
    offset: int

    def __post_init__(self) -> None:
        if not isinstance(self.space, str) or not self.space:
            raise ValueError("address space must be a nonempty string")
        if type(self.offset) is not int or self.offset < 0:
            raise ValueError("address offset must be a nonnegative integer")

    def __str__(self) -> str:
        return f"{self.space}:{self.offset:x}"


@dataclass(frozen=True, slots=True)
class Function:
    program_id: str
    entry: Address
    name: str
    body_sha256: str
    body_ranges: tuple[tuple[Address, Address], ...] = ()


@dataclass(frozen=True, slots=True)
class Decompilation:
    function: Function
    revision: int
    c: str
    prototype: str
    completed: bool
    timed_out: bool
    cancelled: bool
    failed_to_start: bool
    error: str

    @property
    def successful(self) -> bool:
        return self.completed and not (
            self.timed_out or self.cancelled or self.failed_to_start
        )


@dataclass(frozen=True, slots=True)
class TypeProposal:
    """A reviewable proposal. Confidence is evidence ranking, not a probability."""

    object_id: str
    kind: str
    confidence: float
    evidence: tuple[str, ...]
    description: Mapping[str, Any]

    def __post_init__(self) -> None:
        if not self.object_id or not self.kind:
            raise ValueError("proposal object_id and kind must be nonempty")
        if not math.isfinite(self.confidence) or not 0 <= self.confidence <= 1:
            raise ValueError("proposal confidence must be finite and between zero and one")
