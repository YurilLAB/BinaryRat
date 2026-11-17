"""Experimental BinaryRat API. Apache-2.0; Copyright 2026 YurilLAB."""

from .client import EngineClient, EngineError, ProtocolError
from .exports import ExportError, load_export, parse_export
from .models import Address, Decompilation, Function, TypeProposal

__version__ = "0.1.0"
API_VERSION = "0.1.0"
PROTOCOL_VERSION = 1

__all__ = [
    "Address", "Function", "Decompilation", "TypeProposal", "EngineClient",
    "EngineError", "ProtocolError", "ExportError", "load_export", "parse_export",
    "API_VERSION", "PROTOCOL_VERSION",
]
