"""Experimental BinaryRat API. Apache-2.0; Copyright 2026 YurilLAB."""

from .client import EngineClient, EngineError, ProtocolError
from .exports import ExportError, load_export, parse_export
from .live import (
    CrossReference,
    DataTypeInfo,
    DecompilationBackend,
    LayoutRecoveryError,
    LiveProgramError,
    Page,
    ProgramDecompilation,
    ProgramDecompilationRun,
    ProgramFunction,
    ProgramInfo,
    ProgramView,
    StaleProgramError,
    decompile_program,
    open_program,
)
from .models import Address, Decompilation, Function, TypeProposal
from .summary_layout import (
    SummaryLayoutReport,
    SummaryReportError,
    decode_summary_report,
    load_summary_report,
    parse_summary_report,
)

__version__ = "0.1.0"
API_VERSION = "0.1.0"
PROTOCOL_VERSION = 1

__all__ = [
    "Address", "Function", "Decompilation", "TypeProposal", "EngineClient",
    "EngineError", "ProtocolError", "ExportError", "load_export", "parse_export",
    "CrossReference", "DataTypeInfo", "DecompilationBackend", "LiveProgramError", "Page",
    "ProgramDecompilation", "ProgramDecompilationRun",
    "ProgramFunction", "ProgramInfo", "ProgramView", "StaleProgramError", "decompile_program", "open_program",
    "LayoutRecoveryError", "SummaryLayoutReport", "SummaryReportError", "decode_summary_report",
    "load_summary_report", "parse_summary_report",
    "API_VERSION", "PROTOCOL_VERSION",
]
