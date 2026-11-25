"""Experimental BinaryRat API. Apache-2.0; Copyright 2026 YurilLAB."""

from .call_sites import (
    CallArgument,
    CallSite,
    CallSitesReport,
    CallSitesReportError,
    CallTarget,
    decode_call_sites_report,
    load_call_sites_report,
    parse_call_sites_report,
)
from .client import EngineClient, EngineError, ProtocolError
from .exports import ExportError, load_export, parse_export
from .live import (
    CallSitesError,
    CrossReference,
    DataTypeInfo,
    DecompilationBackend,
    InstructionPcode,
    LayoutRecoveryError,
    LiveProgramError,
    Page,
    PcodeListing,
    PcodeOperation,
    PcodeVarnode,
    ProgramDecompilation,
    ProgramDecompilationRun,
    ProgramFunction,
    ProgramInfo,
    ProgramView,
    StackStringsError,
    StaleProgramError,
    decompile_program,
    open_program,
)
from .models import Address, Decompilation, Function, TypeProposal
from .arithmetic import ArithmeticExpression, ArithmeticRefusal, ExpressionNode
from .arithmetic_proof import ArithmeticProof, prove_equivalence
from .stack_strings import (
    StackString,
    StackStringsReport,
    StackStringsReportError,
    decode_stack_strings_report,
    load_stack_strings_report,
    parse_stack_strings_report,
)
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
    "InstructionPcode", "PcodeListing", "PcodeOperation", "PcodeVarnode",
    "ArithmeticExpression", "ArithmeticRefusal", "ExpressionNode", "ArithmeticProof", "prove_equivalence",
    "ProgramDecompilation", "ProgramDecompilationRun",
    "ProgramFunction", "ProgramInfo", "ProgramView", "StaleProgramError", "decompile_program", "open_program",
    "LayoutRecoveryError", "SummaryLayoutReport", "SummaryReportError", "decode_summary_report",
    "load_summary_report", "parse_summary_report",
    "CallArgument", "CallSite", "CallSitesError", "CallSitesReport", "CallSitesReportError", "CallTarget",
    "decode_call_sites_report", "load_call_sites_report", "parse_call_sites_report",
    "StackString", "StackStringsError", "StackStringsReport", "StackStringsReportError",
    "decode_stack_strings_report", "load_stack_strings_report", "parse_stack_strings_report",
    "API_VERSION", "PROTOCOL_VERSION",
]
