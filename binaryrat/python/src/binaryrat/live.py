"""Read-only access to a saved Ghidra 12.2 program through PyGhidra.

Apache-2.0; Copyright 2026 YurilLAB.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import CancelledError
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path
from threading import Event, Lock, Thread
from time import monotonic
from typing import Any, Generic, Literal, TypeVar

from .call_sites import (
    MAX_CALLERS as _MAX_CALL_SITE_CALLERS,
    MAX_SITES as _MAX_CALL_SITES,
    MAX_TIMEOUT_SECONDS as _MAX_CALL_SITE_TIMEOUT_SECONDS,
    CallSitesReport,
    decode_call_sites_report,
)
from .models import Address
from .stack_strings import MAX_FUNCTIONS as _MAX_STACK_STRING_FUNCTIONS
from .stack_strings import StackStringsReport, decode_stack_strings_report
from .summary_layout import SummaryLayoutReport, decode_summary_report

_T = TypeVar("_T")
_MAX_PAGE_SIZE = 1000
_MAX_PAGE_OFFSET = 100_000
_MAX_REFERENCES_FROM = 100_000
_MAX_TYPE_COUNT = 100_000
_DECOMPILER_PAYLOAD_MB = 4
_OFFSET_MASK = (1 << 64) - 1
_STARTUP_LOCK = Lock()
_SCHEDULED_TIMEOUT_SECONDS = 86_400
# binaryrat.SummaryLayouts limits: summaries per run and seconds per decompile.
_MAX_SUMMARIES = 256
_MAX_SUMMARY_TIMEOUT_SECONDS = 600
_MAX_STACK_STRINGS_TIMEOUT_SECONDS = 60
_MAX_PCODE_OPERATIONS = 128
_MAX_PCODE_INPUTS = 8

DecompilationBackend = Literal["auto", "scheduled", "stock"]


class LiveProgramError(RuntimeError):
    """A live Program view cannot satisfy a read."""


class LayoutRecoveryError(LiveProgramError):
    """The Java summary layout service refused or failed a recovery."""


class CallSitesError(LiveProgramError):
    """The Java call-site service refused or failed a recovery."""


class StackStringsError(LiveProgramError):
    """The Java stack-string service refused or failed a scan."""


class StaleProgramError(LiveProgramError):
    """The Program modification number changed since this view opened."""


@dataclass(frozen=True, slots=True)
class ProgramInfo:
    name: str
    path: str
    executable_sha256: str | None
    language_id: str
    compiler_spec_id: str
    image_base: Address
    revision: int


@dataclass(frozen=True, slots=True)
class ProgramFunction:
    name: str
    qualified_name: str
    entry: Address
    signature: str
    external: bool
    thunk: bool


@dataclass(frozen=True, slots=True)
class CrossReference:
    source: Address
    target: Address
    type_name: str
    operand_index: int
    primary: bool


@dataclass(frozen=True, slots=True)
class PcodeVarnode:
    """Storage or a literal in Ghidra's address space, with its size in bytes."""

    address: Address
    size: int


@dataclass(frozen=True, slots=True)
class PcodeOperation:
    """One operation. The site and sequence identify its original SLEIGH instruction step."""

    mnemonic: str
    site: Address
    sequence: int
    output: PcodeVarnode | None
    inputs: tuple[PcodeVarnode | None, ...]
    input_count: int


@dataclass(frozen=True, slots=True)
class PcodeListing:
    """Ordered operations. Counts include any operands or operations beyond the limits."""

    operations: tuple[PcodeOperation, ...]
    operation_count: int

    @property
    def truncated(self) -> bool:
        return (len(self.operations) < self.operation_count or
                any(len(op.inputs) < op.input_count for op in self.operations))


@dataclass(frozen=True, slots=True)
class InstructionPcode:
    """Listing instruction boundaries and raw and override-aware SLEIGH p-code."""

    address: Address
    length: int
    parsed_length: int
    mnemonic: str
    revision: int
    raw: PcodeListing
    effective: PcodeListing


@dataclass(frozen=True, slots=True)
class DataTypeInfo:
    category: str
    name: str
    display_name: str
    length: int | None


@dataclass(frozen=True, slots=True)
class ProgramDecompilation:
    function: ProgramFunction
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
class ProgramDecompilationRun:
    """A result and the backend and cache outcome that produced it."""

    result: ProgramDecompilation
    backend: Literal["scheduled", "stock"]
    cache_status: str | None


@dataclass(frozen=True, slots=True)
class Page(Generic[_T]):
    """A page and the offset to supply to the same query for the next page."""

    items: tuple[_T, ...]
    next_offset: int | None
    truncated: bool = False


def _check_cancel(cancel: Event | None) -> None:
    if cancel is not None and cancel.is_set():
        raise CancelledError("Ghidra read cancelled")


def _require_extension(feature: str) -> None:
    from ghidra.framework import Application

    if Application.getModuleRootDir("BinaryRat") is None:
        raise LiveProgramError(f"{feature} require the BinaryRat extension")


@contextmanager
def _monitor(cancel: Event | None, deadline: float | None = None) -> Iterator[Any]:
    from ghidra.util.task import TaskMonitor, TaskMonitorAdapter

    if cancel is None and deadline is None:
        yield TaskMonitor.DUMMY
        return
    _check_cancel(cancel)
    monitor = TaskMonitorAdapter(True)
    finished = Event()

    def forward() -> None:
        while True:
            remaining = 0.05 if deadline is None else max(0.0, deadline - monotonic())
            if finished.wait(min(remaining, 0.05) if cancel is not None else remaining):
                return
            if ((cancel is not None and cancel.is_set()) or
                    (deadline is not None and monotonic() >= deadline)):
                monitor.cancel()
                return

    forwarder = Thread(target=forward, name="binaryrat-live-cancel", daemon=True)
    forwarder.start()
    try:
        yield monitor
    finally:
        finished.set()
        forwarder.join()


def _iter_java(values: Any) -> Iterator[Any]:
    while values.hasNext():
        yield values.next()


def _address(value: Any) -> Address:
    return Address(str(value.getAddressSpace().getName()), int(value.getOffset()) & _OFFSET_MASK)


def _varnode(node: Any) -> PcodeVarnode | None:
    return None if node is None else PcodeVarnode(_address(node.getAddress()), int(node.getSize()))


def _pcode_listing(operations: Any, limit: int, cancel: Event | None) -> PcodeListing:
    rows = []
    for index in range(min(len(operations), limit)):
        _check_cancel(cancel)
        op = operations[index]
        seq = op.getSeqnum()
        count = int(op.getNumInputs())
        inputs = tuple(_varnode(op.getInput(i)) for i in range(min(count, _MAX_PCODE_INPUTS)))
        rows.append(PcodeOperation(str(op.getMnemonic()), _address(seq.getTarget()),
                                   int(seq.getTime()) & 0xffffffff, _varnode(op.getOutput()),
                                   inputs, count))
    return PcodeListing(tuple(rows), len(operations))


def _function(value: Any) -> ProgramFunction:
    return ProgramFunction(
        str(value.getName()),
        str(value.getName(True)),
        _address(value.getEntryPoint()),
        str(value.getPrototypeString(True, True)),
        bool(value.isExternal()),
        bool(value.isThunk()),
    )


def _reference(value: Any) -> CrossReference:
    return CrossReference(
        _address(value.getFromAddress()),
        _address(value.getToAddress()),
        str(value.getReferenceType().getName()),
        int(value.getOperandIndex()),
        bool(value.isPrimary()),
    )


def _data_type(value: Any) -> DataTypeInfo:
    size = int(value.getLength())
    return DataTypeInfo(
        str(value.getCategoryPath().getPath()),
        str(value.getName()),
        str(value.getDisplayName()),
        size if size >= 0 else None,
    )


class ProgramView:
    """Context-owned access to one saved Program revision.

    Reads return Python values and are serialized per view. The modification
    number is checked around each read, without holding a transaction. An
    optional cancellation event is checked between records and forwarded to
    Ghidra's task monitor during a decompilation. Returned values remain
    usable after the context exits.
    """

    def __init__(self, program: Any, path: str, cancel: Event | None, scheduled_service: Any = None,
                 *, foreground: bool = False):
        self._program: Any | None = program
        self._decompiler: Any | None = None
        self._scheduled_service = scheduled_service
        self._scheduled_session: Any | None = None
        self._scheduled_timeout: int | None = None
        self._foreground = foreground
        self._cancel = cancel
        self._lock = Lock()
        revision = int(program.getModificationNumber())
        digest = program.getExecutableSHA256()
        digest = str(digest) if digest else None
        self._info = ProgramInfo(
            str(program.getName()),
            path,
            digest if digest != "unknown" else None,
            str(program.getLanguageID()),
            str(program.getCompilerSpec().getCompilerSpecID()),
            _address(program.getImageBase()),
            revision,
        )
        self._check(program)

    @property
    def info(self) -> ProgramInfo:
        return self._info

    @property
    def decompilation_backend(self) -> Literal["scheduled", "stock"]:
        """Which backend this view uses for decompilation."""
        return "stock" if self._scheduled_service is None else "scheduled"

    def _invalidate(self) -> None:
        with self._lock:
            self._program = None
            decompiler, self._decompiler = self._decompiler, None
            if decompiler is not None:
                self._close_decompiler(decompiler)
            self._close_scheduled()

    def _close_scheduled(self) -> None:
        session, self._scheduled_session = self._scheduled_session, None
        self._scheduled_timeout = None
        if session is not None:
            from jpype import JException

            try:
                session.close()
            except JException as cause:
                raise LiveProgramError(f"Could not close the BinaryRat decompilation session: {cause}") from cause

    def _check(self, program: Any) -> None:
        if program.isClosed():
            raise LiveProgramError("Ghidra Program is closed")
        _check_cancel(self._cancel)
        if int(program.getModificationNumber()) != self._info.revision:
            raise StaleProgramError("Ghidra Program changed while the view was open")

    @contextmanager
    def _read(self, *, deadline: float | None = None) -> Iterator[Any]:
        if deadline is None:
            self._lock.acquire()
        else:
            remaining = deadline - monotonic()
            if remaining <= 0 or not self._lock.acquire(timeout=remaining):
                raise TimeoutError("Ghidra read timed out waiting for the Program view")
        try:
            program = self._program
            if program is None:
                raise LiveProgramError("Program view is closed")
            self._check(program)
            yield program
            self._check(program)
        finally:
            self._lock.release()

    @staticmethod
    def _native_address(program: Any, address: Address) -> Any:
        from ghidra.program.model.address import AddressOutOfBoundsException

        if not isinstance(address, Address) or address.offset > _OFFSET_MASK:
            raise ValueError("expected an Address with an unsigned 64-bit offset")
        space = program.getAddressFactory().getAddressSpace(address.space)
        if space is None:
            raise ValueError(f"unknown Ghidra address space: {address.space}")
        offset = address.offset
        signed_offset = offset if offset < (1 << 63) else offset - (1 << 64)
        try:
            value = space.getAddressInThisSpaceOnly(signed_offset)
        except AddressOutOfBoundsException as cause:
            raise ValueError(f"address is outside its space: {address}") from cause
        if _address(value) != address:
            raise ValueError(f"address is outside its space: {address}")
        return value

    def _page(
        self, values: Iterable[Any], transform: Callable[[Any], _T], offset: int, limit: int
    ) -> Page[_T]:
        records = []
        for index, value in enumerate(values):
            _check_cancel(self._cancel)
            if index < offset:
                continue
            if len(records) == limit:
                next_offset = offset + limit
                if next_offset > _MAX_PAGE_OFFSET:
                    return Page(tuple(records), None, truncated=True)
                return Page(tuple(records), next_offset)
            records.append(transform(value))
        return Page(tuple(records), None)

    @staticmethod
    def _validate_page(offset: int, limit: int) -> None:
        if type(offset) is not int or not 0 <= offset <= _MAX_PAGE_OFFSET:
            raise ValueError(f"offset must be between 0 and {_MAX_PAGE_OFFSET}")
        if type(limit) is not int or not 1 <= limit <= _MAX_PAGE_SIZE:
            raise ValueError(f"limit must be between 1 and {_MAX_PAGE_SIZE}")

    def functions(self, *, offset: int = 0, limit: int = 100) -> Page[ProgramFunction]:
        """List non-external functions in ascending Ghidra address order."""
        self._validate_page(offset, limit)
        with self._read() as program:
            return self._page(
                _iter_java(program.getFunctionManager().getFunctions(True)),
                _function, offset, limit,
            )

    def function_at(self, entry: Address) -> ProgramFunction | None:
        """Look up a function at its exact entry address."""
        with self._read() as program:
            function = program.getFunctionManager().getFunctionAt(
                self._native_address(program, entry)
            )
            return _function(function) if function is not None else None

    def function_containing(self, address: Address) -> ProgramFunction | None:
        """Look up the local function whose body contains an address, such as a call site."""
        with self._read() as program:
            function = program.getFunctionManager().getFunctionContaining(
                self._native_address(program, address)
            )
            return _function(function) if function is not None and not function.isExternal() else None

    def instruction_pcode(
        self, address: Address, *, max_operations: int = _MAX_PCODE_OPERATIONS,
    ) -> InstructionPcode | None:
        """Inspect an existing Listing instruction at any byte within it, or return None.

        The address must be in a memory space. Each listing preserves Ghidra's order and
        copies up to max_operations (1–128), with up to eight inputs per operation.
        Check raw.truncated and effective.truncated before interpreting a complete sequence.
        A defined instruction with no operations has an empty listing. Ghidra lifts the
        whole instruction even when a smaller display limit is requested.
        """
        if type(max_operations) is not int or not 1 <= max_operations <= _MAX_PCODE_OPERATIONS:
            raise ValueError(f"max_operations must be between 1 and {_MAX_PCODE_OPERATIONS}")
        with self._read() as program:
            from jpype import JBoolean, JException

            location = self._native_address(program, address)
            if not location.isMemoryAddress():
                raise ValueError("instruction p-code requires a memory address")
            if program.getCurrentTransactionInfo() is not None:
                raise LiveProgramError("Wait for the Program edit or analysis to finish")
            try:
                instruction = program.getListing().getInstructionContaining(location)
                result = None
                if instruction is not None:
                    raw = _pcode_listing(instruction.getPcode(), max_operations, self._cancel)
                    # Select the boolean overload. getPcode(int) lifts an individual operand.
                    effective = _pcode_listing(instruction.getPcode(JBoolean(True)), max_operations,
                                               self._cancel)
                    result = InstructionPcode(
                        _address(instruction.getMinAddress()), int(instruction.getLength()),
                        int(instruction.getParsedLength()), str(instruction.getMnemonicString()),
                        self.info.revision, raw, effective,
                    )
            except JException as cause:
                self._check(program)
                raise LiveProgramError(f"Could not read instruction p-code at {address}: {cause}") from cause
            if program.getCurrentTransactionInfo() is not None:
                raise LiveProgramError("Wait for the Program edit or analysis to finish")
            return result

    def functions_named(self, name: str, *, limit: int = 100) -> Page[ProgramFunction]:
        """Find local functions by simple name, or by qualified name such as ``ns::f``.

        A name can repeat across namespaces and, for unnamed sections, within one. The
        page lists matches in ascending entry order; ``next_offset`` is never set.
        """
        if not isinstance(name, str) or not name or len(name) > 2000 or not name.isprintable():
            raise ValueError("function name must be a printable string of 1 to 2000 characters")
        self._validate_page(0, limit)
        if name.endswith("::"):
            raise ValueError("function name must not end with '::'")
        # A function's own name can contain "::" (template arguments such as make<ns::T>), so
        # the symbol to look up is the whole name or what follows any of its "::".
        simples = dict.fromkeys(
            [name] + [name[index + 2:] for index in range(len(name)) if name.startswith("::", index)])
        from ghidra.program.model.symbol import SymbolType

        with self._read() as program:
            manager = program.getFunctionManager()
            matches: dict[Address, ProgramFunction] = {}
            for simple in simples:
                for symbol in _iter_java(program.getSymbolTable().getSymbols(simple)):
                    _check_cancel(self._cancel)
                    if symbol.getSymbolType() != SymbolType.FUNCTION or symbol.isExternal():
                        continue
                    function = manager.getFunctionAt(symbol.getAddress())
                    if function is None or function.isExternal():
                        continue
                    if name not in (str(function.getName()), str(function.getName(True))):
                        continue
                    found = _function(function)
                    if found.entry in matches:
                        continue
                    if len(matches) == limit:
                        return Page(tuple(sorted(matches.values(), key=lambda f: f.entry)), None,
                                    truncated=True)
                    matches[found.entry] = found
            return Page(tuple(sorted(matches.values(), key=lambda f: f.entry)), None)

    def xrefs_to(
        self, target: Address, *, offset: int = 0, limit: int = 100
    ) -> Page[CrossReference]:
        self._validate_page(offset, limit)
        with self._read() as program:
            address = self._native_address(program, target)
            if address.isStackAddress() or address.isRegisterAddress():
                raise ValueError("incoming xrefs require a non-stack, non-register address")
            return self._page(
                _iter_java(program.getReferenceManager().getReferencesTo(address)),
                _reference, offset, limit,
            )

    def xrefs_from(
        self, source: Address, *, offset: int = 0, limit: int = 100
    ) -> Page[CrossReference]:
        self._validate_page(offset, limit)
        with self._read() as program:
            address = self._native_address(program, source)
            manager = program.getReferenceManager()
            if int(manager.getReferenceCountFrom(address)) > _MAX_REFERENCES_FROM:
                raise LiveProgramError(f"outgoing references exceed {_MAX_REFERENCES_FROM}")
            return self._page(
                manager.getReferencesFrom(address),
                _reference, offset, limit,
            )

    def data_types(self, *, offset: int = 0, limit: int = 100) -> Page[DataTypeInfo]:
        """Read type summaries in the order provided by the Program's manager."""
        self._validate_page(offset, limit)
        with self._read() as program:
            manager = program.getDataTypeManager()
            if int(manager.getDataTypeCount(True)) > _MAX_TYPE_COUNT:
                raise LiveProgramError(f"data type count exceeds {_MAX_TYPE_COUNT}")
            return self._page(
                _iter_java(manager.getAllDataTypes()),
                _data_type, offset, limit,
            )

    def data_type(self, category: str, name: str) -> DataTypeInfo | None:
        """Look up a type using its category and name."""
        if not isinstance(category, str) or not category.startswith("/"):
            raise ValueError("type category must start with '/'")
        if not isinstance(name, str) or not name:
            raise ValueError("type name must be a nonempty string")
        with self._read() as program:
            from ghidra.program.model.data import DataTypePath

            value = program.getDataTypeManager().getDataType(DataTypePath(category, name))
            return _data_type(value) if value is not None else None

    @staticmethod
    def _close_decompiler(decompiler: Any) -> None:
        try:
            decompiler.stopProcess()
        finally:
            decompiler.closeProgram()

    def _get_decompiler(self, program: Any) -> Any:
        from ghidra.app.decompiler import DecompInterface, DecompileOptions

        if self._decompiler is not None:
            return self._decompiler
        decompiler = DecompInterface()
        try:
            options = DecompileOptions()
            options.grabFromProgram(program)
            options.setMaxPayloadMBytes(_DECOMPILER_PAYLOAD_MB)
            if not decompiler.setOptions(options):
                raise LiveProgramError(str(decompiler.getLastMessage()))
            if not decompiler.openProgram(program):
                raise LiveProgramError(str(decompiler.getLastMessage()))
        except BaseException:
            self._close_decompiler(decompiler)
            raise
        self._decompiler = decompiler
        return decompiler

    def _decompile_scheduled(
        self, program: Any, function: Any, summary: ProgramFunction, timeout: int, monitor: Any,
    ) -> ProgramDecompilationRun:
        from ghidra.util.exception import CancelledException
        from jpype import JException

        try:
            if self._scheduled_timeout != timeout:
                self._close_scheduled()
                workers = int(self._scheduled_service.DEFAULT_WORKERS) if self._foreground else 1
                self._scheduled_session = self._scheduled_service.open(program, workers, timeout)
                self._scheduled_timeout = timeout
            submit = (self._scheduled_session.decompileForegroundWithMetrics if self._foreground
                      else self._scheduled_session.decompileWithMetrics)
            run = submit(function, monitor)
            result = run.output()
            lookup = run.lookup()
            output = ProgramDecompilation(
                summary, self._info.revision, str(result.c()), str(result.prototype()),
                bool(result.completed()), bool(result.timedOut()), bool(result.cancelled()),
                bool(result.failedToStart()), str(result.error() or ""),
            )
            return ProgramDecompilationRun(
                output, "scheduled", "disabled" if lookup is None else str(lookup.kind().name()).lower(),
            )
        except CancelledException as cause:
            raise CancelledError("BinaryRat decompilation cancelled") from cause
        except JException as cause:
            raise LiveProgramError(f"BinaryRat scheduled decompilation failed: {cause}") from cause

    def decompile(self, entry: Address, *, timeout_seconds: int = 30) -> ProgramDecompilation:
        """Decompile one function with the backend selected when the view opened."""
        return self.decompile_with_metrics(entry, timeout_seconds=timeout_seconds).result

    def decompile_with_metrics(
        self, entry: Address, *, timeout_seconds: int = 30,
    ) -> ProgramDecompilationRun:
        """Decompile one function and report the backend and cache outcome."""
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds < (1 << 31):
            raise ValueError("timeout_seconds must be a positive 32-bit integer")
        if self._scheduled_service is not None and timeout_seconds > _SCHEDULED_TIMEOUT_SECONDS:
            raise ValueError(f"scheduled timeout_seconds must be between 1 and {_SCHEDULED_TIMEOUT_SECONDS}")
        with self._read() as program:
            function = program.getFunctionManager().getFunctionAt(
                self._native_address(program, entry)
            )
            if function is None:
                raise LookupError(f"no function at {entry}")
            summary = _function(function)
            with _monitor(self._cancel) as monitor:
                if self._scheduled_service is not None:
                    return self._decompile_scheduled(program, function, summary, timeout_seconds, monitor)
                result = self._get_decompiler(program).decompileFunction(function, timeout_seconds, monitor)
            code = result.getDecompiledFunction()
            output = ProgramDecompilation(
                summary,
                self._info.revision,
                str(code.getC()) if code is not None else "",
                str(code.getSignature()) if code is not None else "",
                bool(result.decompileCompleted()),
                bool(result.isTimedOut()),
                bool(result.isCancelled()),
                bool(result.failedToStart()),
                str(result.getErrorMessage() or ""),
            )
            return ProgramDecompilationRun(output, "stock", None)


    def solve_layout(
        self, entry: Address, parameter_index: int = 0, *, max_summaries: int = 32,
        timeout_seconds: int = 30,
    ) -> SummaryLayoutReport:
        """Recover summary layout evidence for one pointer parameter, read-only.

        Runs the extension's Java ``binaryrat.SummaryLayouts`` service in this JVM, the
        same code as ``BinaryRatSolveLayouts.java``: each reached function parameter is
        decompiled once under a memory-watched lease and the engine's summary solver
        follows calls through recursive cycles. The selected parameter is asserted to
        point at the object's start. Requires the BinaryRat extension.
        """
        for name, value, low, high in (("parameter_index", parameter_index, 0, 65_535),
                                       ("max_summaries", max_summaries, 1, _MAX_SUMMARIES),
                                       ("timeout_seconds", timeout_seconds, 1, _MAX_SUMMARY_TIMEOUT_SECONDS)):
            if type(value) is not int or not low <= value <= high:
                raise ValueError(f"{name} must be an integer from {low} to {high}")
        _require_extension("Summary layouts")
        from ghidra.util.exception import CancelledException
        from jpype import JClass, JException

        with self._read() as program:
            function = program.getFunctionManager().getFunctionAt(
                self._native_address(program, entry)
            )
            if function is None:
                raise LookupError(f"no function at {entry}")
            with _monitor(self._cancel) as monitor:
                try:
                    text = str(JClass("binaryrat.SummaryLayouts").recoverJson(
                        program, function, parameter_index, timeout_seconds, max_summaries, monitor))
                except CancelledException as cause:
                    raise CancelledError("BinaryRat summary layout cancelled") from cause
                except JException as cause:
                    if program.isClosed() or int(program.getModificationNumber()) != self._info.revision:
                        raise StaleProgramError("Ghidra Program changed during layout recovery") from cause
                    raise LayoutRecoveryError(f"BinaryRat summary layout failed: {cause}") from cause
        report = decode_summary_report(text)
        digest = self._info.executable_sha256
        if report.revision != self._info.revision or (
                digest is not None and report.program_id != "sha256:" + digest.lower()):
            raise StaleProgramError("summary layout report does not describe this Program revision")
        return report

    def call_sites(
        self, entry: Address, *, max_sites: int = 64, max_callers: int = 32, timeout_seconds: int = 30,
    ) -> CallSitesReport:
        """List every call to a function with its decompiled statement and constant arguments.

        Runs the extension's Java ``binaryrat.CallSites`` service in this JVM, the same code as
        ``BinaryRatCallSites.java``: calls through thunks of the function count as calls to it,
        and each caller is decompiled once under a memory-watched lease. Arguments the decompiler
        proved constant carry their value; a value that points at a defined string or a labelled
        address carries the string or symbol. Read-only. Requires the BinaryRat extension.
        """
        for name, value, low, high in (("max_sites", max_sites, 1, _MAX_CALL_SITES),
                                       ("max_callers", max_callers, 1, _MAX_CALL_SITE_CALLERS),
                                       ("timeout_seconds", timeout_seconds, 1,
                                        _MAX_CALL_SITE_TIMEOUT_SECONDS)):
            if type(value) is not int or not low <= value <= high:
                raise ValueError(f"{name} must be an integer from {low} to {high}")
        _require_extension("Call sites")
        from ghidra.util.exception import CancelledException
        from jpype import JClass, JException

        with self._read() as program:
            function = program.getFunctionManager().getFunctionAt(
                self._native_address(program, entry)
            )
            if function is None:
                raise LookupError(f"no function at {entry}")
            with _monitor(self._cancel) as monitor:
                try:
                    text = str(JClass("binaryrat.CallSites").recoverJson(
                        program, function, timeout_seconds, max_sites, max_callers, monitor))
                except CancelledException as cause:
                    raise CancelledError("BinaryRat call-site listing cancelled") from cause
                except JException as cause:
                    if program.isClosed() or int(program.getModificationNumber()) != self._info.revision:
                        raise StaleProgramError("Ghidra Program changed while listing call sites") from cause
                    raise CallSitesError(f"BinaryRat call sites failed: {cause}") from cause
        report = decode_call_sites_report(text)
        digest = self._info.executable_sha256
        if report.revision != self._info.revision or (
                digest is not None and report.program_id != "sha256:" + digest.lower()):
            raise StaleProgramError("call-site report does not describe this Program revision")
        return report

    def stack_strings(
        self, entry: Address | None = None, *, minimum_length: int = 4, max_functions: int = 10_000,
        timeout_seconds: int | None = None,
    ) -> StackStringsReport:
        """Strings that functions build on the stack with constant stores, read-only.

        Runs the extension's Java ``binaryrat.StackStrings`` service in this JVM, the same code
        as ``BinaryRatStackStrings.java``: each function's instructions are read without the
        decompiler, register constants are followed through straight-line code, and the
        engine assembles the stores Ghidra's stack analysis marked as stack writes. Scans one
        function, or every function (up to ``max_functions``) when ``entry`` is None.
        A timeout requests cancellation of the scan and raises TimeoutError if it expires.
        Requires the BinaryRat extension.
        """
        for name, value, low, high in (("minimum_length", minimum_length, 1, 64),
                                       ("max_functions", max_functions, 1, _MAX_STACK_STRING_FUNCTIONS)):
            if type(value) is not int or not low <= value <= high:
                raise ValueError(f"{name} must be an integer from {low} to {high}")
        if timeout_seconds is not None and (
                type(timeout_seconds) is not int or not 1 <= timeout_seconds <= _MAX_STACK_STRINGS_TIMEOUT_SECONDS):
            raise ValueError(f"timeout_seconds must be an integer from 1 to {_MAX_STACK_STRINGS_TIMEOUT_SECONDS}")
        _require_extension("Stack strings")
        from ghidra.util.exception import CancelledException
        from jpype import JClass, JException

        deadline = None if timeout_seconds is None else monotonic() + timeout_seconds

        def check_deadline() -> None:
            if deadline is not None and monotonic() >= deadline:
                raise TimeoutError("BinaryRat stack-string scan timed out")

        with self._read(deadline=deadline) as program:
            check_deadline()
            function = None
            if entry is not None:
                function = program.getFunctionManager().getFunctionAt(self._native_address(program, entry))
                if function is None:
                    raise LookupError(f"no function at {entry}")
            with _monitor(self._cancel, deadline) as monitor:
                try:
                    text = str(JClass("binaryrat.StackStrings").recoverJson(
                        program, function, minimum_length, max_functions, monitor))
                except CancelledException as cause:
                    check_deadline()
                    raise CancelledError("BinaryRat stack-string scan cancelled") from cause
                except JException as cause:
                    if program.isClosed() or int(program.getModificationNumber()) != self._info.revision:
                        raise StaleProgramError("Ghidra Program changed while listing stack strings") from cause
                    check_deadline()
                    raise StackStringsError(f"BinaryRat stack strings failed: {cause}") from cause
        check_deadline()
        report = decode_stack_strings_report(text)
        check_deadline()
        digest = self._info.executable_sha256
        if report.revision != self._info.revision or (
                digest is not None and report.program_id != "sha256:" + digest.lower()):
            raise StaleProgramError("stack-string report does not describe this Program revision")
        return report


def _start(install_dir: Path | None, max_heap_mb: int | None) -> None:
    try:
        import pyghidra
    except ModuleNotFoundError as cause:
        if cause.name != "pyghidra":
            raise
        raise LiveProgramError("Install PyGhidra from the Ghidra 12.2 distribution") from cause

    with _STARTUP_LOCK:
        if not pyghidra.started():
            launcher = pyghidra.HeadlessPyGhidraLauncher(install_dir=install_dir)
            if launcher.app_info.version != "12.2":
                raise LiveProgramError(
                    f"Live access requires Ghidra 12.2, got {launcher.app_info.version}"
                )
            if max_heap_mb is not None:
                launcher.add_vmargs(f"-Xmx{max_heap_mb}m")
            launcher.start()
        from ghidra.framework import Application

        version = str(Application.getApplicationVersion())
        if version != "12.2":
            raise LiveProgramError(f"Live access requires Ghidra 12.2, got {version}")
        if install_dir is not None:
            active = Path(str(Application.getInstallationDirectory().getAbsolutePath())).resolve()
            if install_dir != active:
                raise LiveProgramError(f"PyGhidra is already using {active}")
        if max_heap_mb is not None:
            from java.lang import Runtime

            if int(Runtime.getRuntime().maxMemory()) > max_heap_mb * (1024 * 1024):
                raise LiveProgramError("running JVM heap exceeds the requested ceiling")


def _scheduled_service(backend: DecompilationBackend) -> Any:
    if backend == "stock":
        return None
    from ghidra.framework import Application
    from jpype import JClass, JException

    if Application.getModuleRootDir("BinaryRat") is None:
        if backend == "auto":
            return None
        raise LiveProgramError("Scheduled decompilation requires the BinaryRat extension")
    try:
        # The Java package name matches this Python package. Resolve the Java
        # class explicitly rather than asking Python's normal import machinery.
        return JClass("binaryrat.DecompilationSession")
    except (TypeError, JException) as cause:
        raise LiveProgramError("Installed BinaryRat extension lacks the shared decompilation service") from cause


def decompile_program(
    program: Any, entry: Address, *, timeout_seconds: int | None = None, cancel: Event | None = None,
) -> ProgramDecompilationRun:
    """Decompile a caller-owned live Program in the current PyGhidra JVM.

    Call from a worker, with a stable Program revision and no running
    auto-analysis. The call reads the supplied Program, including its current
    edits, through BinaryRat's foreground decompilation service.
    """
    try:
        from jpype import isJVMStarted
    except ModuleNotFoundError as cause:
        if cause.name != "jpype":
            raise
        raise LiveProgramError("decompile_program requires a Program in an initialized PyGhidra JVM") from cause

    if not isJVMStarted():
        raise LiveProgramError("decompile_program requires a Program in an initialized PyGhidra JVM")
    from ghidra.program.model.listing import Program
    from java.lang import Object
    from javax.swing import SwingUtilities

    if not isinstance(program, Program):
        raise TypeError("expected a live Ghidra Program")
    if SwingUtilities.isEventDispatchThread():
        raise LiveProgramError("decompile_program must run off the Ghidra UI thread")
    _check_cancel(cancel)
    service = _scheduled_service("scheduled")
    timeout = int(service.DEFAULT_TIMEOUT_SECONDS) if timeout_seconds is None else timeout_seconds
    consumer = Object()
    if not program.addConsumer(consumer):
        raise LiveProgramError("Ghidra Program is closed")
    with ExitStack() as cleanup:
        cleanup.callback(program.release, consumer)
        domain_file = program.getDomainFile()
        path = str(domain_file.getPathname()) if domain_file is not None else str(program.getName())
        view = ProgramView(program, path, cancel, service, foreground=True)
        cleanup.callback(view._invalidate)
        return view.decompile_with_metrics(entry, timeout_seconds=timeout)


@contextmanager
def open_program(
    project_file: str | Path,
    program_path: str,
    *,
    install_dir: str | Path | None = None,
    cancel: Event | None = None,
    max_heap_mb: int | None = None,
    backend: DecompilationBackend = "auto",
) -> Iterator[ProgramView]:
    """Open a saved Program in a local .gpr project using read-only storage.

    Pass the Program's absolute path inside its project. The context releases
    the Program and project storage. Later calls in the same Python process
    reuse the PyGhidra JVM. The automatic backend uses scheduling when the
    BinaryRat extension is installed and stock Ghidra on a plain installation.
    A scheduled operation reports startup, engine or cache errors to its caller.
    """
    if backend not in ("auto", "scheduled", "stock"):
        raise ValueError("backend must be 'auto', 'scheduled' or 'stock'")
    marker = Path(project_file).resolve()
    if marker.suffix != ".gpr":
        raise ValueError("project_file must be a Ghidra .gpr project marker")
    if not marker.is_file():
        raise FileNotFoundError(marker)
    if (not isinstance(program_path, str) or not program_path.startswith("/")
            or any(part in ("", ".", "..") for part in program_path[1:].split("/"))
            or any(character in program_path for character in ("\x00", "\\"))):
        raise ValueError("program_path must be an absolute path inside the project")
    if max_heap_mb is not None and (type(max_heap_mb) is not int or max_heap_mb < 256):
        raise ValueError("max_heap_mb must be an integer of at least 256")
    _check_cancel(cancel)
    _start(Path(install_dir).resolve() if install_dir is not None else None, max_heap_mb)
    scheduled_service = _scheduled_service(backend)
    from ghidra.framework.data import DefaultProjectData
    from ghidra.framework.model import DomainFile, DomainFileFilter, ProjectLocator
    from ghidra.program.model.listing import Program
    from ghidra.util import PropertyFile
    from ghidra.util.exception import CancelledException
    from java.lang import Object
    from jpype import JException

    locator = ProjectLocator(str(marker.parent), marker.name)
    # Ghidra 12.2 stores project properties under this name. Detect SERVER even
    # when a damaged shared project has no repository name.
    try:
        properties = PropertyFile(locator.getProjectDir(), "project")
    except JException as cause:
        raise LiveProgramError(f"Could not read the Ghidra project: {cause}") from cause
    if properties.getString(DefaultProjectData.SERVER_NAME, None) is not None:
        raise LiveProgramError("Live access requires a local Ghidra project")
    # DefaultProjectData creates the version store if absent, even on a read.
    version_store = marker.with_suffix(".rep") / str(DefaultProjectData.VERSIONED_FOLDER_NAME)
    if not version_store.is_dir():
        raise FileNotFoundError(version_store)
    _check_cancel(cancel)
    with ExitStack() as cleanup:
        # pyghidra.open_project and program_context request writable ownership.
        # Use the underlying read-only storage and release the exact consumer.
        # A damaged project, or a Program saved by a newer Ghidra, fails in Java here.
        try:
            project = DefaultProjectData(locator, False, False)
        except JException as cause:
            raise LiveProgramError(f"Could not open the Ghidra project: {cause}") from cause
        cleanup.callback(project.close)
        try:
            file = project.getFile(program_path, DomainFileFilter.NON_LINKED_FILE_FILTER)
        except JException as cause:
            raise LiveProgramError(f"Could not read {program_path}: {cause}") from cause
        if file is None:
            raise FileNotFoundError(f"No saved Program at {program_path}")
        if not Program.class_.isAssignableFrom(file.getDomainObjectClass()):
            raise TypeError(f"{program_path} is not a Ghidra Program")
        _check_cancel(cancel)
        consumer = Object()
        try:
            with _monitor(cancel) as monitor:
                program = file.getReadOnlyDomainObject(consumer, DomainFile.DEFAULT_VERSION, monitor)
                cleanup.callback(program.release, consumer)
        except CancelledException as cause:
            raise CancelledError("Ghidra Program open cancelled") from cause
        except JException as cause:
            raise LiveProgramError(f"Could not open {program_path}: {cause}") from cause
        view = ProgramView(program, program_path, cancel, scheduled_service)
        cleanup.callback(view._invalidate)
        yield view
