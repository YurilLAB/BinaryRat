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
from typing import Any, Generic, TypeVar

from .models import Address

_T = TypeVar("_T")
_MAX_PAGE_SIZE = 1000
_MAX_PAGE_OFFSET = 100_000
_MAX_REFERENCES_FROM = 100_000
_MAX_TYPE_COUNT = 100_000
_DECOMPILER_PAYLOAD_MB = 4
_OFFSET_MASK = (1 << 64) - 1
_STARTUP_LOCK = Lock()


class LiveProgramError(RuntimeError):
    """A live Program view cannot satisfy a read."""


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
class Page(Generic[_T]):
    """A page and the offset to supply to the same query for the next page."""

    items: tuple[_T, ...]
    next_offset: int | None
    truncated: bool = False


def _check_cancel(cancel: Event | None) -> None:
    if cancel is not None and cancel.is_set():
        raise CancelledError("Ghidra read cancelled")


@contextmanager
def _monitor(cancel: Event | None) -> Iterator[Any]:
    from ghidra.util.task import TaskMonitor, TaskMonitorAdapter

    if cancel is None:
        yield TaskMonitor.DUMMY
        return
    _check_cancel(cancel)
    monitor = TaskMonitorAdapter(True)
    finished = Event()

    def forward() -> None:
        while not finished.wait(0.05):
            if cancel.is_set():
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

    def __init__(self, program: Any, path: str, cancel: Event | None):
        self._program: Any | None = program
        self._decompiler: Any | None = None
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

    def _invalidate(self) -> None:
        with self._lock:
            self._program = None
            decompiler, self._decompiler = self._decompiler, None
            if decompiler is not None:
                self._close_decompiler(decompiler)

    def _check(self, program: Any) -> None:
        if program.isClosed():
            raise LiveProgramError("Ghidra Program is closed")
        _check_cancel(self._cancel)
        if int(program.getModificationNumber()) != self._info.revision:
            raise StaleProgramError("Ghidra Program changed while the view was open")

    @contextmanager
    def _read(self) -> Iterator[Any]:
        with self._lock:
            program = self._program
            if program is None:
                raise LiveProgramError("Program view is closed")
            self._check(program)
            yield program
            self._check(program)

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

    def decompile(self, entry: Address, *, timeout_seconds: int = 30) -> ProgramDecompilation:
        """Decompile one function with the view's stock decompiler."""
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds < (1 << 31):
            raise ValueError("timeout_seconds must be a positive 32-bit integer")
        with self._read() as program:
            function = program.getFunctionManager().getFunctionAt(
                self._native_address(program, entry)
            )
            if function is None:
                raise LookupError(f"no function at {entry}")
            summary = _function(function)
            decompiler = self._get_decompiler(program)
            with _monitor(self._cancel) as monitor:
                result = decompiler.decompileFunction(function, timeout_seconds, monitor)
            code = result.getDecompiledFunction()
            return ProgramDecompilation(
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


@contextmanager
def open_program(
    project_file: str | Path,
    program_path: str,
    *,
    install_dir: str | Path | None = None,
    cancel: Event | None = None,
    max_heap_mb: int | None = None,
) -> Iterator[ProgramView]:
    """Open a saved Program in a local .gpr project using read-only storage.

    Pass the Program's absolute path inside its project. The context releases
    the Program and project storage. Later calls in the same Python process
    reuse the PyGhidra JVM.
    """
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
    from ghidra.framework.data import DefaultProjectData
    from ghidra.framework.model import DomainFile, DomainFileFilter, ProjectLocator
    from ghidra.program.model.listing import Program
    from ghidra.util import PropertyFile
    from ghidra.util.exception import CancelledException
    from java.lang import Object

    locator = ProjectLocator(str(marker.parent), marker.name)
    # Ghidra 12.2 stores project properties under this name. Detect SERVER even
    # when a damaged shared project has no repository name.
    properties = PropertyFile(locator.getProjectDir(), "project")
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
        project = DefaultProjectData(locator, False, False)
        cleanup.callback(project.close)
        file = project.getFile(program_path, DomainFileFilter.NON_LINKED_FILE_FILTER)
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
        view = ProgramView(program, program_path, cancel)
        cleanup.callback(view._invalidate)
        yield view
