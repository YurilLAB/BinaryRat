"""Single-program PyGhidra service for trusted local clients.

Apache-2.0; Copyright 2026 YurilLAB.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Iterator
from dataclasses import asdict, dataclass, field, is_dataclass
import json
from itertools import chain
import re
import secrets
import socket
from socketserver import BaseRequestHandler, TCPServer
from time import monotonic
from typing import Any, TypeVar

from .call_sites import CallSitesReport, parse_call_sites_report
from .live import (
    _MAX_PAGE_OFFSET,
    _MAX_STACK_STRINGS_TIMEOUT_SECONDS,
    CallSitesError,
    CrossReference,
    DataTypeInfo,
    LayoutRecoveryError,
    LiveProgramError,
    Page,
    ProgramDecompilation,
    ProgramFunction,
    ProgramInfo,
    ProgramView,
    StackStringsError,
    StaleProgramError,
    open_program,
)
from .models import Address
from .stack_strings import StackStringsReport, StackStringsReportError, parse_stack_strings_report
from .summary_layout import SummaryLayoutReport, parse_summary_report

LIVE_PROTOCOL_VERSION = 1
READY_PREFIX = "binaryrat-live "
_HOST = "127.0.0.1"
_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}")
_MAX_REQUEST = 16 * 1024
_MAX_RESPONSE = 1024 * 1024
_IO_TIMEOUT = 5.0
_MAX_DECOMPILE_SECONDS = 60
# A service request decompiles at most this many function parameters.
_MAX_SERVICE_SUMMARIES = 64
# Call-site reports carry statements; these keep a reply well under the response limit.
_MAX_SERVICE_SITES = 256
_MAX_SERVICE_CALLERS = 64
_DEFAULT_SERVICE_STACK_FUNCTIONS = 32
_MAX_SERVICE_STACK_FUNCTIONS = 64
_T = TypeVar("_T")


class LiveProtocolError(RuntimeError):
    """The local service transport or message was invalid."""


class LiveRequestError(LiveProgramError):
    """The local service rejected the requested read."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(f"live request failed: {code}")


def _reject_constant(value: str) -> None:
    raise ValueError(f"unexpected JSON constant {value}")


def _object(line: bytes | str) -> dict[str, Any]:
    try:
        value = json.loads(line, parse_constant=_reject_constant)
    except (ValueError, RecursionError) as cause:
        raise LiveProtocolError("invalid JSON packet") from cause
    if not isinstance(value, dict):
        raise LiveProtocolError("expected a JSON object")
    return value


def _frame(sock: socket.socket, maximum: int, deadline: float) -> bytes:
    packet = bytearray()
    while len(packet) < maximum:
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise TimeoutError("live read deadline expired")
        sock.settimeout(remaining)
        chunk = sock.recv(min(4096, maximum - len(packet)))
        if not chunk:
            raise LiveProtocolError("incomplete live packet")
        packet.extend(chunk)
        if b"\n" in chunk:
            if packet.count(b"\n") != 1 or not packet.endswith(b"\n"):
                raise LiveProtocolError("expected one live packet")
            return bytes(packet)
    raise LiveProtocolError("live packet exceeds byte limit")


def _packet_items(value: Any, active: set[int]) -> Iterator[Any]:
    yield value
    if isinstance(value, (dict, list, tuple)):
        marker = id(value)
        if marker in active:
            raise ValueError("Circular reference detected")
        active.add(marker)
        children = chain.from_iterable(value.items()) if isinstance(value, dict) else value
        for child in children:
            yield from _packet_items(child, active)
        active.remove(marker)


def _encode(value: Any, maximum: int) -> bytes:
    packet = bytearray()
    encoder = json.JSONEncoder(ensure_ascii=True, allow_nan=False, separators=(",", ":"))
    # iterencode can allocate an entire escaped string before yielding it.
    # Bound the precheck by a lower estimate of the packet's total size.
    remaining = maximum
    for item in _packet_items(value, set()):
        remaining -= 1 + (len(item) if isinstance(item, str) else 0)
        if remaining < 0:
            raise LiveProtocolError("live packet exceeds byte limit")
        # A non-BMP character takes at most twelve ASCII bytes in JSON.
        if isinstance(item, str) and len(item) > maximum // 12:
            length = 2
            for offset in range(0, len(item), 1024):
                length += len(encoder.encode(item[offset:offset + 1024])) - 2
                if length >= maximum:
                    raise LiveProtocolError("live packet exceeds byte limit")
    for piece in encoder.iterencode(value):
        if len(packet) + len(piece) >= maximum:
            raise LiveProtocolError("live packet exceeds byte limit")
        packet.extend(piece.encode("ascii"))
    packet.extend(b"\n")
    return bytes(packet)


def _send(sock: socket.socket, packet: bytes, deadline: float) -> None:
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise TimeoutError("live write deadline expired")
    sock.settimeout(remaining)
    sock.sendall(packet)


@dataclass(frozen=True, slots=True)
class LiveEndpoint:
    """Loopback port and secret received over the service's private output pipe."""

    port: int
    token: str = field(repr=False)
    backend: str | None = None

    def __post_init__(self) -> None:
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise ValueError("invalid local service port")
        if not isinstance(self.token, str) or _TOKEN.fullmatch(self.token) is None:
            raise ValueError("invalid local service token")
        if self.backend not in (None, "scheduled", "stock"):
            raise ValueError("invalid local service decompilation backend")

    @classmethod
    def from_ready_line(cls, line: str) -> LiveEndpoint:
        if not line.startswith(READY_PREFIX):
            raise LiveProtocolError("expected a local service ready line")
        item = _object(line[len(READY_PREFIX):])
        if type(item.get("version")) is not int or item["version"] != LIVE_PROTOCOL_VERSION:
            raise LiveProtocolError("unsupported live protocol version")
        try:
            return cls(item["port"], item["token"], item.get("backend"))
        except (KeyError, ValueError) as cause:
            raise LiveProtocolError("invalid local service endpoint") from cause


def _function(item: dict[str, Any]) -> ProgramFunction:
    return ProgramFunction(**(item | {"entry": Address(**item["entry"])}))


def _reference(item: dict[str, Any]) -> CrossReference:
    return CrossReference(**(item | {
        "source": Address(**item["source"]),
        "target": Address(**item["target"]),
    }))


def _page(item: dict[str, Any], decode: Callable[[dict[str, Any]], _T]) -> Page[_T]:
    return Page(
        tuple(decode(row) for row in item["items"]), item["next_offset"], item["truncated"]
    )


class LiveClient:
    """Typed read client for a single Program served by a local PyGhidra JVM."""

    def __init__(self, endpoint: LiveEndpoint, *, timeout: float = 65):
        if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not 0 < timeout <= 3600):
            raise ValueError("timeout must be between zero and 3600 seconds")
        self._endpoint = endpoint
        self._timeout = timeout

    def _request(self, method: str, **arguments: Any) -> Any:
        packet = _encode({
            "version": LIVE_PROTOCOL_VERSION,
            "token": self._endpoint.token,
            "method": method,
            "args": arguments,
        }, _MAX_REQUEST)
        deadline = monotonic() + self._timeout
        try:
            with socket.create_connection((_HOST, self._endpoint.port), self._timeout) as sock:
                _send(sock, packet, deadline)
                reply = _object(_frame(sock, _MAX_RESPONSE, deadline))
        except OSError as cause:
            raise LiveProtocolError("could not complete the local service request") from cause
        version = reply.get("version")
        if type(version) is not int or version != LIVE_PROTOCOL_VERSION:
            raise LiveProtocolError("unsupported live protocol version")
        if set(reply) == {"version", "result"}:
            return reply["result"]
        code = reply.get("error")
        if set(reply) == {"version", "error"} and isinstance(code, str):
            raise LiveRequestError(code)
        raise LiveProtocolError("malformed live service response")

    def info(self) -> ProgramInfo:
        item = self._request("info")
        return ProgramInfo(**(item | {"image_base": Address(**item["image_base"])}))

    def functions(self, *, offset: int = 0, limit: int = 100) -> Page[ProgramFunction]:
        return _page(self._request("functions", offset=offset, limit=limit), _function)

    def function_at(self, entry: Address) -> ProgramFunction | None:
        item = self._request("function_at", entry=asdict(entry))
        return _function(item) if item is not None else None

    def xrefs_to(
        self, target: Address, *, offset: int = 0, limit: int = 100
    ) -> Page[CrossReference]:
        return _page(self._request(
            "xrefs_to", target=asdict(target), offset=offset, limit=limit
        ), _reference)

    def xrefs_from(
        self, source: Address, *, offset: int = 0, limit: int = 100
    ) -> Page[CrossReference]:
        return _page(self._request(
            "xrefs_from", source=asdict(source), offset=offset, limit=limit
        ), _reference)

    def data_types(self, *, offset: int = 0, limit: int = 100) -> Page[DataTypeInfo]:
        return _page(
            self._request("data_types", offset=offset, limit=limit),
            lambda item: DataTypeInfo(**item),
        )

    def data_type(self, category: str, name: str) -> DataTypeInfo | None:
        item = self._request("data_type", category=category, name=name)
        return DataTypeInfo(**item) if item is not None else None

    def decompile(self, entry: Address, *, timeout_seconds: int = 30) -> ProgramDecompilation:
        item = self._request("decompile", entry=asdict(entry), timeout_seconds=timeout_seconds)
        return ProgramDecompilation(**(item | {"function": _function(item["function"])}))

    def solve_layout(
        self, entry: Address, parameter_index: int = 0, *, max_summaries: int = 32,
        timeout_seconds: int = 30,
    ) -> SummaryLayoutReport:
        """Summary layout evidence from the served Program, validated before it is returned.

        The whole recovery must finish within this client's timeout.
        """
        return parse_summary_report(self._request(
            "solve_layout", entry=asdict(entry), parameter_index=parameter_index,
            max_summaries=max_summaries, timeout_seconds=timeout_seconds,
        ))

    def call_sites(
        self, entry: Address, *, max_sites: int = 64, max_callers: int = 32, timeout_seconds: int = 30,
    ) -> CallSitesReport:
        """Calls to a function in the served Program, validated before they are returned.

        The whole listing must finish within this client's timeout.
        """
        return parse_call_sites_report(self._request(
            "call_sites", entry=asdict(entry), max_sites=max_sites, max_callers=max_callers,
            timeout_seconds=timeout_seconds,
        ))

    def stack_strings(
        self, entry: Address | None = None, *, minimum_length: int = 4,
        max_functions: int = _DEFAULT_SERVICE_STACK_FUNCTIONS, timeout_seconds: int = 30,
    ) -> StackStringsReport:
        """List stack strings in one function or a bounded batch in the served Program."""
        return parse_stack_strings_report(self._request(
            "stack_strings", entry=None if entry is None else asdict(entry), minimum_length=minimum_length,
            max_functions=max_functions, timeout_seconds=timeout_seconds,
        ))


class _Service(TCPServer):
    """Serial, bounded requests over IPv4 loopback."""

    request_queue_size = 8

    def __init__(self, view: ProgramView, token: str):
        self._view = view
        self._token = token
        self.last_authorized = monotonic()
        self._request_authorized = False
        self.idle_deadline = float("inf")
        self._operations = {
            "functions": (view.functions, None),
            "function_at": (view.function_at, "entry"),
            "xrefs_to": (view.xrefs_to, "target"),
            "xrefs_from": (view.xrefs_from, "source"),
            "data_types": (view.data_types, None),
            "data_type": (view.data_type, None),
            "decompile": (view.decompile, "entry"),
            # The validated report document is sent unchanged.
            "solve_layout": (lambda **arguments: view.solve_layout(**arguments).document, "entry"),
            "call_sites": (lambda **arguments: view.call_sites(**arguments).document, "entry"),
            "stack_strings": (self._stack_strings, "entry"),
        }
        super().__init__((_HOST, 0), _Connection)

    def server_bind(self) -> None:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()

    def _stack_strings(
        self, entry: Address | None = None, *, minimum_length: int = 4,
        max_functions: int = _DEFAULT_SERVICE_STACK_FUNCTIONS, timeout_seconds: int = 30,
    ) -> dict[str, Any]:
        if (type(minimum_length) is not int or not 1 <= minimum_length <= 64 or
                type(max_functions) is not int or not 1 <= max_functions <= _MAX_SERVICE_STACK_FUNCTIONS or
                type(timeout_seconds) is not int or not 1 <= timeout_seconds <= _MAX_STACK_STRINGS_TIMEOUT_SECONDS):
            raise LiveRequestError("bad_request")
        try:
            return self._view.stack_strings(entry, minimum_length=minimum_length, max_functions=max_functions,
                                            timeout_seconds=timeout_seconds).document
        except TimeoutError as cause:
            raise LiveRequestError("timed_out") from cause
        except (StackStringsError, StackStringsReportError) as cause:
            raise LiveRequestError("stack_strings_failed") from cause

    def reply(self, request: dict[str, Any]) -> Any:
        version, token = request.get("version"), request.get("token")
        if not isinstance(token, str) or _TOKEN.fullmatch(token) is None:
            raise LiveRequestError("unauthorized")
        if not secrets.compare_digest(token, self._token):
            raise LiveRequestError("unauthorized")
        self._request_authorized = True
        if (set(request) != {"version", "token", "method", "args"}
                or type(version) is not int or version != LIVE_PROTOCOL_VERSION):
            raise LiveRequestError("bad_request")
        method, arguments = request["method"], request["args"]
        if not isinstance(method, str) or not isinstance(arguments, dict):
            raise LiveRequestError("bad_request")
        if method == "info" and not arguments:
            return self._view.info
        if method not in self._operations:
            raise LiveRequestError("bad_request")
        offset = arguments.get("offset", 0)
        if type(offset) is int and offset > _MAX_PAGE_OFFSET:
            raise LiveRequestError("offset_limit")
        operation, address_key = self._operations[method]
        if address_key is not None:
            address = arguments.get(address_key)
            if address is not None or method != "stack_strings":
                if not isinstance(address, dict) or set(address) != {"space", "offset"}:
                    raise LiveRequestError("bad_request")
                arguments = arguments | {address_key: Address(**address)}
        if method in ("decompile", "solve_layout", "call_sites"):
            timeout = arguments.get("timeout_seconds", 30)
            if type(timeout) is not int or not 1 <= timeout <= _MAX_DECOMPILE_SECONDS:
                raise LiveRequestError("bad_request")
        if method == "solve_layout":
            summaries = arguments.get("max_summaries", 32)
            if (type(summaries) is not int or not 1 <= summaries <= _MAX_SERVICE_SUMMARIES or
                    not set(arguments) <= {"entry", "parameter_index", "max_summaries", "timeout_seconds"}):
                raise LiveRequestError("bad_request")
        if method == "call_sites":
            sites, callers = arguments.get("max_sites", 64), arguments.get("max_callers", 32)
            if (type(sites) is not int or not 1 <= sites <= _MAX_SERVICE_SITES or
                    type(callers) is not int or not 1 <= callers <= _MAX_SERVICE_CALLERS or
                    not set(arguments) <= {"entry", "max_sites", "max_callers", "timeout_seconds"}):
                raise LiveRequestError("bad_request")
        result = operation(**arguments)
        if isinstance(result, ProgramDecompilation) and len(result.c) >= _MAX_RESPONSE:
            raise LiveRequestError("response_too_large")
        return result

    def serve_until_idle(self, idle_timeout: int) -> None:
        while (remaining := self.last_authorized + idle_timeout - monotonic()) > 0:
            self.timeout = remaining
            self._request_authorized = False
            self.idle_deadline = self.last_authorized + idle_timeout
            try:
                self.handle_request()
            finally:
                self.idle_deadline = float("inf")
            if self._request_authorized:
                self.last_authorized = monotonic()


class _Connection(BaseRequestHandler):
    server: _Service

    def handle(self) -> None:
        version = {"version": LIVE_PROTOCOL_VERSION}
        try:
            deadline = min(self.server.idle_deadline, monotonic() + _IO_TIMEOUT)
            request = _object(_frame(self.request, _MAX_REQUEST, deadline))
            if monotonic() >= self.server.idle_deadline:
                return
            result = self.server.reply(request)
            try:
                response = _encode(version | {
                    "result": asdict(result) if is_dataclass(result) else result
                }, _MAX_RESPONSE)
            except LiveProtocolError:
                raise LiveRequestError("response_too_large") from None
        except LiveRequestError as cause:
            response = _encode(version | {"error": cause.code}, _MAX_RESPONSE)
        except StaleProgramError:
            response = _encode(version | {"error": "stale_program"}, _MAX_RESPONSE)
        except LayoutRecoveryError:
            response = _encode(version | {"error": "layout_failed"}, _MAX_RESPONSE)
        except CallSitesError:
            response = _encode(version | {"error": "call_sites_failed"}, _MAX_RESPONSE)
        except LiveProgramError:
            response = _encode(version | {"error": "program_unavailable"}, _MAX_RESPONSE)
        except LookupError:
            response = _encode(version | {"error": "not_found"}, _MAX_RESPONSE)
        except (OSError, ValueError, TypeError, LiveProtocolError):
            response = _encode(version | {"error": "bad_request"}, _MAX_RESPONSE)
        except Exception:
            # A Java exception can include filesystem and other local details.
            response = _encode(version | {"error": "read_failed"}, _MAX_RESPONSE)
        try:
            _send(self.request, response, monotonic() + _IO_TIMEOUT)
        except OSError:
            pass


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve a saved Ghidra Program on loopback")
    parser.add_argument("project_file")
    parser.add_argument("program_path")
    parser.add_argument("--install-dir")
    parser.add_argument("--backend", choices=("auto", "scheduled", "stock"), default="auto",
                        help="auto uses BinaryRat scheduling when the extension is installed")
    parser.add_argument("--idle-timeout", type=int, default=300, metavar="SECONDS")
    parser.add_argument("--max-heap-mb", type=int, default=1024)
    args = parser.parse_args()
    if not 1 <= args.idle_timeout <= 3600:
        parser.error("--idle-timeout must be between 1 and 3600 seconds")
    if args.max_heap_mb < 256:
        parser.error("--max-heap-mb must be at least 256")
    try:
        with open_program(
            args.project_file, args.program_path, install_dir=args.install_dir,
            max_heap_mb=args.max_heap_mb, backend=args.backend,
        ) as view:
            token = secrets.token_urlsafe(32)
            with _Service(view, token) as service:
                ready = {
                    "version": LIVE_PROTOCOL_VERSION,
                    "port": service.server_address[1],
                    "token": token,
                    "backend": view.decompilation_backend,
                }
                print(READY_PREFIX + json.dumps(ready), flush=True)
                service.serve_until_idle(args.idle_timeout)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
