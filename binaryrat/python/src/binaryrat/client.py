"""A serialized, correlated JSONL client for a persistent native engine.

The engine owns no JVM in this MVP. Apache-2.0; Copyright 2026 YurilLAB.
"""

from __future__ import annotations

import json
import math
import queue
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Iterable, Mapping


class ProtocolError(RuntimeError):
    """An invalid, missing or incompatible engine response."""


class EngineError(RuntimeError):
    """A well-formed error returned by the engine."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


class EngineClient:
    """Own one native process; requests are serialized across Python threads.

    A timeout makes the connection unusable and terminates the engine, preventing
    a late response from being mistaken for the next request. stderr is inherited,
    never buffered into an unread pipe. This is not a PyGhidra/JVM daemon.
    """

    def __init__(
        self,
        executable: str | Path = "binaryrat-engine",
        *,
        cache_dir: str | Path | None = None,
        timeout: float = 60.0,
        max_response_bytes: int = 64 * 1024 * 1024,
    ):
        if not math.isfinite(timeout) or timeout <= 0 or type(max_response_bytes) is not int or max_response_bytes <= 0:
            raise ValueError("timeout and max_response_bytes must be positive")
        argv = [str(executable), "serve"]
        if cache_dir is not None:
            argv += ["--cache", str(cache_dir)]
        self._process = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
            encoding="utf-8", errors="strict", bufsize=1,
        )
        self._timeout = timeout
        self._limit = max_response_bytes
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._responses: queue.Queue[str | BaseException] = queue.Queue(maxsize=2)
        self._next_id = 0
        self._reader = threading.Thread(target=self._read_responses, daemon=True)
        self._reader.start()

    def _read_responses(self) -> None:
        assert self._process.stdout is not None
        try:
            while not self._stop.is_set():
                line = self._process.stdout.readline(self._limit + 1)
                if not line:
                    raise EOFError("engine closed stdout")
                if len(line.encode("utf-8")) > self._limit:
                    raise ValueError("engine response exceeds maximum size")
                self._deliver(line)
        except BaseException as error:
            self._deliver(error)

    def _deliver(self, response: str | BaseException) -> None:
        while not self._stop.is_set():
            try:
                self._responses.put(response, timeout=0.1)
                return
            except queue.Full:
                continue

    def _abort(self) -> None:
        self._stop.set()
        if self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait()

    def request(self, op: str, **fields: Any) -> Any:
        """Issue one protocol-v1 operation; return its JSON result."""
        if "id" in fields or "op" in fields:
            raise ValueError("id and op are reserved protocol fields")
        with self._lock:
            if self._stop.is_set():
                raise ProtocolError("client is closed")
            self._next_id += 1
            request_id = str(self._next_id)
            payload = json.dumps({"id": request_id, "op": op, **fields}, allow_nan=False)
            if len(payload.encode("utf-8")) > 16 * 1024 * 1024:
                raise ValueError("request exceeds native protocol limit of 16 MiB")
            assert self._process.stdin is not None
            deadline = time.monotonic() + self._timeout
            sent: queue.Queue[BaseException | None] = queue.Queue(maxsize=1)

            def write_request() -> None:
                try:
                    assert self._process.stdin is not None
                    self._process.stdin.write(payload + "\n")
                    self._process.stdin.flush()
                    sent.put(None)
                except BaseException as error:
                    sent.put(error)

            # Pipes can block on write when a failed peer stops reading. A writer
            # thread lets the same deadline cover both transmission and response.
            writer = threading.Thread(target=write_request, daemon=True)
            writer.start()
            try:
                write_error = sent.get(timeout=max(0, deadline - time.monotonic()))
                if write_error is not None:
                    raise ProtocolError(f"engine request write failed: {write_error}") from write_error
                response = self._responses.get(timeout=max(0, deadline - time.monotonic()))
                if isinstance(response, BaseException):
                    raise ProtocolError(str(response)) from response
                row = json.loads(response)
                if not isinstance(row, dict) or row.get("id") != request_id:
                    raise ProtocolError("response id does not match request")
                if type(row.get("protocol_version")) is not int or row["protocol_version"] != 1:
                    raise ProtocolError("unsupported protocol_version")
                if type(row.get("ok")) is not bool:
                    raise ProtocolError("response ok must be boolean")
                if row["ok"]:
                    if "result" not in row:
                        raise ProtocolError("successful response has no result")
                    return row["result"]
                error = row.get("error")
                if not isinstance(error, dict) or not all(
                    isinstance(error.get(key), str) for key in ("code", "message")
                ):
                    raise ProtocolError("malformed engine error")
                raise EngineError(error["code"], error["message"])
            except EngineError:
                raise
            except (OSError, ValueError, queue.Empty, ProtocolError) as error:
                self._abort()
                if isinstance(error, ProtocolError):
                    raise
                if isinstance(error, queue.Empty):
                    raise ProtocolError("engine response timed out") from error
                raise ProtocolError(f"invalid engine response: {error}") from error
            finally:
                writer.join(timeout=2)

    def _object_request(self, op: str, **fields: Any) -> Mapping[str, Any]:
        result = self.request(op, **fields)
        if not isinstance(result, dict):
            with self._lock:
                self._abort()
            raise ProtocolError(f"{op} result must be an object")
        return result

    def ping(self) -> Mapping[str, Any]:
        return self._object_request("ping")

    def cache_put(
        self, key: Mapping[str, Any], value: Mapping[str, Any], dependencies: Iterable[str] = ()
    ) -> Any:
        return self.request("cache.put", key=dict(key), value=dict(value), dependencies=list(dependencies))

    def cache_get(self, key: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._object_request("cache.get", key=dict(key))

    def cache_invalidate(self, dependencies: Iterable[str]) -> Mapping[str, Any]:
        return self._object_request("cache.invalidate", dependencies=list(dependencies))

    def recover_types(self, observations: Iterable[Mapping[str, Any]]) -> Mapping[str, Any]:
        return self._object_request("types.recover", observations=[dict(item) for item in observations])

    def solve_types(
        self,
        summaries: Iterable[Mapping[str, Any]],
        edges: Iterable[Mapping[str, Any]],
        roots: Iterable[Mapping[str, Any]],
        *,
        maximum_extent: int | None = None,
        maximum_states: int | None = None,
        maximum_derived: int | None = None,
    ) -> Mapping[str, Any]:
        """Propagate per-parameter access summaries along forwarding calls (op ``types.solve``).

        ``summaries`` are ``{"id", "accesses": [{"offset", "width", "evidence_id",
        "storage_view"?}]}``; ``edges`` are ``{"caller", "callee", "offset", "evidence_id"}``
        meaning callee pointer == caller pointer + offset; ``roots`` are ``{"summary",
        "object_id"}`` (1 to 16). Limits are per root and at most 65536.
        """
        fields: dict[str, Any] = dict(
            summaries=[dict(item) for item in summaries],
            edges=[dict(item) for item in edges],
            roots=[dict(item) for item in roots],
        )
        for name, value in (("maximum_extent", maximum_extent), ("maximum_states", maximum_states),
                            ("maximum_derived", maximum_derived)):
            if value is not None:
                fields[name] = value
        return self._object_request("types.solve", **fields)

    def stack_strings(
        self, groups: Iterable[Mapping[str, Any]], *, minimum_length: int | None = None,
    ) -> Mapping[str, Any]:
        """Assemble strings from constant stack writes (op ``strings.stack``).

        ``groups`` are ``{"id", "writes": [{"offset", "bytes", "order"}]}``: ``bytes`` is 1 to 64
        bytes of lowercase hex in memory order and a write with a higher ``order`` replaces
        earlier bytes. Each group's result lists ``{"offset", "byte_length", "encoding",
        "text", "terminated", "orders"}``; ``minimum_length`` (1 to 64, default 4) counts
        characters.
        """
        fields: dict[str, Any] = dict(groups=[
            dict(group, writes=[dict(write) for write in group["writes"]]) for group in groups])
        if minimum_length is not None:
            fields["minimum_length"] = minimum_length
        return self._object_request("strings.stack", **fields)

    def close(self) -> None:
        with self._lock:
            if not self._stop.is_set():
                # A normal EOF lets the native server flush/close its cache.
                assert self._process.stdin is not None
                try:
                    self._process.stdin.close()
                    self._process.wait(timeout=2)
                except (OSError, subprocess.TimeoutExpired):
                    self._abort()
                self._stop.set()
            self._reader.join(timeout=2)
            if self._process.stdout is not None:
                self._process.stdout.close()
            if self._process.stdin is not None and not self._process.stdin.closed:
                try:
                    self._process.stdin.close()
                except OSError:
                    pass

    def __enter__(self) -> EngineClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
