"""Live Program facade tests. Apache-2.0; Copyright 2026 YurilLAB."""

from concurrent.futures import CancelledError
from contextlib import ExitStack, redirect_stderr
import io
from hashlib import sha256
import json
import os
from pathlib import Path
from queue import Queue
from random import Random
import secrets
import shutil
import socket
import subprocess
import sys
from threading import Event, Thread, enumerate as active_threads
from tempfile import TemporaryDirectory
from time import monotonic, sleep
import tracemalloc
import unittest
from unittest.mock import Mock, patch

from binaryrat import (
    Address, LayoutRecoveryError, LiveProgramError, Page, StaleProgramError, decompile_program,
    open_program,
)
from binaryrat.decompile_cli import _parse_function, _resolve, main as decompile_main
from binaryrat.live import ProgramView, StackStringsError, _monitor
from binaryrat.live_service import (
    LIVE_PROTOCOL_VERSION,
    READY_PREFIX,
    LiveClient,
    LiveEndpoint,
    LiveProtocolError,
    LiveRequestError,
    _Service,
    _encode,
    _frame,
)
from binaryrat.stack_strings import StackStringsReportError


_INSTALL_DIR = os.environ.get("BINARYRAT_GHIDRA_INSTALL_DIR")
_REQUIRE_SHARED_SERVICE = os.environ.get("BINARYRAT_REQUIRE_SHARED_SERVICE") == "1"


class LiveProgramInputTests(unittest.TestCase):
    def test_cli_function_parser_separates_addresses_and_names(self):
        from argparse import ArgumentTypeError

        self.assertEqual(_parse_function("ram:0xffffffffffffffff"), ("address", ("ram", (1 << 64) - 1, None)))
        self.assertEqual(_parse_function("0x0A"), ("address", (None, 10, None)))
        # A bare hexadecimal token is an address, remembered in case a name was meant.
        self.assertEqual(_parse_function("add"), ("address", (None, 0xADD, "add")))
        for name in ("main", "ns::f", ".text", "FUN_140001000", "operator<<", "_start"):
            with self.subTest(name=name):
                self.assertEqual(_parse_function(name), ("name", name))
        self.assertEqual(_parse_function("name:add"), ("name", "add"))
        for bad in ("", "name:", "0x", "1x", "ram:", "ram:1:2", "ram:0x10000000000000000", "ram: 1",
                    "ram:main", "a b", "f\x1b", "10000000000000000"):
            with self.subTest(entry=bad), self.assertRaises(ArgumentTypeError):
                _parse_function(bad)

    def test_cli_function_parser_fuzz(self):
        from argparse import ArgumentTypeError
        import random

        rng = random.Random(20261120)
        pieces = ["0", "1", "9", "a", "F", "x", "X", "0x", ":", "::", "ram", "name:", "_", ".", "-",
                  " ", "\t", "\x1b", "\u00e9", "\U0001f400", "main", "ns", "f" * 17, "<", ">"]
        for _ in range(20000):
            value = "".join(rng.choice(pieces) for _ in range(rng.randrange(0, 7)))
            try:
                kind, parsed = _parse_function(value)
            except ArgumentTypeError:
                continue
            if kind == "name":
                self.assertTrue(parsed and parsed.isprintable(), value)
                if not value.startswith("name:"):
                    self.assertFalse(parsed[0].isdigit() or any(c.isspace() for c in parsed), value)
            else:
                space, offset, bare = parsed
                self.assertEqual(kind, "address")
                self.assertTrue(0 <= offset < 1 << 64, value)
                self.assertEqual(bare is not None, space is None and not value[:2].lower() == "0x", value)
        for _ in range(2000):
            offset = rng.randrange(1 << 64)
            space = rng.choice((None, "ram", "overlay_1", "OTHER"))
            text = (f"{space}:" if space else "") + rng.choice(("0x", "0X", "")) + f"{offset:x}"
            self.assertEqual(_parse_function(text)[1][:2], (space, offset), text)

    def test_missing_project_and_invalid_domain_path(self):
        with TemporaryDirectory() as tmp:
            marker = Path(tmp) / "unknown.gpr"
            with self.assertRaises(FileNotFoundError), open_program(marker, "/program"):
                pass
            marker.touch()
            with self.assertRaisesRegex(ValueError, "backend"):
                with open_program(marker, "/program", backend="unknown"):
                    self.fail("unknown backend was accepted")
            for name in ("program", "/", "//program", "/nested/../program", "/dir\\program"):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    with open_program(marker, name):
                        self.fail("invalid program path was accepted")

    def test_cancelled_open_does_not_start_the_jvm(self):
        with TemporaryDirectory() as tmp:
            marker = Path(tmp) / "cancel.gpr"
            marker.touch()
            cancellation = Event()
            cancellation.set()
            with self.assertRaises(CancelledError), open_program(
                marker, "/program", cancel=cancellation
            ):
                pass

    def test_page_reads_only_the_required_rows(self):
        view = ProgramView.__new__(ProgramView)
        view._cancel = None
        rows = iter(range(1_000_000))
        self.assertEqual(view._page(rows, str, 20, 2), Page(("20", "21"), 22))
        self.assertEqual(next(rows), 23)
        self.assertEqual(view._page(range(100002), str, 100000, 1),
                         Page(("100000",), None, truncated=True))

    def test_transport_rejects_oversize_and_partial_frames(self):
        self.assertEqual(_encode({"x": "a"}, 10), b'{"x":"a"}\n')
        with self.assertRaises(LiveProtocolError):
            _encode({"x": "α"}, 10)
        first, second = socket.socketpair()
        with first, second:
            second.sendall(b'{"incomplete":')
            with self.assertRaises(TimeoutError):
                _frame(first, 1024, monotonic() + 0.05)

    def test_frame_encoding_matches_json_and_bounds_rejected_strings(self):
        # Include escaped characters across a chunk boundary and non-BMP code points.
        label = "x" * 1023 + '"\\\n\N{GRINNING FACE}' * 300
        shared = {1: label, None: False}
        sample = {label: [label, None, True, (1, 0.5)], "repeated": [shared, shared]}
        expected = (json.dumps(sample, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")
        self.assertEqual(_encode(sample, len(expected)), expected)
        with self.assertRaises(LiveProtocolError):
            _encode(sample, len(expected) - 1)

        oversized = [(16 * 1024, {"name": "\N{GREEK CAPITAL LETTER OMEGA}" * (1 << 20)}),
                     (1 << 20, {"name": "\N{GRINNING FACE}" * (1 << 18)})]
        already_tracing = tracemalloc.is_tracing()
        if not already_tracing:
            tracemalloc.start()
        try:
            baseline = tracemalloc.get_traced_memory()[0]
            tracemalloc.reset_peak()
            for limit, value in oversized:
                with self.assertRaises(LiveProtocolError):
                    _encode(value, limit)
            self.assertLess(tracemalloc.get_traced_memory()[1] - baseline, 512 * 1024)
        finally:
            if not already_tracing:
                tracemalloc.stop()

    def test_circular_client_argument_is_rejected_before_connecting(self):
        client = LiveClient(LiveEndpoint(12345, "a" * 43))
        cycle = []
        cycle.append({"cycle": cycle})
        with patch("socket.create_connection") as connect:
            with self.assertRaisesRegex(ValueError, "Circular reference"):
                client.data_type(cycle, "Name")
            connect.assert_not_called()

    def test_live_stack_strings_bounds_and_errors(self):
        token = secrets.token_urlsafe(32)
        entry = Address("ram", 16)
        view = Mock(spec=ProgramView)
        report = {
            "schema_version": 1, "analysis_mode": "read_only_stack_strings", "program_id": None,
            "revision": 3, "language_id": "x86:LE:64:default", "compiler_spec_id": "gcc",
            "function": None, "minimum_length": 4, "function_limit": 32, "functions_scanned": 0,
            "functions_skipped": 0, "functions_partial": 0, "stack_writes": 0, "truncated": False, "strings": [],
        }
        view.stack_strings.return_value.document = report
        with _Service(view, token) as service:
            worker = Thread(target=service.serve_forever, daemon=True, kwargs={"poll_interval": 0.01})
            worker.start()
            try:
                client = LiveClient(LiveEndpoint(service.server_address[1], token), timeout=5)
                self.assertEqual(client.stack_strings().document, report)
                view.stack_strings.assert_called_once_with(None, minimum_length=4, max_functions=32,
                                                           timeout_seconds=30)
                self.assertEqual(client._request("stack_strings"), report)
                client.stack_strings(entry, minimum_length=64, max_functions=64, timeout_seconds=60)
                view.stack_strings.assert_called_with(entry, minimum_length=64, max_functions=64,
                                                      timeout_seconds=60)
                view.stack_strings.reset_mock()
                for bad in (dict(minimum_length=0), dict(minimum_length=65), dict(minimum_length=True),
                            dict(max_functions=0), dict(max_functions=65), dict(max_functions="32"),
                            dict(timeout_seconds=0), dict(timeout_seconds=61), dict(timeout_seconds=True),
                            dict(timeout_seconds=None), dict(entry="ram:10"),
                            dict(entry={"space": "ram", "offset": 16, "name": "fixture"}),
                            dict(project_file="another.gpr")):
                    with self.subTest(bad=bad), self.assertRaisesRegex(LiveRequestError, "bad_request"):
                        client._request("stack_strings", **bad)
                unauthorized = LiveClient(LiveEndpoint(service.server_address[1], secrets.token_urlsafe(32)))
                with self.assertRaisesRegex(LiveRequestError, "unauthorized"):
                    unauthorized.stack_strings()
                view.stack_strings.assert_not_called()

                for cause, code in ((TimeoutError("internal details"), "timed_out"),
                                    (StackStringsError("internal details"), "stack_strings_failed"),
                                    (StackStringsReportError("internal details"), "stack_strings_failed"),
                                    (StaleProgramError("internal details"), "stale_program"),
                                    (LookupError("internal details"), "not_found")):
                    view.stack_strings.side_effect = cause
                    with self.subTest(code=code), self.assertRaises(LiveRequestError) as failure:
                        client.stack_strings(entry)
                    self.assertEqual(failure.exception.code, code)
                    self.assertNotIn("internal details", str(failure.exception))
                view.stack_strings.side_effect = None
                view.stack_strings.return_value.document = {"strings": "x" * (1 << 20)}
                with self.assertRaisesRegex(LiveRequestError, "response_too_large"):
                    client.stack_strings()
                view.stack_strings.return_value.document = report | {"revision": "invalid"}
                with self.assertRaises(StackStringsReportError):
                    client.stack_strings()
                view.stack_strings.return_value.document = report
                self.assertEqual(client.stack_strings().revision, 3)
            finally:
                service.shutdown()
                worker.join(5)
            self.assertFalse(worker.is_alive())


@unittest.skipUnless(_INSTALL_DIR or _REQUIRE_SHARED_SERVICE,
                     "set BINARYRAT_GHIDRA_INSTALL_DIR to run PyGhidra tests")
class LiveGhidraTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import pyghidra

        if _INSTALL_DIR is None:
            raise AssertionError("BINARYRAT_REQUIRE_SHARED_SERVICE needs BINARYRAT_GHIDRA_INSTALL_DIR")
        cls.install = Path(_INSTALL_DIR).resolve()
        pyghidra.start(install_dir=cls.install)
        from ghidra.app.util.opinion import BinaryLoader
        from ghidra.framework import Application
        from ghidra.program.flatapi import FlatProgramAPI
        from ghidra.program.model.data import (
            CategoryPath, DataTypeConflictHandler, IntegerDataType, StructureDataType,
        )
        from java.lang import Object

        if _REQUIRE_SHARED_SERVICE and Application.getModuleRootDir("BinaryRat") is None:
            raise AssertionError("the bundled Ghidra installation must supply the BinaryRat extension")
        temporary = TemporaryDirectory(prefix="binaryrat-live-")
        cls.addClassCleanup(temporary.cleanup)
        cls.marker = Path(temporary.name) / "fixture.gpr"
        cls.program_path = "/program"
        # call next function; ret; mov eax, 42; ret
        image = bytes.fromhex("e801000000 c3 b82a000000 c3")
        input_file = cls.marker.with_suffix(".raw")
        input_file.write_bytes(image)
        with ExitStack() as cleanup:
            project = pyghidra.open_project(cls.marker.parent, cls.marker.stem, create=True)
            cleanup.callback(project.close)
            results = (pyghidra.program_loader().source(str(input_file)).name("program")
                       .loaders(BinaryLoader.class_).language("x86:LE:64:default")
                       .project(project).projectFolderPath("/").load())
            cleanup.callback(results.close)
            consumer = Object()
            program = results.getPrimaryDomainObject(consumer)
            cleanup.callback(program.release, consumer)
            flat = FlatProgramAPI(program)
            entry = program.getMinAddress()
            target = entry.add(6)
            cls.entry = Address("ram", int(entry.getOffset()))
            cls.target = Address("ram", int(target.getOffset()))
            with pyghidra.transaction(program, "Create bounded test fixture"):
                if not flat.disassemble(entry):
                    raise AssertionError("test fixture did not disassemble")
                if flat.getInstructionAt(target) is None and not flat.disassemble(target):
                    raise AssertionError("test fixture callee did not disassemble")
                if not flat.createFunction(entry, "dispatch") or not flat.createFunction(target, "answer"):
                    raise AssertionError("test fixture functions were not created")
                structure = StructureDataType(CategoryPath("/fixtures"), "Record", 0)
                structure.add(IntegerDataType.dataType, "value", None)
                program.getDataTypeManager().addDataType(
                    structure, DataTypeConflictHandler.DEFAULT_HANDLER
                )
            results.save(pyghidra.task_monitor())

        # reader: mov eax,[rdi+4]; ret
        # holder: sub rsp,8; add rdi,16; call reader; add rsp,8; ret
        # walker, as gcc -O0 emits it: the argument is reloaded into RDI before the self call,
        # so the decompiler shows walker(param_1). (A pass-through RDI shows walker().)
        cls.layout_path = "/layout"
        layout_image = bytes.fromhex(
            "8b4704 c3"
            "4883ec08 4883c710 e8efffffff 4883c408 c3"
            "55 4889e5 4883ec10 48897df8 488b45f8 8b4008 85c0 740d 488b45f8 4889c7 e8ddffffff 90 c9 c3"
        )
        layout_file = cls.marker.with_name("layout.raw")
        layout_file.write_bytes(layout_image)
        with ExitStack() as cleanup:
            project = pyghidra.open_project(cls.marker.parent, cls.marker.stem)
            cleanup.callback(project.close)
            # gcc (SysV): the first pointer argument is RDI, as the bytes above assume.
            results = (pyghidra.program_loader().source(str(layout_file)).name("layout")
                       .loaders(BinaryLoader.class_).language("x86:LE:64:default").compiler("gcc")
                       .project(project).projectFolderPath("/").load())
            cleanup.callback(results.close)
            consumer = Object()
            program = results.getPrimaryDomainObject(consumer)
            cleanup.callback(program.release, consumer)
            flat = FlatProgramAPI(program)
            base = program.getMinAddress()
            entries = {"reader": base, "holder": base.add(4), "walker": base.add(22)}
            cls.reader, cls.holder, cls.walker = (
                Address("ram", int(entries[name].getOffset())) for name in ("reader", "holder", "walker"))
            cls.holder_call = Address("ram", cls.holder.offset + 8)
            with pyghidra.transaction(program, "Create summary layout fixture"):
                for name, entry in entries.items():
                    if flat.getInstructionAt(entry) is None and not flat.disassemble(entry):
                        raise AssertionError(f"layout fixture {name} did not disassemble")
                    if not flat.createFunction(entry, name):
                        raise AssertionError(f"layout fixture {name} was not created")
            results.save(pyghidra.task_monitor())

        # builds_text: push rbp; mov rbp,rsp; mov dword [rbp-8], "live"; mov byte [rbp-4], 0;
        # pop rbp; ret. Ghidra's stack analysis puts [rbp-8] at stack offset -0x10.
        from ghidra.app.cmd.function import NewFunctionStackAnalysisCmd

        cls.strings_path = "/strings"
        strings_file = cls.marker.with_name("strings.raw")
        strings_file.write_bytes(bytes.fromhex("554889e5 c745f86c697665 c645fc00 5dc3"))
        with ExitStack() as cleanup:
            project = pyghidra.open_project(cls.marker.parent, cls.marker.stem)
            cleanup.callback(project.close)
            results = (pyghidra.program_loader().source(str(strings_file)).name("strings")
                       .loaders(BinaryLoader.class_).language("x86:LE:64:default").compiler("gcc")
                       .project(project).projectFolderPath("/").load())
            cleanup.callback(results.close)
            consumer = Object()
            program = results.getPrimaryDomainObject(consumer)
            cleanup.callback(program.release, consumer)
            flat = FlatProgramAPI(program)
            entry = program.getMinAddress()
            cls.strings_entry = Address("ram", int(entry.getOffset()))
            with pyghidra.transaction(program, "Create stack-string fixture"):
                if not flat.disassemble(entry) or not flat.createFunction(entry, "builds_text"):
                    raise AssertionError("stack-string fixture was not created")
                if not NewFunctionStackAnalysisCmd(entry, True).applyTo(program, pyghidra.task_monitor()):
                    raise AssertionError("stack-string fixture stack analysis failed")
            results.save(pyghidra.task_monitor())

    def snapshot(self):
        directory = self.marker.with_suffix(".rep")
        return {
            path.relative_to(directory): sha256(path.read_bytes()).hexdigest()
            for path in directory.rglob("*") if path.is_file()
        }

    def test_real_functions_references_types_and_decompiler(self):
        before = self.snapshot()
        with open_program(self.marker, self.program_path, install_dir=self.install) as view:
            underlying = view._program
            self.assertEqual(view.info.path, self.program_path)
            self.assertEqual(view.info.language_id, "x86:LE:64:default")
            first = view.functions(limit=1)
            second = view.functions(offset=first.next_offset, limit=1)
            self.assertEqual([item.name for item in first.items + second.items],
                             ["dispatch", "answer"])
            self.assertEqual(first.next_offset, 1)
            self.assertIsNone(second.next_offset)
            self.assertEqual(view.functions(offset=500), Page((), None))
            self.assertEqual(view.function_at(self.entry), first.items[0])
            self.assertIsNone(view.function_at(Address("ram", self.entry.offset + 1)))
            # The call instruction's interior and the next instruction belong to dispatch.
            for interior in (1, 5):
                self.assertEqual(view.function_containing(Address("ram", self.entry.offset + interior)),
                                 first.items[0])
            self.assertIsNone(view.function_containing(Address("ram", self.entry.offset + 0x100000)))
            self.assertEqual(view.functions_named("answer"), Page(second.items, None))
            self.assertEqual(view.functions_named("answer", limit=1), Page(second.items, None))
            self.assertEqual(view.functions_named("missing"), Page((), None))
            for bad in ("", "a" * 2001, "x\n", "ns::"):
                with self.subTest(name=bad), self.assertRaises(ValueError):
                    view.functions_named(bad)

            outgoing = view.xrefs_from(self.entry)
            incoming = view.xrefs_to(self.target)
            self.assertEqual(outgoing.items, incoming.items)
            self.assertEqual(len(incoming.items), 1)
            self.assertEqual(incoming.items[0].target, self.target)
            self.assertIn("CALL", incoming.items[0].type_name)

            record = view.data_type("/fixtures", "Record")
            self.assertEqual(record.length, 4)
            self.assertIn(record, view.data_types().items)
            self.assertIsNone(view.data_type("/fixtures", "unknown"))

            result = view.decompile(self.target)
            self.assertTrue(result.successful, result.error)
            self.assertRegex(result.c, r"return\s+(0x2a|42);")
            self.assertEqual(result.revision, view.info.revision)

        self.assertEqual(before, self.snapshot(), "opening for inspection modified project storage")
        self.assertTrue(underlying.isClosed(), "releasing the view left its Program open")
        self.assertEqual(first.items[0].name, "dispatch")
        with self.assertRaisesRegex(LiveProgramError, "closed"):
            view.functions()

    def test_missing_read_and_failed_open_do_not_leak(self):
        with self.assertRaises(FileNotFoundError), open_program(self.marker, "/missing"):
            pass
        with self.assertRaisesRegex(RuntimeError, "stop inspection"):
            with open_program(self.marker, self.program_path) as view:
                raise RuntimeError("stop inspection")
        with self.assertRaisesRegex(LiveProgramError, "closed"):
            view.data_types()
        with open_program(self.marker, self.program_path) as reopened:
            self.assertEqual(reopened.function_at(self.target).name, "answer")

    def test_cancelled_and_stale_reads_fail_closed(self):
        import pyghidra
        from ghidra.program.model.symbol import SourceType

        cancellation = Event()
        before = self.snapshot()
        with open_program(self.marker, self.program_path, cancel=cancellation) as view:
            cancellation.set()
            with self.assertRaises(CancelledError):
                view.xrefs_from(self.entry)
            cancellation.clear()
            # A temporary read-only DomainObject can still be edited in memory.
            # Inject a write through the private test handle to check the read guard.
            with self.assertRaises(StaleProgramError), view._read() as program:
                with pyghidra.transaction(program, "Inject an in-memory change"):
                    manager = program.getFunctionManager()
                    address = view._native_address(program, self.target)
                    manager.getFunctionAt(address).setName("changed", SourceType.USER_DEFINED)
            with self.assertRaises(StaleProgramError):
                view.functions()
        self.assertEqual(before, self.snapshot())

    def test_monitor_forwards_cancellation_and_joins_its_thread(self):
        cancellation = Event()
        with _monitor(cancellation) as monitor:
            cancellation.set()
            deadline = monotonic() + 2
            while not monitor.isCancelled() and monotonic() < deadline:
                sleep(0.01)
            self.assertTrue(monitor.isCancelled())
        self.assertFalse(any(thread.name == "binaryrat-live-cancel" for thread in active_threads()))

    def test_monitor_cancels_at_the_scan_deadline(self):
        with _monitor(None, monotonic() + 0.05) as monitor:
            grace = monotonic() + 2
            while not monitor.isCancelled() and monotonic() < grace:
                sleep(0.01)
            self.assertTrue(monitor.isCancelled())
        self.assertFalse(any(thread.name == "binaryrat-live-cancel" for thread in active_threads()))

    def test_incomplete_shared_project_is_rejected(self):
        from ghidra.framework.data import DefaultProjectData
        from ghidra.util import PropertyFile
        from java.io import File

        with TemporaryDirectory(prefix="binaryrat-shared-") as temp:
            marker = Path(temp) / self.marker.name
            shutil.copyfile(self.marker, marker)
            folder = marker.with_suffix(".rep")
            shutil.copytree(self.marker.with_suffix(".rep"), folder)
            properties = PropertyFile(File(str(folder)), "project")
            properties.putString(DefaultProjectData.SERVER_NAME, "127.0.0.1")
            properties.writeState()
            with self.assertRaisesRegex(LiveProgramError, "local Ghidra project"):
                with open_program(marker, self.program_path):
                    self.fail("opened a remote project")

    def test_bounds(self):
        with open_program(self.marker, self.program_path) as view:
            for options in (dict(offset=-1), dict(offset=100001), dict(limit=True), dict(limit=1001)):
                with self.subTest(options=options), self.assertRaises(ValueError):
                    view.functions(**options)
            with self.assertRaises(ValueError):
                view.function_at(Address("unknown", 0))
            with self.assertRaises(ValueError):
                view.function_at(Address("ram", 1 << 64))
            with self.assertRaises(ValueError):
                view.decompile(self.entry, timeout_seconds=0)
            with self.assertRaises(LookupError):
                view.decompile(Address("ram", self.entry.offset + 1))
            with patch("binaryrat.live._MAX_REFERENCES_FROM", 0):
                with self.assertRaisesRegex(LiveProgramError, "outgoing references exceed"):
                    view.xrefs_from(self.entry)
            with patch("binaryrat.live._MAX_TYPE_COUNT", 0):
                with self.assertRaisesRegex(LiveProgramError, "data type count exceeds"):
                    view.data_types()
                self.assertIsNotNone(view.data_type("/fixtures", "Record"))
            with self.assertRaisesRegex(ValueError, "incoming xrefs"):
                view.xrefs_to(Address("stack", 0))

    def test_native_reply_ceiling_and_cleanup(self):
        from java.lang import ProcessHandle

        def child_ids():
            with ProcessHandle.current().children() as children:
                return {int(child.pid()) for child in children.toArray() if child.isAlive()}

        with open_program(self.marker, self.program_path, backend="stock") as view:
            # A must-fail ceiling on the same stock decompiler proves the
            # option reached the process before its first response.
            with patch("binaryrat.live._DECOMPILER_PAYLOAD_MB", 0):
                with self.assertRaisesRegex(LiveProgramError, "Buffer size exceeded"):
                    view.decompile(self.target)
            before = child_ids()
            self.assertTrue(view.decompile(self.target).successful)
            started = child_ids() - before
            self.assertEqual(len(started), 1)
            for _ in range(5):
                self.assertTrue(view.decompile(self.target).successful)
                self.assertEqual(child_ids() - before, started)
        deadline = monotonic() + 5
        while child_ids() & started and monotonic() < deadline:
            sleep(0.01)
        self.assertFalse(child_ids() & started, "view close leaked a native decompiler")

    def test_cli_selects_functions_by_name_interior_address_or_listing(self):
        executable = shutil.which("binaryrat-decompile")
        base = [*([executable] if executable is not None else [sys.executable, "-m", "binaryrat.decompile_cli"]),
                str(self.marker), self.program_path]
        options = ["--install-dir", str(self.install), "--backend", "stock"]
        before = self.snapshot()
        with open_program(self.marker, self.program_path, backend="stock") as view:
            stock = view.decompile(self.target)

        def run(*arguments):
            return subprocess.run([*base, *arguments, *options], encoding="utf-8", capture_output=True,
                                  timeout=120)

        named = run("answer", "--json")
        self.assertEqual(named.returncode, 0, named.stderr)
        self.assertEqual(json.loads(named.stdout)["c"], stock.c)
        interior = run(f"{self.entry.space}:{self.entry.offset + 5:x}", "--json")
        self.assertEqual(interior.returncode, 0, interior.stderr)
        self.assertEqual(json.loads(interior.stdout)["function"]["name"], "dispatch")
        self.assertIn(f"is inside dispatch at {self.entry}", interior.stderr)
        listed = run("--list", "--match", "ANS")
        self.assertEqual(listed.returncode, 0, listed.stderr)
        self.assertEqual(listed.stdout.splitlines(), [f"{self.target}  {stock.function.signature}"])
        missing = run("missing")
        self.assertEqual(missing.returncode, 2)
        self.assertIn('no function named "missing"', missing.stderr)
        self.assertEqual(before, self.snapshot())

    def test_scheduled_backend_is_shared_with_the_cli(self):
        from ghidra.framework import Application

        if Application.getModuleRootDir("BinaryRat") is None:
            with self.assertRaisesRegex(LiveProgramError, "requires the BinaryRat extension"):
                with open_program(self.marker, self.program_path, backend="scheduled"):
                    self.fail("opened a scheduled view without its extension")
            self.skipTest("live scheduled checks require the BinaryRat extension")
        before = self.snapshot()
        with open_program(self.marker, self.program_path, backend="stock") as view:
            stock = view.decompile(self.target)
        with open_program(self.marker, self.program_path) as view:
            self.assertEqual(view.decompilation_backend, "scheduled")
            self.assertEqual(view.decompile(self.target), stock)
            session = view._scheduled_session
            self.assertIsNotNone(session)
            self.assertEqual(view.decompile(self.target), stock)
            self.assertIs(view._scheduled_session, session)
            self.assertEqual(view.decompile(self.target, timeout_seconds=45), stock)
            self.assertIsNot(view._scheduled_session, session)
        self.assertIsNone(view._scheduled_session)
        with TemporaryDirectory(prefix="binaryrat scheduled cache ") as directory:
            environment = {
                key: value for key, value in os.environ.items()
                if key not in ("BINARYRAT_ENGINE", "BINARYRAT_CACHE_DIR")
            }
            environment["BINARYRAT_CACHE_DIR"] = directory
            executable = shutil.which("binaryrat-decompile")
            if _REQUIRE_SHARED_SERVICE:
                self.assertIsNotNone(executable, "install the BinaryRat wheel to test its CLI")
            command = [
                *([executable] if executable is not None else [sys.executable, "-m", "binaryrat.decompile_cli"]),
                str(self.marker),
                self.program_path, str(self.target), "--install-dir", str(self.install), "--json",
            ]
            for cache_status in ("miss", "replayed"):
                reply = subprocess.run(command, env=environment, encoding="utf-8", capture_output=True,
                                       timeout=90)
                self.assertEqual(reply.returncode, 0, reply.stderr)
                result = json.loads(reply.stdout)
                self.assertEqual(result["backend"], "scheduled")
                self.assertEqual(result["cache_status"], cache_status)
                self.assertEqual(result["c"], stock.c)
                self.assertEqual(result["prototype"], stock.prototype)
            self.assertTrue(any(path.is_file() for path in Path(directory).rglob("*")),
                            "the scheduled CLI did not use the configured cache directory")
            environment["BINARYRAT_ENGINE"] = str(Path(directory) / "missing-engine")
            failed = subprocess.run(command, env=environment, encoding="utf-8", capture_output=True, timeout=90)
            self.assertEqual(failed.returncode, 2)
            self.assertIn("BinaryRat scheduled decompilation failed", failed.stderr)
            self.assertFalse(failed.stdout.strip(), "scheduled failure produced an apparent stock result")
        self.assertEqual(before, self.snapshot())

    def test_instruction_pcode_is_scoped_read_only_and_cancellable(self):
        import pyghidra
        from ghidra.framework import Application
        from ghidra.program.model.listing import FlowOverride
        from ghidra.program.model.pcode import PcodeOp
        from ghidra.util.exception import CancelledException
        from ghidra.util.task import TaskMonitor, TaskMonitorAdapter
        from java.io import IOException
        from jpype import JClass

        if Application.getModuleRootDir("BinaryRat") is None:
            self.skipTest("instruction p-code checks require the BinaryRat extension")
        read = JClass("binaryrat.desktop.InstructionPcode").read
        before = self.snapshot()
        with open_program(self.marker, self.program_path, backend="stock") as view:
            program = view._program
            entry = view._native_address(program, self.entry)
            target = view._native_address(program, self.target)
            revision = program.getModificationNumber()
            snapshot = read(program, entry, entry.add(2), revision, TaskMonitor.DUMMY)
            self.assertEqual(snapshot.instructionAddress(), entry)
            self.assertIn("CALL", str(snapshot.instruction()).upper())
            operations = list(map(str, snapshot.operations()))
            self.assertTrue(any(line.startswith("CALL ") for line in operations), operations)
            self.assertFalse(snapshot.truncated())
            self.assertEqual(read(program, entry, entry, revision, TaskMonitor.DUMMY), snapshot)
            for offset in Random(0xB17).sample(range(6, 1024), 64):
                with self.subTest(offset=offset), self.assertRaisesRegex(IOException, "outside"):
                    read(program, entry, entry.add(offset), revision, TaskMonitor.DUMMY)
            with self.assertRaisesRegex(IOException, "outside"):
                read(program, target, entry, revision, TaskMonitor.DUMMY)
            constant = program.getAddressFactory().getConstantSpace().getAddress(1)
            with self.assertRaisesRegex(IOException, "memory"):
                read(program, entry, constant, revision, TaskMonitor.DUMMY)
            with self.assertRaisesRegex(IOException, "changed"):
                read(program, entry, entry, revision - 1, TaskMonitor.DUMMY)
            with pyghidra.transaction(program, "Busy Program test"):
                with self.assertRaisesRegex(IOException, "finish"):
                    read(program, entry, entry, revision, TaskMonitor.DUMMY)
            cancelled = TaskMonitorAdapter(True)
            cancelled.cancel()
            with self.assertRaises(CancelledException):
                read(program, entry, entry, program.getModificationNumber(), cancelled)
            with pyghidra.transaction(program, "Set a temporary branch override"):
                instruction = program.getListing().getInstructionAt(entry)
                instruction.setFlowOverride(FlowOverride.BRANCH)
            self.assertNotIn(PcodeOp.CALL, [op.getOpcode() for op in instruction.getPcode(True)])
            raw = read(program, entry, entry, program.getModificationNumber(), TaskMonitor.DUMMY)
            self.assertEqual(list(map(str, raw.operations())), operations)
            self.assertEqual(list(snapshot.overridden()), [])
            overridden = list(map(str, raw.overridden()))
            self.assertTrue(any(line.startswith("BRANCH ") for line in overridden), overridden)
            self.assertFalse(any(line.startswith("CALL ") for line in overridden), overridden)
            self.assertEqual(list(map(str, raw.notes())), ["Flow override: BRANCH"])
        self.assertEqual(before, self.snapshot())

    def test_instruction_pcode_preserves_the_program_overlay(self):
        import pyghidra
        from ghidra.framework import Application
        from ghidra.program.database import ProgramDB
        from ghidra.program.flatapi import FlatProgramAPI
        from ghidra.util.task import TaskMonitor
        from java.io import IOException
        from java.lang import Object
        from jpype import JArray, JByte, JClass

        if Application.getModuleRootDir("BinaryRat") is None:
            self.skipTest("instruction p-code checks require the BinaryRat extension")
        read = JClass("binaryrat.desktop.InstructionPcode").read
        with open_program(self.marker, self.program_path, backend="stock") as template:
            language = template._program.getLanguage()
            spec_id = template._program.getCompilerSpec().getCompilerSpecID()
        spec = language.getCompilerSpecByID(spec_id)
        consumer = Object()
        with ExitStack() as cleanup:
            overlays = []
            for label in ("local", "foreign"):
                program = ProgramDB(label, language, spec, consumer)
                cleanup.callback(program.release, consumer)
                flat = FlatProgramAPI(program)
                with pyghidra.transaction(program, "Create overlay fixture"):
                    start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000)
                    block = flat.createMemoryBlock("mirror", start, JArray(JByte)([-61]), True)
                    overlay = block.getStart()
                    self.assertTrue(flat.disassemble(overlay))
                    self.assertIsNotNone(flat.createFunction(overlay, "overlay_return"))
                overlays.append((program, overlay))
            local, local_entry = overlays[0]
            foreign_entry = overlays[1][1]
            self.assertEqual(local_entry, foreign_entry)
            snapshot = read(local, local_entry, local_entry, local.getModificationNumber(),
                            TaskMonitor.DUMMY)
            self.assertTrue(snapshot.instructionAddress().getAddressSpace().isOverlaySpace())
            self.assertEqual(snapshot.instructionAddress(), local_entry)
            self.assertTrue(any(str(operation).startswith("RETURN ")
                                for operation in snapshot.operations()))
            with self.assertRaisesRegex(IOException, "memory"):
                read(local, local_entry, foreign_entry, local.getModificationNumber(),
                     TaskMonitor.DUMMY)

    def test_foreground_adapter_reads_a_live_program_with_unsaved_metadata(self):
        import pyghidra
        from ghidra.framework import Application
        from ghidra.program.model.symbol import SourceType
        from javax.swing import SwingUtilities
        from jpype import JProxy

        if Application.getModuleRootDir("BinaryRat") is None:
            self.skipTest("live foreground checks require the BinaryRat extension")
        before = self.snapshot()
        with open_program(self.marker, self.program_path, backend="stock") as view:
            program = view._program
            entry = view._native_address(program, self.target)
            with pyghidra.transaction(program, "Rename a function in memory"):
                function = program.getFunctionManager().getFunctionAt(entry)
                function.setName("live_answer", SourceType.USER_DEFINED)
            run = decompile_program(program, self.target)
            self.assertEqual(run.backend, "scheduled")
            self.assertTrue(run.result.successful, run.result.error)
            self.assertEqual(run.result.function.name, "live_answer")
            self.assertFalse(program.isClosed(), "exiting the adapter closed its caller's Program")
            blocked = []

            def read_on_edt():
                try:
                    decompile_program(program, self.target)
                except LiveProgramError as error:
                    blocked.append(str(error))

            SwingUtilities.invokeAndWait(JProxy("java.lang.Runnable", dict(run=read_on_edt)))
            self.assertEqual(blocked, ["decompile_program must run off the Ghidra UI thread"])
        self.assertTrue(program.isClosed(), "the adapter left a consumer on the Program")
        with self.assertRaisesRegex(LiveProgramError, "closed"):
            decompile_program(program, self.target)
        self.assertEqual(before, self.snapshot())
        with open_program(self.marker, self.program_path, backend="stock") as view:
            self.assertEqual(view.function_at(self.target).name, "answer")

    def test_summary_layouts_through_the_shared_service(self):
        from ghidra.framework import Application

        before = self.snapshot()
        if Application.getModuleRootDir("BinaryRat") is None:
            with open_program(self.marker, self.layout_path) as view:
                with self.assertRaisesRegex(LiveProgramError, "require the BinaryRat extension"):
                    view.solve_layout(self.holder)
            self.skipTest("summary layouts require the BinaryRat extension")
        with open_program(self.marker, self.layout_path) as view:
            report = view.solve_layout(self.holder)
            self.assertEqual((report.function, report.revision), (self.holder, view.info.revision))
            self.assertEqual([(item.offset, item.width) for item in report.fields], [(20, 4)])
            self.assertTrue(report.complete)
            reached = next(index for index, state in enumerate(report.states)
                           if report.summary(state.summary).function == self.reader)
            self.assertEqual([(edge.offset, edge.site) for edge in report.call_path(reached)],
                             [(16, self.holder_call)])
            walk = view.solve_layout(self.walker)
            self.assertEqual([(item.consistent, len(item.summaries)) for item in walk.components], [(True, 1)])
            self.assertEqual([(item.offset, item.width) for item in walk.fields], [(8, 4)])
            self.assertTrue(walk.complete)
            with self.assertRaisesRegex(LayoutRecoveryError, "summary layout failed"):
                view.solve_layout(self.holder, 5)
            for bad in (dict(max_summaries=0), dict(max_summaries=257), dict(timeout_seconds=601),
                        dict(parameter_index=-1), dict(parameter_index=True)):
                with self.subTest(bad=bad), self.assertRaises(ValueError):
                    view.solve_layout(self.holder, **bad)
            with self.assertRaises(LookupError):
                view.solve_layout(Address("ram", self.holder.offset + 1))
        self.assertEqual(before, self.snapshot())

        executable = shutil.which("binaryrat-live")
        runner = [executable] if executable is not None else [sys.executable, "-m", "binaryrat.live_service"]
        process = subprocess.Popen(
            [*runner, str(self.marker), self.layout_path, "--install-dir", str(self.install),
             "--idle-timeout", "30", "--max-heap-mb", "512"],
            stdout=subprocess.PIPE, text=True, encoding="utf-8",
        )
        try:
            line = process.stdout.readline()
            while line and not line.startswith(READY_PREFIX):
                line = process.stdout.readline()
            client = LiveClient(LiveEndpoint.from_ready_line(line), timeout=300)
            self.assertEqual(client.solve_layout(self.holder), report)
            self.assertEqual(client.solve_layout(self.walker, max_summaries=4), walk)
            with self.assertRaisesRegex(LiveRequestError, "layout_failed"):
                client.solve_layout(self.holder, 5)
            for bad in (dict(max_summaries=65), dict(timeout_seconds=61), dict(max_summaries="8")):
                with self.subTest(bad=bad), self.assertRaisesRegex(LiveRequestError, "bad_request"):
                    client.solve_layout(self.holder, **bad)
            with self.assertRaisesRegex(LiveRequestError, "bad_request"):
                client._request("solve_layout", entry=dict(space="ram", offset=self.holder.offset),
                                follow_depth=4)
            with self.assertRaisesRegex(LiveRequestError, "not_found"):
                client.solve_layout(Address("ram", self.holder.offset + 1))
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            process.stdout.close()
        self.assertEqual(before, self.snapshot())

    def test_call_sites_through_the_shared_service(self):
        from ghidra.framework import Application

        before = self.snapshot()
        if Application.getModuleRootDir("BinaryRat") is None:
            with open_program(self.marker, self.program_path) as view:
                with self.assertRaisesRegex(LiveProgramError, "require the BinaryRat extension"):
                    view.call_sites(self.target)
            self.skipTest("call sites require the BinaryRat extension")
        with open_program(self.marker, self.program_path) as view:
            report = view.call_sites(self.target)
            self.assertEqual((report.root_function, report.revision), (self.target, view.info.revision))
            self.assertEqual([(site.site, site.caller, site.status) for site in report.sites],
                             [(self.entry, self.entry, "decompiled")])
            self.assertIn("answer(", report.sites[0].statement)
            self.assertEqual((report.decompiled_callers, report.truncated), (1, False))
            uncalled = view.call_sites(self.entry)
            self.assertEqual((uncalled.sites, uncalled.decompiled_callers), ((), 0))
            for bad in (dict(max_sites=0), dict(max_sites=1025), dict(max_callers=0), dict(max_callers=257),
                        dict(timeout_seconds=601), dict(max_sites=True), dict(timeout_seconds="30")):
                with self.subTest(bad=bad), self.assertRaises(ValueError):
                    view.call_sites(self.target, **bad)
            with self.assertRaises(LookupError):
                view.call_sites(Address("ram", self.target.offset + 1))
        with open_program(self.marker, self.layout_path) as view:
            read = view.call_sites(self.reader)
            self.assertEqual([(site.site, site.caller) for site in read.sites], [(self.holder_call, self.holder)])
            walk = view.call_sites(self.walker)
            self.assertEqual([(site.caller, site.status) for site in walk.sites], [(self.walker, "decompiled")])
            self.assertEqual([argument.render() for argument in walk.sites[0].arguments], ["param_1"])
        self.assertEqual(before, self.snapshot())

        executable = shutil.which("binaryrat-decompile")
        program = [*([executable] if executable is not None else [sys.executable, "-m", "binaryrat.decompile_cli"]),
                   str(self.marker), self.program_path]
        options = ["--call-sites", "--install-dir", str(self.install)]
        command = [*program, "answer", *options]
        listed = subprocess.run(command, encoding="utf-8", capture_output=True, timeout=180)
        self.assertEqual(listed.returncode, 0, listed.stderr)
        self.assertEqual(listed.stdout.splitlines()[0], f"Calls to answer at {self.target}: 1 site in 1 caller")
        as_json = subprocess.run([*command, "--json"], encoding="utf-8", capture_output=True, timeout=180)
        self.assertEqual(as_json.returncode, 0, as_json.stderr)
        self.assertEqual(json.loads(as_json.stdout), report.document)
        none = subprocess.run([*program, "dispatch", *options], encoding="utf-8", capture_output=True,
                              timeout=180)
        self.assertEqual(none.returncode, 1, none.stderr)
        self.assertEqual(before, self.snapshot())

        runner = [shutil.which("binaryrat-live") or sys.executable]
        if runner[0] == sys.executable:
            runner.extend(["-m", "binaryrat.live_service"])
        process = subprocess.Popen(
            [*runner, str(self.marker), self.program_path, "--install-dir", str(self.install),
             "--idle-timeout", "30", "--max-heap-mb", "512"],
            stdout=subprocess.PIPE, text=True, encoding="utf-8",
        )
        try:
            line = process.stdout.readline()
            while line and not line.startswith(READY_PREFIX):
                line = process.stdout.readline()
            client = LiveClient(LiveEndpoint.from_ready_line(line), timeout=300)
            self.assertEqual(client.call_sites(self.target), report)
            for bad in (dict(max_sites=257), dict(max_callers=65), dict(timeout_seconds=61), dict(max_sites="8")):
                with self.subTest(bad=bad), self.assertRaisesRegex(LiveRequestError, "bad_request"):
                    client.call_sites(self.target, **bad)
            with self.assertRaisesRegex(LiveRequestError, "bad_request"):
                client._request("call_sites", entry=dict(space="ram", offset=self.target.offset), depth=2)
            with self.assertRaisesRegex(LiveRequestError, "not_found"):
                client.call_sites(Address("ram", self.target.offset + 1))
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            process.stdout.close()
        self.assertEqual(before, self.snapshot())

    def test_names_holding_scope_marks_and_a_project_java_cannot_open(self):
        import pyghidra
        from ghidra.app.util.opinion import BinaryLoader
        from ghidra.program.flatapi import FlatProgramAPI
        from java.lang import Object

        # Ghidra keeps a buffer file it could not read open until the JVM collects it.
        with TemporaryDirectory(ignore_cleanup_errors=True) as root:
            marker = Path(root) / "names.gpr"
            raw = marker.with_suffix(".raw")
            raw.write_bytes(bytes.fromhex("c3c3"))
            with ExitStack() as cleanup:
                project = pyghidra.open_project(marker.parent, marker.stem, create=True)
                cleanup.callback(project.close)
                results = (pyghidra.program_loader().source(str(raw)).name("named")
                           .loaders(BinaryLoader.class_).language("x86:LE:64:default")
                           .project(project).projectFolderPath("/").load())
                cleanup.callback(results.close)
                consumer = Object()
                program = results.getPrimaryDomainObject(consumer)
                cleanup.callback(program.release, consumer)
                flat = FlatProgramAPI(program)
                with pyghidra.transaction(program, "Name functions as a C++ demangler does"):
                    for offset, name in ((0, "make<ns::Item>"), (1, "pair<a::b,c::d>")):
                        entry = program.getMinAddress().add(offset)
                        if flat.getInstructionAt(entry) is None and not flat.disassemble(entry):
                            raise AssertionError("name fixture did not disassemble")
                        function = flat.createFunction(entry, name)
                        if function is None:
                            raise AssertionError("name fixture function was not created")
                    function.setParentNamespace(flat.createNamespace(None, "outer"))
                results.save(pyghidra.task_monitor())

            with open_program(marker, "/named", install_dir=self.install) as view:
                # The whole name is the symbol; it is not split at the "::" inside it.
                plain = view.functions_named("make<ns::Item>")
                self.assertEqual([(item.name, item.entry.offset) for item in plain.items],
                                 [("make<ns::Item>", 0)])
                scoped = view.functions_named("outer::pair<a::b,c::d>")
                self.assertEqual([(item.qualified_name, item.entry.offset) for item in scoped.items],
                                 [("outer::pair<a::b,c::d>", 1)])
                self.assertEqual(view.functions_named("pair<a::b,c::d>"), scoped)
                for partial in ("Item>", "ns::Item>", "c::d>", "outer::make<ns::Item>"):
                    self.assertEqual(view.functions_named(partial), Page((), None), partial)
                self.assertEqual(_resolve(view, _parse_function("name:make<ns::Item>")).entry.offset, 0)

            # A Program whose database Java cannot read is one clear error, in the API and the CLI.
            databases = list(marker.with_suffix(".rep").rglob("*.gbf"))
            self.assertTrue(databases)
            for database in databases:
                database.write_bytes(b"not a Ghidra buffer file")
            with self.assertRaisesRegex(LiveProgramError, "Could not open /named"):
                with open_program(marker, "/named", install_dir=self.install):
                    self.fail("a damaged Program opened")
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                status = decompile_main([str(marker), "/named", "name:make<ns::Item>", "--backend", "stock",
                                         "--install-dir", str(self.install), "--max-heap-mb", "1048576"])
            self.assertEqual(status, 2)
            self.assertIn("binaryrat-decompile: Could not open /named", stderr.getvalue())

    def test_stack_strings_through_the_shared_service(self):
        from ghidra.framework import Application

        before = self.snapshot()
        if Application.getModuleRootDir("BinaryRat") is None:
            with open_program(self.marker, self.strings_path) as view:
                with self.assertRaisesRegex(LiveProgramError, "require the BinaryRat extension"):
                    view.stack_strings()
            self.skipTest("stack strings require the BinaryRat extension")
        with open_program(self.marker, self.strings_path) as view:
            whole = view.stack_strings(max_functions=32, timeout_seconds=30)
            self.assertEqual((whole.revision, whole.functions_scanned), (view.info.revision, 1))
            self.assertEqual([(item.function, item.stack_offset, item.text, item.terminated, item.render())
                              for item in whole.strings], [(self.strings_entry, -16, "live", True, '"live"')])
            one = view.stack_strings(self.strings_entry, timeout_seconds=30)
            self.assertEqual((one.function, one.strings), (self.strings_entry, whole.strings))
            one_for_client = view.stack_strings(self.strings_entry, max_functions=32, timeout_seconds=30)
            self.assertEqual(view.stack_strings(minimum_length=5).strings, ())
            for bad in (dict(minimum_length=0), dict(minimum_length=65), dict(max_functions=0),
                        dict(max_functions=200_001), dict(minimum_length=True), dict(timeout_seconds=0),
                        dict(timeout_seconds=61), dict(timeout_seconds=True)):
                with self.subTest(bad=bad), self.assertRaises(ValueError):
                    view.stack_strings(**bad)
            with patch("binaryrat.live.monotonic", side_effect=(0, 2)):
                with self.assertRaisesRegex(TimeoutError, "stack-string scan timed out"):
                    view.stack_strings(timeout_seconds=1)
            with self.assertRaises(LookupError):
                view.stack_strings(Address("ram", self.strings_entry.offset + 1))
        with open_program(self.marker, self.program_path) as view:
            self.assertEqual(view.stack_strings().strings, ())
        self.assertEqual(before, self.snapshot())

        executable = shutil.which("binaryrat-decompile")
        base = [*([executable] if executable is not None else [sys.executable, "-m", "binaryrat.decompile_cli"]),
                str(self.marker)]
        options = ["--stack-strings", "--install-dir", str(self.install)]
        listed = subprocess.run([*base, self.strings_path, *options], encoding="utf-8", capture_output=True,
                                timeout=180)
        self.assertEqual(listed.returncode, 0, listed.stderr)
        self.assertEqual(listed.stdout.splitlines(), [
            "Stack strings in 1 function: 1", f'{Address("ram", self.strings_entry.offset + 4)}  builds_text  stack -0x10  "live"'])
        as_json = subprocess.run([*base, self.strings_path, "builds_text", *options, "--json"], encoding="utf-8",
                                 capture_output=True, timeout=180)
        self.assertEqual(as_json.returncode, 0, as_json.stderr)
        self.assertEqual(json.loads(as_json.stdout), one.document)
        empty = subprocess.run([*base, self.program_path, *options], encoding="utf-8", capture_output=True,
                               timeout=180)
        self.assertEqual(empty.returncode, 1, empty.stderr)
        self.assertEqual(before, self.snapshot())

        executable = shutil.which("binaryrat-live")
        runner = [executable] if executable is not None else [sys.executable, "-m", "binaryrat.live_service"]
        process = subprocess.Popen(
            [*runner, str(self.marker), self.strings_path, "--install-dir", str(self.install),
             "--idle-timeout", "30", "--max-heap-mb", "512"],
            stdout=subprocess.PIPE, text=True, encoding="utf-8",
        )
        ready = Queue(1)

        def read_until_ready():
            for line in process.stdout:
                if line.startswith(READY_PREFIX):
                    ready.put(line)
                    return
            ready.put("")

        reader = Thread(target=read_until_ready, daemon=True)
        reader.start()
        try:
            client = LiveClient(LiveEndpoint.from_ready_line(ready.get(timeout=90)))
            self.assertEqual(client.stack_strings(), whole)
            self.assertEqual(client.stack_strings(self.strings_entry), one_for_client)
            self.assertEqual(client.stack_strings(minimum_length=5).strings, ())
            with self.assertRaisesRegex(LiveRequestError, "not_found"):
                client.stack_strings(Address("ram", self.strings_entry.offset + 1))
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            reader.join(5)
            process.stdout.close()
        self.assertEqual(before, self.snapshot())

    def test_live_service_reuses_jvm_across_independent_clients(self):
        from ghidra.framework import Application

        before = self.snapshot()
        executable = shutil.which("binaryrat-live")
        if _REQUIRE_SHARED_SERVICE:
            self.assertIsNotNone(executable, "install the BinaryRat wheel to test its live command")
        runner = [executable] if executable is not None else [sys.executable, "-m", "binaryrat.live_service"]
        process = subprocess.Popen(
            [*runner, str(self.marker),
             self.program_path, "--install-dir", str(self.install), "--idle-timeout", "8",
             "--max-heap-mb", "512"],
            stdout=subprocess.PIPE, text=True, encoding="utf-8",
        )
        ready = Queue(1)

        def read_until_ready():
            for line in process.stdout:
                if line.startswith(READY_PREFIX):
                    ready.put(line)
                    return
            ready.put("")

        reader = Thread(target=read_until_ready, daemon=True)
        reader.start()
        try:
            ready_line = ready.get(timeout=90)
            endpoint = LiveEndpoint.from_ready_line(ready_line)
            expected = "stock" if Application.getModuleRootDir("BinaryRat") is None else "scheduled"
            self.assertEqual(endpoint.backend, expected)
            client = LiveClient(endpoint)
            self.assertEqual(client.info().path, self.program_path)
            first = client.functions(limit=1)
            self.assertEqual(first.items[0].entry, self.entry)
            self.assertEqual(first.next_offset, 1)
            self.assertEqual(client.xrefs_from(self.entry).items,
                             client.xrefs_to(self.target).items)
            self.assertEqual(client.data_type("/fixtures", "Record").length, 4)
            self.assertIn("Record", {item.name for item in client.data_types().items})

            # The secret goes through a private input pipe, never argv.
            second = subprocess.run(
                [sys.executable, "-c", """
from dataclasses import asdict
import json
import sys
from binaryrat import Address
from binaryrat.live_service import LiveClient, LiveEndpoint
client = LiveClient(LiveEndpoint.from_ready_line(sys.stdin.readline()))
print(json.dumps(asdict(client.decompile(Address('ram', int(sys.stdin.readline()))))))
"""], input=ready_line + str(self.target.offset) + "\n",
                text=True, encoding="utf-8", capture_output=True, timeout=20, check=True,
            )
            self.assertEqual(json.loads(second.stdout)["function"]["name"], "answer")
            self.assertTrue(json.loads(second.stdout)["completed"])
            self.assertIsNone(process.poll())

            unauthorized = LiveClient(LiveEndpoint(endpoint.port, secrets.token_urlsafe(32)))
            with self.assertRaisesRegex(LiveRequestError, "unauthorized"):
                unauthorized.info()
            with self.assertRaisesRegex(LiveRequestError, "bad_request"):
                client.decompile(self.target, timeout_seconds=61)
            with self.assertRaisesRegex(LiveRequestError, "offset_limit"):
                client.functions(offset=100001)
            with self.assertRaisesRegex(LiveRequestError, "bad_request"):
                client._request("open_program", project_file=str(self.marker))

            # An oversized packet gets a bounded error without closing the JVM.
            with socket.create_connection(("127.0.0.1", endpoint.port), 5) as sock:
                sock.sendall(b" " * (16 * 1024))
                with sock.makefile("rb") as stream:
                    self.assertEqual(json.loads(stream.readline()), {
                        "version": LIVE_PROTOCOL_VERSION, "error": "bad_request",
                    })
            self.assertEqual(client.function_at(self.target).name, "answer")
            self.assertEqual(process.wait(timeout=15), 0)
            self.assertEqual(before, self.snapshot())
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            reader.join(5)
            process.stdout.close()


if __name__ == "__main__":
    unittest.main()
