"""Live Program facade tests. Apache-2.0; Copyright 2026 YurilLAB."""

from concurrent.futures import CancelledError
from contextlib import ExitStack
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
from unittest.mock import patch

from binaryrat import (
    Address, LayoutRecoveryError, LiveProgramError, Page, StaleProgramError, decompile_program,
    open_program,
)
from binaryrat.decompile_cli import _parse_entry
from binaryrat.live import ProgramView, _monitor
from binaryrat.live_service import (
    LIVE_PROTOCOL_VERSION,
    READY_PREFIX,
    LiveClient,
    LiveEndpoint,
    LiveProtocolError,
    LiveRequestError,
    _encode,
    _frame,
)


_INSTALL_DIR = os.environ.get("BINARYRAT_GHIDRA_INSTALL_DIR")
_REQUIRE_SHARED_SERVICE = os.environ.get("BINARYRAT_REQUIRE_SHARED_SERVICE") == "1"


class LiveProgramInputTests(unittest.TestCase):
    def test_cli_entry_parser_checks_unsigned_hex_and_preserves_space(self):
        from argparse import ArgumentTypeError

        self.assertEqual(_parse_entry("ram:0xffffffffffffffff"), ("ram", (1 << 64) - 1))
        self.assertEqual(_parse_entry("0A"), (None, 10))
        for bad in ("-1", "0x", "ram:", "ram:1:2", "ram:0x10000000000000000", "ram: 1"):
            with self.subTest(entry=bad), self.assertRaises(ArgumentTypeError):
                _parse_entry(bad)

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
            self.assertEqual(raw, snapshot)
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
