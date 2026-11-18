"""Live Program facade tests. Apache-2.0; Copyright 2026 YurilLAB."""

from concurrent.futures import CancelledError
from contextlib import ExitStack
from hashlib import sha256
import json
import os
from pathlib import Path
from queue import Queue
import secrets
import shutil
import socket
import subprocess
import sys
from threading import Event, Thread, enumerate as active_threads
from tempfile import TemporaryDirectory
from time import monotonic, sleep
import unittest
from unittest.mock import patch

from binaryrat import Address, LiveProgramError, Page, StaleProgramError, open_program
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


class LiveProgramInputTests(unittest.TestCase):
    def test_missing_project_and_invalid_domain_path(self):
        with TemporaryDirectory() as tmp:
            marker = Path(tmp) / "unknown.gpr"
            with self.assertRaises(FileNotFoundError), open_program(marker, "/program"):
                pass
            marker.touch()
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


@unittest.skipUnless(_INSTALL_DIR, "set BINARYRAT_GHIDRA_INSTALL_DIR to run PyGhidra tests")
class LiveGhidraTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import pyghidra

        cls.install = Path(_INSTALL_DIR).resolve()
        pyghidra.start(install_dir=cls.install)
        from ghidra.app.util.opinion import BinaryLoader
        from ghidra.program.flatapi import FlatProgramAPI
        from ghidra.program.model.data import (
            CategoryPath, DataTypeConflictHandler, IntegerDataType, StructureDataType,
        )
        from java.lang import Object

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

        with open_program(self.marker, self.program_path) as view:
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

    def test_live_service_reuses_jvm_across_independent_clients(self):
        before = self.snapshot()
        process = subprocess.Popen(
            [sys.executable, "-m", "binaryrat.live_service", str(self.marker),
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
