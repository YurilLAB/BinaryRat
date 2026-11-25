"""Recheck a portable summary against saved Ghidra Programs. Apache-2.0; Copyright 2026 YurilLAB."""

from contextlib import ExitStack, redirect_stderr, redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from binaryrat import Address, open_program
from binaryrat.layout_explain import main
from binaryrat.summary_review import make_review


_INSTALL = os.environ.get("BINARYRAT_GHIDRA_INSTALL_DIR")
_REQUIRED = os.environ.get("BINARYRAT_REQUIRE_SHARED_SERVICE") == "1"


@unittest.skipUnless(_INSTALL or _REQUIRED, "set BINARYRAT_GHIDRA_INSTALL_DIR for project review checks")
class ProjectReviewTests(unittest.TestCase):
    def test_project_check_regenerates_evidence_after_patching_program_bytes(self):
        import pyghidra

        self.assertTrue(_INSTALL, "the required project review check needs a Ghidra installation")
        pyghidra.start(install_dir=Path(_INSTALL).resolve())
        from ghidra.app.util.opinion import BinaryLoader
        from ghidra.framework import Application
        from ghidra.program.flatapi import FlatProgramAPI
        from java.lang import Object

        if Application.getModuleRootDir("BinaryRat") is None:
            if _REQUIRED:
                self.fail("the bundle must contain the BinaryRat summary solver")
            self.skipTest("project review recovery requires the BinaryRat extension")
        with TemporaryDirectory(prefix="binaryrat-review-") as folder:
            root = Path(folder)
            binary = root / "reader.raw"
            # SysV: mov eax,[rdi+4]; ret. Both Programs originate from the same input bytes.
            binary.write_bytes(bytes.fromhex("8b4704c3"))
            for name, displacement in (("first", 4), ("second", 8)):
                with ExitStack() as cleanup:
                    project = pyghidra.open_project(root, name, create=True)
                    cleanup.callback(project.close)
                    loaded = (pyghidra.program_loader().source(str(binary)).name("reader")
                              .loaders(BinaryLoader.class_).language("x86:LE:64:default").compiler("gcc")
                              .project(project).projectFolderPath("/").load())
                    cleanup.callback(loaded.close)
                    consumer = Object()
                    program = loaded.getPrimaryDomainObject(consumer)
                    cleanup.callback(program.release, consumer)
                    entry = program.getMinAddress()
                    flat = FlatProgramAPI(program)
                    with pyghidra.transaction(program, "Define the reader fixture"):
                        if displacement != 4:
                            program.getMemory().setByte(entry.add(2), displacement)
                        self.assertTrue(flat.disassemble(entry))
                        self.assertIsNotNone(flat.createFunction(entry, "reader"))
                    loaded.save(pyghidra.task_monitor())
            first = root / "first.gpr"
            second = root / "second.gpr"
            with open_program(first, "/reader") as view:
                captured = view.solve_layout(Address("ram", 0), max_summaries=3)
                self.assertEqual([(f.offset, f.width) for f in captured.fields], [(4, 4)])
            with open_program(second, "/reader") as view:
                changed = view.solve_layout(Address("ram", 0), max_summaries=3)
                self.assertEqual(changed.program_id, captured.program_id)
                self.assertEqual([(f.offset, f.width) for f in changed.fields], [(8, 4)])
            handoff = root / "handoff.json"
            handoff.write_text(make_review(captured), encoding="ascii")
            for project, status, kind in ((first, 0, "matched"), (second, 1, "changed")):
                output, errors = StringIO(), StringIO()
                with redirect_stdout(output), redirect_stderr(errors):
                    rc = main([str(handoff), "--check-project", str(project), "/reader", "--install-dir", _INSTALL])
                self.assertEqual(rc, status, (output.getvalue(), errors.getvalue()))
                result = json.loads(output.getvalue())
                self.assertEqual((result["status"], result["verification"]), (kind, "saved_program"))
                self.assertEqual(result["captured_revision"], captured.revision)


if __name__ == "__main__":
    unittest.main()
