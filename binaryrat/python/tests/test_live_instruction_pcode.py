"""Structured instruction p-code from a real Listing. Apache-2.0; Copyright 2026 YurilLAB."""

from concurrent.futures import CancelledError
from contextlib import ExitStack
import os
from pathlib import Path
from random import Random
from tempfile import TemporaryDirectory
from threading import Event
import unittest
from unittest.mock import patch

from binaryrat import Address, LiveProgramError, PcodeVarnode, StaleProgramError, open_program
from binaryrat.live import _pcode_listing


_INSTALL = os.environ.get("BINARYRAT_GHIDRA_INSTALL_DIR")


@unittest.skipUnless(_INSTALL or os.environ.get("BINARYRAT_REQUIRE_SHARED_SERVICE") == "1",
                     "set BINARYRAT_GHIDRA_INSTALL_DIR for live p-code checks")
class InstructionPcodeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import pyghidra

        if not _INSTALL:
            raise AssertionError("required p-code checks need BINARYRAT_GHIDRA_INSTALL_DIR")
        pyghidra.start(install_dir=Path(_INSTALL).resolve())
        from ghidra.app.util.opinion import BinaryLoader
        from ghidra.program.flatapi import FlatProgramAPI
        from ghidra.program.model.listing import FlowOverride
        from java.lang import Object

        temporary = TemporaryDirectory(prefix="binaryrat-pcode-")
        cls.addClassCleanup(temporary.cleanup)
        cls.marker = Path(temporary.name) / "evidence.gpr"
        source = cls.marker.with_suffix(".bin")
        # mov rax,-1; nop; call 0x12; ret; <data>; ret; <data>
        image = bytearray.fromhex("48 b8 ffffffffffffffff 90 e802000000 c3 ff c3 ff")
        cls.moves_start = len(image)
        rng = Random(0xB164)
        cls.moves = [(register, rng.getrandbits(64)) for register in range(16) for _ in range(4)]
        for register, value in cls.moves:
            # REX.W[B] + B8+rd + imm64, in little endian.
            image.extend([0x48 | (register >> 3), 0xb8 | (register & 7)])
            image.extend(value.to_bytes(8, "little"))
        image.append(0xc3)
        source.write_bytes(image)
        with ExitStack() as cleanup:
            project = pyghidra.open_project(cls.marker.parent, cls.marker.stem, create=True)
            cleanup.callback(project.close)
            loaded = (pyghidra.program_loader().source(str(source)).name("instructions")
                      .loaders(BinaryLoader.class_).language("x86:LE:64:default")
                      .project(project).projectFolderPath("/").load())
            cleanup.callback(loaded.close)
            consumer = Object()
            program = loaded.getPrimaryDomainObject(consumer)
            cleanup.callback(program.release, consumer)
            flat = FlatProgramAPI(program)
            with pyghidra.transaction(program, "Define Listing instructions and override one call"):
                if not flat.disassemble(program.getMinAddress()):
                    raise AssertionError("could not decode test instructions")
                if not flat.disassemble(program.getMinAddress().add(cls.moves_start)):
                    raise AssertionError("could not decode generated immediate moves")
                flat.getInstructionAt(program.getMinAddress().add(11)).setFlowOverride(FlowOverride.BRANCH)
            loaded.save(pyghidra.task_monitor())

    def test_selected_instruction_boundaries_operands_and_empty_semantics(self):
        with open_program(self.marker, "/instructions") as view:
            result = view.instruction_pcode(Address("ram", 0))
            self.assertEqual(result, view.instruction_pcode(Address("ram", 9)))
            self.assertEqual((result.address, result.mnemonic, result.length, result.parsed_length),
                             (Address("ram", 0), "MOV", 10, 10))
            self.assertEqual(result.revision, view.info.revision)
            self.assertEqual(result.raw, result.effective)
            self.assertFalse(result.raw.truncated)
            op, = result.raw.operations
            self.assertEqual((op.mnemonic, op.site, op.sequence), ("COPY", result.address, 0))
            self.assertEqual(op.inputs, (PcodeVarnode(Address("const", (1 << 64) - 1), 8),))
            self.assertEqual(op.output, PcodeVarnode(Address("register", 0), 8))  # RAX
            nop = view.instruction_pcode(Address("ram", 10))
            self.assertEqual((nop.mnemonic, nop.raw.operations, nop.effective.operation_count),
                             ("NOP", (), 0))
            self.assertFalse(nop.effective.truncated)
            for address in (17, 19, 0x10000):
                self.assertIsNone(view.instruction_pcode(Address("ram", address)))
            for address in (Address("register", 0), Address("unknown", 0), Address("ram", 1 << 64)):
                with self.subTest(address=address), self.assertRaises(ValueError):
                    view.instruction_pcode(address)
            for limit in (0, 129, True, 2.5):
                with self.subTest(limit=limit), self.assertRaises(ValueError):
                    view.instruction_pcode(result.address, max_operations=limit)
        self.assertEqual(result.effective.operations[0], op)
        with self.assertRaises(LiveProgramError):
            view.instruction_pcode(result.address)

    def test_call_override_and_bounded_prefixes(self):
        with open_program(self.marker, "/instructions") as view:
            address = Address("ram", 13)
            full = view.instruction_pcode(address)
            self.assertEqual((full.address, full.length), (Address("ram", 11), 5))
            self.assertEqual(full.raw.operations[-1].mnemonic, "CALL")
            self.assertEqual(full.effective.operations[-1].mnemonic, "BRANCH")
            for listing in (full.raw, full.effective):
                self.assertEqual(listing.operations[-1].inputs[0].address, Address("ram", 18))
                self.assertIsNone(listing.operations[-1].output)
                self.assertEqual(listing.operation_count, len(listing.operations))
                self.assertFalse(listing.truncated)
            self.assertGreater(full.raw.operation_count, 1)
            for limit in range(1, full.raw.operation_count + 2):
                limited = view.instruction_pcode(address, max_operations=limit)
                for prefix, reference in ((limited.raw, full.raw), (limited.effective, full.effective)):
                    self.assertEqual(prefix.operations, reference.operations[:limit])
                    self.assertEqual(prefix.operation_count, reference.operation_count)
                    self.assertEqual(prefix.truncated, limit < reference.operation_count)

    def test_seeded_mov_immediates_preserve_values_registers_and_sites(self):
        registers = "RAX RCX RDX RBX RSP RBP RSI RDI R8 R9 R10 R11 R12 R13 R14 R15".split()
        with open_program(self.marker, "/instructions") as view:
            language = view._program.getLanguage()
            for index, (register, value) in enumerate(self.moves):
                start = self.moves_start + 10 * index
                with self.subTest(index=index, register=register, value=value):
                    result = view.instruction_pcode(Address("ram", start + index % 10))
                    self.assertEqual((result.address, result.length), (Address("ram", start), 10))
                    self.assertEqual(result.raw, result.effective)
                    op, = result.raw.operations
                    self.assertFalse(result.raw.truncated)
                    self.assertEqual((op.mnemonic, op.site), ("COPY", result.address))
                    self.assertEqual(op.inputs, (PcodeVarnode(Address("const", value), 8),))
                    expected = language.getRegister(registers[register]).getAddress()
                    self.assertEqual(op.output, PcodeVarnode(Address("register", int(expected.getOffset())), 8))

    def test_in_progress_edit_mid_read_edit_and_cancellation(self):
        import pyghidra
        from ghidra.program.model.listing import FlowOverride

        cancel = Event()
        address = Address("ram", 11)
        with open_program(self.marker, "/instructions", cancel=cancel) as view:
            program = view._program
            with pyghidra.transaction(program, "Hold test edit open"):
                with self.assertRaisesRegex(LiveProgramError, "edit or analysis"):
                    view.instruction_pcode(address)
            cancel.set()
            with self.assertRaises(CancelledError):
                view.instruction_pcode(address)
        with open_program(self.marker, "/instructions") as view:
            program = view._program
            instruction = program.getListing().getInstructionAt(view._native_address(program, address))

            def edit_after_raw(operations, limit, cancel):
                listing = _pcode_listing(operations, limit, cancel)
                with pyghidra.transaction(program, "Remove saved override in memory"):
                    instruction.setFlowOverride(FlowOverride.NONE)
                return listing

            with patch("binaryrat.live._pcode_listing", side_effect=edit_after_raw):
                with self.assertRaises(StaleProgramError):
                    view.instruction_pcode(address)
        with open_program(self.marker, "/instructions") as view:
            self.assertEqual(view.instruction_pcode(address).effective.operations[-1].mnemonic, "BRANCH")

    def test_omitted_operands_are_counted(self):
        from ghidra.program.model.pcode import PcodeOp, Varnode
        from jpype import JArray

        with open_program(self.marker, "/instructions") as view:
            address = view._native_address(view._program, Address("ram", 18))
            # One CALLOTHER with nine arguments. Include a null slot before the cut.
            args = JArray(Varnode)([None, *[Varnode(address, width) for width in range(1, 9)]])
            foreign = PcodeOp(address, 42, PcodeOp.CALLOTHER, args)
            listing = _pcode_listing([foreign], 128, None)
            self.assertTrue(listing.truncated)
            row, = listing.operations
            self.assertEqual((row.input_count, row.sequence), (9, 42))
            self.assertIsNone(row.inputs[0])
            self.assertEqual([node.size for node in row.inputs[1:]], list(range(1, 8)))
