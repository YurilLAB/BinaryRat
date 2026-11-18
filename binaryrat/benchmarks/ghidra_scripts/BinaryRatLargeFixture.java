// Disassemble the sampled LLVM exports in a disposable Ghidra project.
// @category BinaryRat.Tests
/* Copyright 2026 YurilLAB. SPDX-License-Identifier: Apache-2.0 */

import java.nio.file.Files;
import java.nio.file.Path;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;

public class BinaryRatLargeFixture extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (!isRunningHeadless() || currentProgram == null || getScriptArgs().length != 1) {
            throw new IllegalArgumentException("Import the ELF in a disposable project with a sample TSV");
        }
        var functions = currentProgram.getFunctionManager();
        int count = 0;
        for (String line : Files.readAllLines(Path.of(getScriptArgs()[0]))) {
            monitor.checkCancelled();
            String[] fields = line.split("\\t", -1);
            if (fields.length != 3 || fields[2].isEmpty()) {
                throw new IllegalArgumentException("Invalid sample row: " + line);
            }
            long size = Long.parseUnsignedLong(fields[1], 16);
            if (size < 64 || size > 3072) {
                throw new IllegalArgumentException("Invalid sample size: " + line);
            }
            Address address = currentProgram.getImageBase().addNoWrap(
                Long.parseUnsignedLong(fields[0], 16));
            Address end = address.addNoWrap(size - 1);
            MemoryBlock block = currentProgram.getMemory().getBlock(address);
            if (block == null || !block.isExecute() || !block.contains(end)) {
                throw new IllegalStateException("Symbol is outside executable bytes: " + line);
            }
            var extent = new AddressSet(address, end);
            var disassemble = new DisassembleCommand(address, extent, true);
            disassemble.enableCodeAnalysis(false);
            disassemble.applyTo(currentProgram, monitor);
            if (currentProgram.getListing().getInstructionAt(address) == null) {
                throw new IllegalStateException("Selected entry could not be disassembled: " + line);
            }
            Function existing = functions.getFunctionAt(address);
            if (existing != null) {
                if (!existing.getName().equals(fields[2])) {
                    throw new IllegalStateException("ELF symbol differs from sample row: " + line);
                }
                functions.removeFunction(address);
            }
            var instructions = currentProgram.getListing().getInstructions(extent, true);
            var body = new AddressSet();
            while (instructions.hasNext()) {
                var instruction = instructions.next();
                if (!extent.contains(instruction.getMinAddress(), instruction.getMaxAddress())) {
                    throw new IllegalStateException("Instruction overlaps sample boundary: " + line);
                }
                body.add(instruction.getMinAddress(), instruction.getMaxAddress());
            }
            Function function = functions.createFunction(fields[2], address, body, SourceType.IMPORTED);
            if (function == null || !function.getName().equals(fields[2]) ||
                    !extent.contains(function.getBody())) {
                throw new IllegalStateException("Inconsistent sample function: " + line);
            }
            count++;
        }
        println("BinaryRat selected sample functions=" + count + " base=" +
            currentProgram.getImageBase());
    }
}
