// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package binaryrat.desktop;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Reads the instruction's raw p-code before decompiler simplification and flow overrides. */
public final class InstructionPcode {
    private static final int MAX_OPERATIONS = 128;
    private static final int MAX_INPUTS = 8;
    private static final int MAX_TEXT = 256;
    private static final int MAX_VARNODE_TEXT = 64;

    private InstructionPcode() {
    }

    public record Snapshot(Address instructionAddress, String instruction, List<String> operations,
            boolean truncated) {
        public Snapshot {
            operations = List.copyOf(operations);
        }
    }

    /**
     * Resolve a Listing location in the specified function and read one instruction's p-code.
     * Call off the EDT. Check the selection and revision again before publishing the result.
     */
    public static Snapshot read(Program program, Address functionEntry, Address location,
            long expectedRevision, TaskMonitor monitor) throws IOException, CancelledException {
        monitor.checkCancelled();
        Object consumer = new Object();
        if (!program.addConsumer(consumer)) {
            throw new IOException("The selected Program is closed.");
        }
        try {
            checkReadable(program, expectedRevision);
            if (!isProgramMemoryAddress(program, functionEntry) ||
                !isProgramMemoryAddress(program, location)) {
                throw new IOException("Select an instruction in the Program's memory.");
            }

            var function = program.getFunctionManager().getFunctionAt(functionEntry);
            if (function == null || function.isExternal()) {
                throw new IOException("The location is outside the selected local function.");
            }
            var body = function.getBody();
            if (!body.contains(location)) {
                throw new IOException("The location is outside the selected local function.");
            }
            var instruction = program.getListing().getInstructionContaining(location);
            if (instruction == null ||
                !body.contains(instruction.getMinAddress(), instruction.getMaxAddress())) {
                throw new IOException("There is no instruction in the selected function at that location.");
            }
            Address instructionAddress = instruction.getMinAddress();
            monitor.checkCancelled();
            String instructionText = instruction.toString();
            // Ghidra generates an array for this single instruction. Bound our rendered output
            // independently of the language's expansion of the instruction and its operands.
            var operations = instruction.getPcode();
            int count = Math.min(operations.length, MAX_OPERATIONS);
            var lines = new ArrayList<String>(count);
            boolean truncated = operations.length > count || instructionText.length() > MAX_TEXT;
            for (int i = 0; i < count; i++) {
                monitor.checkCancelled();
                var op = operations[i];
                var line = new StringBuilder();
                if (op.getOutput() != null) {
                    truncated |= appendVarnode(line, op.getOutput());
                    line.append(" = ");
                }
                line.append(op.getMnemonic());
                int inputs = Math.min(op.getNumInputs(), MAX_INPUTS);
                for (int j = 0; j < inputs; j++) {
                    line.append(j == 0 ? " " : ", ");
                    truncated |= appendVarnode(line, op.getInput(j));
                }
                if (op.getNumInputs() > inputs) {
                    line.append(", …");
                    truncated = true;
                }
                truncated |= line.length() > MAX_TEXT;
                lines.add(compact(line.toString(), MAX_TEXT));
            }
            monitor.checkCancelled();
            checkReadable(program, expectedRevision);
            return new Snapshot(instructionAddress, compact(instructionText, MAX_TEXT),
                lines, truncated);
        }
        finally {
            program.release(consumer);
        }
    }

    private static boolean isProgramMemoryAddress(Program program, Address address) {
        if (address == null || !address.isMemoryAddress() ||
            !program.getAddressFactory().isValidAddress(address)) {
            return false;
        }
        // Overlay equality alone can also match an identically named overlay in another Program.
        var space = address.getAddressSpace();
        return !space.isOverlaySpace() ||
            space == program.getAddressFactory().getAddressSpace(space.getName());
    }

    private static void checkReadable(Program program, long expectedRevision) throws IOException {
        if (program.getCurrentTransactionInfo() != null) {
            throw new IOException("Wait for the Program edit or analysis to finish.");
        }
        if (program.getModificationNumber() != expectedRevision) {
            throw new IOException("The Program changed. Inspect the instruction again.");
        }
    }

    private static boolean appendVarnode(StringBuilder line, Varnode node) {
        String text = node == null ? "?" : node.toString();
        line.append(compact(text, MAX_VARNODE_TEXT));
        return text.length() > MAX_VARNODE_TEXT;
    }

    private static String compact(String text, int limit) {
        if (text.length() > limit) {
            int end = limit - 1;
            if (Character.isHighSurrogate(text.charAt(end - 1))) {
                end--;
            }
            text = text.substring(0, end) + "…";
        }
        return text.replace('\r', ' ').replace('\n', ' ').replace('\t', ' ');
    }
}
