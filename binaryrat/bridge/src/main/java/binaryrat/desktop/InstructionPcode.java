// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package binaryrat.desktop;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import ghidra.app.util.pcode.StringPcodeFormatter;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Reads one instruction's p-code as the processor specification defines it and, when
 * the Program overrides its flow, as the decompiler reads it after those overrides.
 */
public final class InstructionPcode {
    private static final int MAX_OPERATIONS = 128;
    private static final int MAX_INPUTS = 8;
    private static final int MAX_TEXT = 256;
    private static final int MAX_VARNODE_TEXT = 64;

    private InstructionPcode() {
    }

    /**
     * @param operations raw p-code, one formatted operation or internal label per line
     * @param overridden p-code after flow, fall-through and call overrides; empty when equal
     * @param notes the instruction's flow, fall-through and length overrides
     */
    public record Snapshot(Address instructionAddress, String instruction, List<String> operations,
            List<String> overridden, List<String> notes, boolean truncated) {
        public Snapshot {
            operations = List.copyOf(operations);
            overridden = List.copyOf(overridden);
            notes = List.copyOf(notes);
        }
    }

    private record Rendered(List<String> lines, boolean truncated) {
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
            // Ghidra generates these arrays for this single instruction. Bound our rendered
            // output independently of the language's expansion of the instruction.
            PcodeOp[] raw = instruction.getPcode(false);
            PcodeOp[] withOverrides = instruction.getPcode(true);
            Rendered rawText = render(program, raw, monitor);
            Rendered overriddenText = samePcode(raw, withOverrides) ?
                new Rendered(List.of(), false) : render(program, withOverrides, monitor);
            boolean truncated = rawText.truncated() || overriddenText.truncated() ||
                instructionText.length() > MAX_TEXT;
            List<String> notes = notes(instruction);
            monitor.checkCancelled();
            checkReadable(program, expectedRevision);
            return new Snapshot(instructionAddress, compact(instructionText, MAX_TEXT), rawText.lines(),
                overriddenText.lines(), notes, truncated);
        }
        finally {
            program.release(consumer);
        }
    }

    /** Text for a read-only dialog. The first three lines are the instruction and a heading. */
    public static String describe(Snapshot evidence) {
        var text = new StringBuilder();
        text.append(evidence.instructionAddress()).append("  ").append(evidence.instruction())
            .append("\n\nRaw p-code from the processor specification\n");
        appendOperations(text, evidence.operations());
        if (!evidence.overridden().isEmpty()) {
            text.append("\nP-code after Listing overrides (what the decompiler reads)\n");
            appendOperations(text, evidence.overridden());
        }
        if (!evidence.notes().isEmpty()) {
            text.append('\n');
            evidence.notes().forEach(note -> text.append(note).append('\n'));
        }
        if (evidence.truncated()) {
            text.append("\nSome operations or operands were shortened.\n");
        }
        return text.toString();
    }

    private static void appendOperations(StringBuilder text, List<String> operations) {
        if (operations.isEmpty()) {
            text.append("This instruction has no p-code operations.\n");
        }
        operations.forEach(line -> text.append("  ").append(line).append('\n'));
    }

    private static List<String> notes(Instruction instruction) {
        var notes = new ArrayList<String>();
        if (instruction.getFlowOverride() != FlowOverride.NONE) {
            notes.add("Flow override: " + instruction.getFlowOverride());
        }
        if (instruction.isFallThroughOverridden()) {
            Address fallThrough = instruction.getFallThrough();
            notes.add("Fall-through override: " + (fallThrough == null ? "none" : fallThrough));
        }
        if (instruction.isLengthOverridden()) {
            notes.add("Length override: " + instruction.getLength() + " bytes");
        }
        return notes;
    }

    private static boolean samePcode(PcodeOp[] left, PcodeOp[] right) {
        if (left.length != right.length) {
            return false;
        }
        for (int i = 0; i < left.length; i++) {
            if (left[i].getOpcode() != right[i].getOpcode() ||
                left[i].getNumInputs() != right[i].getNumInputs() ||
                !sameVarnode(left[i].getOutput(), right[i].getOutput())) {
                return false;
            }
            for (int j = 0; j < left[i].getNumInputs(); j++) {
                if (!sameVarnode(left[i].getInput(j), right[i].getInput(j))) {
                    return false;
                }
            }
        }
        return true;
    }

    private static boolean sameVarnode(Varnode left, Varnode right) {
        return left == null ? right == null :
            right != null && left.getAddress().equals(right.getAddress()) && left.getSize() == right.getSize();
    }

    private static Rendered render(Program program, PcodeOp[] operations, TaskMonitor monitor)
            throws CancelledException {
        monitor.checkCancelled();
        int count = Math.min(operations.length, MAX_OPERATIONS);
        boolean truncated = operations.length > count;
        List<PcodeOp> shown = Arrays.asList(operations).subList(0, count);
        List<String> lines;
        try {
            // The Listing's PCode field uses this formatter: register names, $U temporaries,
            // CALLOTHER names and labels for branches inside the instruction.
            lines = new StringPcodeFormatter().formatOps(program.getLanguage(),
                program.getAddressFactory(), shown).lines().filter(line -> !line.isBlank()).toList();
        }
        catch (RuntimeException unsupported) {
            return plain(shown, truncated, monitor);
        }
        var result = new ArrayList<String>(lines.size());
        for (String line : lines) {
            monitor.checkCancelled();
            truncated |= line.length() > MAX_TEXT;
            result.add(compact(line.strip(), MAX_TEXT));
        }
        return new Rendered(result, truncated);
    }

    /** Varnode tuples for p-code the formatter cannot render. */
    private static Rendered plain(List<PcodeOp> shown, boolean truncated, TaskMonitor monitor)
            throws CancelledException {
        var result = new ArrayList<String>(shown.size());
        for (PcodeOp op : shown) {
            monitor.checkCancelled();
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
            result.add(compact(line.toString(), MAX_TEXT));
        }
        return new Rendered(result, truncated);
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
