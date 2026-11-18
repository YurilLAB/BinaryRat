// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.plugin.core.analysis.FindNoReturnFunctionsAnalyzer;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitorAdapter;

/** Differential fixture for the stock no-return reducer and its Program changes. */
public class BinaryRatNoReturnParity extends GhidraScript {
    private static final int CASE_SIZE = 0x200;
    private static final int CALLER_SIZE = 0x20;
    private static final int CALLER_START = 0x10;
    private static final int CALL_COUNT = 3;
    private static final int TARGET_OFFSET = 0x100;
    private static final int RET = 0xc3;
    private static final int NOP = 0x90;

    private enum Evidence {
        INT3(true), DATA(true), UNDEFINED(true), NEXT_FUNCTION(true), OFFCUT_FUNCTION(true),
        INCOMING_CALL(true), SAME_FUNCTION_READ(true), UNOWNED_READ(true),
        LATER_SAME_FUNCTION_READ(false), OTHER_FUNCTION_READ(false), NORMAL_CONTINUATION(false),
        FALLTHROUGH_FIXUP(false);

        final boolean expected;

        Evidence(boolean expected) {
            this.expected = expected;
        }
    }

    @Override
    public AnalysisMode getScriptAnalysisMode() {
        return AnalysisMode.DISABLED;
    }

    @Override
    protected void run() throws Exception {
        if (!isRunningHeadless() || getScriptArgs().length != 1 ||
            !currentProgram.getLanguageID().toString().equals("x86:LE:64:default")) {
            throw new IllegalArgumentException("Use a disposable x86-64 Program and supply a report path");
        }

        var base = toAddr(0x100000);
        if (getScriptArgs()[0].equals("check-fall-through-edits")) {
            checkFallThroughEdits(base);
            return;
        }
        var bytes = ByteBuffer.allocate(Evidence.values().length * CASE_SIZE)
            .order(ByteOrder.LITTLE_ENDIAN);
        for (Evidence evidence : Evidence.values()) {
            int offset = evidence.ordinal() * CASE_SIZE;
            bytes.put(offset, (byte) RET);
            bytes.put(offset + TARGET_OFFSET, (byte) RET);
            for (int n = 0; n < CALL_COUNT; n++) {
                int entry = offset + CALLER_START + n * CALLER_SIZE;
                int call = entry + 1;
                int fall = call + 5;
                bytes.put(entry, (byte) NOP);
                bytes.put(call, (byte) 0xe8);
                bytes.putInt(call + 1, offset + TARGET_OFFSET - fall);
                // Make the offcut instruction two bytes. Test the real mnemonic for
                // plain INT3, INT3 after NOP, and INT3 with an operand-size prefix.
                int first = switch (evidence) {
                    case OFFCUT_FUNCTION -> 0x31;
                    case INT3 -> n == 0 ? 0xcc : n == 1 ? NOP : 0x66;
                    case FALLTHROUGH_FIXUP -> 0xcc;
                    default -> NOP;
                };
                bytes.put(fall, (byte) first);
                int second = switch (evidence) {
                    case OFFCUT_FUNCTION -> 0xc0;
                    case INT3 -> 0xcc;
                    default -> RET;
                };
                bytes.put(fall + 1, (byte) second);
                bytes.put(fall + 2, (byte) RET);
            }
        }
        createMemoryBlock("NoReturnFixture", base, bytes.array(), false).setExecute(true);

        var sourceCalls = new AddressSet();
        var disassembler = Disassembler.getDisassembler(currentProgram, monitor, null);
        for (Evidence evidence : Evidence.values()) {
            var caseStart = base.add(evidence.ordinal() * CASE_SIZE);
            var target = caseStart.add(TARGET_OFFSET);
            decode(disassembler, target);
            createFixtureFunction(target, target);
            if (evidence == Evidence.FALLTHROUGH_FIXUP) {
                currentProgram.getFunctionManager().getFunctionAt(target).setCallFixup("fentry");
            }
            if (evidence == Evidence.OTHER_FUNCTION_READ) {
                decode(disassembler, caseStart);
                createFixtureFunction(caseStart, caseStart);
            }
            for (int n = 0; n < CALL_COUNT; n++) {
                var entry = caseStart.add(CALLER_START + n * CALLER_SIZE);
                var call = entry.add(1);
                var fall = call.add(5);
                decode(disassembler, entry);
                decode(disassembler, call);
                sourceCalls.add(call);

                switch (evidence) {
                    case DATA -> currentProgram.getListing().createData(fall, ByteDataType.dataType);
                    case UNDEFINED -> { }
                    default -> {
                        decode(disassembler, fall);
                        if (evidence != Evidence.OFFCUT_FUNCTION &&
                            (evidence != Evidence.INT3 || n != 2)) {
                            decode(disassembler, fall.add(1));
                        }
                        decode(disassembler, fall.add(2));
                    }
                }
                if (evidence == Evidence.NEXT_FUNCTION || evidence == Evidence.OFFCUT_FUNCTION) {
                    var next = evidence == Evidence.NEXT_FUNCTION ? fall : fall.add(1);
                    createFixtureFunction(next, next);
                }
                if (evidence != Evidence.UNOWNED_READ) {
                    var end = switch (evidence) {
                        case DATA, UNDEFINED, NEXT_FUNCTION, OFFCUT_FUNCTION -> fall.subtract(1);
                        default -> fall.add(1);
                    };
                    createFixtureFunction(entry, end);
                }

                var references = currentProgram.getReferenceManager();
                switch (evidence) {
                    case INCOMING_CALL -> references.addMemoryReference(target, fall,
                        RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, Reference.MNEMONIC);
                    case SAME_FUNCTION_READ -> dataReference(entry, fall);
                    case LATER_SAME_FUNCTION_READ -> dataReference(fall.add(1), fall);
                    case UNOWNED_READ -> dataReference(target, fall);
                    case OTHER_FUNCTION_READ -> dataReference(caseStart, fall);
                    default -> { }
                }
            }
        }

        var analyzer = configuredAnalyzer();
        var cancelled = new TaskMonitorAdapter(true);
        cancelled.cancel();
        try {
            analyzer.added(currentProgram, sourceCalls, cancelled, new MessageLog());
            throw new IllegalStateException("No-return analyzer ignored cancellation");
        }
        catch (CancelledException expected) {
            effects(base, false);
        }
        require(analyzer.added(currentProgram, sourceCalls, monitor, new MessageLog()),
            "No-return analyzer failed");
        var report = effects(base, true);
        Files.writeString(Path.of(getScriptArgs()[0]), String.join("\n", report) + "\n",
            StandardCharsets.UTF_8);
        println("BINARYRAT_NO_RETURN_PARITY passed " + report.size() + " cases");
    }

    private FindNoReturnFunctionsAnalyzer configuredAnalyzer() {
        var analyzer = new FindNoReturnFunctionsAnalyzer();
        var options = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES)
            .getOptions(analyzer.getName());
        analyzer.registerOptions(options, currentProgram);
        options.setBoolean("Repair Flow Damage", false);
        analyzer.optionsChanged(options, currentProgram);
        return analyzer;
    }

    private void checkFallThroughEdits(Address base) throws Exception {
        var start = base.add(Evidence.NORMAL_CONTINUATION.ordinal() * CASE_SIZE);
        var call = start.add(CALLER_START + 1);
        var listing = currentProgram.getListing();
        var target = currentProgram.getFunctionManager().getFunctionAt(start.add(TARGET_OFFSET));
        var analyzer = configuredAnalyzer();
        var calls = new AddressSet();
        var nodes = new ArrayList<Instruction>();
        for (int n = 0; n < CALL_COUNT; n++) {
            var source = call.add(n * CALLER_SIZE);
            calls.add(source);
            nodes.add(listing.getInstructionAt(source.add(5)));
        }
        // Exhaust every graph on three NOPs. Each can lead to any NOP or its normal RET.
        int choices = nodes.size() + 1;
        int graphCount = (int) Math.pow(choices, nodes.size());
        for (int graph = 0; graph < graphCount; graph++) {
            int successors = graph;
            for (var node : nodes) {
                int next = successors % choices;
                successors /= choices;
                node.setFallThrough(next == nodes.size()
                    ? node.getDefaultFallThrough() : nodes.get(next).getAddress());
            }
            require(analyzer.added(currentProgram, calls, boundedMonitor(), new MessageLog()),
                "Analyzer failed on graph " + graph);
            require(!target.hasNoReturn(), "Unexpected no-return result for graph " + graph);
        }
        // Backward, acyclic edits can still reach genuine no-return evidence.
        var trap = base.add(Evidence.INT3.ordinal() * CASE_SIZE + CALLER_START + 6);
        nodes.forEach(node -> node.setFallThrough(trap));
        require(analyzer.added(currentProgram, calls, boundedMonitor(), new MessageLog()),
            "Analyzer failed on the backward INT3 control");
        require(target.hasNoReturn(), "Acyclic backward paths lost their INT3 evidence");
        println("BINARYRAT_FALL_THROUGH_EDITS passed " + graphCount + " graphs and INT3");
    }

    private static TaskMonitorAdapter boundedMonitor() {
        return new TaskMonitorAdapter(true) {
            private int checks;

            @Override
            public void checkCancelled() throws CancelledException {
                if (++checks >= 256) {
                    throw new CancelledException();
                }
            }
        };
    }

    private void decode(Disassembler disassembler, Address address) {
        disassembler.disassemble(address, new AddressSet(address), false);
        require(currentProgram.getListing().getInstructionAt(address) != null,
            "Fixture instruction missing at " + address);
    }

    private void createFixtureFunction(Address entry, Address last) throws Exception {
        require(currentProgram.getFunctionManager().createFunction(null, entry,
            new AddressSet(entry, last), SourceType.DEFAULT) != null,
            "Unable to create fixture function at " + entry);
    }

    private void dataReference(Address from, Address to) {
        currentProgram.getReferenceManager().addMemoryReference(from, to, RefType.READ,
            SourceType.USER_DEFINED, Reference.MNEMONIC);
    }

    private List<String> effects(Address base, boolean analyzed) {
        var report = new ArrayList<String>();
        for (Evidence evidence : Evidence.values()) {
            var caseStart = base.add(evidence.ordinal() * CASE_SIZE);
            var target = caseStart.add(TARGET_OFFSET);
            boolean expected = analyzed && evidence.expected;
            var function = currentProgram.getFunctionManager().getFunctionAt(target);
            var bookmark = currentProgram.getBookmarkManager().getBookmark(target,
                BookmarkType.ANALYSIS, "Non-Returning Function");
            require(function.hasNoReturn() == expected && (bookmark != null) == expected,
                "Unexpected target result for " + evidence);
            var row = new StringBuilder(evidence.name()).append(' ').append(function.hasNoReturn())
                .append(' ').append(bookmark != null);
            for (int n = 0; n < CALL_COUNT; n++) {
                var call = caseStart.add(CALLER_START + n * CALLER_SIZE + 1);
                var instruction = currentProgram.getListing().getInstructionAt(call);
                var override = expected ? FlowOverride.CALL_RETURN : FlowOverride.NONE;
                require(instruction.getFlowOverride() == override,
                    "Unexpected call override at " + call + " for " + evidence);
                var caller = currentProgram.getFunctionManager().getFunctionContaining(call);
                row.append(' ').append(instruction.getFlowOverride()).append(' ')
                    .append(caller == null ? "unowned" : caller.getBody());
            }
            report.add(row.toString());
        }
        return report;
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }
}
