// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.app.plugin.core.analysis.FindNoReturnFunctionsAnalyzer;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;

/** Builds a disposable call-heavy Program and times stock no-return discovery. */
public class BinaryRatBenchmarkNoReturn extends GhidraScript {
    private static final int RETURNING_CALLERS = 1_800;
    private static final int WARMUP_PASSES = 2;
    private static final int TIMED_PASSES = 4;
    private static final int STRIDE = 16;
    private static final int CALL = 1;
    private static final int FALL = 6;
    private static final int LAST = 9;
    private static final int POSITIVE_COUNT = 3;

    @Override
    public AnalysisMode getScriptAnalysisMode() {
        return AnalysisMode.DISABLED;
    }

    @Override
    protected void run() throws Exception {
        var args = getScriptArgs();
        if (!isRunningHeadless() || currentProgram == null || args.length != 1 ||
            !currentProgram.getLanguageID().toString().equals("x86:LE:64:default")) {
            throw new IllegalArgumentException("Use a disposable x86-64 Program and supply a report path");
        }

        var base = toAddr(0x100000);
        var bytes = ByteBuffer.allocate((RETURNING_CALLERS + POSITIVE_COUNT + 3) * STRIDE)
            .order(ByteOrder.LITTLE_ENDIAN);
        int normalTargetOffset = (RETURNING_CALLERS + POSITIVE_COUNT + 1) * STRIDE;
        int positiveTargetOffset = normalTargetOffset + STRIDE;
        bytes.put(0, (byte) 0xc3);
        bytes.put(normalTargetOffset, (byte) 0xc3);
        bytes.put(positiveTargetOffset, (byte) 0xc3);
        for (int index = 0; index < RETURNING_CALLERS + POSITIVE_COUNT; index++) {
            int entry = (index + 1) * STRIDE;
            bytes.put(entry, (byte) 0x90);
            bytes.put(entry + CALL, (byte) 0xe8);
            int target = index < RETURNING_CALLERS ? normalTargetOffset : positiveTargetOffset;
            bytes.putInt(entry + CALL + 1, target - (entry + FALL));
            bytes.put(entry + FALL, (byte) (index < RETURNING_CALLERS ? 0x90 : 0xcc));
            bytes.put(entry + 7, (byte) 0x90);
            bytes.put(entry + 8, (byte) 0x90);
            bytes.put(entry + LAST, (byte) 0xc3);
        }

        createMemoryBlock("Trial", base, bytes.array(), false).setExecute(true);
        var decoder = Disassembler.getDisassembler(currentProgram, monitor, null);
        for (Address target : new Address[] {base, base.add(normalTargetOffset), base.add(positiveTargetOffset)}) {
            decodeAndCreate(decoder, target, target);
        }
        var normalCalls = new AddressSet();
        var positiveCalls = new AddressSet();
        var references = currentProgram.getReferenceManager();
        for (int index = 0; index < RETURNING_CALLERS + POSITIVE_COUNT; index++) {
            monitor.checkCancelled();
            var entry = base.add((index + 1) * STRIDE);
            var call = entry.add(CALL);
            var last = entry.add(LAST);
            if (index < RETURNING_CALLERS) {
                decodeAndCreate(decoder, entry, last);
                normalCalls.add(call);
                if (index % 16 == 0) {
                    references.addMemoryReference(base, entry.add(FALL), RefType.READ,
                        SourceType.USER_DEFINED, Reference.MNEMONIC);
                }
            }
            else {
                // Separate bounded decodes avoid following the INT3 trap.
                decodeAndCreate(decoder, entry, entry.add(FALL - 1));
                decoder.disassemble(entry.add(FALL), new AddressSet(entry.add(FALL)), false);
                require(currentProgram.getListing().getInstructionAt(entry.add(FALL))
                    .getMnemonicString().equals("INT3"), "Missing INT3");
                positiveCalls.add(call);
            }
        }
        var analyzer = new FindNoReturnFunctionsAnalyzer();
        var options = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES)
            .getOptions(analyzer.getName());
        analyzer.registerOptions(options, currentProgram);
        options.setBoolean("Repair Flow Damage", false);
        analyzer.optionsChanged(options, currentProgram);

        long revision = currentProgram.getModificationNumber();
        var observations = new JsonArray();
        for (int index = 0; index < TIMED_PASSES + WARMUP_PASSES; index++) {
            long started = System.nanoTime();
            require(analyzer.added(currentProgram, normalCalls, monitor, new MessageLog()),
                "Analyzer failed");
            long elapsed = System.nanoTime() - started;
            require(currentProgram.getModificationNumber() == revision, "Timed read-pass changed the Program");
            if (index >= WARMUP_PASSES) {
                observations.add(elapsed);
            }
        }
        require(analyzer.added(currentProgram, positiveCalls, monitor, new MessageLog()),
            "Positive control failed");

        var functions = currentProgram.getFunctionManager();
        var normal = functions.getFunctionAt(base.add(normalTargetOffset));
        var positive = functions.getFunctionAt(base.add(positiveTargetOffset));
        require(!normal.hasNoReturn() && positive.hasNoReturn(), "Incorrect target flags");
        require(currentProgram.getBookmarkManager().getBookmark(positive.getEntryPoint(),
            BookmarkType.ANALYSIS, "Non-Returning Function") != null, "Positive control missing bookmark");
        var stable = new StringBuilder();
        var listing = currentProgram.getListing();
        stable.append(RETURNING_CALLERS).append('/').append(listing.getNumInstructions())
            .append('/').append(functions.getFunctionCount()).append('/')
            .append(references.getReferenceSourceCount()).append('/')
            .append(references.getReferenceDestinationCount()).append('\n');
        for (int index = 0; index < RETURNING_CALLERS + POSITIVE_COUNT; index++) {
            var entry = base.add((index + 1) * STRIDE);
            var callAddress = entry.add(CALL);
            var call = listing.getInstructionAt(callAddress);
            var expected = index < RETURNING_CALLERS ? FlowOverride.NONE : FlowOverride.CALL_RETURN;
            require(call.getFlowOverride() == expected, "Unexpected call change at " + callAddress);
            var callTarget = index < RETURNING_CALLERS ? normal.getEntryPoint() : positive.getEntryPoint();
            var flows = call.getFlows();
            require(flows.length == 1 && flows[0].equals(callTarget),
                "Unexpected call destination at " + callAddress);
            stable.append(entry).append('/').append(callTarget).append('/')
                .append(call.getFlowOverride()).append('/').append(functions.getFunctionAt(entry).getBody())
                .append('\n');
        }
        var json = new JsonObject();
        json.addProperty("schema_version", 1);
        json.addProperty("java_version", System.getProperty("java.runtime.version"));
        json.addProperty("heap_max_bytes", Runtime.getRuntime().maxMemory());
        json.addProperty("active_processors", Runtime.getRuntime().availableProcessors());
        json.addProperty("callers", RETURNING_CALLERS);
        json.addProperty("positive_calls", POSITIVE_COUNT);
        json.addProperty("fixture_bytes", bytes.capacity());
        json.addProperty("bytes_sha256",
            HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes.array())));
        json.addProperty("effects_sha256", HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
            .digest(stable.toString().getBytes(StandardCharsets.UTF_8))));
        json.add("timed_analyzer_wall_ns", observations);
        Files.writeString(Path.of(args[0]), json.toString() + "\n", StandardCharsets.UTF_8);
        println("BINARYRAT_NO_RETURN_TIMING passed");
    }

    private void decodeAndCreate(Disassembler decoder, Address entry, Address last) throws Exception {
        var body = new AddressSet(entry, last);
        decoder.disassemble(entry, body, false);
        require(currentProgram.getListing().getInstructionAt(entry) != null, "Missing code at " + entry);
        require(currentProgram.getFunctionManager().createFunction(null, entry, body, SourceType.DEFAULT)
            != null, "Missing function at " + entry);
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }
}
