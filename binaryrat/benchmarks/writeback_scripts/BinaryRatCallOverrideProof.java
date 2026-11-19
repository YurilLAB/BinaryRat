// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0

import java.io.IOException;
import java.util.HexFormat;
import java.util.Random;

import binaryrat.desktop.InstructionPcode;
import binaryrat.writeback.CallPrototypeOverride;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.database.ProgramDB;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/** Regression for the packaged correction service on a disposable Ghidra database. */
public class BinaryRatCallOverrideProof extends GhidraScript {
    private static final String PROTOTYPE = "int call_target(int value)";
    private static final int FUZZ_CASES = 256;
    private ProgramDB program;
    private Address callerEntry;
    private Address peerCall;
    private Address indirectCall;
    private Address calleeEntry;

    @Override
    protected void run() throws Exception {
        if (!isRunningHeadless() || currentProgram != null) {
            throw new IllegalStateException("Run as a headless project-only preScript");
        }
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
        program = new ProgramDB("BinaryRat disposable call fixture", language,
            language.getCompilerSpecByID(new CompilerSpecID("gcc")), this);
        try {
            setup();
            controls();
            malformedAndFuzz();
            suggestions();
            rollbackAndUndo();
            replacement();
            instructionPcode();
            println("BINARYRAT_CALL_OVERRIDE_OK malformed_cases=" + FUZZ_CASES +
                " direct_and_indirect=true cancellation_rollback=true undo_redo=true" +
                " decompiler_suggestion=true replacement=true pcode=true");
        }
        finally {
            program.release(this);
        }
    }

    private void setup() throws Exception {
        var space = program.getAddressFactory().getDefaultAddressSpace();
        callerEntry = space.getAddress(0x1000);
        peerCall = callerEntry.add(5);
        indirectCall = callerEntry.add(15);
        calleeEntry = space.getAddress(0x1020);
        var flat = new FlatProgramAPI(program, monitor);
        int transaction = program.startTransaction("Build disposable x86 call fixture");
        boolean commit = false;
        try {
            var memory = program.getMemory();
            var code = memory.createInitializedBlock(".text", callerEntry, 64, (byte) 0x90,
                monitor, false);
            code.setExecute(true);
            // call callee; call callee; mov edi, 7; call rax; ret
            memory.setBytes(callerEntry, HexFormat.of().parseHex("e81b000000e816000000bf07000000ffd0c3"));
            // mov eax, 42; ret
            memory.setBytes(calleeEntry, HexFormat.of().parseHex("b82a000000c3"));
            require(flat.disassemble(callerEntry) && flat.createFunction(callerEntry, "caller") != null,
                "could not create caller");
            flat.disassemble(calleeEntry);
            require(flat.createFunction(calleeEntry, "callee") != null, "could not create callee");
            commit = true;
        }
        finally {
            program.endTransaction(transaction, commit);
        }
        state.getProject().getProjectData().getRootFolder().createFile("call-fixture", program, monitor);
        require(program.canSave(), "headless proof did not acquire a writable project Program");
        program.clearUndo();
    }

    private void controls() throws Exception {
        var direct = candidate(callerEntry.add(1));
        require(!direct.indirect() && direct.callSite().equals(callerEntry) &&
            direct.targetName().equals("callee"), "interior address did not normalize to the direct call");
        require(candidate(indirectCall).indirect(), "unresolved indirect call not recognized");
        expect(IOException.class, "Select a call instruction", () -> candidate(indirectCall.add(2)));
        expect(IOException.class, "Select a call instruction", () ->
            CallPrototypeOverride.inspect(program, calleeEntry, callerEntry, revision()));
        expect(IOException.class, "Program changed", () ->
            CallPrototypeOverride.inspect(program, callerEntry, callerEntry, revision() - 1));
        expect(IOException.class, "fresh call-site review", () ->
            CallPrototypeOverride.apply(null, direct, PROTOTYPE, monitor));
        Thread.currentThread().interrupt();
        try {
            expect(IOException.class, "Interrupted before applying", () ->
                CallPrototypeOverride.apply(program, direct, PROTOTYPE, monitor));
            require(Thread.currentThread().isInterrupted(), "pre-interrupted submit lost its interrupt flag");
        }
        finally {
            Thread.interrupted();
        }
        TaskMonitorAdapter cancelled = new TaskMonitorAdapter(true);
        cancelled.cancel();
        expect(CancelledException.class, "", () ->
            CallPrototypeOverride.apply(program, direct, PROTOTYPE, cancelled));

        int transaction = program.startTransaction("Unrelated active edit");
        try {
            expect(IOException.class, "active edit", () ->
                CallPrototypeOverride.apply(program, direct, PROTOTYPE, monitor));
            program.getSymbolTable().createLabel(peerCall, "prt_analyst_label", SourceType.USER_DEFINED);
        }
        finally {
            program.endTransaction(transaction, true);
        }
        expect(IOException.class, "Program changed", () ->
            CallPrototypeOverride.apply(program, direct, PROTOTYPE, monitor));
        expect(IOException.class, "protected prt label", () -> candidate(peerCall));
        require(program.getSymbolTable().getPrimarySymbol(peerCall).getName().equals("prt_analyst_label"),
            "analyst label was changed");
        require(override(callerEntry) == null, "a rejected call installed an override");
        program.clearUndo();
    }

    private void malformedAndFuzz() throws Exception {
        var direct = candidate(callerEntry);
        long before = revision();
        int types = typeCount();
        for (String signature : new String[] {"", "void incomplete(", "int call_target(int,)",
            "int call_target(int,,char)", "int call_target(...,int)", "int call_target(void,...)",
            "int call_target(int,...) extra", "int call_target(\nint)", "x".repeat(1025),
            "int call_target(" + "int,".repeat(64) + "int)"}) {
            expect(IOException.class, "", () ->
                CallPrototypeOverride.apply(program, direct, signature, monitor));
        }
        Random random = new Random(1202);
        for (int i = 0; i < FUZZ_CASES; i++) {
            monitor.checkCancelled();
            String unknownType = "binaryrat_missing_" + Long.toUnsignedString(random.nextLong(), 36);
            String input = "int call_target(" + unknownType + " value)";
            expect(ParseException.class, "", () ->
                CallPrototypeOverride.apply(program, direct, input, monitor));
        }
        require(before == revision() && typeCount() == types && !program.canUndo() &&
            override(callerEntry) == null, "rejected signatures changed Program state");
    }

    private void rollbackAndUndo() throws Exception {
        var direct = candidate(callerEntry);
        int types = typeCount();
        int[] baselineCalls = inputCounts();
        String originalCallee = program.getFunctionManager().getFunctionAt(calleeEntry)
            .getPrototypeString(true, true);
        TaskMonitor cancelAfterWrite = new TaskMonitorAdapter(true) {
            @Override
            public void checkCancelled() throws CancelledException {
                if (override(callerEntry) != null) {
                    throw new CancelledException("Cancel after native prototype creation");
                }
                super.checkCancelled();
            }
        };
        expect(CancelledException.class, "", () ->
            CallPrototypeOverride.apply(program, direct, PROTOTYPE, cancelAfterWrite));
        require(!program.canUndo() && override(callerEntry) == null && typeCount() == types,
            "cancelled native write left a marker, associated datatype, or undo record");

        TaskMonitor cancelAfterCommit = new TaskMonitorAdapter(true) {
            @Override
            public void checkCancelled() throws CancelledException {
                if (program.getCurrentTransactionInfo() == null && override(callerEntry) != null) {
                    throw new CancelledException("Cancel after native transaction commit");
                }
                super.checkCancelled();
            }
        };
        var lateCancellation = CallPrototypeOverride.apply(program, candidate(callerEntry),
            PROTOTYPE, cancelAfterCommit);
        require(lateCancellation.committedAfterCancellation() && override(callerEntry) != null,
            "late cancellation concealed a native commit");
        program.undo();

        var saved = CallPrototypeOverride.apply(program, candidate(callerEntry), PROTOTYPE, monitor);
        require(!saved.committedAfterCancellation() && override(callerEntry) != null,
            "native direct override was not committed");
        int[] editedCalls = inputCounts();
        require(editedCalls[0] == 2 && baselineCalls[0] != editedCalls[0] &&
            editedCalls[1] == baselineCalls[1], "direct override did not change only its selected p-code call");
        require(override(peerCall) == null &&
            originalCallee.equals(program.getFunctionManager().getFunctionAt(calleeEntry)
                .getPrototypeString(true, true)), "override changed the peer call or callee signature");
        var existing = candidate(callerEntry);
        require(existing.replacesOverride() &&
            existing.suggestionSource() == CallPrototypeOverride.Suggestion.EXISTING_OVERRIDE &&
            existing.suggestedSignature().equals("int callee(int value)"),
            "an existing override was not offered for review: " + existing.suggestedSignature());
        program.undo();
        require(override(callerEntry) == null && typeCount() == types,
            "native undo did not remove the new signature and marker");
        program.redo();
        require(override(callerEntry) != null, "native redo did not restore the signature");

        CallPrototypeOverride.apply(program, candidate(indirectCall),
            "void call_target(int value, ...)", monitor);
        var applied = override(indirectCall);
        require(applied != null && applied.hasVarArgs() && applied.getArguments().length == 1,
            "native indirect variadic override was not committed");
        require(inputCounts()[2] >= 2, "decompiler did not apply the indirect override's fixed parameter");
        program.undo();
        require(override(indirectCall) == null && override(callerEntry) != null,
            "undo of the indirect call changed the direct call");
    }

    private void suggestions() throws Exception {
        long before = revision();
        int types = typeCount();
        var indirect = CallPrototypeOverride.inspect(program, callerEntry, indirectCall, revision(), monitor);
        require(indirect.indirect() &&
            indirect.suggestionSource() == CallPrototypeOverride.Suggestion.DECOMPILER,
            "indirect call was not offered the decompiler's view: " + indirect.suggestionSource());
        var parsed = new FunctionSignatureParser(program.getDataTypeManager(), null)
            .parse(null, indirect.suggestedSignature());
        require(parsed.getArguments().length == 1,
            "decompiler suggestion missed the EDI argument: " + indirect.suggestedSignature());
        println("Decompiler suggestion at " + indirectCall + ": " + indirect.suggestedSignature());
        var direct = CallPrototypeOverride.inspect(program, callerEntry, callerEntry, revision(), monitor);
        require(direct.directFixedArguments() && !direct.replacesOverride() &&
            direct.callingConventions().getFirst().equals(Function.DEFAULT_CALLING_CONVENTION_STRING) &&
            direct.callingConventions().contains(direct.callingConvention()),
            "direct call review lacks its calling conventions: " + direct.callingConventions());
        expect(IOException.class, "calling conventions", () ->
            CallPrototypeOverride.apply(program, direct, PROTOTYPE, "binaryrat_missing_convention", monitor));
        require(before == revision() && typeCount() == types && !program.canUndo() &&
            override(indirectCall) == null, "inspection or a rejected convention changed the Program");
    }

    private void replacement() throws Exception {
        require(override(callerEntry) != null && override(indirectCall) == null &&
            overrideTypes() == 1, "replacement starts from the direct override only");
        var review = candidate(callerEntry);
        long before = revision();
        expect(IOException.class, "already uses", () ->
            CallPrototypeOverride.apply(program, review, "int callee(int value)", monitor));
        require(before == revision(), "re-applying the same prototype changed the Program");
        String other = review.callingConventions().stream()
            .filter(name -> !name.equals(review.callingConvention())).findFirst().orElseThrow();
        var result = CallPrototypeOverride.apply(program, review, "long callee(long value)", other, monitor);
        var replaced = override(callerEntry);
        require(result.replacedOverride() && replaced != null &&
            replaced.getReturnType().getName().equals("long") &&
            replaced.getCallingConventionName().equals(other) && markers(callerEntry) == 1 &&
            overrideTypes() == 1, "replacement left " + markers(callerEntry) + " markers and " +
                overrideTypes() + " override types: " + replaced);
        expect(IOException.class, "Program changed", () ->
            CallPrototypeOverride.apply(program, review, "short callee(short value)", monitor));
        program.undo();
        var restored = override(callerEntry);
        require(restored != null && restored.getReturnType().getName().equals("int") &&
            markers(callerEntry) == 1 && overrideTypes() == 1,
            "one undo did not restore the previous override: " + restored);
        program.redo();
        require(override(callerEntry).getReturnType().getName().equals("long"),
            "redo did not restore the replacement");
        program.undo();

        int transaction = program.startTransaction("Unreadable override marker");
        try {
            var caller = program.getFunctionManager().getFunctionAt(callerEntry);
            program.getSymbolTable().createLabel(indirectCall, "prt_deadbeef_1000",
                HighFunction.findCreateOverrideSpace(caller), SourceType.USER_DEFINED);
        }
        finally {
            program.endTransaction(transaction, true);
        }
        expect(IOException.class, "protected prt label", () -> candidate(indirectCall));
        program.undo();
        require(markers(indirectCall) == 0, "fixture marker was not undone");
    }

    private void instructionPcode() throws Exception {
        var raw = InstructionPcode.read(program, callerEntry, indirectCall.add(1), revision(), monitor);
        require(raw.instructionAddress().equals(indirectCall) && raw.overridden().isEmpty() &&
            raw.notes().isEmpty() && !raw.truncated() &&
            raw.operations().stream().anyMatch(line -> line.endsWith("= COPY RAX")) &&
            raw.operations().stream().anyMatch(line -> line.startsWith("CALLIND $U")) &&
            raw.operations().contains("RSP = INT_SUB RSP, 8:8"),
            "p-code was not formatted with register names: " + raw.operations());
        int transaction = program.startTransaction("Flow override fixture");
        try {
            program.getListing().getInstructionAt(indirectCall).setFlowOverride(FlowOverride.CALL_RETURN);
        }
        finally {
            program.endTransaction(transaction, true);
        }
        var overridden = InstructionPcode.read(program, callerEntry, indirectCall, revision(), monitor);
        require(overridden.operations().equals(raw.operations()) &&
            overridden.overridden().stream().anyMatch(line -> line.startsWith("RETURN")) &&
            overridden.notes().contains("Flow override: CALL_RETURN") &&
            InstructionPcode.describe(overridden).contains("what the decompiler reads"),
            "flow override view: " + InstructionPcode.describe(overridden));
        expect(IOException.class, "instruction override", () -> candidate(indirectCall));
        program.undo();
    }

    /** Function definitions that Ghidra keeps for call-site overrides. */
    private int overrideTypes() {
        var category = program.getDataTypeManager().getCategory(new CategoryPath(HighFunctionDBUtil.AUTO_CAT));
        return category == null ? 0 : category.getDataTypes().length;
    }

    private int markers(Address address) {
        var caller = program.getFunctionManager().getFunctionAt(callerEntry);
        var scope = HighFunction.findOverrideSpace(caller);
        int count = 0;
        for (var symbol : program.getSymbolTable().getSymbols(address)) {
            if (symbol.getSymbolType() == SymbolType.LABEL && scope != null &&
                scope.equals(symbol.getParentNamespace()) && symbol.getName().startsWith("prt")) {
                count++;
            }
        }
        return count;
    }

    private int[] inputCounts() {
        var decompiler = new DecompInterface();
        try {
            require(decompiler.openProgram(program), "could not open program in native decompiler");
            Function caller = program.getFunctionManager().getFunctionAt(callerEntry);
            var result = decompiler.decompileFunction(caller, 15, monitor);
            require(result.decompileCompleted() && result.getHighFunction() != null,
                "native decompile failed: " + result.getErrorMessage());
            HighFunction high = result.getHighFunction();
            return new int[] {inputs(high, callerEntry), inputs(high, peerCall), inputs(high, indirectCall)};
        }
        finally {
            decompiler.dispose();
        }
    }

    private int inputs(HighFunction high, Address callSite) {
        var operations = high.getPcodeOps(callSite);
        while (operations.hasNext()) {
            var op = operations.next();
            if (op.getOpcode() == PcodeOp.CALL || op.getOpcode() == PcodeOp.CALLIND) {
                return op.getNumInputs();
            }
        }
        throw new IllegalStateException("missing native high p-code call at " + callSite);
    }

    private CallPrototypeOverride.Candidate candidate(Address address) throws IOException {
        return CallPrototypeOverride.inspect(program, callerEntry, address, revision());
    }

    private long revision() {
        return program.getModificationNumber();
    }

    private int typeCount() {
        return program.getDataTypeManager().getDataTypeCount(true);
    }

    private FunctionSignature override(Address address) {
        var caller = program.getFunctionManager().getFunctionAt(callerEntry);
        var scope = HighFunction.findOverrideSpace(caller);
        var symbols = program.getSymbolTable().getSymbolsAsIterator(address);
        while (symbols.hasNext()) {
            var symbol = symbols.next();
            if (symbol.getSymbolType() == SymbolType.LABEL &&
                symbol.getParentNamespace().equals(scope) && symbol.getName().startsWith("prt_")) {
                var data = HighFunctionDBUtil.readOverride(symbol);
                if (data != null && data.getDataType() instanceof FunctionSignature signature) {
                    return signature;
                }
            }
        }
        return null;
    }

    private static void expect(Class<? extends Exception> type, String message, Operation action)
            throws Exception {
        try {
            action.run();
        }
        catch (Exception error) {
            if (type.isInstance(error) && (message.isEmpty() ||
                (error.getMessage() != null && error.getMessage().contains(message)))) {
                return;
            }
            throw error;
        }
        throw new IllegalStateException("expected " + type.getSimpleName() + ": " + message);
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }

    @FunctionalInterface
    private interface Operation {
        void run() throws Exception;
    }
}
