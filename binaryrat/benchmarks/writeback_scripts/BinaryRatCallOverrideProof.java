// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0

import java.io.IOException;
import java.util.HexFormat;
import java.util.Random;

import binaryrat.writeback.CallPrototypeOverride;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.program.database.ProgramDB;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
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
            rollbackAndUndo();
            println("BINARYRAT_CALL_OVERRIDE_OK malformed_cases=" + FUZZ_CASES +
                " direct_and_indirect=true cancellation_rollback=true undo_redo=true");
        }
        finally {
            program.release(this);
        }
    }

    private void setup() throws Exception {
        var space = program.getAddressFactory().getDefaultAddressSpace();
        callerEntry = space.getAddress(0x1000);
        peerCall = callerEntry.add(5);
        indirectCall = callerEntry.add(10);
        calleeEntry = space.getAddress(0x1020);
        var flat = new FlatProgramAPI(program, monitor);
        int transaction = program.startTransaction("Build disposable x86 call fixture");
        boolean commit = false;
        try {
            var memory = program.getMemory();
            var code = memory.createInitializedBlock(".text", callerEntry, 64, (byte) 0x90,
                monitor, false);
            code.setExecute(true);
            // call callee; call callee; call rax; ret
            memory.setBytes(callerEntry, HexFormat.of().parseHex("e81b000000e816000000ffd0c3"));
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
        expect(IOException.class, "signature override", () -> candidate(callerEntry));
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
