// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package binaryrat.writeback;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.SwingUtilities;

import ghidra.app.plugin.core.analysis.AnalysisWorker;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.framework.model.TransactionInfo;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Explicitly apply a type at one reviewed call instruction using Ghidra's native override. */
public final class CallPrototypeOverride {
    public static final int MAX_SIGNATURE_LENGTH = 1024;
    private static final int MAX_ARGUMENTS = 64;
    private static final String TRANSACTION = "Apply BinaryRat call-site signature";
    private static final String AUTO_ANALYSIS_TRANSACTION = "Auto Analysis";
    private static final String OVERRIDE_PREFIX = "prt";

    private CallPrototypeOverride() {
    }

    /** Bound to the specific Program and revision from which the analyst's review was prepared. */
    public static final class Candidate {
        private final Program program;
        private final Address functionEntry;
        private final Address callSite;
        private final long revision;
        private final String callerName;
        private final String targetName;
        private final boolean indirect;
        private final String suggestedSignature;
        private final String callingConvention;

        private Candidate(Program program, Site site, long revision, String suggestion,
                String convention) {
            this.program = program;
            this.functionEntry = site.caller().getEntryPoint();
            this.callSite = site.address();
            this.revision = revision;
            this.callerName = site.caller().getName(true);
            this.targetName = site.target() == null ? "Indirect target" : site.target().getName(true);
            this.indirect = site.target() == null;
            this.suggestedSignature = suggestion;
            this.callingConvention = convention;
        }

        public Address functionEntry() {
            return functionEntry;
        }

        public Address callSite() {
            return callSite;
        }

        public long revision() {
            return revision;
        }

        public String callerName() {
            return callerName;
        }

        public String targetName() {
            return targetName;
        }

        public boolean indirect() {
            return indirect;
        }

        public String suggestedSignature() {
            return suggestedSignature;
        }

        public String callingConvention() {
            return callingConvention;
        }
    }

    public record Result(boolean committedAfterCancellation) {
    }

    /** Inspect a Listing location in the selected caller. An interior byte is normalized. */
    public static Candidate inspect(Program program, Address functionEntry, Address callSite,
            long revision) throws IOException {
        Objects.requireNonNull(program, "program");
        Object consumer = retain(program);
        try {
            AutoAnalysisManager analysis = AutoAnalysisManager.getAnalysisManager(program);
            checkIdle(program, analysis, revision);
            Site site = findSite(program, functionEntry, callSite);
            String suggestion = "";
            String convention = Function.DEFAULT_CALLING_CONVENTION_STRING;
            if (site.target() != null) {
                Function target = site.target();
                String current = target.getCallingConventionName();
                if (program.getCompilerSpec().getCallingConvention(current) != null) {
                    convention = current;
                }
                if (target.getParameterCount() <= MAX_ARGUMENTS) {
                    FunctionDefinitionDataType proposal = new FunctionDefinitionDataType(
                        CategoryPath.ROOT, "call_target", target.getSignature(true),
                        program.getDataTypeManager());
                    suggestion = proposal.getPrototypeString();
                }
            }
            if (suggestion.length() > MAX_SIGNATURE_LENGTH) {
                suggestion = "";
            }
            Candidate candidate = new Candidate(program, site, revision, suggestion, convention);
            checkIdle(program, analysis, revision);
            return candidate;
        }
        finally {
            program.release(consumer);
        }
    }

    /** Apply only the new override reviewed for this Program and revision. Run off the EDT. */
    public static Result apply(Program program, Candidate candidate, String signature,
            TaskMonitor monitor) throws Exception {
        if (SwingUtilities.isEventDispatchThread()) {
            throw new IllegalStateException("Run the call-site correction off the Swing thread");
        }
        if (Thread.currentThread().isInterrupted()) {
            throw new IOException("Interrupted before applying the call-site correction");
        }
        if (candidate == null || candidate.program != program) {
            throw new IOException("Open a fresh call-site review in this Program");
        }
        Objects.requireNonNull(monitor, "monitor");
        monitor.checkCancelled();
        String text = validateSignatureText(signature);
        Object consumer = retain(program);
        try {
            AutoAnalysisManager analysis = AutoAnalysisManager.getAnalysisManager(program);
            checkIdle(program, analysis, candidate.revision());
            Site site = findSite(program, candidate.functionEntry(), candidate.callSite());
            FunctionSignature original = site.target() == null ? null : site.target().getSignature(true);
            var parser = new FunctionSignatureParser(program.getDataTypeManager(), null);
            FunctionDefinitionDataType prototype = parser.parse(original, text);
            prototype.setCallingConvention(candidate.callingConvention());
            prototype.setNoReturn(original != null && original.hasNoReturn());
            checkIdle(program, analysis, candidate.revision());
            return submit(program, analysis, candidate, prototype, monitor);
        }
        catch (InterruptedException interruption) {
            Thread.currentThread().interrupt();
            if (monitor.isCancelEnabled()) {
                monitor.cancel();
            }
            throw new IOException(
                "Interrupted while waiting for Ghidra. Check the selected call before retrying.", interruption);
        }
        finally {
            program.release(consumer);
        }
    }

    private static Result submit(Program program, AutoAnalysisManager analysis, Candidate candidate,
            FunctionDefinitionDataType prototype, TaskMonitor monitor) throws Exception {
        AtomicReference<TransactionInfo> written = new AtomicReference<>();
        boolean cancelledAfterWrite = false;
        try {
            boolean ran = analysis.scheduleWorker(new AnalysisWorker() {
                @Override
                public String getWorkerName() {
                    return TRANSACTION;
                }

                @Override
                public boolean analysisWorkerCallback(Program current, Object ignored,
                        TaskMonitor workerMonitor) throws Exception {
                    workerMonitor.checkCancelled();
                    TransactionInfo scope = current.getCurrentTransactionInfo();
                    String parent = scope == null ? "" : scope.getDescription();
                    if (current != program || scope == null ||
                        (!TRANSACTION.equals(parent) && !AUTO_ANALYSIS_TRANSACTION.equals(parent)) ||
                        scope.getStatus() != TransactionInfo.Status.NOT_DONE ||
                        !scope.getOpenSubTransactions().equals(List.of(parent))) {
                        throw new IOException("Call-site correction requires its own Ghidra analysis transaction");
                    }
                    checkRevision(current, candidate.revision());
                    Site site = findSite(current, candidate.functionEntry(), candidate.callSite());
                    checkRevision(current, candidate.revision());
                    workerMonitor.checkCancelled();
                    int transaction = current.startTransaction(TRANSACTION);
                    boolean commit = false;
                    try {
                        HighFunctionDBUtil.writeOverride(site.caller(), site.address(), prototype);
                        if (!matchesOverride(site.caller(), site.address(), prototype)) {
                            throw new IOException("Ghidra did not install the reviewed call signature");
                        }
                        workerMonitor.checkCancelled();
                        commit = true;
                    }
                    finally {
                        current.endTransaction(transaction, commit);
                    }
                    written.set(scope);
                    return true;
                }
            }, null, false, monitor);
            if (!ran) {
                throw new CancelledException("Call-site correction did not complete");
            }
        }
        catch (InvocationTargetException failure) {
            if (failure.getCause() instanceof Exception cause) {
                throw cause;
            }
            throw failure;
        }
        catch (CancelledException failure) {
            if (written.get() == null) {
                throw failure;
            }
            cancelledAfterWrite = true;
        }
        TransactionInfo scope = written.get();
        if (scope == null) {
            throw new IOException("Ghidra did not write the reviewed call signature");
        }
        // In CodeBrowser the scheduler returns after the callback, before the outer transaction.
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (!(program.canUndo() && scope.hasCommittedDBTransaction())) {
            if (scope.getStatus() == TransactionInfo.Status.ABORTED) {
                throw new IOException("Ghidra rolled back the call-site correction");
            }
            if (System.nanoTime() - deadline >= 0) {
                throw new IOException("Ghidra has not confirmed the call-site correction. Check before retrying.");
            }
            Thread.sleep(20);
        }
        Function caller = program.getFunctionManager().getFunctionAt(candidate.functionEntry());
        if (caller == null || !matchesOverride(caller, candidate.callSite(), prototype)) {
            throw new IOException("The reviewed call signature is no longer present");
        }
        return new Result(cancelledAfterWrite || monitor.isCancelled());
    }

    private static Object retain(Program program) throws IOException {
        Object consumer = new Object();
        if (!program.addConsumer(consumer)) {
            throw new IOException("The selected Program is closed");
        }
        return consumer;
    }

    private static void checkIdle(Program program, AutoAnalysisManager analysis, long revision)
            throws IOException {
        checkRevision(program, revision);
        if (analysis.isAnalyzing() || program.getCurrentTransactionInfo() != null) {
            throw new IOException("Wait for Ghidra analysis or the active edit to finish");
        }
    }

    private static void checkRevision(Program program, long revision) throws IOException {
        if (program.isClosed() || !program.isChangeable() || !program.canSave()) {
            throw new IOException("Call-site correction requires an open writable Program");
        }
        if (program.getModificationNumber() != revision) {
            throw new IOException("The Program changed. Review the call site again");
        }
    }

    private static Site findSite(Program program, Address functionEntry, Address location)
            throws IOException {
        if (functionEntry == null || location == null || !location.isMemoryAddress()) {
            throw new IOException("Select a call instruction in the selected function");
        }
        Function caller = program.getFunctionManager().getFunctionAt(functionEntry);
        var instruction = program.getListing().getInstructionContaining(location);
        if (caller == null || caller.isExternal() || instruction == null ||
            !caller.getBody().contains(location) ||
            !caller.getBody().contains(instruction.getMinAddress()) ||
            !instruction.getFlowType().isCall()) {
            throw new IOException("Select a call instruction in the selected function");
        }
        Address address = instruction.getMinAddress();
        if (address.getAddressSpace().isOverlaySpace() || instruction.isInDelaySlot() ||
            instruction.getDelaySlotDepth() != 0 || instruction.getFlowOverride() != FlowOverride.NONE ||
            instruction.isLengthOverridden()) {
            throw new IOException("This call uses an overlay, delay slot, or instruction override");
        }
        PcodeOp call = null;
        for (PcodeOp op : instruction.getPcode()) {
            if (op.getOpcode() == PcodeOp.CALL || op.getOpcode() == PcodeOp.CALLIND) {
                if (call != null) {
                    throw new IOException("The instruction contains more than one p-code call");
                }
                call = op;
            }
        }
        if (call == null || call.getNumInputs() == 0) {
            throw new IOException("The instruction does not have an unambiguous p-code call");
        }
        Address destination = call.getOpcode() == PcodeOp.CALL ?
            call.getInput(0).getAddress() : null;
        for (var reference : program.getReferenceManager().getFlowReferencesFrom(address)) {
            var type = reference.getReferenceType();
            if (type.isOverride() || (type.isCall() && !reference.getToAddress().equals(destination))) {
                throw new IOException("The call has a redirected or ambiguous target reference");
            }
        }
        Function target = null;
        if (destination != null) {
            target = program.getFunctionManager().getFunctionAt(destination);
            if (target == null || target.isExternal() || target.isThunk() || target.getCallFixup() != null) {
                throw new IOException("The direct call requires a local target without a thunk or call fixup");
            }
        }
        var symbols = program.getSymbolTable().getSymbolsAsIterator(address);
        while (symbols.hasNext()) {
            var symbol = symbols.next();
            // The stock writer may delete any other prt* label at this address.
            if (symbol.getSymbolType() == SymbolType.LABEL &&
                symbol.getName().startsWith(OVERRIDE_PREFIX)) {
                throw new IOException("A signature override or protected prt label already exists at this call");
            }
        }
        return new Site(caller, address, target);
    }

    private static boolean matchesOverride(Function caller, Address address, FunctionSignature expected) {
        var namespace = HighFunction.findOverrideSpace(caller);
        if (namespace == null) {
            return false;
        }
        var symbols = caller.getProgram().getSymbolTable().getSymbolsAsIterator(address);
        while (symbols.hasNext()) {
            var symbol = symbols.next();
            if (symbol.getSymbolType() != SymbolType.LABEL ||
                !symbol.getParentNamespace().equals(namespace) ||
                !symbol.getName().startsWith(OVERRIDE_PREFIX + "_")) {
                continue;
            }
            var override = HighFunctionDBUtil.readOverride(symbol);
            return override != null && override.getDataType() instanceof FunctionSignature actual &&
                sameSignature(expected, actual);
        }
        return false;
    }

    private static boolean sameSignature(FunctionSignature expected, FunctionSignature actual) {
        if (!DataTypeUtilities.isSameOrEquivalentDataType(expected.getReturnType(), actual.getReturnType()) ||
            expected.hasVarArgs() != actual.hasVarArgs() || expected.hasNoReturn() != actual.hasNoReturn() ||
            !expected.getCallingConventionName().equals(actual.getCallingConventionName())) {
            return false;
        }
        var originalArgs = expected.getArguments();
        var installedArgs = actual.getArguments();
        if (originalArgs.length != installedArgs.length) {
            return false;
        }
        for (int i = 0; i < originalArgs.length; i++) {
            if (!originalArgs[i].getName().equals(installedArgs[i].getName()) ||
                !originalArgs[i].isEquivalent(installedArgs[i])) {
                return false;
            }
        }
        return true;
    }

    private static String validateSignatureText(String signature) throws IOException {
        if (signature == null || signature.length() > MAX_SIGNATURE_LENGTH ||
            signature.chars().anyMatch(Character::isISOControl)) {
            throw new IOException("Use one C-style signature of at most " + MAX_SIGNATURE_LENGTH + " characters");
        }
        String text = signature.strip();
        int open = text.indexOf('(');
        int close = text.indexOf(')');
        if (open <= 0 || close <= open || close != text.length() - 1 ||
            text.indexOf('(', open + 1) >= 0) {
            throw new IOException("Enter a complete C-style signature such as int call_target(int value)");
        }
        String args = text.substring(open + 1, close).strip();
        if (!args.isEmpty() && !args.equals("void")) {
            String[] parameters = args.split(",", -1);
            if (parameters.length > MAX_ARGUMENTS) {
                throw new IOException("Call-site corrections support at most " + MAX_ARGUMENTS + " parameters");
            }
            for (int i = 0; i < parameters.length; i++) {
                String parameter = parameters[i].strip();
                if (parameter.isEmpty() || parameter.equals("void") ||
                    (parameter.equals("...") && (i == 0 || i != parameters.length - 1))) {
                    throw new IOException("Use complete parameter declarations and put ... after the fixed parameters");
                }
            }
        }
        return text;
    }

    private record Site(Function caller, Address address, Function target) {
    }
}
