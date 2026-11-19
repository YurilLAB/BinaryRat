// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package binaryrat.writeback;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

import javax.swing.SwingUtilities;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.plugin.core.analysis.AnalysisWorker;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.framework.model.TransactionInfo;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.DataTypeSymbol;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Explicitly apply a type at one reviewed call instruction using Ghidra's native override. */
public final class CallPrototypeOverride {
    public static final int MAX_SIGNATURE_LENGTH = 1024;
    /** Limit for the decompilation that suggests a prototype from the call's current p-code. */
    public static final int SUGGESTION_TIMEOUT_SECONDS = 30;
    private static final int MAX_ARGUMENTS = 64;
    private static final String TRANSACTION = "Apply BinaryRat call-site signature";
    private static final String AUTO_ANALYSIS_TRANSACTION = "Auto Analysis";
    private static final String OVERRIDE_PREFIX = "prt";
    private static final String DEFAULT_NAME = "call_target";
    private static final Pattern IDENTIFIER = Pattern.compile("[A-Za-z_][A-Za-z0-9_]{0,127}");

    private CallPrototypeOverride() {
    }

    /** Where the prototype offered for review came from. */
    public enum Suggestion {
        /** Nothing reliable: the analyst writes the prototype. */
        NONE,
        /** The called function's own signature, set by a user or an import. */
        CALLEE,
        /** The decompiler's current view of this call's inputs and output. */
        DECOMPILER,
        /** The override already at this call, which a new prototype replaces. */
        EXISTING_OVERRIDE
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
        private final boolean variadicTarget;
        private final String suggestedSignature;
        private final Suggestion suggestionSource;
        private final String callingConvention;
        private final List<String> callingConventions;
        private final String replacedOverride;
        private final FunctionSignature replacedSignature;

        private Candidate(Program program, Site site, long revision, Offer offer, String convention,
                List<String> conventions) {
            this.program = program;
            this.functionEntry = site.caller().getEntryPoint();
            this.callSite = site.address();
            this.revision = revision;
            this.callerName = site.caller().getName(true);
            this.targetName = site.target() == null ? "Indirect target" : site.target().getName(true);
            this.indirect = site.target() == null;
            this.variadicTarget = site.target() != null && site.target().hasVarArgs();
            this.suggestedSignature = offer.text();
            this.suggestionSource = offer.source();
            this.callingConvention = convention;
            this.callingConventions = List.copyOf(conventions);
            this.replacedOverride = site.override() == null ? null : site.override().getName();
            this.replacedSignature = site.override() == null ? null : overrideSignature(site.override());
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

        /** A direct call to a fixed-argument function: editing the callee usually fits better. */
        public boolean directFixedArguments() {
            return !indirect && !variadicTarget;
        }

        public String suggestedSignature() {
            return suggestedSignature;
        }

        public Suggestion suggestionSource() {
            return suggestionSource;
        }

        /** The calling convention preselected for review. */
        public String callingConvention() {
            return callingConvention;
        }

        /** {@code default} followed by the Program's compiler-specification conventions. */
        public List<String> callingConventions() {
            return callingConventions;
        }

        /** True when applying replaces the signature override already at this call. */
        public boolean replacesOverride() {
            return replacedOverride != null;
        }
    }

    public record Result(boolean committedAfterCancellation, boolean replacedOverride) {
    }

    private record Offer(String text, Suggestion source) {
        static final Offer NONE = new Offer("", Suggestion.NONE);
    }

    /** Inspect a Listing location in the selected caller without decompiling it. */
    public static Candidate inspect(Program program, Address functionEntry, Address callSite,
            long revision) throws IOException {
        try {
            return inspect(program, functionEntry, callSite, revision, null);
        }
        catch (CancelledException impossible) {
            throw new IOException(impossible);
        }
    }

    /**
     * Inspect a Listing location in the selected caller. An interior byte is normalized. With a
     * monitor, a call without a user-defined callee signature is decompiled once so the review
     * starts from the decompiler's view of its inputs and output. Run off the EDT.
     */
    public static Candidate inspect(Program program, Address functionEntry, Address callSite,
            long revision, TaskMonitor monitor) throws IOException, CancelledException {
        Objects.requireNonNull(program, "program");
        Object consumer = retain(program);
        try {
            AutoAnalysisManager analysis = AutoAnalysisManager.getAnalysisManager(program);
            checkIdle(program, analysis, revision);
            Site site = findSite(program, functionEntry, callSite);
            Function target = site.target();
            List<String> conventions = conventions(program);
            String convention = Function.DEFAULT_CALLING_CONVENTION_STRING;
            Offer offer = Offer.NONE;
            if (site.override() != null) {
                FunctionSignature current = overrideSignature(site.override());
                offer = offer(prototype(current, nameFor(target), program), Suggestion.EXISTING_OVERRIDE);
                convention = current.getCallingConventionName();
            }
            else {
                if (target != null) {
                    convention = target.getCallingConventionName();
                }
                if (target != null &&
                    target.getSignatureSource().isHigherPriorityThan(SourceType.ANALYSIS)) {
                    offer = offer(prototype(target.getSignature(true), nameFor(target), program),
                        Suggestion.CALLEE);
                }
                if (offer.source() == Suggestion.NONE && monitor != null) {
                    offer = offer(decompiledCall(program, site, monitor), Suggestion.DECOMPILER);
                }
                if (offer.source() == Suggestion.NONE && target != null) {
                    offer = offer(prototype(target.getSignature(true), nameFor(target), program),
                        Suggestion.CALLEE);
                }
            }
            if (!conventions.contains(convention)) {
                convention = Function.DEFAULT_CALLING_CONVENTION_STRING;
            }
            Candidate candidate = new Candidate(program, site, revision, offer, convention, conventions);
            checkIdle(program, analysis, revision);
            return candidate;
        }
        finally {
            program.release(consumer);
        }
    }

    /** Apply the reviewed signature with the candidate's calling convention. Run off the EDT. */
    public static Result apply(Program program, Candidate candidate, String signature,
            TaskMonitor monitor) throws Exception {
        return apply(program, candidate, signature,
            candidate == null ? null : candidate.callingConvention(), monitor);
    }

    /** Apply only the new override reviewed for this Program and revision. Run off the EDT. */
    public static Result apply(Program program, Candidate candidate, String signature,
            String callingConvention, TaskMonitor monitor) throws Exception {
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
        if (callingConvention == null || !candidate.callingConventions().contains(callingConvention)) {
            throw new IOException("Choose one of the Program's calling conventions");
        }
        Object consumer = retain(program);
        try {
            AutoAnalysisManager analysis = AutoAnalysisManager.getAnalysisManager(program);
            checkIdle(program, analysis, candidate.revision());
            Site site = findSite(program, candidate.functionEntry(), candidate.callSite());
            checkSameOverride(site, candidate);
            FunctionSignature original = site.target() == null ? null : site.target().getSignature(true);
            var parser = new FunctionSignatureParser(program.getDataTypeManager(), null);
            FunctionDefinitionDataType prototype = parser.parse(original, text);
            prototype.setCallingConvention(callingConvention);
            prototype.setNoReturn(candidate.replacedSignature != null ?
                candidate.replacedSignature.hasNoReturn() : original != null && original.hasNoReturn());
            if (candidate.replacedSignature != null && sameSignature(prototype, candidate.replacedSignature)) {
                throw new IOException("This call already uses that prototype");
            }
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
                    checkSameOverride(site, candidate);
                    checkRevision(current, candidate.revision());
                    workerMonitor.checkCancelled();
                    int transaction = current.startTransaction(TRANSACTION);
                    boolean commit = false;
                    try {
                        if (site.override() != null) {
                            // The stock writer keeps markers in the override namespace, so remove
                            // the reviewed one first. Both edits share this undo step.
                            DataTypeSymbol previous = HighFunctionDBUtil.readOverride(site.override());
                            site.override().delete();
                            previous.cleanupUnusedOverride();
                        }
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
        return new Result(cancelledAfterWrite || monitor.isCancelled(), candidate.replacesOverride());
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

    private static void checkSameOverride(Site site, Candidate candidate) throws IOException {
        String present = site.override() == null ? null : site.override().getName();
        if (!Objects.equals(present, candidate.replacedOverride)) {
            throw new IOException("The call's signature override changed. Review the call site again");
        }
    }

    private static List<String> conventions(Program program) {
        var names = new ArrayList<String>();
        names.add(Function.DEFAULT_CALLING_CONVENTION_STRING);
        for (String name : program.getFunctionManager().getCallingConventionNames()) {
            if (!names.contains(name) && !Function.UNKNOWN_CALLING_CONVENTION_STRING.equals(name)) {
                names.add(name);
            }
        }
        return names;
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
        return new Site(caller, address, target, existingOverride(program, caller, address));
    }

    /**
     * The single readable signature override of this caller at the call, or null. The stock
     * writer may delete other {@code prt} labels at the address, so any other one blocks the edit.
     */
    private static Symbol existingOverride(Program program, Function caller, Address address)
            throws IOException {
        var namespace = HighFunction.findOverrideSpace(caller);
        Symbol existing = null;
        var symbols = program.getSymbolTable().getSymbolsAsIterator(address);
        while (symbols.hasNext()) {
            var symbol = symbols.next();
            if (symbol.getSymbolType() != SymbolType.LABEL || !symbol.getName().startsWith(OVERRIDE_PREFIX)) {
                continue;
            }
            boolean override = namespace != null && namespace.equals(symbol.getParentNamespace()) &&
                symbol.getName().startsWith(OVERRIDE_PREFIX + "_") && !symbol.hasReferences() &&
                overrideSignature(symbol) != null;
            if (!override) {
                throw new IOException("A protected prt label exists at this call. BinaryRat leaves it unchanged");
            }
            if (existing != null) {
                throw new IOException("This call has more than one signature override");
            }
            existing = symbol;
        }
        return existing;
    }

    private static FunctionSignature overrideSignature(Symbol symbol) {
        DataTypeSymbol data = HighFunctionDBUtil.readOverride(symbol);
        return data != null && data.getDataType() instanceof FunctionSignature signature ? signature : null;
    }

    private static boolean matchesOverride(Function caller, Address address, FunctionSignature expected) {
        var namespace = HighFunction.findOverrideSpace(caller);
        if (namespace == null) {
            return false;
        }
        FunctionSignature installed = null;
        int markers = 0;
        var symbols = caller.getProgram().getSymbolTable().getSymbolsAsIterator(address);
        while (symbols.hasNext()) {
            var symbol = symbols.next();
            if (symbol.getSymbolType() == SymbolType.LABEL && namespace.equals(symbol.getParentNamespace()) &&
                symbol.getName().startsWith(OVERRIDE_PREFIX)) {
                markers++;
                installed = overrideSignature(symbol);
            }
        }
        return markers == 1 && installed != null && sameSignature(expected, installed);
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

    private static String nameFor(Function target) {
        return target != null && IDENTIFIER.matcher(target.getName()).matches() ? target.getName() : DEFAULT_NAME;
    }

    private static String prototype(FunctionSignature signature, String name, Program program) {
        if (signature == null || signature.getArguments().length > MAX_ARGUMENTS) {
            return "";
        }
        return new FunctionDefinitionDataType(CategoryPath.ROOT, name, signature,
            program.getDataTypeManager()).getPrototypeString();
    }

    /** A suggestion is only offered when it passes the same checks as typed input. */
    private static Offer offer(String text, Suggestion source) {
        if (text == null || text.isBlank()) {
            return Offer.NONE;
        }
        try {
            return new Offer(validateSignatureText(text), source);
        }
        catch (IOException unusable) {
            return Offer.NONE;
        }
    }

    /** The decompiler's current inputs and output at this call, as Ghidra's own override offers. */
    private static String decompiledCall(Program program, Site site, TaskMonitor monitor)
            throws CancelledException {
        var decompiler = new DecompInterface();
        try {
            var options = new DecompileOptions();
            options.grabFromProgram(program);
            decompiler.setOptions(options);
            decompiler.toggleSyntaxTree(true);
            decompiler.setSimplificationStyle("decompile");
            if (!decompiler.openProgram(program)) {
                return "";
            }
            var result = decompiler.decompileFunction(site.caller(), SUGGESTION_TIMEOUT_SECONDS, monitor);
            monitor.checkCancelled();
            HighFunction high = result == null ? null : result.getHighFunction();
            if (high == null) {
                return "";
            }
            var operations = high.getPcodeOps(site.address());
            while (operations.hasNext()) {
                PcodeOpAST op = operations.next();
                if (op.getOpcode() == PcodeOp.CALL || op.getOpcode() == PcodeOp.CALLIND) {
                    return describeCall(op, site.target());
                }
            }
            return "";
        }
        finally {
            decompiler.dispose();
        }
    }

    private static String describeCall(PcodeOp op, Function target) {
        if (op.getNumInputs() - 1 > MAX_ARGUMENTS) {
            return "";
        }
        // A callee signature from analysis is a guess; the call's own varnodes are evidence.
        Parameter[] declared = target == null ||
            target.getSignatureSource().isLowerOrEqualPriorityThan(SourceType.ANALYSIS) ?
                new Parameter[0] : target.getParameters();
        DataType output = op.getOutput() == null ? null : type(op.getOutput());
        var text = new StringBuilder();
        text.append(output == null ? VoidDataType.dataType.getDisplayName() : output.getDisplayName())
            .append(' ').append(nameFor(target)).append('(');
        for (int i = 1; i < op.getNumInputs(); i++) {
            Parameter parameter = i - 1 < declared.length ? declared[i - 1] : null;
            DataType known = parameter == null || Undefined.isUndefined(parameter.getDataType()) ?
                null : parameter.getDataType();
            DataType type = known != null ? known : type(op.getInput(i));
            if (type == null) {
                return "";
            }
            String name = parameter != null && parameter.getSource() != SourceType.DEFAULT &&
                IDENTIFIER.matcher(parameter.getName()).matches() ? parameter.getName() : "param_" + i;
            text.append(i == 1 ? "" : ", ").append(type.getDisplayName()).append(' ').append(name);
        }
        return text.append(')').toString();
    }

    private static DataType type(Varnode varnode) {
        var high = varnode.getHigh();
        return high == null ? null : high.getDataType();
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

    private record Site(Function caller, Address address, Function target, Symbol override) {
    }
}
