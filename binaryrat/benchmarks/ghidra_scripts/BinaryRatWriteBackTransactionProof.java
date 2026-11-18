// SPDX-License-Identifier: Apache-2.0
// Verify Ghidra native transaction behavior on an in-memory fixture.

import java.lang.reflect.InvocationTargetException;
import java.util.Objects;

import ghidra.app.plugin.core.analysis.AnalysisWorker;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.StringPropertyMap;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

public class BinaryRatWriteBackTransactionProof extends GhidraScript {
    private static final String MAP = "BinaryRat.WriteBackProof.Application";
    private static final String MARKER = "approved-proof-record";
    private static final String WORKER = "BinaryRat transaction proof";

    private Program program;
    private AutoAnalysisManager analysis;
    private Address editable;
    private Address protectedFunction;

    private enum Fault { NONE, FAIL_AFTER_TYPE, CANCEL_AFTER_MARKER, CANCEL_AFTER_COMMIT_POINT }

    private record State(String prototype, String returnStorage, String returnType,
                         SourceType source, String comment, String marker) {}

    @Override
    protected void run() throws Exception {
        if (!isRunningHeadless() || currentProgram != null) {
            throw new IllegalStateException("Run this test as a headless project-only preScript");
        }
        Language language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
        program = new ProgramDB("BinaryRat transaction proof", language,
            language.getCompilerSpecByID(new CompilerSpecID("gcc")), this);
        try {
            var space = program.getAddressFactory().getDefaultAddressSpace();
            editable = space.getAddress(0x1000);
            protectedFunction = space.getAddress(0x1010);
            analysis = AutoAnalysisManager.getAnalysisManager(program);
            expectIdle("setup");
            setUpFixture();
            program.clearUndo();
            State initial = state(editable);
            State protectedInitial = state(protectedFunction);

            controlWithoutAbortScope(initial);

            assertThrowingWorker(() -> apply(editable, initial, revision(),
                                             Fault.FAIL_AFTER_TYPE, true),
                                 "forced failure after first mutation");
            verifyPreserved(initial, protectedInitial, "failure rollback");
            expect(!program.canUndo(), "failed worker created a native undo entry");
            println("PASS rollback_after_first_mutation");

            try {
                apply(editable, initial, revision(), Fault.CANCEL_AFTER_MARKER, true);
                throw new IllegalStateException("cancelled worker unexpectedly returned");
            }
            catch (CancelledException expected) {
                // The caller's monitor reports cancellation after direct headless invocation.
            }
            verifyPreserved(initial, protectedInitial, "cancel rollback");
            expect(!program.canUndo(), "cancelled worker created a native undo entry");
            println("PASS cancellation_rolls_back_type_and_marker");

            long staleRevision = revision();
            editAnalystComment();
            State edited = state(editable);
            String undoAfterAnalyst = program.getUndoName();
            expect(staleRevision != revision(), "analyst edit did not change revision");
            expect(!apply(editable, initial, staleRevision, Fault.NONE, true),
                   "stale revision was accepted");
            expect(!apply(editable, initial, revision(), Fault.NONE, true),
                   "stale expected values were accepted after revision was refreshed");
            expect(undoAfterAnalyst.equals(program.getUndoName()),
                   "stale proposal replaced the analyst's undo entry");
            verifyPreserved(edited, protectedInitial, "stale guards");
            println("PASS stale_revision_and_expected_values_preserve_analyst_edit");

            expect(!apply(protectedFunction, protectedInitial, revision(), Fault.NONE, true),
                   "protected user-defined signature was accepted");
            expect(undoAfterAnalyst.equals(program.getUndoName()),
                   "protected rejection changed the native undo entry");
            verifyPreserved(edited, protectedInitial, "protected signature");
            println("PASS preexisting_user_defined_signature_preserved");

            expect(apply(editable, edited, revision(), Fault.NONE, true),
                   "valid proposal failed");
            expectIdle("successful apply");
            State applied = state(editable);
            expect(ByteDataType.dataType.getPathName().equals(applied.returnType()),
                   "successful proposal did not apply the return type");
            expect(applied.source() == SourceType.USER_DEFINED,
                   "approved edit did not set user-defined signature source");
            expect(MARKER.equals(applied.marker()), "approved marker was not written");
            expect(edited.comment().equals(applied.comment()), "existing analyst comment changed");
            expect(protectedInitial.equals(state(protectedFunction)), "unrelated protected state changed");
            expect(program.canUndo(), "successful application left no native undo entry");
            println("PASS approved_edits_commit_in_one_worker");

            program.undo();
            verifyPreserved(edited, protectedInitial, "native undo");
            expect(undoAfterAnalyst.equals(program.getUndoName()),
                   "one undo failed to expose the previous analyst action");
            expect(program.canRedo(), "native redo is unavailable");

            program.redo();
            verifyPreserved(applied, protectedInitial, "native redo");
            println("PASS native_undo_redo_preserves_marker_and_analyst_work");

            program.undo();
            try {
                apply(editable, edited, revision(), Fault.CANCEL_AFTER_COMMIT_POINT, true);
                throw new IllegalStateException("late-cancelled worker unexpectedly returned");
            }
            catch (CancelledException expected) {
                // The managed wrapper reports cancellation after committing the dirty state.
            }
            verifyPreserved(applied, protectedInitial, "late cancelled commit");
            expect(program.canUndo(), "late cancellation lost the accepted native undo entry");
            program.undo();
            verifyPreserved(edited, protectedInitial, "late committed edit's native undo");
            println("PASS late_cancellation_reports_cancelled_after_explicit_commit_point");

            int unrelated = program.startTransaction("Unrelated analyst transaction");
            boolean commitUnrelated = false;
            try {
                function(editable).setComment("Unrelated in-flight analyst work");
                try {
                    apply(editable, state(editable), revision(), Fault.NONE, true);
                    throw new IllegalStateException("nested launch unexpectedly passed ownership gate");
                }
                catch (IllegalStateException expected) {
                    expect(expected.getMessage().equals(
                        "worker submission saw a live analysis or unrelated transaction"),
                        "unexpected unrelated transaction failure: " + expected);
                }
                commitUnrelated = true;
            }
            finally {
                program.endTransaction(unrelated, commitUnrelated);
            }
            expect("Unrelated in-flight analyst work".equals(state(editable).comment()),
                   "rejected nesting corrupted unrelated analyst work");
            expect(protectedInitial.equals(state(protectedFunction)), "protected state changed");
            println("PASS refuses_unrelated_open_transaction");
        }
        finally {
            program.release(this);
        }
        println("BINARYRAT_WRITEBACK_TRANSACTION_PROOF_PASS");
    }

    private void setUpFixture() throws Exception {
        int id = program.startTransaction("Disposable baseline");
        boolean commit = false;
        try {
            program.getMemory().createInitializedBlock(".text", editable, 32,
                (byte) 0xc3, monitor, false).setExecute(true);
            var functions = program.getFunctionManager();
            Function target = functions.createFunction("editable", editable,
                new AddressSet(editable), SourceType.USER_DEFINED);
            Function peer = functions.createFunction("protected", protectedFunction,
                new AddressSet(protectedFunction), SourceType.USER_DEFINED);
            program.getUsrPropertyManager().createStringPropertyMap(MAP);
            target.setReturnType(IntegerDataType.dataType, SourceType.ANALYSIS);
            target.setSignatureSource(SourceType.ANALYSIS);
            target.setComment("Preexisting analyst note on editable function");
            peer.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
            peer.setSignatureSource(SourceType.USER_DEFINED);
            peer.setComment("Preexisting analyst note on protected function");
            markers().add(protectedFunction, "preexisting-protected-marker");
            commit = true;
        }
        finally {
            program.endTransaction(id, commit);
        }
    }

    private void editAnalystComment() {
        int id = program.startTransaction("External analyst edit for stale guard");
        boolean commit = false;
        try {
            function(editable).setComment("Later analyst note must survive");
            commit = true;
        }
        finally {
            program.endTransaction(id, commit);
        }
    }

    private void controlWithoutAbortScope(State baseline) throws Exception {
        assertThrowingWorker(() -> apply(editable, baseline, revision(), Fault.FAIL_AFTER_TYPE, false),
                             "forced failure after first mutation");
        expect(ByteDataType.dataType.getPathName().equals(state(editable).returnType()),
               "control did not reproduce a committed mutation after a worker exception");
        expect(program.canUndo(), "control's partial write created no native undo entry");
        program.undo();
        expect(baseline.equals(state(editable)), "control undo did not restore baseline");
        program.clearUndo();
        println("PASS control_worker_without_abort_scope_commits_first_edit");
    }

    private boolean apply(Address address, State expected, long expectedRevision,
                          Fault fault, boolean useAbortScope) throws Exception {
        expectIdle("worker submission");
        TaskMonitorAdapter task = new TaskMonitorAdapter(true);
        return analysis.scheduleWorker(new AnalysisWorker() {
            @Override
            public String getWorkerName() {
                return WORKER;
            }

            @Override
            public boolean analysisWorkerCallback(Program workerProgram, Object context,
                                                  TaskMonitor workerMonitor) throws Exception {
                expect(workerProgram == program && program.getCurrentTransactionInfo() != null,
                       "worker did not enter its managed Program transaction");
                workerMonitor.checkCancelled();
                State current = state(address);
                if (revision() != expectedRevision || !current.equals(expected) ||
                    current.source().isHigherPriorityThan(SourceType.ANALYSIS)) {
                    return false;
                }

                if (!useAbortScope) {
                    return performEdits(address, fault, task, workerMonitor);
                }
                int id = workerProgram.startTransaction("Explicit abort scope");
                boolean commit = false;
                try {
                    performEdits(address, fault, task, workerMonitor);
                    workerMonitor.checkCancelled();
                    commit = true;
                }
                finally {
                    workerProgram.endTransaction(id, commit);
                }
                if (fault == Fault.CANCEL_AFTER_COMMIT_POINT) {
                    task.cancel();
                }
                return true;
            }
        }, null, true, task);
    }

    private boolean performEdits(Address address, Fault fault, TaskMonitorAdapter callerMonitor,
                                 TaskMonitor workerMonitor) throws Exception {
        function(address).setReturnType(ByteDataType.dataType, SourceType.USER_DEFINED);
        if (fault == Fault.FAIL_AFTER_TYPE) {
            throw new IllegalStateException("forced failure after first mutation");
        }
        markers().add(address, MARKER);
        if (fault == Fault.CANCEL_AFTER_MARKER) {
            callerMonitor.cancel();
        }
        workerMonitor.checkCancelled();
        return true;
    }

    private void verifyPreserved(State expectedEditable, State expectedProtected, String label) {
        expectIdle(label);
        expect(expectedEditable.equals(state(editable)), label + " changed editable state: " + state(editable));
        expect(expectedProtected.equals(state(protectedFunction)), label + " changed protected state");
    }

    private void expectIdle(String label) {
        expect(!analysis.isAnalyzing() && program.getCurrentTransactionInfo() == null,
               label + " saw a live analysis or unrelated transaction");
    }

    private State state(Address address) {
        Function function = function(address);
        return new State(function.getPrototypeString(false, true),
                         function.getReturn().getVariableStorage().toString(),
                         function.getReturnType().getPathName(), function.getSignatureSource(),
                         function.getComment(), markers().getString(address));
    }

    private StringPropertyMap markers() {
        return Objects.requireNonNull(program.getUsrPropertyManager().getStringPropertyMap(MAP));
    }

    private Function function(Address address) {
        return Objects.requireNonNull(program.getFunctionManager().getFunctionAt(address));
    }

    private long revision() {
        return program.getModificationNumber();
    }

    private void assertThrowingWorker(ThrowingCall call, String expectedMessage) throws Exception {
        try {
            call.invoke();
            throw new IllegalStateException("worker unexpectedly completed");
        }
        catch (InvocationTargetException reported) {
            expect(expectedMessage.equals(reported.getCause().getMessage()),
                   "unexpected worker exception: " + reported.getCause());
        }
    }

    @FunctionalInterface
    private interface ThrowingCall {
        void invoke() throws Exception;
    }

    private static void expect(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }
}
