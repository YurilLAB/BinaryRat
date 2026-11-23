// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package binaryrat.desktop;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.io.IOException;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JTextArea;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingUtilities;

import binaryrat.SummaryLayouts;
import binaryrat.writeback.LayoutEvidenceTable;
import binaryrat.writeback.SummaryLayoutEvidenceBrowser;
import binaryrat.writeback.SummaryLayoutWriteBack;
import binaryrat.writeback.SummaryLayoutWriteBack.Prepared;
import docking.DialogComponentProvider;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;

/** Runs a live summary review from CodeBrowser and confirms a single guarded parameter write. */
final class SummaryLayoutCursor {
    static final String ACTION = "Recover Summary Layout at Cursor";
    private static final int TIMEOUT_SECONDS = 30;
    private final PluginTool tool;
    private boolean working;

    SummaryLayoutCursor(PluginTool tool) {
        this.tool = tool;
    }

    void show(ProgramLocation location) {
        if (location == null) {
            return;
        }
        if (working) {
            tool.setStatusInfo("A summary layout operation is in progress.");
            return;
        }
        Program program = location.getProgram();
        if (!active(program) || !LayoutEvidenceTable.supported(tool)) {
            tool.setStatusInfo("Open an active Program with the CodeBrowser table and navigation services.");
            return;
        }
        long revision = program.getModificationNumber();
        Function function = program.getFunctionManager().getFunctionContaining(location.getAddress());
        if (!SummaryLayouts.supportedFunction(program, function)) {
            tool.setStatusInfo("Select a local function within the 64 KiB body limit.");
            return;
        }
        tool.showDialog(new SelectionDialog(program, function, revision));
    }

    private boolean active(Program program) {
        var manager = tool.getService(ProgramManager.class);
        return manager != null && !program.isClosed() && manager.getCurrentProgram() == program;
    }

    private boolean current(Program program, long revision) {
        return active(program) && program.getModificationNumber() == revision;
    }

    private final class SelectionDialog extends DialogComponentProvider {
        private final Program program;
        private final Function function;
        private final long revision;
        private final JSpinner parameter = new JSpinner(new SpinnerNumberModel(0, 0, 255, 1));

        SelectionDialog(Program program, Function function, long revision) {
            super(ACTION, true);
            this.program = program;
            this.function = function;
            this.revision = revision;
            parameter.setName("BinaryRat summary parameter index");
            var panel = new JPanel(new BorderLayout(6, 6));
            panel.add(new JLabel("Function " + function.getName(true) + " at " +
                function.getEntryPoint().toString(true)), BorderLayout.NORTH);
            var label = new JLabel("Zero-based parameter index");
            label.setLabelFor(parameter);
            panel.add(label, BorderLayout.WEST);
            panel.add(parameter, BorderLayout.CENTER);
            addWorkPanel(panel);
            addOKButton();
            setOkButtonText("Recover");
            addCancelButton();
        }

        @Override
        protected void okCallback() {
            if (!current(program, revision) || working) {
                setStatusText("The Program changed. Select the function again.");
                return;
            }
            try {
                parameter.commitEdit();
            }
            catch (java.text.ParseException failure) {
                setStatusText("Enter a parameter index from 0 to 255.");
                return;
            }
            int index = (Integer) parameter.getValue();
            close();
            recover(program, function, revision, index);
        }
    }

    private void recover(Program program, Function function, long revision, int parameter) {
        launch(program, "Recover Summary Layout", monitor -> {
            if (!current(program, revision)) {
                throw new IOException("The Program changed. Select the function again");
            }
            if (AutoAnalysisManager.getAnalysisManager(program).isAnalyzing()) {
                throw new IOException("Wait for Ghidra analysis to finish");
            }
            monitor.setMessage("Following pointer arguments through direct calls…");
            var recovered = SummaryLayoutWriteBack.recover(program, function, parameter,
                TIMEOUT_SECONDS, SummaryLayouts.DEFAULT_SUMMARIES, monitor);
            monitor.setMessage("Checking cited instructions against the open Program…");
            var view = SummaryLayoutEvidenceBrowser.read(program, recovered.report(), monitor);
            if (view.evidence().rows().isEmpty()) {
                return "BinaryRat found no exact field evidence. " + view.status();
            }
            Prepared prepared = recovered.proposal();
            Address entry = function.getEntryPoint();
            Runnable review = prepared == null ? null : () -> confirm(program, entry, prepared);
            String refusal = prepared == null ? "Apply unavailable: " + recovered.refusal() + "." : "";
            LayoutEvidenceTable.showSummary(tool, program, view, review, refusal, monitor);
            return null;
        });
    }

    private void confirm(Program program, Address entry, Prepared prepared) {
        if (!current(program, prepared.review().revision())) {
            tool.setStatusInfo("The Program changed. Recover the layout again.");
            return;
        }
        if (!working) {
            tool.showDialog(new ReviewDialog(program, entry, prepared));
        }
    }

    private final class ReviewDialog extends DialogComponentProvider {
        private final Program program;
        private final Prepared prepared;

        ReviewDialog(Program program, Address entry, Prepared prepared) {
            super(LayoutEvidenceTable.REVIEW_ACTION, true);
            this.program = program;
            this.prepared = prepared;
            var review = prepared.review();
            var text = new StringBuilder()
                .append("Program ").append(program.getName()).append('\n')
                .append("Function ").append(review.functionName()).append(" at ")
                .append(entry.toString(true)).append(", parameter ")
                .append(review.parameterIndex()).append('\n')
                .append("Current type  ").append(review.originalType()).append('\n')
                .append("Proposed pointer to  ").append(review.destination()).append('\n')
                .append("Minimum observed extent  ").append(review.minimumExtent()).append(" bytes\n\n")
                .append("Observed fields\n");
            for (var field : review.fields()) {
                text.append("  +0x").append(Integer.toHexString(field.offset())).append("    ")
                    .append(field.width()).append(field.width() == 1 ? " byte" : " bytes")
                    .append("    ").append(field.support())
                    .append(field.support() == 1 ? " observation" : " observations")
                    .append("    ").append(String.join(", ", field.sites())).append('\n');
            }
            text.append("\nApply creates the structure with undefined field types and updates this parameter.\n")
                .append("The signature becomes user-defined. One Undo reverts the complete change.");
            var details = new JTextArea(text.toString(), 14, 65);
            details.setName("BinaryRat reviewed summary layout");
            details.setEditable(false);
            details.setLineWrap(true);
            details.setWrapStyleWord(true);
            details.setCaretPosition(0);
            var scroll = new JScrollPane(details);
            scroll.setPreferredSize(new Dimension(660, 270));
            addWorkPanel(scroll);
            addOKButton();
            setOkButtonText("Apply");
            addCancelButton();
        }

        @Override
        protected void okCallback() {
            if (!current(program, prepared.review().revision()) || working) {
                setStatusText("The Program changed. Recover the layout again.");
                return;
            }
            close();
            launch(program, "Apply Reviewed Parameter Type", monitor -> {
                if (!current(program, prepared.review().revision())) {
                    throw new IOException("The Program changed. Recover the layout again");
                }
                var result = SummaryLayoutWriteBack.apply(program, prepared, monitor);
                return "Applied " + result.dataTypePath() + ". Use Undo to revert." +
                    (result.committedAfterCancellation() ? " The write committed before cancellation." : "");
            });
        }
    }

    @FunctionalInterface
    private interface Work {
        String run(TaskMonitor monitor) throws Exception;
    }

    private void launch(Program program, String title, Work work) {
        working = true;
        TaskLauncher.launch(new Task(title, true, true, false) {
            @Override
            public void run(TaskMonitor monitor) {
                String result;
                try {
                    monitor.checkCancelled();
                    monitor.setIndeterminate(true);
                    if (!program.addConsumer(this)) {
                        throw new IOException("The Program is closed");
                    }
                    try {
                        result = work.run(monitor);
                    }
                    finally {
                        program.release(this);
                    }
                }
                catch (CancelledException cancelled) {
                    result = title + " cancelled.";
                }
                catch (Exception failure) {
                    String detail = failure.getMessage();
                    result = title + " failed: " +
                        (detail == null ? failure.getClass().getSimpleName() : detail);
                }
                String status = result;
                SwingUtilities.invokeLater(() -> {
                    working = false;
                    if (status != null) {
                        tool.setStatusInfo(status);
                    }
                });
            }
        });
    }
}
