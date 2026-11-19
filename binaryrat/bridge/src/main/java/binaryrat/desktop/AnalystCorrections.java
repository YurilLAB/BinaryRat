// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package binaryrat.desktop;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridLayout;
import java.io.IOException;
import java.util.function.Consumer;
import java.util.function.Supplier;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import binaryrat.writeback.CallPrototypeOverride;
import docking.DialogComponentProvider;
import ghidra.app.plugin.core.decompile.PrimaryDecompilerProvider;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;

/** Analyst actions scoped to the Listing instruction shown in BinaryRat's function view. */
final class AnalystCorrections extends JPanel {
    record Selection(Program program, Address functionEntry, Address location, long revision) {}

    private final PluginTool tool;
    private final Supplier<Selection> selection;
    private final JButton pcode = new JButton("Inspect Instruction P-code");
    private final JButton override = new JButton("Override Call Prototype");
    private final JButton interactive = new JButton("Open Interactive Decompiler");
    private final JLabel status = new JLabel(" ");
    private boolean working;

    AnalystCorrections(PluginTool tool, Supplier<Selection> selection) {
        super(new BorderLayout());
        this.tool = tool;
        this.selection = selection;
        pcode.setName("BinaryRat inspect instruction p-code");
        override.setName("BinaryRat override call prototype");
        interactive.setName("BinaryRat open interactive decompiler");
        status.setName("BinaryRat correction status");
        pcode.setToolTipText("Show the raw p-code for the selected Listing instruction");
        override.setToolTipText("Set a prototype for the selected call in the Listing");
        interactive.setToolTipText("Open the selected function and Listing address in Ghidra's decompiler");
        pcode.addActionListener(event -> inspectPcode());
        override.addActionListener(event -> prepareOverride());
        interactive.addActionListener(event -> openInteractive());
        var buttons = new JPanel(new WrapLayout(FlowLayout.LEADING, 5, 5));
        buttons.add(pcode);
        buttons.add(override);
        buttons.add(interactive);
        add(buttons, BorderLayout.NORTH);
        add(status, BorderLayout.SOUTH);
        setActionsAvailable(false);
    }

    void updateActions() {
        setActionsAvailable(selection.get() != null);
    }

    void clearStatus() {
        status.setText(" ");
    }

    private void setActionsAvailable(boolean selected) {
        pcode.setEnabled(selected && !working);
        override.setEnabled(selected && !working);
        interactive.setEnabled(selected);
    }

    private void inspectPcode() {
        var at = selection.get();
        if (at == null || working) {
            return;
        }
        perform(at, "Read Instruction P-code", "P-code unavailable", true,
            monitor -> InstructionPcode.read(at.program(), at.functionEntry(), at.location(),
                at.revision(), monitor),
            evidence -> {
                clearStatus();
                showPcode(evidence);
            });
    }

    private void prepareOverride() {
        var at = selection.get();
        if (at == null || working) {
            return;
        }
        perform(at, "Inspect Call Site", "Override unavailable", true,
            monitor -> CallPrototypeOverride.inspect(at.program(), at.functionEntry(), at.location(),
                at.revision(), monitor),
            candidate -> {
                clearStatus();
                tool.showDialog(new PrototypeDialog(at, candidate), this);
            });
    }

    private void showPcode(InstructionPcode.Snapshot evidence) {
        tool.showDialog(new PcodeDialog(evidence), this);
    }

    private static final class PcodeDialog extends DialogComponentProvider {
        PcodeDialog(InstructionPcode.Snapshot evidence) {
            super("BinaryRat Instruction P-code", false);
            var text = new JTextArea(12, 65);
            text.setName("BinaryRat instruction p-code output");
            text.setEditable(false);
            text.setFont(new Font(Font.MONOSPACED, Font.PLAIN, text.getFont().getSize()));
            text.setText(InstructionPcode.describe(evidence));
            text.setCaretPosition(0);
            addWorkPanel(new JScrollPane(text));
            addDismissButton();
        }
    }

    private void openInteractive() {
        var at = selection.get();
        if (at == null) {
            return;
        }
        var decompiler = tool.getWindowManager().getComponentProvider(PrimaryDecompilerProvider.class);
        if (decompiler == null) {
            status.setText("Enable Ghidra's Decompiler plugin in CodeBrowser.");
            return;
        }
        if (decompiler.getProgram() != at.program()) {
            status.setText("Wait for the interactive decompiler to switch to the selected Program.");
            return;
        }
        if (decompiler.goTo(at.program(), new ProgramLocation(at.program(), at.location()))) {
            decompiler.setVisible(true);
            decompiler.toFront();
            clearStatus();
        }
        else {
            status.setText("Could not open the selected instruction in the interactive decompiler.");
        }
    }

    private final class PrototypeDialog extends DialogComponentProvider {
        private final Selection at;
        private final CallPrototypeOverride.Candidate candidate;
        private final JTextField signature;
        private final JComboBox<String> convention;

        PrototypeDialog(Selection at, CallPrototypeOverride.Candidate candidate) {
            super("Override Call Prototype", true);
            this.at = at;
            this.candidate = candidate;
            signature = new JTextField(candidate.suggestedSignature(), 56);
            signature.setName("BinaryRat call prototype signature");
            signature.setToolTipText("Enter a C prototype such as int call_target(int value)");
            convention = new JComboBox<>(candidate.callingConventions().toArray(String[]::new));
            convention.setName("BinaryRat call prototype convention");
            convention.setSelectedItem(candidate.callingConvention());
            convention.setToolTipText("Calling convention the decompiler uses for this call");
            var prompt = new JLabel("C prototype for " + candidate.targetName() + " at " +
                candidate.callSite() + " in " + candidate.callerName());
            prompt.setLabelFor(signature);
            var conventionLabel = new JLabel("Calling convention");
            conventionLabel.setLabelFor(convention);
            var conventionRow = new JPanel(new FlowLayout(FlowLayout.LEADING, 0, 0));
            conventionRow.add(conventionLabel);
            conventionRow.add(Box.createHorizontalStrut(8));
            conventionRow.add(convention);

            var notes = new JPanel(new GridLayout(0, 1, 0, 2));
            var origin = new JLabel(origin(candidate));
            origin.setName("BinaryRat call prototype origin");
            notes.add(origin);
            if (candidate.replacesOverride()) {
                notes.add(new JLabel("Apply replaces the current override at this call. Undo restores it."));
            }
            else {
                notes.add(new JLabel("Applies to this call only. Use Undo to remove it."));
            }
            if (candidate.directFixedArguments()) {
                notes.add(new JLabel("To change every call to " + candidate.targetName() +
                    ", edit its function signature instead."));
            }
            var form = new JPanel(new BorderLayout(0, 6));
            var entry = new JPanel(new BorderLayout(0, 4));
            entry.add(prompt, BorderLayout.NORTH);
            entry.add(signature, BorderLayout.CENTER);
            entry.add(conventionRow, BorderLayout.SOUTH);
            form.add(entry, BorderLayout.NORTH);
            form.add(notes, BorderLayout.SOUTH);
            form.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));
            addWorkPanel(form);
            addOKButton();
            setOkButtonText("Apply");
            addCancelButton();
            setFocusComponent(signature);
        }

        private static String origin(CallPrototypeOverride.Candidate candidate) {
            return switch (candidate.suggestionSource()) {
                case EXISTING_OVERRIDE -> "Showing the override already at this call.";
                case DECOMPILER -> "Suggested from the decompiler's current view of this call.";
                case CALLEE -> "Suggested from the signature of " + candidate.targetName() + ".";
                case NONE -> "No suggestion. For example: int call_target(int value)";
            };
        }

        @Override
        protected void okCallback() {
            if (!at.equals(selection.get()) || working) {
                setStatusText("The selection or Program changed. Reopen the override from the Listing.");
                return;
            }
            String value = signature.getText();
            String chosen = (String) convention.getSelectedItem();
            close();
            perform(at, "Write Call Prototype", "Override failed", false,
                monitor -> CallPrototypeOverride.apply(at.program(), candidate, value, chosen, monitor),
                result -> status.setText("Call prototype override " +
                    (result.replacedOverride() ? "replaced" : "applied") + " at " + candidate.callSite() +
                    ". Use Undo to revert." + (result.committedAfterCancellation() ?
                        " The write committed before cancellation." : "")));
        }
    }

    @FunctionalInterface
    private interface Operation<T> {
        T run(TaskMonitor monitor) throws Exception;
    }

    private <T> void perform(Selection at, String title, String failure, boolean stillSelected,
            Operation<T> operation, Consumer<T> onSuccess) {
        working = true;
        status.setText(title + " at " + at.location() + "…");
        updateActions();
        TaskLauncher.launch(new Task(title, true, false, false) {
            @Override
            public void run(TaskMonitor monitor) {
                Runnable finish;
                try {
                    monitor.checkCancelled();
                    if (!at.program().addConsumer(this)) {
                        throw new IOException("The selected Program is closed");
                    }
                    try {
                        T result = operation.run(monitor);
                        if (stillSelected) {
                            monitor.checkCancelled();
                        }
                        finish = () -> onSuccess.accept(result);
                    }
                    finally {
                        at.program().release(this);
                    }
                }
                catch (CancelledException cancelled) {
                    finish = () -> status.setText(title + " cancelled.");
                }
                catch (Exception error) {
                    String message = error.getMessage();
                    if (message == null || message.isBlank()) {
                        message = error.getClass().getSimpleName();
                    }
                    String detail = message.length() > 220 ? message.substring(0, 220) + "…" : message;
                    finish = () -> status.setText(failure + ": " + detail);
                }
                Runnable outcome = finish;
                SwingUtilities.invokeLater(() -> {
                    working = false;
                    updateActions();
                    var programs = tool.getService(ProgramManager.class);
                    if (programs == null || programs.getCurrentProgram() != at.program()) {
                        return;
                    }
                    if (stillSelected && !at.equals(selection.get())) {
                        status.setText("The selection or Program changed.");
                        return;
                    }
                    outcome.run();
                });
            }
        });
    }
}
