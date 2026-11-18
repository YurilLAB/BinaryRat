// Browse the instructions cited by a BinaryRat layout report in the current Program.
// @category BinaryRat
// @menupath Tools.BinaryRat.Browse Layout Evidence
// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0

import java.io.IOException;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

import javax.swing.SwingUtilities;

import binaryrat.writeback.LayoutEvidenceBrowser;
import binaryrat.writeback.LayoutEvidenceBrowser.Review;
import binaryrat.writeback.LayoutEvidenceBrowser.Row;
import docking.DockingWindowManager;
import docking.widgets.dialogs.InputDialog;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.app.tablechooser.AbstractComparableColumnDisplay;
import ghidra.app.tablechooser.AddressableRowObject;
import ghidra.app.tablechooser.TableChooserDialog;
import ghidra.app.util.query.TableService;
import ghidra.framework.model.DomainObjectListener;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.CancelledListener;

public class BinaryRatBrowseLayout extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (isRunningHeadless() || state.getTool() == null) {
            printerr("Browse Layout Evidence requires a CodeBrowser window.");
            return;
        }
        // GhidraScript opens an implicit transaction, including for read-only tools.
        end(true);
        Program program = currentProgram;
        if (program == null) {
            popup("Open an analyzed program before browsing layout evidence.");
            return;
        }
        var tool = state.getTool();
        var tables = tool.getService(TableService.class);
        var programs = tool.getService(ProgramManager.class);
        if (tables == null || programs == null || tool.getService(GoToService.class) == null) {
            popup("Open Browse Layout Evidence from a CodeBrowser with table and navigation services.");
            return;
        }

        try {
            Path file = chooseReport();
            // The analyst can switch or close a tab while the path dialog or parser is active.
            // Keep the selected Program alive only while reading and publishing the result.
            Object consumer = new Object();
            Boolean active = Swing.runNow(() -> programs.getCurrentProgram() == program);
            if (active == null) {
                throw new CancelledException();
            }
            if (!active || !program.addConsumer(consumer)) {
                throw new IOException("The active program changed. Reopen the report in its CodeBrowser.");
            }
            Review review;
            try {
                monitor.setMessage("Checking layout evidence against the open program");
                review = LayoutEvidenceBrowser.read(program, file, monitor);
                monitor.checkCancelled();
                if (!review.rows().isEmpty()) {
                    showEvidence(tables, programs, program, review);
                }
            }
            finally {
                program.release(consumer);
            }
            if (review.rows().isEmpty()) {
                popup("This report has no exact field-access instructions to browse.");
            }
        }
        catch (CancelledException cancelled) {
            // Dismissing the dialog or cancelling a load leaves no partial table.
        }
        catch (IOException | IllegalArgumentException e) {
            popup("Could not open the layout evidence. " + e.getMessage());
        }
    }

    private Path chooseReport() throws CancelledException {
        AtomicReference<InputDialog> open = new AtomicReference<>();
        CancelledListener cancel = () -> SwingUtilities.invokeLater(() -> {
            InputDialog dialog = open.get();
            if (dialog != null && dialog.isVisible()) {
                dialog.close();
            }
        });
        monitor.addCancelledListener(cancel);
        try {
            String file = Swing.runNow(() -> {
                if (monitor.isCancelled()) {
                    return null;
                }
                InputDialog dialog = new InputDialog("Choose a BinaryRat layout report",
                    "Layout JSON path");
                open.set(dialog);
                try {
                    DockingWindowManager.showDialog(state.getTool().getToolFrame(), dialog);
                    return dialog.isCanceled() ? null : dialog.getValue();
                }
                finally {
                    open.set(null);
                    dialog.dispose();
                }
            });
            monitor.checkCancelled();
            if (file == null) {
                throw new CancelledException();
            }
            if (file.isBlank()) {
                throw new IllegalArgumentException("Enter the path to a saved JSON layout report.");
            }
            return Path.of(file);
        }
        finally {
            monitor.removeCancelledListener(cancel);
            // An interrupted runNow caller can return while the modal dialog is still open.
            cancel.cancelled();
        }
    }

    private void showEvidence(TableService tables, ProgramManager programs, Program program,
            Review review) throws IOException, CancelledException {
        long revision = review.revision();
        String title = "BinaryRat Layout Evidence — " + review.functionName() +
            " (parameter " + review.parameterIndex() + ")";
        AtomicReference<TableChooserDialog> created = new AtomicReference<>();
        var tool = state.getTool();
        DomainObjectListener changed = event -> {
            if (program.getModificationNumber() != revision) {
                Swing.runIfSwingOrRunLater(() -> {
                    TableChooserDialog table = created.get();
                    if (table != null && table.isVisible()) {
                        table.close();
                        tool.setStatusInfo("Layout evidence closed after a program change.");
                    }
                });
            }
        };
        boolean shown = false;
        try {
            TableChooserDialog table = Swing.runNow(() -> {
                TableChooserDialog dialog = tables.createTableChooserDialog(null, program, title, null, false);
                created.set(dialog);
                addColumn(dialog, "Offset", Integer.class, Row::offset);
                addColumn(dialog, "Width", Integer.class, Row::width);
                addColumn(dialog, "Access", String.class, Row::operation);
                addColumn(dialog, "Function", String.class, Row::functionName);
                addColumn(dialog, "P-code order", Long.class, Row::pcodeOrder);
                addColumn(dialog, "Overlaps", Boolean.class, Row::overlaps);
                addColumn(dialog, "Instruction bytes", String.class,
                    row -> row.instructionBytesVerified() ? "Verified" : "Unrecorded");
                return dialog;
            });
            if (table == null) {
                throw new CancelledException();
            }

            // TableChooserDialog accepts rows from a worker thread and filters/sorts asynchronously.
            for (Row row : review.rows()) {
                monitor.checkCancelled();
                table.add(new EvidenceRow(row));
            }

            Boolean visible = Swing.runNow(() -> {
                if (monitor.isCancelled() || programs.getCurrentProgram() != program || program.isClosed()) {
                    return false;
                }
                table.setClosedListener(() -> program.removeListener(changed));
                program.addListener(changed);
                if (program.getModificationNumber() != revision) {
                    return false;
                }
                table.setStatusText("Double-click an instruction to open it in the Listing.");
                table.show();
                return true;
            });
            monitor.checkCancelled();
            if (visible == null) {
                throw new CancelledException();
            }
            if (!visible) {
                throw new IOException("The active program changed. Reopen the report to check its evidence.");
            }
            shown = true;
        }
        finally {
            if (!shown) {
                // Run after any late creation or publication callback, even if this worker
                // has already been interrupted. The EDT owns both listener and dialog cleanup.
                SwingUtilities.invokeLater(() -> {
                    program.removeListener(changed);
                    TableChooserDialog table = created.getAndSet(null);
                    if (table != null) {
                        table.close();
                    }
                });
            }
        }
    }

    private record EvidenceRow(Row source) implements AddressableRowObject {
        @Override
        public Address getAddress() {
            return source.address();
        }
    }

    private static <T extends Comparable<T>> void addColumn(TableChooserDialog table, String name,
            Class<T> type, Function<Row, T> value) {
        table.addCustomColumn(new AbstractComparableColumnDisplay<T>() {
            @Override
            public String getColumnName() {
                return name;
            }

            @Override
            public Class<T> getColumnClass() {
                return type;
            }

            @Override
            public T getColumnValue(AddressableRowObject object) {
                return value.apply(((EvidenceRow) object).source());
            }
        });
    }
}
