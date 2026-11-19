// Browse the instructions cited by a BinaryRat layout report in the current Program.
// @category BinaryRat
// @menupath Tools.BinaryRat.Browse Layout Evidence
// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.SwingUtilities;

import binaryrat.writeback.LayoutEvidenceBrowser;
import binaryrat.writeback.LayoutEvidenceBrowser.Review;
import binaryrat.writeback.LayoutEvidenceTable;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.ProgramManager;
import ghidra.program.model.listing.Program;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.filechooser.ExtensionFileFilter;
import ghidra.util.task.CancelledListener;

public class BinaryRatBrowseLayout extends GhidraScript {
    static final String PICKER_TITLE = "Choose a BinaryRat layout report";

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
        var programs = tool.getService(ProgramManager.class);
        if (!LayoutEvidenceTable.supported(tool)) {
            popup("Open Browse Layout Evidence from a CodeBrowser with table and navigation services.");
            return;
        }

        try {
            Path file = chooseReport();
            // The analyst can switch or close a tab while the file dialog or parser is active.
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
                    LayoutEvidenceTable.show(tool, program, review, monitor);
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
        AtomicReference<GhidraFileChooser> open = new AtomicReference<>();
        CancelledListener cancel = () -> SwingUtilities.invokeLater(() -> {
            GhidraFileChooser chooser = open.get();
            if (chooser != null && chooser.isVisible()) {
                chooser.close();
            }
        });
        monitor.addCancelledListener(cancel);
        try {
            File file = Swing.runNow(() -> {
                if (monitor.isCancelled()) {
                    return null;
                }
                GhidraFileChooser chooser = new GhidraFileChooser(state.getTool().getToolFrame());
                open.set(chooser);
                try {
                    chooser.setTitle(PICKER_TITLE);
                    chooser.setApproveButtonText("Open");
                    chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
                    chooser.setFileFilter(new ExtensionFileFilter("json", "BinaryRat layout reports"));
                    // Recover Layout at Cursor saves to the home folder by default and records
                    // the folder of each new report, which wins over the default.
                    chooser.setCurrentDirectory(new File(System.getProperty("user.home")));
                    chooser.setLastDirectoryPreference(LayoutEvidenceTable.DIRECTORY_PREFERENCE);
                    return chooser.getSelectedFile();
                }
                finally {
                    open.set(null);
                    chooser.dispose();
                }
            });
            monitor.checkCancelled();
            if (file == null) {
                throw new CancelledException();
            }
            return file.toPath();
        }
        finally {
            monitor.removeCancelledListener(cancel);
            // An interrupted runNow caller can return while the modal dialog is still open.
            cancel.cancelled();
        }
    }
}
