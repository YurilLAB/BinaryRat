// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package guifixture;

import java.awt.Component;
import java.awt.Container;
import java.awt.Rectangle;
import java.awt.Window;
import java.awt.event.MouseEvent;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.function.Predicate;
import java.util.stream.Stream;
import javax.swing.*;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import docking.ComponentProvider;
import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.GhidraScriptService;
import ghidra.app.services.ProgramManager;
import ghidra.base.help.GhidraHelpService;
import ghidra.base.project.GhidraProject;
import ghidra.framework.Application;
import ghidra.framework.GhidraApplicationConfiguration;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.util.table.field.AddressBasedLocation;
import ghidra.util.task.Task;
import ghidra.util.task.TaskListener;
import ghidra.util.task.TaskMonitor;
import ghidra.util.extensions.ExtensionUtils;

/** Run the shipped scripts through the actual Script Manager in a visible CodeBrowser. */
public class LayoutNavigationProbe implements GhidraLaunchable {
    @Override
    public void launch(GhidraApplicationLayout layout, String[] args) {
        try {
            GhidraApplicationConfiguration config = new GhidraApplicationConfiguration();
            config.setShowSplashScreen(false);
            Application.initializeApplication(layout, config);
            GhidraHelpService.install();
            ExtensionUtils.initializeExtensions();
            Preferences.setProperty("SHOW_TIPS", "false");
            GhidraProject project = GhidraProject.openProject(args[0], "layout", true);
            PluginTool tool = swing(() -> {
                // The stock test tool explicitly adds the foreground plugin below.
                // A new extension can prompt to configure it before this launch returns.
                new Timer(100, event -> {
                    JDialog notice = dialog("New Plugins Found!");
                    if (notice != null) {
                        widget(notice, JButton.class, button -> "No".equals(button.getText()))
                            .doClick(0);
                    }
                }).start();
                FrontEndTool front = new FrontEndTool(project.getProjectManager());
                front.setActiveProject(project.getProject());
                front.setVisible(true);
                var file = project.getProject().getProjectData().getFile("/" + args[1]);
                return project.getProject().getToolServices().launchDefaultTool(List.of(file));
            });
            inspect(tool, Path.of(args[2]));
            System.exit(0);
        }
        catch (Throwable error) {
            error.printStackTrace();
            System.exit(1);
        }
    }

    private static <T> T swing(Callable<T> evaluate) throws Exception {
        FutureTask<T> task = new FutureTask<>(evaluate);
        SwingUtilities.invokeAndWait(task);
        return task.get();
    }

    private static <T> T await(String label, Callable<T> query) throws Exception {
        long end = System.nanoTime() + 80_000_000_000L;
        while (System.nanoTime() < end) {
            T value = swing(query);
            if (value != null) {
                return value;
            }
            Thread.sleep(100);
        }
        throw new AssertionError("Timed out awaiting " + label + ". Visible dialogs: " +
            swing(() -> Arrays.stream(Window.getWindows()).filter(Window::isShowing)
                .filter(JDialog.class::isInstance).map(JDialog.class::cast).map(JDialog::getTitle).toList()));
    }

    private static JDialog dialog(String title) {
        return Arrays.stream(Window.getWindows()).filter(Window::isShowing)
            .filter(JDialog.class::isInstance).map(JDialog.class::cast)
            .filter(d -> d.getTitle().startsWith(title)).findFirst().orElse(null);
    }

    private static Stream<Component> descendants(Component component) {
        if (component instanceof Container container) {
            return Stream.concat(Stream.of(component), Arrays.stream(container.getComponents())
                .flatMap(LayoutNavigationProbe::descendants));
        }
        return Stream.of(component);
    }

    private static <T extends Component> T widget(JDialog dialog, Class<T> type, Predicate<T> match) {
        return descendants(dialog).filter(Component::isShowing).filter(type::isInstance)
            .map(type::cast).filter(match).findFirst().orElseThrow();
    }

    private static CountDownLatch script(PluginTool tool, String name) throws Exception {
        CountDownLatch done = new CountDownLatch(1);
        swing(() -> {
            tool.getService(GhidraScriptService.class).runScript(name, new TaskListener() {
                public void taskCompleted(Task task) { done.countDown(); }
                public void taskCancelled(Task task) { done.countDown(); }
            });
            return null;
        });
        return done;
    }

    private static void inspect(PluginTool tool, Path report) throws Exception {
        Program program = await("CodeBrowser Program",
            () -> tool.getService(ProgramManager.class).getCurrentProgram());
        CodeViewerService listing = tool.getService(CodeViewerService.class);
        Address entry = program.getSymbolTable().getGlobalSymbols("read_packed").getFirst().getAddress();
        Address interior = program.getListing().getInstructionAfter(entry).getAddress();
        if (!program.getFunctionManager().getFunctionAt(entry).getBody().contains(interior)) {
            throw new AssertionError("Fixture needs an interior instruction in read_packed");
        }
        swing(() -> listing.goTo(new ProgramLocation(program, interior), true));
        await("interior Listing location", () -> (interior.equals(listing.getCurrentLocation().getAddress()) ?
            Boolean.TRUE : null));
        long recoveryStart = System.nanoTime();
        CountDownLatch recovery = script(tool, "BinaryRatRecoverLayouts.java");
        JDialog options = await("parameter options", () -> dialog("Recover Layout at Cursor"));
        swing(() -> {
            // The dialog lists the Listing's parameters to help choose an index.
            if (descendants(options).filter(JLabel.class::isInstance).map(c -> ((JLabel) c).getText())
                    .filter(text -> text != null).map(text -> text.replace("&nbsp;", " ").replaceAll("<[^>]*>", " "))
                    .noneMatch(text -> text.contains("0: PackedRecord * record"))) {
                throw new AssertionError("Recover Layout at Cursor did not list the parameters");
            }
            widget(options, JTextField.class, w -> w.getText().endsWith(".json")).setText(report.toString());
            widget(options, JButton.class, b -> b.getText().equals("OK")).doClick();
            return null;
        });
        await("published GUI recovery report", () -> Files.isRegularFile(report) ? Boolean.TRUE : null);
        // Recovery opens the new report's evidence table directly.
        JDialog recovered = await("evidence table opened by recovery", () -> dialog("BinaryRat Layout Evidence"));
        if (!recovery.await(10, TimeUnit.SECONDS)) {
            throw new AssertionError("Recovery script did not finish after publishing");
        }
        double recoverSeconds = (System.nanoTime() - recoveryStart) / 1e9;
        JsonObject raw = JsonParser.parseString(Files.readString(report)).getAsJsonObject();
        if (!"read_packed".equals(raw.getAsJsonObject("function").get("name").getAsString()) ||
                raw.get("parameter_index").getAsInt() != 0 ||
                raw.get("revision").getAsLong() != program.getModificationNumber()) {
            throw new AssertionError("Recovery selected the wrong function, parameter, or revision");
        }
        JsonObject load = raw.getAsJsonArray("observations").asList().stream()
            .map(v -> v.getAsJsonObject()).filter(o -> o.get("offset").getAsInt() == 1 &&
                o.get("width").getAsInt() == 4 && o.get("operation").getAsString().equals("LOAD"))
            .findFirst().orElseThrow();
        Address evidence = program.getAddressFactory().getAddressSpace(load.get("address_space").getAsString())
            .getAddress(Long.parseUnsignedLong(load.get("address").getAsString(), 16));
        byte[] bytes = program.getListing().getInstructionAt(evidence).getParsedBytes();
        String expected = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        if (!expected.equals(load.get("instruction_sha256").getAsString())) {
            throw new AssertionError("Cited instruction bytes differ from the active Listing");
        }
        if (evidence.equals(entry)) {
            throw new AssertionError("Fixture needs distinct navigation addresses");
        }
        String disassembly = program.getListing().getInstructionAt(evidence).toString();
        await("recovered evidence row", () -> evidenceRow(recovered, evidence, disassembly) >= 0 ? Boolean.TRUE : null);
        swing(() -> {
            widget(recovered, JButton.class, b -> "Dismiss".equals(b.getText())).doClick();
            return null;
        });
        await("recovered evidence table dismissed", () -> recovered.isShowing() ? null : Boolean.TRUE);
        swing(() -> listing.goTo(new ProgramLocation(program, entry), true));
        await("distinct starting address", () -> entry.equals(listing.getCurrentLocation().getAddress()) ?
            Boolean.TRUE : null);
        CountDownLatch interrupted = script(tool, "BinaryRatBrowseLayout.java");
        JDialog picker = await("interruptible report picker", () -> dialog("Choose a BinaryRat layout report"));
        // Inject an interruption only into this script's worker while it awaits Swing.
        List<Thread> workers = Thread.getAllStackTraces().entrySet().stream()
            .filter(e -> "BinaryRatBrowseLayout.java".equals(e.getKey().getName()))
            .filter(e -> Arrays.stream(e.getValue()).anyMatch(frame ->
                "BinaryRatBrowseLayout".equals(frame.getClassName()) && "chooseReport".equals(frame.getMethodName())))
            .map(e -> e.getKey()).toList();
        if (workers.size() != 1) {
            throw new AssertionError("Cannot identify the single active Browse script worker");
        }
        workers.getFirst().interrupt();
        await("interrupted picker dismissed", () -> picker.isShowing() ? null : Boolean.TRUE);
        if (!interrupted.await(10, TimeUnit.SECONDS) || swing(() -> dialog("BinaryRat Layout Evidence")) != null) {
            throw new AssertionError("Interrupted browse left an active script or result table");
        }
        long browseStart = System.nanoTime();
        CountDownLatch browse = script(tool, "BinaryRatBrowseLayout.java");
        JDialog open = await("report picker", () -> dialog("Choose a BinaryRat layout report"));
        swing(() -> {
            widget(open, JTextField.class, w -> "filenameTextField".equals(w.getName())).setText(report.toString());
            widget(open, JButton.class, b -> "Open".equals(b.getText())).doClick();
            return null;
        });
        JDialog evidenceTable = await("layout evidence table", () -> dialog("BinaryRat Layout Evidence"));
        await("evidence row", () -> {
            JTable table = widget(evidenceTable, JTable.class, t -> true);
            int column = table.getColumnModel().getColumnIndex("Location");
            int row = evidenceRow(evidenceTable, evidence, disassembly);
            if (row >= 0) {
                if (evidence.equals(listing.getCurrentLocation().getAddress())) {
                    throw new AssertionError("Listing already at evidence before row activation");
                }
                Rectangle cell = table.getCellRect(row, column, true);
                for (int clicks = 1; clicks <= 2; clicks++) {
                    for (int event : new int[] { MouseEvent.MOUSE_PRESSED, MouseEvent.MOUSE_RELEASED,
                            MouseEvent.MOUSE_CLICKED }) {
                        table.dispatchEvent(new MouseEvent(table, event, System.currentTimeMillis(), 0,
                            cell.x + cell.width / 2, cell.y + cell.height / 2, clicks, false, MouseEvent.BUTTON1));
                    }
                }
                return Boolean.TRUE;
            }
            return null;
        });
        await("CodeBrowser navigating to the cited instruction", () -> {
            ProgramLocation loc = listing.getCurrentLocation();
            return loc != null && loc.getProgram() == program && evidence.equals(loc.getAddress()) ?
                Boolean.TRUE : null;
        });
        if (!browse.await(10, TimeUnit.SECONDS)) {
            throw new AssertionError("Nonmodal browser script did not finish after displaying results");
        }
        double browseSeconds = (System.nanoTime() - browseStart) / 1e9;
        if (program.isChanged()) {
            throw new AssertionError("Recovering or browsing evidence dirtied the opened Program");
        }
        inspectForeground(tool, program, listing, entry, interior);
        if (!swing(evidenceTable::isShowing)) {
            throw new AssertionError("Evidence table closed before the fixture edit");
        }
        try (var transaction = program.openTransaction("Diagnostic edit on disposable fixture")) {
            program.getBookmarkManager().setBookmark(entry, "Note", "GUI probe", "Test stale evidence closure");
        }
        await("table closing after fixture edit", () -> !evidenceTable.isShowing() ? Boolean.TRUE : null);
        CountDownLatch cancelled = script(tool, "BinaryRatRecoverLayouts.java");
        JDialog again = await("second parameter dialog", () -> dialog("Recover Layout at Cursor"));
        swing(() -> {
            widget(again, JButton.class, b -> "Cancel".equals(b.getText())).doClick();
            return null;
        });
        if (!cancelled.await(10, TimeUnit.SECONDS) || swing(() -> dialog("Save BinaryRat Layout Report")) != null) {
            throw new AssertionError("Cancelled recovery still active or displayed the destination picker");
        }
        System.out.printf(Locale.ROOT, "BINARYRAT_GUI_NAVIGATION_OK %s %s %s %.3f %.3f%n",
            entry, interior, evidence, recoverSeconds, browseSeconds);
    }

    /** The row citing an instruction, checked for its verified bytes, hex offset and disassembly. */
    private static int evidenceRow(JDialog dialog, Address evidence, String disassembly) {
        JTable table = widget(dialog, JTable.class, t -> true);
        var columns = table.getColumnModel();
        for (int row = 0; row < table.getRowCount(); row++) {
            Object location = table.getValueAt(row, columns.getColumnIndex("Location"));
            if (!(location instanceof AddressBasedLocation address) || !evidence.equals(address.getAddress())) {
                continue;
            }
            if (!"Verified".equals(table.getValueAt(row, columns.getColumnIndex("Instruction bytes")))) {
                throw new AssertionError("Evidence row is missing an instruction byte verification");
            }
            if (!"+0x1".equals(String.valueOf(table.getValueAt(row, columns.getColumnIndex("Offset")))) ||
                    !disassembly.equals(table.getValueAt(row, columns.getColumnIndex("Instruction")))) {
                throw new AssertionError("Evidence row lacks its hex offset or disassembly");
            }
            return row;
        }
        return -1;
    }

    private static void inspectForeground(PluginTool tool, Program program, CodeViewerService listing,
            Address entry, Address interior) throws Exception {
        ProgramManager manager = tool.getService(ProgramManager.class);
        var baselineOwners = new IdentityHashMap<Object, Boolean>();
        program.getConsumerList().forEach(owner -> baselineOwners.put(owner, Boolean.TRUE));
        var otherAddress = program.getSymbolTable().getGlobalSymbols("forward_packed")
            .getFirst().getAddress();
        var file = program.getDomainFile();
        var copy = file.copyTo(file.getParent().createFolder("foreground-other"), TaskMonitor.DUMMY);
        ComponentProvider view = swing(() -> {
            ComponentProvider existing = tool.getWindowManager().getComponentProvider("BinaryRat Function");
            if (existing == null) {
                tool.addPlugin("binaryrat.desktop.BinaryRatForegroundPlugin");
                existing = tool.getWindowManager().getComponentProvider("BinaryRat Function");
            }
            listing.goTo(new ProgramLocation(program, entry), true);
            existing.setVisible(true);
            return existing;
        });
        long firstMillis = awaitForeground(view, "read_packed");
        var sessionOwners = program.getConsumerList().stream()
            .filter(owner -> owner.getClass() == Object.class && !baselineOwners.containsKey(owner))
            .toList();
        if (sessionOwners.size() != 1) {
            throw new AssertionError("Expected a Program owner for the first foreground session");
        }
        swing(() -> {
            listing.goTo(new ProgramLocation(program, interior), true);
            if (!foregroundStatus(view).getText().startsWith("Ready: read_packed")) {
                throw new AssertionError("Moving inside the function restarted decompilation");
            }
            return null;
        });

        // Hold a Program transaction without edits. The request must wait with progress
        // instead of racing the writer. Navigate away while it waits to supersede it.
        int transaction = program.startTransaction("Hold fixture for foreground cancellation");
        try {
            swing(() -> listing.goTo(new ProgramLocation(program, otherAddress), true));
            await("foreground waiting for stable Program", () ->
                foregroundStatus(view).getText().startsWith("Waiting for Ghidra") ? Boolean.TRUE : null);
            swing(() -> {
                listing.goTo(new ProgramLocation(program, entry), true);
                descendants(view.getComponent()).filter(JButton.class::isInstance)
                    .map(JButton.class::cast).filter(button -> "Cancel".equals(button.getText()))
                    .findFirst().orElseThrow().doClick(0);
                if (!foregroundStatus(view).getText().contains("cancelled") ||
                    !foregroundOutput(view).getText().isEmpty()) {
                    throw new AssertionError("Cancelled request left a stale foreground result");
                }
                foregroundLimit(view).setValue(1);
                listing.goTo(new ProgramLocation(program, otherAddress), true);
                return null;
            });
            await("foreground request budget expiring", () ->
                foregroundStatus(view).getText().contains("limit reached") &&
                    foregroundOutput(view).getText().isEmpty() ? Boolean.TRUE : null);
        }
        finally {
            program.endTransaction(transaction, true);
        }
        swing(() -> {
            foregroundLimit(view).setValue(30);
            descendants(view.getComponent()).filter(JButton.class::isInstance)
                .map(JButton.class::cast).filter(button -> "Refresh".equals(button.getText()))
                .findFirst().orElseThrow().doClick(0);
            return null;
        });
        long secondMillis = awaitForeground(view, "forward_packed");
        if (program.isChanged()) {
            throw new AssertionError("Foreground inspection dirtied the active Program");
        }

        Program second = swing(() -> manager.openProgram(copy));
        if (second == null || second == program) {
            throw new AssertionError("Could not open the independent foreground test tab");
        }
        await("inactive tab releasing BinaryRat session", () ->
            manager.getCurrentProgram() == second && sessionOwners.stream().noneMatch(program::isUsedBy) ?
                Boolean.TRUE : null);
        swing(() -> {
            view.setVisible(false);
            if (!manager.closeProgram(second, true)) {
                throw new AssertionError("Could not close the disposable foreground test tab");
            }
            manager.setCurrentProgram(program);
            listing.goTo(new ProgramLocation(program, entry), true);
            return null;
        });
        System.out.printf(Locale.ROOT, "BINARYRAT_GUI_FOREGROUND_OK %d %d 2%n", firstMillis, secondMillis);
    }

    private static long awaitForeground(ComponentProvider view, String function) throws Exception {
        long started = System.nanoTime();
        await("foreground output for " + function, () ->
            foregroundStatus(view).getText().startsWith("Ready: " + function + " at ") &&
                foregroundOutput(view).getText().contains(function + "(") ? Boolean.TRUE : null);
        return TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);
    }

    private static JLabel foregroundStatus(ComponentProvider view) {
        return descendants(view.getComponent()).filter(JLabel.class::isInstance).map(JLabel.class::cast)
            .filter(label -> "BinaryRat foreground status".equals(label.getName())).findFirst().orElseThrow();
    }

    private static JTextArea foregroundOutput(ComponentProvider view) {
        return descendants(view.getComponent()).filter(JTextArea.class::isInstance).map(JTextArea.class::cast)
            .filter(area -> "BinaryRat foreground C".equals(area.getName())).findFirst().orElseThrow();
    }

    private static JSpinner foregroundLimit(ComponentProvider view) {
        return descendants(view.getComponent()).filter(JSpinner.class::isInstance).map(JSpinner.class::cast)
            .findFirst().orElseThrow();
    }
}
