// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package guifixture;

import java.awt.Component;
import java.awt.Container;
import java.awt.Rectangle;
import java.awt.Window;
import java.awt.event.KeyEvent;
import java.awt.event.MouseEvent;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.function.Predicate;
import java.util.stream.Stream;
import javax.swing.*;
import javax.swing.event.TableModelListener;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import docking.ComponentProvider;
import docking.DefaultActionContext;
import docking.DockingDialog;
import docking.action.DockingActionIf;
import docking.widgets.EventTrigger;
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
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
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
        // The dialog lists the Listing's parameters to help choose an index. Stripped and
        // debug-info fixtures differ (param_1 versus record), so read the expected entry here.
        Parameter[] parameters = program.getFunctionManager().getFunctionAt(entry).getParameters();
        String listed = parameters.length == 0 ? "The Listing signature has no parameters" :
            "0: " + parameters[0].getDataType().getDisplayName() + " " + parameters[0].getName();
        swing(() -> {
            if (descendants(options).filter(JLabel.class::isInstance).map(c -> ((JLabel) c).getText())
                    .filter(text -> text != null).map(LayoutNavigationProbe::plain)
                    .noneMatch(text -> text.contains(listed))) {
                throw new AssertionError("Recover Layout at Cursor did not list the parameters: " + listed);
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
                doubleClick(table, row, column);
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
        inspectUnionViews(tool, program, listing);
        var otherFile = inspectForeground(tool, program, listing, entry, interior);
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
        inspectArithmetic(tool, program, listing, otherFile);
        closeFixtureTab(tool.getService(ProgramManager.class), listing, program, null);
        System.out.printf(Locale.ROOT, "BINARYRAT_GUI_NAVIGATION_OK %s %s %s %.3f %.3f%n",
            entry, interior, evidence, recoverSeconds, browseSeconds);
    }

    private static void doubleClick(JTable table, int row, int column) {
        Rectangle cell = table.getCellRect(row, column, true);
        table.scrollRectToVisible(cell);
        for (int clicks = 1; clicks <= 2; clicks++) {
            for (int event : new int[] {
                    MouseEvent.MOUSE_PRESSED, MouseEvent.MOUSE_RELEASED, MouseEvent.MOUSE_CLICKED }) {
                table.dispatchEvent(new MouseEvent(table, event, System.currentTimeMillis(), 0,
                    cell.x + cell.width / 2, cell.y + cell.height / 2, clicks, false, MouseEvent.BUTTON1));
            }
        }
    }

    private static JDialog arithmeticChooser(DockingActionIf action, ComponentProvider browser) throws Exception {
        SwingUtilities.invokeLater(() -> action.actionPerformed(browser.getActionContext(null)));
        return await("arithmetic register chooser", () -> dialog("Select Output Register"));
    }

    private static void inspectArithmetic(PluginTool tool, Program program, CodeViewerService listing,
            DomainFile otherFile) throws Exception {
        // This code exists only in the active, unsaved x86-64 Program, on both CI platforms.
        Address first = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x60000);
        byte[] bytes = HexFormat.of().parseHex("4889c84883c0054883e802c3"); // RAX = (RCX + 5) - 2; RET
        var flat = new FlatProgramAPI(program);
        try (var tx = program.openTransaction("Add arithmetic GUI fixture")) {
            flat.createMemoryBlock("arithmetic_gui", first, bytes, false).setExecute(true);
            if (!flat.disassemble(first)) {
                throw new AssertionError("Could not disassemble the arithmetic fixture");
            }
        }
        // Defining the new instructions schedules reference analysis in CodeBrowser.
        program.flushEvents();
        flat.analyzeChanges(program);
        program.flushEvents();
        Address add = first.add(3);
        Address subtract = first.add(7);
        Address end = first.add(10);
        var action = swing(() -> tool.getDockingActionsByOwnerName("BinaryRatWorkspacePlugin").stream()
            .filter(a -> "Explain Selected Register Arithmetic".equals(a.getName())).findFirst().orElseThrow());
        var selected = new ProgramSelection(first, end);
        var browser = (ComponentProvider) listing.getNavigatable();
        swing(() -> {
            listing.goTo(new ProgramLocation(program, first), true);
            listing.getListingPanel().setSelection(new ProgramSelection(), EventTrigger.GUI_ACTION);
            return null;
        });
        await("arithmetic disabled with empty selection", () ->
            action.isEnabledForContext(browser.getActionContext(null)) ? null : Boolean.TRUE);
        var disjoint = new AddressSet(first, first.add(2));
        disjoint.addRange(subtract, end);
        var separate = new ProgramSelection(disjoint);
        swing(() -> {
            listing.getListingPanel().setSelection(separate, EventTrigger.GUI_ACTION);
            return null;
        });
        await("noncontiguous Listing selection", () ->
            separate.equals(listing.getCurrentSelection()) ? Boolean.TRUE : null);
        SwingUtilities.invokeLater(() -> action.actionPerformed(browser.getActionContext(null)));
        await("disjoint arithmetic selection refused", () -> dialog("Select Output Register") == null &&
            tool.getStatusInfo().contains("one contiguous range") ? Boolean.TRUE : null);
        swing(() -> {
            listing.getListingPanel().setSelection(selected, EventTrigger.GUI_ACTION);
            return null;
        });
        await("arithmetic enabled for whole instructions", () ->
            selected.equals(listing.getCurrentSelection()) && action.isEnabledForContext(browser.getActionContext(null))
                && action.isAddToPopup(browser.getActionContext(null)) ? Boolean.TRUE : null);
        var cancelled = arithmeticChooser(action, browser);
        try (var tx = program.openTransaction("Edit while choosing a register")) {
            program.getBookmarkManager().setBookmark(first, "Note", "GUI probe", "Changed before submission");
        }
        swing(() -> { widget(cancelled, JButton.class, b -> "Explain".equals(b.getText())).doClick(0); return null; });
        await("stale register choice refused", () -> cancelled.isShowing() &&
            ((DockingDialog) cancelled).getDialogComponent().getStatusText().contains("Program changed") ?
                Boolean.TRUE : null);
        swing(() -> { widget(cancelled, JButton.class, b -> "Cancel".equals(b.getText())).doClick(); return null; });
        await("cancelled register choice closes", () -> !cancelled.isShowing() ? Boolean.TRUE : null);
        if (swing(() -> tool.getComponentProvider("Arithmetic Explanation").isVisible())) {
            throw new AssertionError("Cancelling a register choice opened arithmetic evidence");
        }
        long revision = program.getModificationNumber();
        var chooser = arithmeticChooser(action, browser);
        var provider = swing(() -> tool.getComponentProvider("Arithmetic Explanation"));
        var table = swing(() -> descendants(provider.getComponent()).filter(JTable.class::isInstance)
            .map(JTable.class::cast).filter(t -> "BinaryRatArithmeticEvidence".equals(t.getName()))
            .findFirst().orElseThrow());
        var published = new CompletableFuture<Long>();
        TableModelListener listener = event -> {
            if (table.getRowCount() > 0) {
                published.complete(System.nanoTime());
            }
        };
        long clicked = swing(() -> {
            var register = widget(chooser, JComboBox.class, w -> "BinaryRatArithmeticRegister".equals(w.getName()));
            register.setSelectedItem("RAX");
            var explain = widget(chooser, JButton.class, b -> "Explain".equals(b.getText()));
            table.getModel().addTableModelListener(listener);
            long start = System.nanoTime();
            explain.doClick(0);
            return start;
        });
        double explainMillis;
        try {
            // Open Program; button dispatch to publication of the rows on the EDT. Excludes choosing a register.
            explainMillis = (published.get(80, TimeUnit.SECONDS) - clicked) / 1e6;
        }
        finally {
            swing(() -> { table.getModel().removeTableModelListener(listener); return null; });
        }
        await("arithmetic provider displaying the result", () -> table.isShowing() ? Boolean.TRUE : null);
        swing(() -> {
            int source = table.getColumnModel().getColumnIndex("Instruction");
            int root = table.getSelectedRow();
            if (root < 0 || !"INT_SUB".equals(table.getValueAt(root, table.getColumnModel().getColumnIndex("Operation")))) {
                throw new AssertionError("The final subtraction should be selected");
            }
            int addRow = checkArithmeticRows(table, program, first, add, subtract);
            if (!first.equals(listing.getCurrentLocation().getAddress())) {
                throw new AssertionError("Double-clicking an input moved the Listing");
            }
            doubleClick(table, addRow, source);
            return null;
        });
        await("arithmetic double-click to add", () ->
            add.equals(listing.getCurrentLocation().getAddress()) ? Boolean.TRUE : null);
        try (var tx = program.openTransaction("Open a transaction without changing the fixture")) {
            swing(() -> {
                int row = table.getRowCount() - 1;
                table.setRowSelectionInterval(row, row);
                pressEnter(table);
                return null;
            });
            await("navigation waited for an active edit and retained the evidence", () ->
                tool.getStatusInfo().contains("Wait for the current Program edit") && table.getRowCount() == 6 &&
                    add.equals(listing.getCurrentLocation().getAddress()) ? Boolean.TRUE : null);
        }
        swing(() -> { pressEnter(table); return null; });
        await("arithmetic Enter to subtract", () ->
            subtract.equals(listing.getCurrentLocation().getAddress()) ? Boolean.TRUE : null);
        if (program.getModificationNumber() != revision) {
            throw new AssertionError("Program revision changed during arithmetic explanation: " + revision +
                " -> " + program.getModificationNumber() + "; undo history: " + program.getAllUndoNames());
        }
        try (var tx = program.openTransaction("Invalidate arithmetic evidence")) {
            program.getBookmarkManager().setBookmark(subtract, "Note", "GUI probe", "Changed after capture");
        }
        await("stale arithmetic rows cleared", () -> table.getRowCount() == 0 &&
            descendants(provider.getComponent()).filter(JLabel.class::isInstance).map(JLabel.class::cast)
                .anyMatch(label -> "BinaryRatArithmeticStatus".equals(label.getName()) &&
                    label.getText().contains("Program changed")) ? Boolean.TRUE : null);
        // Repopulate the panel and change Programs with the old evidence still selected.
        swing(() -> { listing.getListingPanel().setSelection(selected, EventTrigger.GUI_ACTION); return null; });
        await("new selection after edit", () -> selected.equals(listing.getCurrentSelection()) ? Boolean.TRUE : null);
        var reopened = arithmeticChooser(action, browser);
        swing(() -> { widget(reopened, JButton.class, b -> "Explain".equals(b.getText())).doClick(); return null; });
        await("fresh arithmetic evidence", () -> table.getRowCount() == 6 ? Boolean.TRUE : null);
        var manager = tool.getService(ProgramManager.class);
        Program other = swing(() -> manager.openProgram(otherFile));
        await("old evidence discarded on tab switch", () -> other != null && other != program &&
            manager.getCurrentProgram() == other && table.getRowCount() == 0 ? Boolean.TRUE : null);
        swing(() -> { pressEnter(table); return null; });
        if (swing(manager::getCurrentProgram) != other) {
            throw new AssertionError("Old arithmetic evidence reactivated its previous Program");
        }
        closeFixtureTab(manager, listing, other, program);
        System.out.printf(Locale.ROOT, "BINARYRAT_GUI_ARITHMETIC_OK %s %s %.3f%n", add, subtract, explainMillis);
    }

    private static void closeFixtureTab(ProgramManager manager, CodeViewerService listing,
            Program closing, Program remaining) throws Exception {
        // ListingPanel posts margin updates to a later EDT turn. Keep the outgoing
        // database alive while the actual Listing changes, including at process exit.
        Object consumer = new Object();
        if (!closing.addConsumer(consumer)) {
            throw new AssertionError("Fixture Program already closed before switching the Listing");
        }
        try {
            if (remaining != null) {
                swing(() -> { manager.setCurrentProgram(remaining); return null; });
                await("Listing showing remaining tab", () ->
                    listing.getListingPanel().getProgram() == remaining ? Boolean.TRUE : null);
            }
            if (!swing(() -> manager.closeProgram(closing, true))) {
                throw new AssertionError("Could not close the disposable GUI fixture tab");
            }
            await("Listing detached from outgoing Program", () -> manager.getCurrentProgram() == remaining &&
                listing.getListingPanel().getProgram() == remaining ? Boolean.TRUE : null);
        }
        finally {
            closing.release(consumer);
        }
    }

    private static void pressEnter(JTable table) {
        var key = table.getInputMap().get(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0));
        var enter = table.getActionMap().get(key);
        if (enter == null) {
            throw new AssertionError("No Enter binding for arithmetic evidence");
        }
        enter.actionPerformed(new java.awt.event.ActionEvent(table, 0, "Enter"));
    }

    /** Validate the displayed expression and its instruction evidence independently of the service. */
    private static int checkArithmeticRows(JTable table, Program program, Address first, Address add, Address subtract) {
        var columns = table.getColumnModel();
        int op = columns.getColumnIndex("Operation");
        int source = columns.getColumnIndex("Instruction");
        int order = columns.getColumnIndex("P-code order");
        int bits = columns.getColumnIndex("Bits");
        int value = columns.getColumnIndex("Inputs or literal");
        int id = columns.getColumnIndex("Value");
        var sites = Map.of("COPY", first, "INT_ADD", add, "INT_SUB", subtract);
        var arguments = Map.of("COPY", List.of("RCX"), "INT_ADD", List.of("COPY", "0x5"),
            "INT_SUB", List.of("INT_ADD", "0x2"));
        var ids = new HashMap<String, String>();
        int addRow = -1;
        for (int row = 0; row < table.getRowCount(); row++) {
            String operation = (String) table.getValueAt(row, op);
            String inputs = (String) table.getValueAt(row, value);
            Address expected = sites.get(operation);
            String label = expected == null ? inputs : operation;
            if (ids.put(label, (String) table.getValueAt(row, id)) != null ||
                    !Integer.valueOf(64).equals(table.getValueAt(row, bits))) {
                throw new AssertionError("Duplicate arithmetic value or wrong width for " + label);
            }
            if (expected == null) {
                String kind = "RCX".equals(label) ? "INPUT" : "CONSTANT";
                if (!kind.equals(operation) || !"".equals(table.getValueAt(row, source)) ||
                        !"".equals(table.getValueAt(row, order))) {
                    throw new AssertionError("Unexpected evidence for leaf " + label);
                }
                if (kind.equals("INPUT")) {
                    doubleClick(table, row, source);
                }
                continue;
            }
            String expectedInputs = String.join(", ", arguments.get(operation).stream().map(ids::get).toList());
            int sequence = (int) table.getValueAt(row, order);
            var pcode = program.getListing().getInstructionAt(expected).getPcode(true);
            if (!expectedInputs.equals(inputs) || !expected.toString(true).equals(table.getValueAt(row, source)) ||
                    Arrays.stream(pcode).noneMatch(p -> p.getSeqnum().getTime() == sequence &&
                        p.getMnemonic().equals(operation))) {
                throw new AssertionError("Arithmetic row cites the wrong inputs, instruction or p-code operation");
            }
            if (operation.equals("INT_ADD")) {
                addRow = row;
            }
        }
        if (!ids.keySet().equals(Set.of("RCX", "COPY", "0x5", "INT_ADD", "0x2", "INT_SUB"))) {
            throw new AssertionError("Unexpected arithmetic expression: " + ids.keySet());
        }
        return addRow;
    }

    private static void inspectUnionViews(PluginTool tool, Program program, CodeViewerService listing)
            throws Exception {
        String owner = "BinaryRatWorkspacePlugin";
        String menu = "Recover Summary Layout at Cursor";
        Address entry = program.getSymbolTable().getGlobalSymbols("read_overlay_number").getFirst().getAddress();
        long revision = program.getModificationNumber();
        swing(() -> {
            if (tool.getDockingActionsByOwnerName(owner).isEmpty()) {
                tool.addPlugin("binaryrat.desktop.BinaryRatWorkspacePlugin");
            }
            return listing.goTo(new ProgramLocation(program, entry), true);
        });
        var action = await("summary recovery at shared storage", () ->
            listing.getCurrentLocation().getAddress().equals(entry) ?
                tool.getDockingActionsByOwnerName(owner).stream()
                    .filter(item -> item.getName().equals(menu) && item.isEnabled()).findFirst().orElse(null) : null);
        SwingUtilities.invokeLater(() -> action.actionPerformed(new DefaultActionContext()));
        var options = await("union summary selection", () -> dialog(menu));
        swing(() -> { widget(options, JButton.class, b -> b.getText().equals("Recover")).doClick(); return null; });
        var evidence = await("union summary evidence", () -> dialog("BinaryRat Summary Layout Evidence"));
        await("integer and floating-point field loads in the table", () -> {
            JTable table = widget(evidence, JTable.class, t -> true);
            var columns = table.getColumnModel();
            int kind = columns.getColumnIndex("Union candidate view");
            boolean integer = false;
            boolean floating = false;
            for (int i = 0; i < table.getRowCount(); i++) {
                String label = (String) table.getValueAt(i, kind);
                if (label.isEmpty()) {
                    continue;
                }
                if (!"LOAD".equals(table.getValueAt(i, columns.getColumnIndex("Access"))) ||
                        !"+0x0".equals(String.valueOf(table.getValueAt(i, columns.getColumnIndex("Offset")))) ||
                        !"Verified".equals(table.getValueAt(i, columns.getColumnIndex("Instruction bytes")))) {
                    throw new AssertionError("Union row must cite a verified load at the shared offset");
                }
                int width = (Integer) table.getValueAt(i, columns.getColumnIndex("Width"));
                String consumer = (String) table.getValueAt(i, columns.getColumnIndex("Supporting p-code"));
                if (!consumer.contains(" at ram:") || !consumer.contains(" (p-code ")) {
                    throw new AssertionError("Missing qualified consumer location and p-code order: " + consumer);
                }
                integer |= label.equals("integer") && width == 4 && consumer.startsWith("INT_XOR ");
                floating |= label.equals("floating point") && width == 8 && consumer.startsWith("FLOAT_");
            }
            return integer && floating ? Boolean.TRUE : null;
        });
        swing(() -> { widget(evidence, JButton.class, b -> b.getText().equals("Dismiss")).doClick(); return null; });
        if (program.getModificationNumber() != revision || program.isChanged()) {
            throw new AssertionError("Reviewing union candidates changed the Program");
        }
    }

    /** Label HTML from HTMLUtilities.toLiteralHTML as plain text. */
    private static String plain(String html) {
        return html.replaceAll("<[^>]*>", " ").replace("&nbsp;", " ").replace("&lt;", "<")
            .replace("&gt;", ">").replace("&quot;", "\"").replace("&amp;", "&");
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

    private static DomainFile inspectForeground(PluginTool tool, Program program, CodeViewerService listing,
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
        swing(() -> { view.setVisible(false); return null; });
        closeFixtureTab(manager, listing, second, program);
        swing(() -> listing.goTo(new ProgramLocation(program, entry), true));
        System.out.printf(Locale.ROOT, "BINARYRAT_GUI_FOREGROUND_OK %d %d 2%n", firstMillis, secondMillis);
        return copy;
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
