// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package binaryrat.desktop;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ConcurrentModificationException;
import java.util.List;
import java.util.stream.Collectors;

import javax.swing.AbstractAction;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.KeyStroke;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;

import binaryrat.ArithmeticExplanation;
import binaryrat.ArithmeticExplanation.Node;
import binaryrat.ArithmeticExplanation.Result;
import docking.DialogComponentProvider;
import docking.WindowPosition;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;

/** Read-only, revision-bound evidence for one explicit Listing selection. */
final class ArithmeticEvidenceProvider extends ComponentProviderAdapter {
    static final String ACTION = "Explain Selected Register Arithmetic";
    private static final String CHANGED = "The Program changed. Select the instructions and explain them again.";
    private static final String BUSY = "Wait for the current Program edit or analysis to finish.";
    private final PluginTool pluginTool;
    private final JPanel panel = new JPanel(new BorderLayout(6, 6));
    private final JLabel status = new JLabel("Select complete instructions in the Listing and choose " + ACTION + ".");
    private final EvidenceModel model = new EvidenceModel();
    private final JTable table = new JTable(model);
    private final DomainObjectListener changed = event -> SwingUtilities.invokeLater(this::checkRevision);

    // Only the EDT changes the current request, Program and displayed rows.
    private Task pending;
    private Program watched;
    private long revision;

    ArithmeticEvidenceProvider(PluginTool tool, String owner) {
        super(tool, "Arithmetic Explanation", owner);
        pluginTool = tool;
        setIcon(BinaryRatIcons.LOGO_16);
        setDefaultWindowPosition(WindowPosition.BOTTOM);
        table.setName("BinaryRatArithmeticEvidence");
        table.getAccessibleContext().setAccessibleName("Arithmetic explanation and instruction evidence");
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setFillsViewportHeight(true);
        table.setToolTipText("Double-click an instruction row or press Enter to open it in the Listing.");
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent event) {
                if (event.getClickCount() == 2 && SwingUtilities.isLeftMouseButton(event)) {
                    navigate(table.rowAtPoint(event.getPoint()));
                }
            }
        });
        table.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0), "goToEvidence");
        table.getActionMap().put("goToEvidence", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent event) {
                navigate(table.getSelectedRow());
            }
        });
        status.setName("BinaryRatArithmeticStatus");
        panel.add(new JScrollPane(table), BorderLayout.CENTER);
        panel.add(status, BorderLayout.SOUTH);
        panel.setPreferredSize(new Dimension(740, 230));
        addToTool();
    }

    @Override
    public JComponent getComponent() {
        return panel;
    }

    @Override
    public void componentHidden() {
        if (pending != null) {
            reset("Arithmetic explanation cancelled.");
        }
    }

    void select(Program program, ProgramSelection selection) {
        if (program == null || !active(program) || selection == null || selection.isEmpty()) {
            pluginTool.setStatusInfo("Select at least one complete Listing instruction.");
            return;
        }
        if (selection.getNumAddressRanges() != 1 || selection.getInteriorSelection() != null) {
            pluginTool.setStatusInfo("Select one contiguous range of complete Listing instructions.");
            return;
        }
        long expected = program.getModificationNumber();
        if (program.getCurrentTransactionInfo() != null) {
            pluginTool.setStatusInfo(BUSY);
            return;
        }
        try {
            selectRegister(program, selection.getMinAddress(), selection.getMaxAddress(), expected);
        }
        catch (ConcurrentModificationException deleted) {
            // InstructionDB revalidates its handle on each read and throws if it was deleted.
            pluginTool.setStatusInfo(CHANGED);
        }
    }

    private void selectRegister(Program program, Address first, Address lastByte, long expected) {
        var listing = program.getListing();
        var last = listing.getInstructionContaining(lastByte);
        if (listing.getInstructionAt(first) == null || last == null || !lastByte.equals(last.getMaxAddress())) {
            pluginTool.setStatusInfo("Select every byte of the first and last Listing instructions.");
            return;
        }
        var registers = ArithmeticExplanation.registerNames(program);
        if (registers.isEmpty()) {
            pluginTool.setStatusInfo("Arithmetic explanations support x86-64 and AArch64 general-purpose registers.");
            return;
        }
        Register operand = last.getNumOperands() == 0 ? null : last.getRegister(0);
        Address lastStart = last.getMinAddress();
        String preferred = operand == null ? null : operand.getName();
        String blocked = unavailable(program, expected);
        if (blocked != null) {
            pluginTool.setStatusInfo(blocked);
            return;
        }
        pluginTool.showDialog(new RegisterDialog(program, first, lastStart, registers, preferred, expected));
    }

    private final class RegisterDialog extends DialogComponentProvider {
        private final Program program;
        private final Address first;
        private final Address last;
        private final long expected;
        private final JComboBox<String> choices;

        RegisterDialog(Program program, Address first, Address last, List<String> registers,
                String preferred, long expected) {
            super("Select Output Register", true);
            this.program = program;
            this.first = first;
            this.last = last;
            this.expected = expected;
            choices = new JComboBox<>(registers.toArray(String[]::new));
            choices.setName("BinaryRatArithmeticRegister");
            if (preferred != null && registers.contains(preferred)) {
                choices.setSelectedItem(preferred);
            }
            else {
                registers.stream().filter(n -> n.equalsIgnoreCase("RAX") || n.equalsIgnoreCase("X0"))
                    .findFirst().ifPresent(choices::setSelectedItem);
            }
            var contents = new JPanel(new BorderLayout(8, 8));
            contents.add(new JLabel("Instruction starts  " + first.toString(true) + " through " +
                last.toString(true)), BorderLayout.NORTH);
            var label = new JLabel("Register at range exit");
            label.setLabelFor(choices);
            contents.add(label, BorderLayout.WEST);
            contents.add(choices, BorderLayout.CENTER);
            addWorkPanel(contents);
            addOKButton();
            setOkButtonText("Explain");
            addCancelButton();
        }

        @Override
        protected void okCallback() {
            String blocked = unavailable(program, expected);
            if (blocked != null) {
                setStatusText(blocked);
                return;
            }
            String register = (String) choices.getSelectedItem();
            close();
            capture(program, first, last, register, expected);
        }
    }

    private void capture(Program program, Address first, Address last, String register, long expected) {
        reset("Tracing " + register + "…");
        watched = program;
        revision = expected;
        program.addListener(changed);
        setVisible(true);
        toFront();
        pending = new Task(ACTION, true, false, false) {
            @Override
            public void run(TaskMonitor monitor) {
                Result result = null;
                String message = null;
                try {
                    monitor.checkCancelled();
                    if (!program.addConsumer(this)) {
                        throw new IllegalStateException("The Program is closed.");
                    }
                    try {
                        result = ArithmeticExplanation.explain(program, first, last, register, expected, monitor);
                        monitor.checkCancelled();
                    }
                    finally {
                        program.release(this);
                    }
                }
                catch (CancelledException cancelled) {
                    message = "Arithmetic explanation cancelled.";
                }
                catch (RuntimeException failure) {
                    message = "Cannot explain " + register + ": " + failure.getMessage();
                }
                Result completed = result;
                String detail = message;
                SwingUtilities.invokeLater(() -> finish(this, program, first, last, completed, detail));
            }
        };
        TaskLauncher.launch(pending);
    }

    private void finish(Task task, Program program, Address first, Address last, Result result, String detail) {
        if (pending != task) {
            return;
        }
        pending = null;
        String blocked = unavailable(program, revision);
        if (blocked != null) {
            reset(blocked);
            return;
        }
        if (detail != null) {
            reset(detail);
            return;
        }
        model.show(result.nodes());
        int root = result.root();
        table.setRowSelectionInterval(root, root);
        table.scrollRectToVisible(table.getCellRect(root, 0, true));
        status.setText(result.targetRegister() + " = t" + root + " after " + first.toString(true) +
            " through " + last.toString(true) + ". Inputs are register values at entry. " +
            "Double-click an instruction row or press Enter to open it.");
    }

    private boolean active(Program program) {
        var manager = pluginTool.getService(ProgramManager.class);
        return manager != null && !program.isClosed() && manager.getCurrentProgram() == program;
    }

    private boolean current(Program program, long expected) {
        return active(program) && program.getModificationNumber() == expected;
    }

    private String unavailable(Program program, long expected) {
        if (!current(program, expected)) {
            return CHANGED;
        }
        return program.getCurrentTransactionInfo() == null ? null : BUSY;
    }

    private void navigate(int row) {
        if (watched == null || row < 0) {
            return;
        }
        if (!current(watched, revision)) {
            reset(CHANGED);
            return;
        }
        if (watched.getCurrentTransactionInfo() != null) {
            pluginTool.setStatusInfo(BUSY);
            return;
        }
        int index = table.convertRowIndexToModel(row);
        Node node = model.nodes.get(index);
        if (node.site() == null) {
            pluginTool.setStatusInfo(node.operation().equals("INPUT") ?
                "This register is an input at range entry." : "This value is a constant.");
            return;
        }
        var navigation = pluginTool.getService(GoToService.class);
        if (navigation == null || !navigation.goTo(node.site(), watched)) {
            pluginTool.setStatusInfo("Could not navigate to " + node.site().toString(true) + ".");
        }
    }

    private void checkRevision() {
        if (watched != null && !current(watched, revision)) {
            reset(CHANGED);
        }
    }

    void deactivate(Program program) {
        if (watched == program) {
            reset("Select instructions in the active Program.");
        }
    }

    private void reset(String text) {
        if (pending != null) {
            pending.cancel();
            pending = null;
        }
        if (watched != null) {
            watched.removeListener(changed);
            watched = null;
        }
        model.show(List.of());
        status.setText(text);
    }

    void disposeEvidence() {
        reset("");
        removeFromTool();
    }

    private static final class EvidenceModel extends AbstractTableModel {
        private static final String[] COLUMNS = {
            "Value", "Operation", "Inputs or literal", "Bits", "Instruction", "P-code order"
        };
        private List<Node> nodes = List.of();

        void show(List<Node> values) {
            nodes = values;
            fireTableDataChanged();
        }

        @Override
        public int getRowCount() { return nodes.size(); }

        @Override
        public int getColumnCount() { return COLUMNS.length; }

        @Override
        public String getColumnName(int column) { return COLUMNS[column]; }

        @Override
        public Object getValueAt(int row, int column) {
            Node node = nodes.get(row);
            return switch (column) {
                case 0 -> "t" + row;
                case 1 -> node.operation();
                case 2 -> node.site() == null ? node.value() : node.arguments().stream()
                    .map(i -> "t" + i).collect(Collectors.joining(", "));
                case 3 -> node.size() * 8;
                case 4 -> node.site() == null ? "" : node.site().toString(true);
                case 5 -> node.site() == null ? "" : node.sequence();
                default -> throw new IndexOutOfBoundsException(column);
            };
        }
    }
}
