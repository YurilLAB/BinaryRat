// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package binaryrat.desktop;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.Font;
import java.io.IOException;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JTextArea;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingUtilities;
import javax.swing.Timer;

import binaryrat.DecompilationSession;
import docking.ActionContext;
import docking.WindowPosition;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.ToolBarData;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitorAdapter;

/** Inspect the selected function and review corrections from its Listing context. */
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "BinaryRat",
    category = "Analysis",
    shortDescription = "Inspect the selected function with BinaryRat",
    description = "Prioritizes the selected function and discards results superseded by navigation.",
    servicesRequired = { ProgramManager.class, CodeViewerService.class }
)
public class BinaryRatForegroundPlugin extends ProgramPlugin {
    private static final int DEBOUNCE_MILLIS = 180;
    private static final int ANALYSIS_RETRY_MILLIS = 350;
    private static final int DISPLAY_LIMIT = 64 * 1024;

    private final ThreadPoolExecutor worker = new ThreadPoolExecutor(1, 1, 0,
        TimeUnit.MILLISECONDS, new ArrayBlockingQueue<>(1),
        Thread.ofPlatform().daemon().name("BinaryRat foreground decompiler").factory());
    private final Timer debounce = new Timer(DEBOUNCE_MILLIS, event -> submit());
    private final Timer expiry = new Timer(0, event -> stop("Foreground request limit reached."));
    private final JPanel panel = new JPanel(new BorderLayout(5, 5));
    private final JLabel status = new JLabel();
    private final JProgressBar progress = new JProgressBar();
    private final JTextArea output = new JTextArea(20, 74);
    private final JSpinner limit = new JSpinner(new SpinnerNumberModel(30, 1,
        DecompilationSession.DEFAULT_TIMEOUT_SECONDS, 1));
    private final JButton cancel = new JButton("Cancel");
    private final Provider provider;
    private final AnalystCorrections corrections;
    private final DomainObjectListener changed = event -> SwingUtilities.invokeLater(
        () -> refreshIfChanged());

    // Navigation, request publication, and Swing state are confined to the EDT.
    private Program watching;
    private Request pending;
    private Scope scope;
    private boolean disposed;

    // The worker owns all access to these handles, including close.
    private DecompilationSession session;
    private Program sessionProgram;
    private long sessionRevision;

    public BinaryRatForegroundPlugin(PluginTool tool) {
        super(tool);
        debounce.setRepeats(false);
        expiry.setRepeats(false);
        output.setName("BinaryRat foreground C");
        output.setEditable(false);
        output.setFont(new Font(Font.MONOSPACED, Font.PLAIN, output.getFont().getSize()));
        status.setName("BinaryRat foreground status");
        progress.setIndeterminate(true);
        progress.getAccessibleContext().setAccessibleName("Foreground decompilation progress");
        JButton refresh = new JButton("Refresh");
        refresh.addActionListener(event -> follow(true));
        cancel.addActionListener(event -> stop("Foreground request cancelled."));
        var controls = new JPanel(new FlowLayout(FlowLayout.LEADING));
        JLabel limitLabel = new JLabel("Request limit (s)");
        limitLabel.setLabelFor(limit);
        limit.setToolTipText("Limit for the next foreground request, including time waiting for analysis");
        controls.add(refresh);
        controls.add(cancel);
        controls.add(limitLabel);
        controls.add(limit);
        controls.add(progress);
        panel.add(controls, BorderLayout.NORTH);
        panel.add(new JScrollPane(output), BorderLayout.CENTER);
        corrections = new AnalystCorrections(tool, this::correctionSelection);
        var information = new JPanel(new BorderLayout());
        information.add(status, BorderLayout.NORTH);
        information.add(corrections, BorderLayout.SOUTH);
        panel.add(information, BorderLayout.SOUTH);
        display("Open a program and select a function.", "", false);
        provider = new Provider();
        provider.addToTool();

        DockingAction action = new DockingAction("Inspect Selected Function", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                if (provider.isVisible()) {
                    provider.toFront();
                    follow(true);
                }
                else {
                    provider.setVisible(true);
                }
            }
        };
        action.setMenuBarData(new MenuData(
            new String[] {"Tools", "BinaryRat", "Inspect Selected Function"}, BinaryRatIcons.LOGO_16));
        action.setToolBarData(new ToolBarData(BinaryRatIcons.LOGO_16, "BinaryRat"));
        action.setDescription("Open the BinaryRat function view for the Listing selection");
        tool.addAction(action);
    }

    private final class Provider extends ComponentProviderAdapter {
        Provider() {
            super(BinaryRatForegroundPlugin.this.tool, "BinaryRat Function",
                BinaryRatForegroundPlugin.this.getName());
            setIcon(BinaryRatIcons.LOGO_16);
            setDefaultWindowPosition(WindowPosition.RIGHT);
        }

        @Override
        public JComponent getComponent() {
            return panel;
        }

        @Override
        public void componentShown() {
            watch(tool.getService(ProgramManager.class).getCurrentProgram());
            follow(true);
        }

        @Override
        public void componentHidden() {
            watch(null);
        }
    }

    @Override
    protected void programActivated(Program program) {
        if (provider.isVisible()) {
            watch(program);
        }
    }

    @Override
    protected void programDeactivated(Program program) {
        if (program == watching) {
            watch(null);
        }
    }

    @Override
    protected void programClosed(Program program) {
        if (program == watching) {
            watch(null);
        }
    }

    @Override
    protected void locationChanged(ProgramLocation location) {
        if (watching != null) {
            select(location, false);
            corrections.updateActions();
        }
    }

    private void watch(Program program) {
        if (disposed || watching == program) {
            return;
        }
        if (watching != null) {
            watching.removeListener(changed);
        }
        corrections.clearStatus();
        stop("Select a function in the listing.");
        replaceWork(this::closeSession);
        watching = program;
        if (program != null && !program.isClosed()) {
            program.addListener(changed);
        }
    }

    private void refreshIfChanged() {
        if (watching == null || watching.isClosed()) {
            return;
        }
        long revision = watching.getModificationNumber();
        if ((pending != null && pending.revision != revision) ||
            (scope != null && scope.revision() != revision)) {
            follow(false);
        }
    }

    private void follow(boolean force) {
        if (watching != null) {
            select(tool.getService(CodeViewerService.class).getCurrentLocation(), force);
        }
    }

    private AnalystCorrections.Selection correctionSelection() {
        if (disposed || watching == null || scope == null || pending != null ||
            watching.isClosed() || scope.revision() != watching.getModificationNumber()) {
            return null;
        }
        var location = tool.getService(CodeViewerService.class).getCurrentLocation();
        if (location == null || location.getProgram() != watching || location.getAddress() == null ||
            !scope.body().contains(location.getAddress())) {
            return null;
        }
        return new AnalystCorrections.Selection(watching, scope.entry(), location.getAddress(),
            scope.revision());
    }

    private void select(ProgramLocation location, boolean force) {
        if (location == null || location.getProgram() != watching || location.getAddress() == null) {
            stop("Select a function in the listing.");
            return;
        }
        var address = location.getAddress();
        long revision = watching.getModificationNumber();
        if (!force &&
            ((pending != null && pending.revision == revision && pending.address.equals(address)) ||
                (scope != null && scope.revision() == revision && scope.body().contains(address)))) {
            return;
        }
        stop("");
        pending = new Request(watching, address, revision);
        display("Queued foreground decompilation for " + address + ".", "", true);
        debounce.setInitialDelay(DEBOUNCE_MILLIS);
        debounce.restart();
        expiry.setInitialDelay(((Integer) limit.getValue()) * 1000);
        expiry.restart();
    }

    private void submit() {
        Request request = pending;
        if (request != null) {
            replaceWork(() -> decompile(request));
        }
    }

    private void replaceWork(Runnable task) {
        worker.getQueue().clear();
        worker.execute(task);
    }

    private void stop(String message) {
        debounce.stop();
        expiry.stop();
        if (pending != null) {
            pending.cancel();
            pending = null;
        }
        scope = null;
        display(message, "", false);
    }

    private void display(String message, String source, boolean busy) {
        status.setText(message);
        output.setText(source);
        output.setCaretPosition(0);
        cancel.setEnabled(busy);
        progress.setVisible(busy);
        corrections.updateActions();
    }

    private boolean accepts(Request request) {
        return !disposed && pending == request && watching == request.program;
    }

    private void publish(Request request, Scope completedScope, String message, String source) {
        SwingUtilities.invokeLater(() -> {
            if (!accepts(request)) {
                return;
            }
            if (request.program.getModificationNumber() != request.revision) {
                follow(true);
                return;
            }
            pending = null;
            expiry.stop();
            scope = completedScope;
            display(message, source, false);
        });
    }

    private void decompile(Request request) {
        if (!request.begin()) {
            return;
        }
        if (!request.program.addConsumer(request)) {
            publish(request, null, "The selected Program closed before decompilation.", "");
            return;
        }
        Program program = request.program;
        Scope resolvedScope = null;
        try {
            if (sessionProgram != program || sessionRevision != request.revision) {
                closeSession();
            }
            if (program.getModificationNumber() != request.revision) {
                publish(request, null, "Program changed.", "");
                return;
            }
            if (program.getCurrentTransactionInfo() != null ||
                AutoAnalysisManager.getAnalysisManager(program).isAnalyzing()) {
                SwingUtilities.invokeLater(() -> {
                    if (accepts(request)) {
                        display("Waiting for Ghidra analysis or an edit to finish.", "", true);
                        debounce.setInitialDelay(ANALYSIS_RETRY_MILLIS);
                        debounce.restart();
                    }
                });
                return;
            }
            var function = program.getFunctionManager().getFunctionContaining(request.address);
            if (function == null || function.isExternal()) {
                publish(request, null, "No local function at " + request.address + ".", "");
                return;
            }
            var body = function.getBody();
            // Bound the navigation snapshot for highly fragmented functions. It must be
            // safe to test membership on the EDT without reading the Program database.
            var resolved = new Scope(request.revision, function.getEntryPoint(),
                body.getNumAddressRanges() <= 4096 ?
                new AddressSet(body) : new AddressSet(request.address));
            resolvedScope = resolved;
            String label = function.getName() + " at " + function.getEntryPoint();
            SwingUtilities.invokeLater(() -> {
                if (accepts(request)) {
                    scope = resolved;
                    display("Decompiling " + label + ".", "", true);
                }
            });
            if (request.obsolete) {
                return;
            }
            if (session == null) {
                session = DecompilationSession.open(program, DecompilationSession.DEFAULT_WORKERS,
                    DecompilationSession.DEFAULT_TIMEOUT_SECONDS);
                sessionProgram = program;
                sessionRevision = request.revision;
            }
            if (request.obsolete) {
                return;
            }
            var result = session.decompileForeground(function, request.monitor);
            if (!result.cacheable() || result.c().isBlank()) {
                String error = compact(result.error().strip(), 240);
                publish(request, resolved, "Decompilation incomplete for " + label + ". " +
                    (error.isEmpty() ? "No usable C output was produced." : error), "");
                return;
            }
            String source = result.c();
            if (source.length() > DISPLAY_LIMIT) {
                source = compact(source, DISPLAY_LIMIT) +
                    "\n\nUse BinaryRat's export to save the complete result.";
            }
            long elapsedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - request.started);
            publish(request, resolved, "Ready: " + label + " (" + elapsedMillis + " ms)", source);
        }
        catch (Exception failure) {
            closeSession();
            if (!request.obsolete && !(failure instanceof CancelledException)) {
                String detail = failure.getMessage();
                publish(request, resolvedScope, "Foreground decompilation failed. " +
                    (detail == null ? failure.getClass().getSimpleName() : compact(detail, 240)), "");
            }
        }
        finally {
            program.release(request);
        }
    }

    private static String compact(String text, int length) {
        return text.length() > length ? text.substring(0, length) + "…" : text;
    }

    private void closeSession() {
        if (session != null) {
            try {
                session.close();
            }
            catch (Exception failure) {
                Msg.warn(this, "Could not close the BinaryRat foreground session", failure);
            }
            finally {
                session = null;
                sessionProgram = null;
            }
        }
    }

    @Override
    protected void dispose() {
        watch(null);
        disposed = true;
        stop("");
        replaceWork(this::closeSession);
        worker.shutdown();
        provider.removeFromTool();
        super.dispose();
    }

    private record Scope(long revision, Address entry, AddressSetView body) {
    }

    private static final class Request {
        final Program program;
        final Address address;
        final long revision;
        final long started = System.nanoTime();
        final TaskMonitorAdapter monitor = new TaskMonitorAdapter(true);
        volatile boolean obsolete;
        private volatile boolean workerStarted;

        Request(Program program, Address address, long revision) {
            this.program = program;
            this.address = address;
            this.revision = revision;
        }

        boolean begin() {
            workerStarted = true;
            return !obsolete;
        }

        void cancel() {
            obsolete = true;
            // A monitor listener can send IPC to the native scheduler. Never invoke
            // those listeners on the EDT while handling navigation or cancellation.
            if (workerStarted) {
                Thread.startVirtualThread(monitor::cancel);
            }
        }
    }
}
