// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package distributionfixture;

import java.awt.Component;
import java.awt.Container;
import java.awt.Window;
import java.awt.event.WindowEvent;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.FutureTask;
import java.util.stream.Stream;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import com.google.gson.JsonParser;

import docking.DefaultActionContext;
import docking.action.DockingActionIf;
import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.plugin.core.decompile.PrimaryDecompilerProvider;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ProgramManager;
import ghidra.base.help.GhidraHelpService;
import ghidra.base.project.GhidraProject;
import ghidra.framework.Application;
import ghidra.framework.GhidraApplicationConfiguration;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.util.ProgramLocation;
import ghidra.util.extensions.ExtensionUtils;

/** Exercise the actual CodeBrowser defaults from a new bundled application profile. */
public final class WorkspaceProbe implements GhidraLaunchable {

    @Override
    public void launch(GhidraApplicationLayout layout, String[] args) {
        try {
            var config = new GhidraApplicationConfiguration();
            config.setShowSplashScreen(false);
            Application.initializeApplication(layout, config);
            GhidraHelpService.install();
            ExtensionUtils.initializeExtensions();
            Preferences.setProperty("SHOW_TIPS", "false");

            var project = GhidraProject.openProject(args[0], "workspace", true);
            var tool = swing(() -> {
                var front = new FrontEndTool(project.getProjectManager());
                front.setActiveProject(project.getProject());
                front.setVisible(true);
                var file = project.getProject().getProjectData().getFile("/" + args[1]);
                require(file != null, "Packaged example import missing");
                return project.getProject().getToolServices().launchDefaultTool(List.of(file));
            });
            inspect(tool, Path.of(args[2]));
            System.out.println("BINARYRAT_WORKSPACE_OK");
            System.exit(0);
        }
        catch (Throwable error) {
            error.printStackTrace();
            System.exit(1);
        }
    }

    private static void inspect(PluginTool tool, Path report) throws Exception {
        require(tool != null, "Default CodeBrowser did not launch");
        var manager = swing(() -> tool.getService(ProgramManager.class));
        require(manager != null, "Default tool lacks the ordinary Program Manager");
        var program = await("active Program", manager::getCurrentProgram);
        var symbol = program.getSymbolTable().getGlobalSymbols("measurement_area").getFirst();
        var function = program.getFunctionManager().getFunctionAt(symbol.getAddress());
        require(function != null, "Example measurement_area was not analyzed");
        var address = function.getEntryPoint();
        long revision = program.getModificationNumber();
        swing(() -> {
            var listing = tool.getService(CodeViewerService.class);
            require(listing != null, "Default tool lacks the ordinary Listing");
            listing.goTo(new ProgramLocation(program, address), true);
            action(tool, "BinaryRatForegroundPlugin", "Inspect Selected Function");
            action(tool, "BinaryRatWorkspacePlugin", "Export Decompilation");
            action(tool, "BinaryRatWorkspacePlugin", "Browse Layout Evidence");
            action(tool, "BinaryRatWorkspacePlugin", "Getting Started");
            return null;
        });
        var profile = await("enabled workspace profile action", () -> {
            var candidate = action(tool, "BinaryRatWorkspacePlugin", "Analyze with Profile");
            return candidate.isEnabled() ? candidate : null;
        });
        SwingUtilities.invokeLater(() -> profile.actionPerformed(new DefaultActionContext()));
        var profileChoices = await("analysis profile dialog", () -> dialog("BinaryRat Analysis Profile"));
        swing(() -> {
            descendants(profileChoices).filter(JButton.class::isInstance).map(JButton.class::cast)
                .filter(button -> button.getText().equals("Cancel")).findFirst().orElseThrow().doClick();
            return null;
        });
        await("profile cancellation", () ->
            !profileChoices.isShowing() && program.getCurrentTransactionInfo() == null ? Boolean.TRUE : null);
        var recovery = await("enabled workspace recovery action", () -> {
            var candidate = action(tool, "BinaryRatWorkspacePlugin", "Recover Layout at Cursor");
            return candidate.isEnabled() ? candidate : null;
        });
        SwingUtilities.invokeLater(() -> recovery.actionPerformed(new DefaultActionContext()));
        var options = await("recover layout dialog", () -> dialog("Recover Layout at Cursor"));
        swing(() -> {
            var destination = descendants(options).filter(JTextField.class::isInstance)
                .map(JTextField.class::cast).filter(field -> field.getText().endsWith(".json"))
                .findFirst().orElseThrow();
            destination.setText(report.toString());
            descendants(options).filter(JButton.class::isInstance).map(JButton.class::cast)
                .filter(button -> button.getText().equals("OK")).findFirst().orElseThrow().doClick();
            return null;
        });
        await("report from the bundled workspace action",
            () -> Files.isRegularFile(report) ? Boolean.TRUE : null);
        var evidence = JsonParser.parseString(Files.readString(report)).getAsJsonObject();
        require(evidence.getAsJsonObject("function").get("name").getAsString().equals("measurement_area"),
            "Wrong function in workspace evidence");
        require(evidence.getAsJsonArray("observations").size() >= 3,
            "Expected three structure accesses in the example");
        require(!program.isChanged() && program.getModificationNumber() == revision,
            "Layout recovery changed the Program");
        inspectCorrections(tool, program, function, revision);
    }

    private static void inspectCorrections(PluginTool tool, Program program, Function function,
            long originalRevision) throws Exception {
        var globals = program.getSymbolTable().getGlobalSymbols("measurement_bias");
        require(globals.size() == 1, "Expected one measurement_bias symbol");
        var callee = program.getFunctionManager().getFunctionAt(globals.getFirst().getAddress());
        require(callee != null, "Example measurement_bias was not analyzed");
        var calls = new ArrayList<Address>();
        var references = program.getReferenceManager().getReferencesTo(callee.getEntryPoint());
        while (references.hasNext()) {
            var reference = references.next();
            if (reference.getReferenceType().isCall()) {
                calls.add(reference.getFromAddress());
            }
        }
        require(calls.size() == 2, "Expected two calls to measurement_bias, found " + calls);
        Address site = calls.stream().filter(function.getBody()::contains).findFirst().orElseThrow();
        Address peerSite = calls.stream().filter(address -> !function.getBody().contains(address))
            .findFirst().orElseThrow();
        Function peerFunction = program.getFunctionManager().getFunctionContaining(peerSite);
        require(peerFunction != null, "Peer call has no enclosing function");
        String calleePrototype = callee.getPrototypeString(true, true);
        String peerPrototype = peerFunction.getPrototypeString(true, true);
        require(overrideAt(function, site) == null && overrideAt(peerFunction, peerSite) == null,
            "Fixture started with prototype overrides");

        goTo(tool, program, function.getEntryPoint());
        var inspectFunction = action(tool, "BinaryRatForegroundPlugin", "Inspect Selected Function");
        SwingUtilities.invokeLater(() -> inspectFunction.actionPerformed(new DefaultActionContext()));
        require(!program.getListing().getInstructionAt(function.getEntryPoint()).getFlowType().isCall(),
            "The function entry must be a non-call for this test");
        click("BinaryRat override call prototype");
        require(correctionStatus("Override unavailable:").contains("Select a call instruction"),
            "The non-call did not report an inapplicable type correction");

        goTo(tool, program, site);
        click("BinaryRat inspect instruction p-code");
        var pcode = await("selected instruction p-code dialog", () -> dialog("BinaryRat Instruction P-code"));
        var pcodeText = swing(() -> namedIn(pcode, JTextArea.class, "BinaryRat instruction p-code output"));
        require(pcodeText != null && !pcodeText.isEditable(), "P-code output must be read-only");
        String raw = swing(pcodeText::getText);
        require(raw.contains(site.toString()) && raw.lines().skip(3).anyMatch(line -> line.contains("CALL")),
            "P-code dialog did not show the selected call instruction\n" + raw);
        close(pcode);
        require(program.getModificationNumber() == originalRevision && !program.isChanged(),
            "Inspecting instruction p-code changed the Program");

        var decompiler = swing(() -> tool.getWindowManager().getComponentProvider(PrimaryDecompilerProvider.class));
        require(decompiler != null, "Default tool lacks the primary interactive decompiler");
        swing(() -> {
            decompiler.setVisible(false);
            return null;
        });
        click("BinaryRat open interactive decompiler");
        await("interactive decompiler ready at the selected measurement_bias call", () -> {
            if (!decompiler.isVisible() || decompiler.getProgram() != program ||
                !(decompiler.getActionContext(null) instanceof DecompilerActionContext context) ||
                context.isDecompiling() || !function.getEntryPoint().equals(context.getFunctionEntryPoint())) {
                return null;
            }
            var token = context.getTokenAtCursor();
            return token != null && token.getLineParent().getAllTokens().stream()
                .anyMatch(part -> part.getText().equals("measurement_bias")) ? Boolean.TRUE : null;
        });
        goTo(tool, program, site);

        var cancelDialog = openOverride();
        swing(() -> {
            signatureField(cancelDialog).setText("unsigned int measurement_bias(unsigned int value)");
            return null;
        });
        press(cancelDialog, "Cancel");
        await("cancellation closed the override dialog", () -> !cancelDialog.isShowing() ? Boolean.TRUE : null);
        require(program.getModificationNumber() == originalRevision && overrideAt(function, site) == null,
            "Cancelling the override changed the Program");

        submitOverride(openOverride(), "int (");
        require(correctionStatus("Override failed:").contains("C-style signature"),
            "Malformed input was not reported as a signature error");
        require(program.getModificationNumber() == originalRevision && overrideAt(function, site) == null,
            "Malformed signature changed the Program");

        var staleDialog = openOverride();
        swing(() -> {
            int transaction = program.startTransaction("Workspace probe: intervening analyst edit");
            try {
                program.getSymbolTable().createLabel(site, "prt_analyst_label", SourceType.USER_DEFINED);
            }
            finally {
                program.endTransaction(transaction, true);
            }
            return null;
        });
        long editedRevision = program.getModificationNumber();
        require(editedRevision != originalRevision, "Fixture edit did not change the Program revision");
        press(staleDialog, "Apply");
        await("stale override dialog reports the revision change", () -> {
            var status = namedIn(staleDialog, JLabel.class, "statusLabel");
            return status != null && status.getText().contains("The selection or Program changed") ?
                Boolean.TRUE : null;
        });
        press(staleDialog, "Cancel");
        await("stale override dialog closed", () -> !staleDialog.isShowing() ? Boolean.TRUE : null);
        require(program.getModificationNumber() == editedRevision && overrideAt(function, site) == null,
            "Stale prototype dialog wrote to the Program");
        click("BinaryRat override call prototype");
        require(correctionStatus("Override unavailable:").contains("protected prt label"),
            "Collision with an analyst label was not reported");
        require(Arrays.stream(program.getSymbolTable().getSymbols(site))
                .anyMatch(symbol -> symbol.getName().equals("prt_analyst_label")),
            "Prototype override removed an analyst label");
        require(program.getModificationNumber() == editedRevision && overrideAt(function, site) == null,
            "Protected-label rejection changed the Program");
        undo(program);
        goTo(tool, program, site);

        submitOverride(openOverride(), "unsigned int measurement_bias(unsigned int value)");
        correctionStatus("Call prototype override applied at " + site);
        var applied = overrideAt(function, site);
        require(applied != null && applied.getReturnType().isEquivalent(UnsignedIntegerDataType.dataType) &&
            applied.getArguments().length == 1 &&
            applied.getArguments()[0].getDataType().isEquivalent(UnsignedIntegerDataType.dataType),
            "Saved prototype override did not have the requested type: " + applied);
        require(overrideAt(peerFunction, peerSite) == null, "Peer call acquired an override");
        require(calleePrototype.equals(callee.getPrototypeString(true, true)) &&
            peerPrototype.equals(peerFunction.getPrototypeString(true, true)),
            "Call-site override changed a function prototype");

        long appliedRevision = program.getModificationNumber();
        click("BinaryRat override call prototype");
        correctionStatus("Override unavailable:");
        require(program.getModificationNumber() == appliedRevision && overrideAt(function, site) != null,
            "Duplicate attempt changed the existing prototype override");

        undo(program);
        require(overrideAt(function, site) == null && overrideAt(peerFunction, peerSite) == null,
            "Native undo did not remove the override");
        await("ready foreground after native undo", () -> {
            var status = namedVisible(JLabel.class, "BinaryRat foreground status");
            var override = namedVisible(JButton.class, "BinaryRat override call prototype");
            return status != null && status.getText().startsWith("Ready: measurement_area") &&
                override != null && override.isEnabled() ? Boolean.TRUE : null;
        });
        System.out.println("BINARYRAT_WORKSPACE_CORRECTIONS_OK");
    }

    private static FunctionDefinition overrideAt(Function function, Address site) {
        var namespace = HighFunction.findOverrideSpace(function);
        if (namespace == null) {
            return null;
        }
        for (var symbol : function.getProgram().getSymbolTable().getSymbols(site)) {
            if (namespace.equals(symbol.getParentNamespace()) && symbol.getSymbolType() == SymbolType.LABEL) {
                var override = HighFunctionDBUtil.readOverride(symbol);
                if (override != null) {
                    return (FunctionDefinition) override.getDataType();
                }
            }
        }
        return null;
    }

    private static void undo(Program program) throws Exception {
        await("completed transaction before undo", () ->
            program.getCurrentTransactionInfo() == null && program.canUndo() ? Boolean.TRUE : null);
        swing(() -> {
            program.undo();
            return null;
        });
    }

    private static void goTo(PluginTool tool, Program program, Address address) throws Exception {
        swing(() -> {
            var listing = tool.getService(CodeViewerService.class);
            require(listing.goTo(new ProgramLocation(program, address), true), "Could not navigate to " + address);
            return null;
        });
    }

    private static void click(String name) throws Exception {
        var button = await("enabled " + name, () -> {
            var candidate = namedVisible(JButton.class, name);
            return candidate != null && candidate.isEnabled() ? candidate : null;
        });
        SwingUtilities.invokeLater(button::doClick);
    }

    private static String correctionStatus(String prefix) throws Exception {
        return await("correction status: " + prefix, () -> {
            var status = namedVisible(JLabel.class, "BinaryRat correction status");
            return status != null && status.getText().startsWith(prefix) ? status.getText() : null;
        });
    }

    private static JDialog openOverride() throws Exception {
        click("BinaryRat override call prototype");
        return await("override prototype dialog", () -> dialog("Override Call Prototype"));
    }

    private static JTextField signatureField(JDialog dialog) {
        var field = namedIn(dialog, JTextField.class, "BinaryRat call prototype signature");
        require(field != null && field.isEditable(), "The signature field is missing or cannot be edited");
        return field;
    }

    private static void submitOverride(JDialog dialog, String signature) throws Exception {
        swing(() -> {
            signatureField(dialog).setText(signature);
            return null;
        });
        press(dialog, "Apply");
        await("submitted override dialog closed", () -> !dialog.isShowing() ? Boolean.TRUE : null);
    }

    private static void press(JDialog dialog, String text) throws Exception {
        var button = swing(() -> descendants(dialog).filter(JButton.class::isInstance)
            .map(JButton.class::cast).filter(candidate -> text.equals(candidate.getText())).findFirst()
            .orElseThrow(() -> new AssertionError("Missing dialog button " + text)));
        SwingUtilities.invokeLater(button::doClick);
    }

    private static void close(JDialog dialog) throws Exception {
        swing(() -> {
            dialog.dispatchEvent(new WindowEvent(dialog, WindowEvent.WINDOW_CLOSING));
            return null;
        });
        await("p-code dialog closed", () -> !dialog.isShowing() ? Boolean.TRUE : null);
    }

    private static <T extends Component> T namedVisible(Class<T> type, String name) {
        return Arrays.stream(Window.getWindows()).filter(Window::isShowing)
            .map(window -> namedIn(window, type, name)).filter(candidate -> candidate != null)
            .findFirst().orElse(null);
    }

    private static <T extends Component> T namedIn(Component ancestor, Class<T> type, String name) {
        return descendants(ancestor).filter(Component::isShowing).filter(type::isInstance)
            .filter(component -> name.equals(component.getName())).map(type::cast).findFirst().orElse(null);
    }

    private static JDialog dialog(String title) {
        return Arrays.stream(Window.getWindows()).filter(Window::isShowing)
            .filter(JDialog.class::isInstance).map(JDialog.class::cast)
            .filter(candidate -> candidate.getTitle().equals(title)).findFirst().orElse(null);
    }

    private static DockingActionIf action(PluginTool tool, String owner, String name) {
        return tool.getDockingActionsByOwnerName(owner).stream()
            .filter(candidate -> candidate.getName().equals(name))
            .filter(candidate -> Arrays.equals(candidate.getMenuBarData().getMenuPath(),
                new String[] {"Tools", "BinaryRat", name}))
            .findFirst().orElseThrow(() -> new AssertionError("Missing workspace menu: " + name));
    }

    private static Stream<Component> descendants(Component component) {
        if (component instanceof Container container) {
            return Stream.concat(Stream.of(component),
                Arrays.stream(container.getComponents()).flatMap(WorkspaceProbe::descendants));
        }
        return Stream.of(component);
    }

    private static <T> T swing(Callable<T> query) throws Exception {
        var task = new FutureTask<>(query);
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
        throw new AssertionError("Timed out awaiting " + label);
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
