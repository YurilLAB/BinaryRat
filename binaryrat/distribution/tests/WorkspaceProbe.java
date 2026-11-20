// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package distributionfixture;

import java.awt.Component;
import java.awt.Container;
import java.awt.Window;
import java.awt.event.WindowEvent;
import java.awt.image.BufferedImage;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.FutureTask;
import java.util.stream.Stream;

import javax.imageio.ImageIO;
import javax.swing.Icon;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import com.google.gson.JsonParser;

import docking.DefaultActionContext;
import docking.action.DockingActionIf;
import docking.framework.ApplicationInformationDisplayFactory;
import generic.theme.GIcon;
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
import resources.icons.DerivedImageIcon;
import resources.icons.UrlImageIcon;

/** Exercise the actual CodeBrowser defaults from a new bundled application profile. */
public final class WorkspaceProbe implements GhidraLaunchable {
    /** Directory beside the JSON report that receives window pictures. */
    private static Path evidence;
    /** The fork's copy of binaryrat/docs/assets/logo.png, the logo in the README. */
    private static final String LOGO = "images/BinaryRatLogo.png";

    private static boolean isLogo(Icon icon, String path) {
        String url = source(icon);
        return url != null && url.endsWith("/" + path);
    }

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
            evidence = Path.of(args[2]).toAbsolutePath().getParent();
            inspectBranding(tool, evidence);
            inspect(tool, Path.of(args[2]));
            System.out.println("BINARYRAT_WORKSPACE_OK");
            System.exit(0);
        }
        catch (Throwable error) {
            error.printStackTrace();
            System.exit(1);
        }
    }

    /** The fork's splash, About and window icons, and BinaryRat's own window, scale the README logo. */
    private static void inspectBranding(PluginTool tool, Path evidence) throws Exception {
        require(ApplicationInformationDisplayFactory.createSplashScreenTitle().equals("Welcome To BinaryRat") &&
            ApplicationInformationDisplayFactory.createAboutTitle().equals("About BinaryRat"),
            "Splash and About titles do not name BinaryRat");
        for (String size : List.of("home", "16", "24", "32", "40", "48", "64", "128", "256")) {
            var icon = new GIcon("icon.base.application." + size);
            int pixels = size.equals("home") ? 16 : Integer.parseInt(size);
            require(isLogo(icon, LOGO) && icon.getIconWidth() == pixels && icon.getIconHeight() == pixels,
                "Application icon " + size + " is " + source(icon) + " at " + icon.getIconWidth());
        }
        var animation = new GIcon("icon.dragon.256");
        require(isLogo(animation, LOGO) && animation.getIconWidth() == 256,
            "Window animations use " + source(animation));
        await("BinaryRat function view registered", () ->
            tool.getComponentProvider("BinaryRat Function") != null ? Boolean.TRUE : null);
        swing(() -> {
            // A tool window shows its template's icon; the application icons cover other windows.
            var toolIcon = tool.getIconURL();
            require(toolIcon.getLocation().equals(LOGO) && isLogo(toolIcon.getSmallIcon(), LOGO) &&
                toolIcon.getSmallIcon().getIconWidth() == 16,
                "CodeBrowser tool icon: " + toolIcon.getLocation() + " / " + toolIcon.getSmallIcon());
            var frameIcons = tool.getToolFrame().getIconImages();
            require(!frameIcons.isEmpty() && frameIcons.getFirst().getWidth(null) == 16,
                "CodeBrowser window icons: " + frameIcons);
            var about = ApplicationInformationDisplayFactory.createAboutComponent();
            var splash = descendants(about).filter(JLabel.class::isInstance).map(label -> ((JLabel) label).getIcon())
                .filter(icon -> isLogo(icon, LOGO)).findFirst().orElse(null);
            require(splash != null && splash.getIconWidth() == 500 && splash.getIconHeight() == 500,
                "About image: " + splash);
            snapshot(about, evidence.resolve("about.png"));
            var provider = tool.getComponentProvider("BinaryRat Function");
            require(isLogo(provider.getIcon(), "images/binaryrat/logo.png") &&
                provider.getIcon().getIconWidth() == 16,
                "BinaryRat function view icon: " + source(provider.getIcon()));
            var inspect = action(tool, "BinaryRatForegroundPlugin", "Inspect Selected Function");
            require(inspect.getToolBarData() != null && inspect.getToolBarData().getIcon() == provider.getIcon(),
                "The toolbar lacks the BinaryRat function view button");
            return null;
        });
    }

    /** The resource URL an icon was loaded from, through theme and scaling wrappers. */
    private static String source(Icon icon) {
        while (true) {
            if (icon instanceof GIcon theme) {
                icon = theme.getDelegate();
            }
            else if (icon instanceof DerivedImageIcon derived) {
                icon = derived.getSourceIcon();
            }
            else {
                return icon instanceof UrlImageIcon url ? url.getUrl().toString() : null;
            }
        }
    }

    /** Paint a Swing component tree into a PNG for the CI evidence. Call on the EDT. */
    private static void snapshot(Component component, Path destination) throws Exception {
        var size = component.isShowing() ? component.getSize() : component.getPreferredSize();
        if (!component.isShowing()) {
            component.setSize(size);
            layout(component);
        }
        var image = new BufferedImage(Math.max(1, size.width), Math.max(1, size.height),
            BufferedImage.TYPE_INT_ARGB);
        var graphics = image.createGraphics();
        try {
            component.printAll(graphics);
        }
        finally {
            graphics.dispose();
        }
        ImageIO.write(image, "png", destination.toFile());
    }

    private static void layout(Component component) {
        component.doLayout();
        if (component instanceof Container container) {
            for (var child : container.getComponents()) {
                layout(child);
            }
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
        // Recovery opens the new report's evidence table, the analyst's next step.
        var table = await("evidence table from the workspace recovery",
            () -> dialog("BinaryRat Layout Evidence — measurement_area (parameter 0)"));
        await("evidence rows with hex offsets and disassembly", () -> {
            var rows = descendants(table).filter(JTable.class::isInstance).map(JTable.class::cast)
                .findFirst().orElse(null);
            if (rows == null || rows.getRowCount() < 3) {
                return null;
            }
            int offset = rows.getColumnModel().getColumnIndex("Offset");
            int instruction = rows.getColumnModel().getColumnIndex("Instruction");
            for (int row = 0; row < rows.getRowCount(); row++) {
                if (!String.valueOf(rows.getValueAt(row, offset)).startsWith("+0x") ||
                        String.valueOf(rows.getValueAt(row, instruction)).isBlank()) {
                    return null;
                }
            }
            return Boolean.TRUE;
        });
        swing(() -> {
            snapshot(table, WorkspaceProbe.evidence.resolve("evidence.png"));
            descendants(table).filter(JButton.class::isInstance).map(JButton.class::cast)
                .filter(button -> button.getText().equals("Dismiss")).findFirst().orElseThrow().doClick();
            return null;
        });
        await("evidence table dismissed", () -> table.isShowing() ? null : Boolean.TRUE);
        inspectCallSites(tool, program, revision);
        inspectStackStrings(tool, program, revision);
        inspectCorrections(tool, program, function, revision);
    }

    /** Stack Strings: main builds "square units" one character at a time. */
    private static void inspectStackStrings(PluginTool tool, Program program, long revision) throws Exception {
        var scan = await("enabled stack-string action", () -> {
            var candidate = action(tool, "BinaryRatWorkspacePlugin", "Stack Strings");
            return candidate.isEnabled() ? candidate : null;
        });
        SwingUtilities.invokeLater(() -> scan.actionPerformed(new DefaultActionContext()));
        var table = await("stack-string table", () -> dialog("BinaryRat Stack Strings"));
        await("the sample's stack string", () -> {
            var rows = descendants(table).filter(JTable.class::isInstance).map(JTable.class::cast)
                .findFirst().orElse(null);
            if (rows == null || rows.getRowCount() < 1) {
                return null;
            }
            var columns = rows.getColumnModel();
            int text = columns.getColumnIndex("Text");
            int terminated = columns.getColumnIndex("Terminated");
            for (int row = 0; row < rows.getRowCount(); row++) {
                if (String.valueOf(rows.getValueAt(row, text)).equals("\"square units\"") &&
                        String.valueOf(rows.getValueAt(row, terminated)).equals("yes")) {
                    return Boolean.TRUE;
                }
            }
            return null;
        });
        require(!program.isChanged() && program.getModificationNumber() == revision,
            "Listing stack strings changed the Program");
        swing(() -> {
            snapshot(table, WorkspaceProbe.evidence.resolve("stackstrings.png"));
            descendants(table).filter(JButton.class::isInstance).map(JButton.class::cast)
                .filter(button -> button.getText().equals("Dismiss")).findFirst().orElseThrow().doClick();
            return null;
        });
        await("stack-string table dismissed", () -> table.isShowing() ? null : Boolean.TRUE);
        System.out.println("BINARYRAT_WORKSPACE_STACK_STRINGS_OK");
    }

    /** Call Sites with Arguments on measurement_bias: main passes 0, measurement_area its area. */
    private static void inspectCallSites(PluginTool tool, Program program, long revision) throws Exception {
        var globals = program.getSymbolTable().getGlobalSymbols("measurement_bias");
        require(globals.size() == 1, "Expected one measurement_bias symbol");
        var bias = program.getFunctionManager().getFunctionAt(globals.getFirst().getAddress());
        require(bias != null, "Example measurement_bias was not analyzed");
        goTo(tool, program, bias.getEntryPoint());
        var listCalls = await("enabled call-site action", () -> {
            var candidate = action(tool, "BinaryRatWorkspacePlugin", "Call Sites with Arguments");
            return candidate.isEnabled() ? candidate : null;
        });
        SwingUtilities.invokeLater(() -> listCalls.actionPerformed(new DefaultActionContext()));
        var table = await("call-site table", () -> dialog("BinaryRat Call Sites — " + bias.getName(true)));
        await("call rows with statements and the constant argument", () -> {
            var rows = descendants(table).filter(JTable.class::isInstance).map(JTable.class::cast)
                .findFirst().orElse(null);
            if (rows == null || rows.getRowCount() < 2) {
                return null;
            }
            var columns = rows.getColumnModel();
            int caller = columns.getColumnIndex("Caller");
            int statement = columns.getColumnIndex("Statement");
            int arguments = columns.getColumnIndex("Arguments");
            int status = columns.getColumnIndex("Status");
            boolean fromArea = false;
            boolean constant = false;
            for (int row = 0; row < rows.getRowCount(); row++) {
                if (!String.valueOf(rows.getValueAt(row, status)).equals("decompiled") ||
                        !String.valueOf(rows.getValueAt(row, statement)).contains(bias.getName() + "(")) {
                    return null;
                }
                fromArea |= String.valueOf(rows.getValueAt(row, caller)).equals("measurement_area");
                constant |= String.valueOf(rows.getValueAt(row, arguments)).equals("0");
            }
            return fromArea && constant ? Boolean.TRUE : null;
        });
        require(!program.isChanged() && program.getModificationNumber() == revision,
            "Listing call sites changed the Program");
        swing(() -> {
            snapshot(table, WorkspaceProbe.evidence.resolve("callsites.png"));
            descendants(table).filter(JButton.class::isInstance).map(JButton.class::cast)
                .filter(button -> button.getText().equals("Dismiss")).findFirst().orElseThrow().doClick();
            return null;
        });
        await("call-site table dismissed", () -> table.isShowing() ? null : Boolean.TRUE);
        System.out.println("BINARYRAT_WORKSPACE_CALL_SITES_OK");
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
        require(raw.contains(site.toString()) && raw.lines().skip(3).anyMatch(line -> line.contains("CALL")) &&
            raw.contains("RSP = INT_SUB RSP"), "P-code dialog did not show the selected call instruction\n" + raw);
        swing(() -> {
            snapshot(pcode, evidence.resolve("pcode.png"));
            return null;
        });
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
        var review = openOverride();
        swing(() -> {
            require(signatureField(review).getText().equals("uint measurement_bias(uint value)"),
                "The existing override was not offered for review: " + signatureField(review).getText());
            var origin = namedIn(review, JLabel.class, "BinaryRat call prototype origin");
            require(origin != null && origin.getText().startsWith("Showing the override already at this call"),
                "The review does not say it replaces the existing override");
            var convention = namedIn(review, JComboBox.class, "BinaryRat call prototype convention");
            require(convention != null && convention.getItemCount() > 1 && convention.getSelectedItem() != null,
                "The review lacks a calling convention choice");
            snapshot(review, evidence.resolve("override.png"));
            return null;
        });
        press(review, "Apply");
        require(correctionStatus("Override failed:").contains("already uses that prototype"),
            "Re-applying the same prototype was not reported");
        require(program.getModificationNumber() == appliedRevision,
            "Re-applying the same prototype changed the Program");

        submitOverride(openOverride(), "int measurement_bias(int value)");
        correctionStatus("Call prototype override replaced at " + site);
        var replaced = overrideAt(function, site);
        require(replaced != null && replaced.getReturnType().getName().equals("int") &&
            overrideMarkers(function, site) == 1, "Replacement did not leave one int override: " + replaced);
        undo(program);
        var restored = overrideAt(function, site);
        require(restored != null && restored.getReturnType().isEquivalent(UnsignedIntegerDataType.dataType) &&
            overrideMarkers(function, site) == 1, "One undo did not restore the previous override");

        undo(program);
        require(overrideAt(function, site) == null && overrideAt(peerFunction, peerSite) == null,
            "Native undo did not remove the override");
        await("ready foreground after native undo", () -> {
            var status = namedVisible(JLabel.class, "BinaryRat foreground status");
            var override = namedVisible(JButton.class, "BinaryRat override call prototype");
            return status != null && status.getText().startsWith("Ready: measurement_area") &&
                override != null && override.isEnabled() ? Boolean.TRUE : null;
        });
        // The default right-hand dock is narrow: every correction button must still be on screen.
        await("correction buttons fully visible", () -> {
            for (String name : List.of("BinaryRat inspect instruction p-code", "BinaryRat override call prototype",
                "BinaryRat open interactive decompiler")) {
                var button = namedVisible(JButton.class, name);
                var visible = button == null ? null : button.getVisibleRect();
                if (visible == null || button.getWidth() == 0 || visible.width != button.getWidth() ||
                    visible.height != button.getHeight()) {
                    return null;
                }
            }
            return Boolean.TRUE;
        });
        swing(() -> {
            snapshot(tool.getToolFrame(), evidence.resolve("codebrowser.png"));
            return null;
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

    private static int overrideMarkers(Function function, Address site) {
        var namespace = HighFunction.findOverrideSpace(function);
        return namespace == null ? 0 : (int) Arrays.stream(function.getProgram().getSymbolTable().getSymbols(site))
            .filter(symbol -> namespace.equals(symbol.getParentNamespace()) &&
                symbol.getSymbolType() == SymbolType.LABEL && symbol.getName().startsWith("prt"))
            .count();
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
