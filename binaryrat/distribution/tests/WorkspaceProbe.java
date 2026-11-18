// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package distributionfixture;

import java.awt.Component;
import java.awt.Container;
import java.awt.Window;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.FutureTask;
import java.util.stream.Stream;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import com.google.gson.JsonParser;

import docking.DefaultActionContext;
import docking.action.DockingActionIf;
import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ProgramManager;
import ghidra.base.help.GhidraHelpService;
import ghidra.base.project.GhidraProject;
import ghidra.framework.Application;
import ghidra.framework.GhidraApplicationConfiguration;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.preferences.Preferences;
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
