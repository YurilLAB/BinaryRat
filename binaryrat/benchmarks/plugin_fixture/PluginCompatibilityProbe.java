// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package pluginfixture;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.FutureTask;
import javax.swing.SwingUtilities;

import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;
import ghidra.framework.Application;
import ghidra.framework.GhidraApplicationConfiguration;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.util.classfinder.ClassSearcher;
import pluginfixture.SelectionSizePlugin.SelectionSize;

public class PluginCompatibilityProbe implements GhidraLaunchable {
    @Override
    public void launch(GhidraApplicationLayout layout, String[] args) {
        try {
            GhidraApplicationConfiguration config = new GhidraApplicationConfiguration();
            config.setShowSplashScreen(false);
            Application.initializeApplication(layout, config);

            Path loadedJar = Path.of(SelectionSizePlugin.class.getProtectionDomain()
                .getCodeSource().getLocation().toURI());
            if (!Files.isSameFile(loadedJar, Path.of(args[0])) ||
                    !ClassSearcher.getClasses(Plugin.class).contains(SelectionSizePlugin.class)) {
                throw new AssertionError("Expected the installed plugin JAR in Ghidra discovery");
            }

            FutureTask<Void> lifecycle = new FutureTask<>(() -> {
                exercisePlugin();
                return null;
            });
            SwingUtilities.invokeAndWait(lifecycle);
            lifecycle.get();
            System.out.println("PLUGIN_COMPATIBILITY_OK");
            System.exit(0);
        }
        catch (Throwable failure) {
            failure.printStackTrace();
            System.exit(1);
        }
    }

    private static void exercisePlugin() throws Exception {
        PluginTool tool = new PluginTool(null, null, null, "Compatibility", true, false, false) {};
        try {
            if (tool.getService(SelectionSize.class) != null) {
                throw new AssertionError("Unexpected selection service before loading plugin");
            }
            tool.addPlugin(SelectionSizePlugin.class.getName());
            SelectionSize service = tool.getService(SelectionSize.class);
            AddressSet selection = new AddressSet();
            if (service == null || service.count(selection) != 0) {
                throw new AssertionError("Loading the plugin did not provide the selection service");
            }

            AddressSpace ram = new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0);
            selection.add(ram.getAddress(1), ram.getAddress(3));
            selection.add(ram.getAddress(7), ram.getAddress(9));
            selection.add(ram.getAddress(8), ram.getAddress(10));
            if (service.count(selection) != 7) {
                throw new AssertionError("Incorrect size for discontiguous, overlapping ranges");
            }

            List<Plugin> plugins = tool.getManagedPlugins().stream()
                .filter(SelectionSizePlugin.class::isInstance).toList();
            if (plugins.size() != 1) {
                throw new AssertionError("Expected one managed instance");
            }
            tool.removePlugins(plugins);
            if (tool.getService(SelectionSize.class) != null) {
                throw new AssertionError("Removing the plugin left a registered service");
            }
        }
        finally {
            tool.close();
        }
    }
}
