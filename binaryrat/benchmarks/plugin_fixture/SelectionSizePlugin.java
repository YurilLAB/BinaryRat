// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package pluginfixture;

import ghidra.MiscellaneousPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.AddressSetView;

/** Example internal plugin with no BinaryRat dependencies. */
@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = MiscellaneousPluginPackage.NAME,
    category = PluginCategoryNames.COMMON,
    shortDescription = "Measure selection size",
    description = "Reports the number of addresses covered by a selection.",
    servicesProvided = SelectionSizePlugin.SelectionSize.class
)
public class SelectionSizePlugin extends Plugin {
    public interface SelectionSize {
        long count(AddressSetView selection);
    }

    public SelectionSizePlugin(PluginTool tool) {
        super(tool);
        registerServiceProvided(SelectionSize.class, AddressSetView::getNumAddresses);
    }
}
