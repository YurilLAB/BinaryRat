// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package binaryrat.desktop;

import generic.theme.GIcon;
import ghidra.framework.plugintool.util.PluginPackage;

/** The BinaryRat tools installed in the bundled CodeBrowser workspace. */
public final class BinaryRatPluginPackage extends PluginPackage {

    public static final String NAME = "BinaryRat";

    public BinaryRatPluginPackage() {
        super(NAME, new GIcon("icon.help"), "BinaryRat analysis and evidence tools.");
    }
}
