// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package binaryrat.desktop;

import ghidra.framework.plugintool.util.PluginPackage;

/** The BinaryRat tools installed in the bundled CodeBrowser workspace. */
public final class BinaryRatPluginPackage extends PluginPackage {

    public static final String NAME = "BinaryRat";

    public BinaryRatPluginPackage() {
        super(NAME, BinaryRatIcons.LOGO_32, "BinaryRat analysis and evidence tools.");
    }
}
