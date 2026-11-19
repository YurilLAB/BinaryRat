// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0

import java.io.File;

import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.util.extensions.ExtensionDetails;
import ghidra.util.extensions.ExtensionUtils;

/** Exercise the same extension installation API as the Ghidra project window. */
public class BinaryRatInstallExtensionFixture extends GhidraScript {
    @Override
    protected void run() throws Exception {
        File archive = new File(getScriptArgs()[0]);
        ExtensionDetails extension = ExtensionUtils.getExtension(archive, false);
        if (extension == null || !extension.getName().equals("BinaryRat") ||
                !Application.getApplicationVersion().equals(extension.getVersion())) {
            throw new IllegalArgumentException("Invalid BinaryRat extension metadata");
        }
        File installation = Application.getApplicationLayout().getExtensionInstallationDirs()
            .getFirst().getFile(false);
        if (!installation.isDirectory() && !installation.mkdirs()) {
            throw new IllegalStateException("Cannot create extension directory " + installation);
        }
        ExtensionUtils.initializeExtensions();
        if (!ExtensionUtils.install(extension, archive, monitor)) {
            throw new IllegalStateException("Installation failed");
        }
        println("BinaryRat test extension installed");
    }
}
