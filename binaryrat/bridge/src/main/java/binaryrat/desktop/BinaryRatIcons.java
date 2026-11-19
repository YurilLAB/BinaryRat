// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package binaryrat.desktop;

import javax.swing.Icon;

import resources.ResourceManager;

/** The README logo at the sizes BinaryRat's own windows, actions and dialogs use. */
public final class BinaryRatIcons {
    /** Rendered by binaryrat/tools/make_branding.py into the extension JAR. */
    public static final String LOGO_16_PATH = "images/binaryrat/logo16.png";
    public static final Icon LOGO_16 = ResourceManager.loadImage(LOGO_16_PATH);
    public static final Icon LOGO_24 = ResourceManager.loadImage("images/binaryrat/logo24.png");
    public static final Icon LOGO_32 = ResourceManager.loadImage("images/binaryrat/logo32.png");
    public static final Icon LOGO_64 = ResourceManager.loadImage("images/binaryrat/logo64.png");

    private BinaryRatIcons() {
    }
}
