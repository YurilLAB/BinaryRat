// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package binaryrat.desktop;

import javax.swing.ImageIcon;

import resources.ResourceManager;

/** The README logo, scaled for BinaryRat's own windows, actions and dialogs. */
public final class BinaryRatIcons {
    /** A byte-for-byte copy of binaryrat/docs/assets/logo.png inside the extension JAR. */
    public static final String LOGO_PATH = "images/binaryrat/logo.png";
    private static final ImageIcon LOGO = ResourceManager.loadImage(LOGO_PATH);
    public static final ImageIcon LOGO_16 = ResourceManager.getScaledIcon(LOGO, 16, 16);
    public static final ImageIcon LOGO_32 = ResourceManager.getScaledIcon(LOGO, 32, 32);
    public static final ImageIcon LOGO_64 = ResourceManager.getScaledIcon(LOGO, 64, 64);

    private BinaryRatIcons() {
    }
}
