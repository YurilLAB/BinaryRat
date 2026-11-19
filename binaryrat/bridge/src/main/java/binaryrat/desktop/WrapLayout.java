// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package binaryrat.desktop;

import java.awt.Component;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Insets;

import javax.swing.JComponent;
import javax.swing.SwingUtilities;

/**
 * A FlowLayout that asks for the height of its wrapped rows. A plain FlowLayout asks for one
 * row, so a narrow dock wraps its last buttons into space it never receives.
 */
final class WrapLayout extends FlowLayout {
    private int laidOutWidth = -1;

    WrapLayout(int align, int horizontalGap, int verticalGap) {
        super(align, horizontalGap, verticalGap);
    }

    @Override
    public void layoutContainer(Container target) {
        super.layoutContainer(target);
        // Parents size this panel from the width of the previous pass. After a width change,
        // ask once more so the row count follows the new width; equal widths stop here.
        if (target.getWidth() != laidOutWidth) {
            laidOutWidth = target.getWidth();
            if (target instanceof JComponent component) {
                SwingUtilities.invokeLater(component::revalidate);
            }
        }
    }

    @Override
    public Dimension preferredLayoutSize(Container target) {
        return layoutSize(target, true);
    }

    @Override
    public Dimension minimumLayoutSize(Container target) {
        return layoutSize(target, false);
    }

    private Dimension layoutSize(Container target, boolean preferred) {
        synchronized (target.getTreeLock()) {
            // Before the first layout the panel has no width; its closest sized ancestor bounds it.
            Container sized = target;
            while (sized.getWidth() == 0 && sized.getParent() != null) {
                sized = sized.getParent();
            }
            Insets insets = target.getInsets();
            int frame = insets.left + insets.right + 2 * getHgap();
            int available = sized.getWidth() == 0 ? Integer.MAX_VALUE : sized.getWidth() - frame;
            int width = 0;
            int height = 0;
            int rowWidth = 0;
            int rowHeight = 0;
            for (Component component : target.getComponents()) {
                if (!component.isVisible()) {
                    continue;
                }
                Dimension size = preferred ? component.getPreferredSize() : component.getMinimumSize();
                if (rowWidth > 0 && rowWidth + getHgap() + size.width > available) {
                    width = Math.max(width, rowWidth);
                    height += (height > 0 ? getVgap() : 0) + rowHeight;
                    rowWidth = 0;
                    rowHeight = 0;
                }
                rowWidth += (rowWidth > 0 ? getHgap() : 0) + size.width;
                rowHeight = Math.max(rowHeight, size.height);
            }
            width = Math.max(width, rowWidth);
            height += (height > 0 ? getVgap() : 0) + rowHeight;
            return new Dimension(width + frame, height + insets.top + insets.bottom + 2 * getVgap());
        }
    }
}
