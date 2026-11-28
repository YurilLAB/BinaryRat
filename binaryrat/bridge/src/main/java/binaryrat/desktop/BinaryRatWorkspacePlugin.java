// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package binaryrat.desktop;

import docking.action.DockingAction;
import docking.action.builder.ActionBuilder;
import docking.widgets.OptionDialogBuilder;
import ghidra.app.context.ListingActionContext;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GhidraScriptService;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

/** Put the supported desktop workflows in a new CodeBrowser workspace. */
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = BinaryRatPluginPackage.NAME,
    category = "Analysis",
    shortDescription = "BinaryRat workspace actions",
    description = "Export, recover and inspect BinaryRat evidence, call sites and stack strings from CodeBrowser.",
    servicesRequired = { GhidraScriptService.class, GoToService.class, ProgramManager.class }
)
public final class BinaryRatWorkspacePlugin extends ProgramPlugin {

    private final DockingAction export;
    private final DockingAction recover;
    private final DockingAction recoverSummary;
    private final ArithmeticEvidenceProvider arithmetic;
    private final DockingAction browse;
    private final DockingAction callSites;
    private final DockingAction stackStrings;
    private final DockingAction profile;

    public BinaryRatWorkspacePlugin(PluginTool tool) {
        super(tool);
        new ActionBuilder("Getting Started", getName())
            .menuPath("Tools", "BinaryRat", "Getting Started")
            .menuGroup("0_help")
            .onAction(context -> showGettingStarted())
            .buildAndInstall(tool);
        export = scriptAction("Export Decompilation", "BinaryRatExport.java", "2_evidence");
        arithmetic = new ArithmeticEvidenceProvider(tool, getName());
        new ActionBuilder(ArithmeticEvidenceProvider.ACTION, getName())
            .menuPath("Tools", "BinaryRat", ArithmeticEvidenceProvider.ACTION)
            .menuGroup("2_evidence")
            .popupMenuPath("BinaryRat", ArithmeticEvidenceProvider.ACTION)
            .withContext(ListingActionContext.class)
            .enabledWhen(this::hasArithmeticSelection)
            .popupWhen(this::hasArithmeticSelection)
            .onAction(context -> arithmetic.select(context.getProgram(), context.getSelection()))
            .buildAndInstall(tool);
        recover = scriptAction("Recover Layout at Cursor", "BinaryRatRecoverLayouts.java", "2_evidence");
        var summary = new SummaryLayoutCursor(tool);
        recoverSummary = new ActionBuilder(SummaryLayoutCursor.ACTION, getName())
            .menuPath("Tools", "BinaryRat", SummaryLayoutCursor.ACTION)
            .menuGroup("2_evidence")
            .enabled(false)
            .onAction(context -> summary.show(currentLocation))
            .buildAndInstall(tool);
        browse = scriptAction("Browse Layout Evidence", "BinaryRatBrowseLayout.java", "2_evidence");
        callSites = scriptAction("Call Sites with Arguments", "BinaryRatCallSites.java", "2_evidence");
        stackStrings = scriptAction("Stack Strings", "BinaryRatStackStrings.java", "2_evidence");
        profile = scriptAction("Analyze with Profile", "BinaryRatProfile.java", "1_analysis");
    }

    @Override
    protected void programActivated(Program program) {
        locationChanged(currentLocation);
    }

    @Override
    protected void programDeactivated(Program program) {
        arithmetic.deactivate(program);
    }

    @Override
    protected void dispose() {
        arithmetic.disposeEvidence();
        super.dispose();
    }

    @Override
    protected void locationChanged(ProgramLocation location) {
        boolean open = currentProgram != null;
        export.setEnabled(open);
        recover.setEnabled(open && location != null);
        recoverSummary.setEnabled(open && location != null);
        browse.setEnabled(open);
        callSites.setEnabled(open && location != null);
        stackStrings.setEnabled(open);
        profile.setEnabled(open);
    }

    private boolean hasArithmeticSelection(ListingActionContext context) {
        return currentProgram != null && currentProgram == context.getProgram() &&
            context.getSelection() != null && !context.getSelection().isEmpty();
    }

    private DockingAction scriptAction(String title, String script, String group) {
        return new ActionBuilder(title, getName())
            .menuPath("Tools", "BinaryRat", title)
            .menuGroup(group)
            .enabled(false)
            .onAction(context -> tool.getService(GhidraScriptService.class).runScript(script, null))
            .buildAndInstall(tool);
    }

    private void showGettingStarted() {
        new OptionDialogBuilder("Getting Started with BinaryRat",
            "<html><b>Open a binary</b><br>" +
            "In the project window, create or open a local project and choose File &rarr; Import File.<br>" +
            "Double-click the imported program to open it in CodeBrowser.<br><br>" +
            "<b>Inspect analysis and evidence</b><br>" +
            "Choose an action from Tools &rarr; BinaryRat, or use the Listing and Decompiler normally.<br>" +
            "The rat button in the toolbar opens the BinaryRat function view for the Listing selection.<br>" +
            "The application archive includes an offline guide in help/GettingStarted.html.</html>")
            .setIcon(BinaryRatIcons.LOGO_64)
            .addOption("OK")
            .show(tool.getToolFrame());
    }
}
