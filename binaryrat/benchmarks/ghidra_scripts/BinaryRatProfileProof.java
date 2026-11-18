// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import binaryrat.analysis.AnalysisProfiles;
import binaryrat.analysis.AnalysisProfiles.Profile;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitorAdapter;

public class BinaryRatProfileProof extends GhidraScript {
    private static final String SNAPSHOT = "binaryrat.analysis.profile.fixture.snapshot";
    private static final String PARAMETERS = "Decompiler Parameter ID";
    private static final String FUNCTION_ID = "Function ID";
    private static final List<String> TRACKED = List.of("DWARF", "PDB Universal", FUNCTION_ID,
        "Call Convention ID", PARAMETERS, "Windows x86 PE RTTI Analyzer",
        "Stack", "Stack.Create Param Variables");

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        require(isRunningHeadless() && args.length >= 1, "Expected headless fixture");
        switch (args[0]) {
            case "seed" -> {
                require(currentProgram.getCurrentTransactionInfo() != null, "Seed must hold a transaction");
                try {
                    AnalysisProfiles.run(currentProgram, Profile.NORMAL, monitor, plan -> {});
                    throw new AssertionError("Active transaction was accepted");
                }
                catch (IllegalStateException rejected) {
                    require(rejected.getMessage().contains("active analysis and edits"),
                        "Unexpected busy Program error");
                }
                Options options = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
                require(options.isRegistered(PARAMETERS) && options.isRegistered(FUNCTION_ID),
                    "Fixture requires parameter inference and Function ID");
                // Force a stable difference even when PE and ELF defaults differ.
                options.setBoolean(PARAMETERS, false);
                options.setBoolean(FUNCTION_ID, true);
                state.addEnvironmentVar(SNAPSHOT, snapshot());
            }
            case "verify" -> {
                Profile profile = Profile.parse(args[1]);
                require(GhidraProgramUtilities.isAnalyzed(currentProgram), "Program was not analyzed");
                require(currentProgram.getFunctionManager().getFunctionCount() > 0 &&
                    currentProgram.getListing().getNumInstructions() > 0, "No useful listing");
                var activity = Arrays.asList(
                    AutoAnalysisManager.getAnalysisManager(currentProgram).getTimedTasks());
                require(activity.contains(PARAMETERS) == (profile == Profile.DEEP),
                    "Unexpected parameter inference activity for " + profile + ": " + activity);
                require(activity.contains(FUNCTION_ID) == (profile != Profile.QUICK),
                    "Unexpected Function ID activity for " + profile + ": " + activity);
                require(snapshot().equals(state.getEnvironmentVar(SNAPSHOT)),
                    "Profile left altered analyzer options");
                println("BINARYRAT_ANALYSIS_PROFILE_PROOF " + profile.key() +
                    " functions=" + currentProgram.getFunctionManager().getFunctionCount() +
                    " analyzers=" + activity.size());
            }
            case "cancel" -> verifyCancellation();
            default -> throw new IllegalArgumentException("Unknown profile test stage");
        }
    }

    private Map<String, List<Boolean>> snapshot() {
        var options = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
        Map<String, List<Boolean>> result = new HashMap<>();
        for (String name : TRACKED) {
            if (options.isRegistered(name)) {
                result.put(name, List.of(options.getBoolean(name, false), options.isDefaultValue(name)));
            }
        }
        return result;
    }

    private void verifyCancellation() throws Exception {
        end(true);
        var before = snapshot();
        var cancel = new TaskMonitorAdapter(true) {
            @Override
            public void setMessage(String message) {
                super.setMessage(message);
                if (message.startsWith("Analyzing with ")) {
                    cancel();
                }
            }
        };
        try {
            AnalysisProfiles.run(currentProgram, Profile.DEEP, cancel, plan ->
                require(plan.options().stream().anyMatch(option ->
                    option.name().equals(PARAMETERS) && !option.previous() && option.enabled()),
                    "Cancellation proof requires a changed option"));
            throw new IllegalStateException("Cancelled profile returned success");
        }
        catch (CancelledException expected) {
            require(cancel.isCancelled(), "Unexpected cancellation cause");
        }
        require(snapshot().equals(before), "Cancelled profile did not restore analyzer options");
        require(!GhidraProgramUtilities.isAnalyzed(currentProgram),
            "Cancelled profile marked the Program analyzed");
        println("BINARYRAT_ANALYSIS_PROFILE_CANCEL_PROOF");
    }

    private static void require(boolean expected, String message) {
        if (!expected) {
            throw new IllegalStateException(message);
        }
    }
}
