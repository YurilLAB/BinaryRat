// Run a documented BinaryRat analysis profile on the current Program.
// @category BinaryRat
// @menupath Tools.BinaryRat.Analyze with Profile
// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0

import java.util.List;

import binaryrat.analysis.AnalysisProfiles;
import binaryrat.analysis.AnalysisProfiles.Profile;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidra.util.timer.GTimer;
import ghidra.util.timer.GTimerMonitor;

public class BinaryRatProfile extends HeadlessScript {
    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            throw new IllegalStateException("Open a Program to run a BinaryRat analysis profile.");
        }
        int timeout = 0;
        Profile profile;
        if (isRunningHeadless()) {
            String[] args = getScriptArgs();
            if (args.length < 1 || args.length > 2) {
                throw new IllegalArgumentException(
                    "Use -preScript BinaryRatProfile.java quick|normal|deep [timeout-seconds]");
            }
            profile = Profile.parse(args[0]);
            if (args.length == 2) {
                timeout = Integer.parseInt(args[1]);
                if (timeout < 1 || timeout > 86400) {
                    throw new IllegalArgumentException("Analysis profile timeout must be in 1..86400 seconds.");
                }
            }
        }
        else {
            profile = askChoice("BinaryRat Analysis Profile",
                "Quick triage defers inference and debug-info import. Normal uses Program settings. " +
                "Deeper enables parameter inference, stack parameter discovery, and PE RTTI.",
                List.of(Profile.values()), Profile.NORMAL);
        }

        // The analysis manager owns the worker's transaction.
        end(true);
        TaskMonitor task = isRunningHeadless() ? new TaskMonitorAdapter(true) : monitor;
        GTimerMonitor deadline = timeout == 0 ? null :
            GTimer.scheduleRunnable(timeout * 1000L, task::cancel);
        try {
            if (isRunningHeadless()) {
                enableHeadlessAnalysis(false);
            }
            AnalysisProfiles.run(currentProgram, profile, task, plan -> {
                println("BinaryRat analysis profile " + profile.key() + ": " + profile.description());
                for (var option : plan.options()) {
                    println("  " + option.name() + " = " + option.enabled());
                }
                for (String option : plan.unavailable()) {
                    println("  " + option + " unavailable for this Program");
                }
            });
            println("BinaryRat analysis profile completed: " + profile.key());
        }
        finally {
            if (deadline != null) {
                deadline.cancel();
            }
        }
    }
}
