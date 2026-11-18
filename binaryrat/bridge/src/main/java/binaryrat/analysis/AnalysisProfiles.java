// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package binaryrat.analysis;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import ghidra.app.plugin.core.analysis.AnalysisWorker;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Runs existing Ghidra analyzers with a temporary overlay of registered options. */
public final class AnalysisProfiles {
    private static final String PARAMETERS = "Decompiler Parameter ID";
    private static final String RTTI = "Windows x86 PE RTTI Analyzer";
    private static final Set<Program> ACTIVE = ConcurrentHashMap.newKeySet();

    public enum Profile {
        QUICK("Quick triage", "Defer debug-info import, Function ID, signature inference, and PE RTTI.",
            List.of(new Setting("DWARF", false), new Setting("PDB Universal", false),
                new Setting("Function ID", false), new Setting("Call Convention ID", false),
                new Setting(PARAMETERS, false), new Setting(RTTI, false))),
        NORMAL("Normal analysis", "Use the Program's configured Ghidra analyzers.", List.of()),
        DEEP("Deeper recovery", "Add decompiler parameter inference, stack parameter discovery, and PE RTTI.",
            List.of(new Setting(PARAMETERS, true), new Setting("Stack", true),
                new Setting("Stack.Create Param Variables", true), new Setting(RTTI, true)));

        private final String label;
        private final String description;
        private final List<Setting> settings;

        Profile(String label, String description, List<Setting> settings) {
            this.label = label;
            this.description = description;
            this.settings = settings;
        }

        public String key() {
            return name().toLowerCase(Locale.ROOT);
        }

        public String description() {
            return description;
        }

        @Override
        public String toString() {
            return label;
        }

        public static Profile parse(String value) {
            return switch (value) {
                case "quick" -> QUICK;
                case "normal" -> NORMAL;
                case "deep" -> DEEP;
                default -> throw new IllegalArgumentException("Analysis profile must be quick, normal, or deep.");
            };
        }
    }

    private record Setting(String name, boolean enabled) {}

    public record Option(String name, boolean previous, boolean enabled, boolean wasDefault) {
        void restore(Options options) {
            if (previous != enabled) {
                if (wasDefault) {
                    options.restoreDefaultValue(name);
                }
                else {
                    options.setBoolean(name, previous);
                }
            }
        }
    }

    public record Plan(Profile profile, List<Option> options, List<String> unavailable) {
        public Plan {
            options = List.copyOf(options);
            unavailable = List.copyOf(unavailable);
        }
    }

    private AnalysisProfiles() {}

    /**
     * Schedule one full analysis through the owning Program's analysis manager. Invoke off the EDT
     * and outside the caller's transaction. Ghidra controls the cancellation granularity and may
     * retain analysis it completed before cancellation. The profile options are scoped to the run.
     * The plan callback runs on the analysis worker before the temporary options are applied.
     */
    public static Plan run(Program program, Profile profile, TaskMonitor monitor,
            Consumer<Plan> beforeAnalysis) throws Exception {
        Objects.requireNonNull(program);
        Objects.requireNonNull(profile);
        Objects.requireNonNull(monitor);
        Objects.requireNonNull(beforeAnalysis);
        monitor.checkCancelled();
        Object consumer = new Object();
        if (program.isClosed() || !program.isChangeable() || !program.addConsumer(consumer)) {
            throw new IllegalArgumentException("Analysis profiles require a mutable Program.");
        }
        try {
            return schedule(program, profile, monitor, beforeAnalysis);
        }
        finally {
            program.release(consumer);
        }
    }

    private static Plan schedule(Program program, Profile profile, TaskMonitor monitor,
            Consumer<Plan> beforeAnalysis) throws Exception {
        AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(program);
        // A queued stock pass can already contain tasks disabled by the quick profile.
        if (manager.isAnalyzing() || program.getCurrentTransactionInfo() != null) {
            throw new IllegalStateException("Wait for active analysis and edits before running a profile.");
        }
        AtomicReference<Plan> result = new AtomicReference<>();
        boolean ran = manager.scheduleWorker(new AnalysisWorker() {
            @Override
            public String getWorkerName() {
                return "BinaryRat " + profile;
            }

            @Override
            public boolean analysisWorkerCallback(Program current, Object ignored, TaskMonitor task)
                    throws CancelledException {
                task.checkCancelled();
                if (!ACTIVE.add(current)) {
                    throw new IllegalStateException("An analysis profile is already active for this Program.");
                }
                Object consumer = new Object();
                boolean retained = false;
                try {
                    retained = current.addConsumer(consumer);
                    if (!retained) {
                        throw new IllegalStateException("The Program closed before profile analysis.");
                    }
                    result.set(analyze(current, manager, profile, task, beforeAnalysis));
                    return true;
                }
                finally {
                    ACTIVE.remove(current);
                    if (retained) {
                        current.release(consumer);
                    }
                }
            }
        }, null, true, monitor);
        monitor.checkCancelled();
        if (!ran || result.get() == null) {
            throw new CancelledException();
        }
        return result.get();
    }

    private static Plan plan(Options options, Profile profile) {
        List<Option> changes = new ArrayList<>();
        List<String> unavailable = new ArrayList<>();
        for (Setting setting : profile.settings) {
            String name = setting.name();
            if (!options.isRegistered(name)) {
                unavailable.add(name);
            }
            else {
                if (options.getType(name) != OptionType.BOOLEAN_TYPE) {
                    throw new IllegalStateException("Expected a boolean analyzer option: " + name);
                }
                changes.add(new Option(name, options.getBoolean(name, false), setting.enabled(),
                    options.isDefaultValue(name)));
            }
        }
        return new Plan(profile, changes, unavailable);
    }

    private static Plan analyze(Program program, AutoAnalysisManager manager, Profile profile,
            TaskMonitor monitor, Consumer<Plan> beforeAnalysis) throws CancelledException {
        Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
        Plan plan = plan(options, profile);
        beforeAnalysis.accept(plan);
        monitor.checkCancelled();
        try {
            for (Option change : plan.options()) {
                if (change.previous() != change.enabled()) {
                    options.setBoolean(change.name(), change.enabled());
                }
            }
            manager.initializeOptions(options);
            monitor.setMessage("Analyzing with " + profile);
            manager.reAnalyzeAll(null);
            manager.startAnalysis(monitor);
            monitor.checkCancelled();
        }
        finally {
            for (Option change : plan.options()) {
                change.restore(options);
            }
            manager.initializeOptions(options);
        }
        GhidraProgramUtilities.markProgramAnalyzed(program);
        return plan;
    }
}
