// Export deterministic stock-decompiler records; optionally run decompilation under the
// C++ engine's admission control, or prove the engine's live cache against fresh output.
// @category BinaryRat
// @menupath Tools.BinaryRat.Export Decompilation
/*
 * Copyright 2026 YurilLAB
 * Licensed under the Apache License, Version 2.0.
 * See the repository LICENSE file for the full license text.
 */

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.stream.Stream;

import javax.swing.JFileChooser;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import binaryrat.CacheProof;
import binaryrat.ChangeTracker;
import binaryrat.DecompOutput;
import binaryrat.EngineClient;
import binaryrat.LiveDecompileCache;
import binaryrat.ScheduledDecompiler;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.parallel.DecompilerCallback;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Minimal Ghidra 12.2 bridge. All decompilation remains in Ghidra's native engine.
 * Run after analysis from CodeBrowser or as a headless postScript.
 * Every mode except cache-proof leaves the Program unmodified; cache-proof edits it
 * and is meant for throwaway headless projects.
 */
public class BinaryRatExport extends GhidraScript {
    private static final int DEFAULT_CHUNK_SIZE = 128;
    private static final List<String> MODES = List.of("serial", "parallel", "compare",
        "compare-reverse", "scheduled", "compare-scheduled", "stock-verified", "cache-proof");
    private long revision;
    private String programId;
    private ScheduleSummary summary;
    private Set<Address> sample;

    private enum Mode { SERIAL, PARALLEL, SCHEDULED }

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            throw new IllegalStateException("Open an analyzed Program before exporting");
        }
        boolean headed = !isRunningHeadless();
        if (headed) {
            // GhidraScript starts a transaction even for read-only tasks. Release the
            // empty transaction before prompting or waiting on the decompiler.
            end(true);
        }
        AutoAnalysisManager analysis = AutoAnalysisManager.getAnalysisManager(currentProgram);
        if (analysis.isAnalyzing()) {
            throw new IllegalStateException("Auto-analysis must finish before exporting");
        }
        String[] args = headed ? desktopArguments() : getScriptArgs();
        if (args.length < 2 || args.length > 6) {
            throw new IllegalArgumentException("Usage: BinaryRatExport.java OUTPUT " +
                String.join("|", MODES) +
                " [WORKERS=4] [TIMEOUT_SECONDS=60] [CHUNK_SIZE=128] [SAMPLE_TSV]");
        }
        if (headed && analysis.isAnalyzing()) {
            throw new IllegalStateException("Auto-analysis must finish before exporting");
        }
        String mode = args[1];
        if (!MODES.contains(mode)) {
            throw new IllegalArgumentException("Mode must be one of " + MODES);
        }
        int workers = positiveInt(args, 2, 4, 256, "workers");
        int timeout = positiveInt(args, 3, 60, 86400, "timeout");
        int chunkSize = positiveInt(args, 4, DEFAULT_CHUNK_SIZE, 65536, "chunk size");
        revision = currentProgram.getModificationNumber();
        if (args.length == 6 && mode.equals("cache-proof")) {
            throw new IllegalArgumentException("SAMPLE_TSV requires an export mode");
        }
        sample = args.length == 6 ? readSample(Path.of(args[5])) : null;
        String sha256 = currentProgram.getExecutableSHA256();
        programId = sha256 == null || sha256.isBlank() ?
            "name:" + currentProgram.getName() : "sha256:" + sha256;
        Path output = Path.of(args[0]).toAbsolutePath().normalize();
        long started = System.nanoTime();
        if (mode.equals("cache-proof")) {
            proveCache(output, timeout);
        }
        else if (mode.startsWith("compare")) {
            boolean scheduled = mode.equals("compare-scheduled");
            String other = scheduled ? "scheduled" : "parallel";
            Path serial = Path.of(output.toString() + ".serial.jsonl");
            Path second = Path.of(output.toString() + "." + other + ".jsonl");
            Mode secondMode = scheduled ? Mode.SCHEDULED : Mode.PARALLEL;
            if (mode.equals("compare-reverse")) {
                export(second, secondMode, workers, timeout, chunkSize);
                export(serial, Mode.SERIAL, workers, timeout, chunkSize);
            }
            else {
                export(serial, Mode.SERIAL, workers, timeout, chunkSize);
                export(second, secondMode, workers, timeout, chunkSize);
            }
            checkEpoch();
            long mismatch = Files.mismatch(serial, second);
            if (mismatch != -1) {
                throw new IOException("Serial/" + other + " output differs at byte " + mismatch +
                    "; inspect " + serial + " and " + second);
            }
            println("BinaryRat exact serial/" + other + " comparison passed: " + serial);
        }
        else if (mode.equals("stock-verified")) {
            exportStockVerified(output, workers, timeout, chunkSize);
        }
        else {
            Mode single = mode.equals("serial") ? Mode.SERIAL :
                mode.equals("parallel") ? Mode.PARALLEL : Mode.SCHEDULED;
            export(output, single, workers, timeout, chunkSize);
        }
        println("BinaryRat export elapsed_seconds=" +
            ((System.nanoTime() - started) / 1_000_000_000.0));
    }

    private Set<Address> readSample(Path path) throws Exception {
        Set<Address> addresses = new HashSet<>();
        try (BufferedReader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            String line;
            while ((line = reader.readLine()) != null) {
                checkEpoch();
                String[] fields = line.split("\\t", -1);
                if (fields.length != 3 || !fields[0].matches("[0-9a-fA-F]{1,16}") ||
                        !fields[1].matches("[0-9a-fA-F]{1,16}") || fields[2].isBlank() ||
                        new BigInteger(fields[1], 16).signum() == 0) {
                    throw new IOException("Expected sample offset, size and name: " + line);
                }
                Address address = currentProgram.getImageBase().addNoWrap(new BigInteger(fields[0], 16));
                Function function = currentProgram.getFunctionManager().getFunctionAt(address);
                if (function == null || !exported(function) || !addresses.add(address)) {
                    throw new IOException("Sample address must name a unique exported function: " + address);
                }
            }
        }
        if (addresses.isEmpty()) {
            throw new IOException("Export sample is empty: " + path);
        }
        return Set.copyOf(addresses);
    }

    private String[] desktopArguments() throws Exception {
        List<String> choices = List.of("Stock-verified (scheduled and stock)", "Scheduled", "Serial");
        String choice = askChoice("BinaryRat Decompilation", "Export mode", choices, choices.getFirst());
        String mode = switch (choice) {
            case "Stock-verified (scheduled and stock)" -> "stock-verified";
            case "Scheduled" -> "scheduled";
            case "Serial" -> "serial";
            default -> throw new IllegalArgumentException("Unknown BinaryRat export mode: " + choice);
        };
        // Ghidra 12.2's script file chooser can dispose its model while an
        // autocomplete event is pending. Use Swing's ordinary save dialog.
        File selected = Swing.runNow(() -> {
            JFileChooser chooser = new JFileChooser();
            chooser.setDialogTitle("Export BinaryRat Decompilation JSONL");
            var tool = state.getTool();
            return chooser.showDialog(tool == null ? null : tool.getToolFrame(), "Export") ==
                JFileChooser.APPROVE_OPTION ? chooser.getSelectedFile() : null;
        });
        if (selected == null) {
            throw new CancelledException();
        }
        Path output = selected.toPath().toAbsolutePath().normalize();
        String reportSuffix = switch (mode) {
            case "stock-verified" -> ".parity.json";
            case "scheduled" -> ".schedule.json";
            default -> null;
        };
        if (existingOutputs(output, reportSuffix) && !askYesNo("Replace BinaryRat Export",
                "Replace the existing export or its report for " + output + "?")) {
            throw new CancelledException();
        }
        return new String[] { output.toString(), mode };
    }

    private static boolean existingOutputs(Path output, String reportSuffix) throws IOException {
        List<Path> destinations = reportSuffix == null ? List.of(output) :
            List.of(output, Path.of(output + reportSuffix));
        boolean replacing = false;
        for (Path destination : destinations) {
            if (Files.exists(destination, LinkOption.NOFOLLOW_LINKS)) {
                if (!Files.isRegularFile(destination, LinkOption.NOFOLLOW_LINKS)) {
                    throw new IOException("Choose a regular output file: " + destination);
                }
                replacing = true;
            }
        }
        return replacing;
    }

    private static int positiveInt(String[] args, int index, int fallback, int maximum,
            String label) {
        int value = args.length > index ? Integer.parseInt(args[index]) : fallback;
        if (value < 1 || value > maximum) {
            throw new IllegalArgumentException(label + " must be in [1, " + maximum + "]");
        }
        return value;
    }

    private static long environment(String name, long fallback) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            return fallback;
        }
        long parsed = Long.parseLong(value.trim());
        if (parsed < 0) {
            throw new IllegalArgumentException(name + " must not be negative");
        }
        return parsed;
    }

    private void checkEpoch() throws Exception {
        monitor.checkCancelled();
        if (currentProgram.getModificationNumber() != revision) {
            throw new IllegalStateException("Program changed during export; discard this epoch and retry");
        }
    }

    private void configure(DecompInterface decompiler) {
        DecompileOptions options = new DecompileOptions();
        options.grabFromProgram(currentProgram);
        decompiler.setOptions(options);
        decompiler.setSimplificationStyle("decompile");
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
    }

    private boolean exported(Function function) {
        MemoryBlock entryBlock = currentProgram.getMemory().getBlock(function.getEntryPoint());
        // ELF imports may represent unresolved externals as functions in an
        // uninitialized EXTERNAL block in the ordinary RAM space.
        return !function.isExternal() && (entryBlock == null || !entryBlock.isExternalBlock());
    }

    private static void deleteTree(Path root) {
        try (Stream<Path> walk = Files.walk(root)) {
            for (Path path : (Iterable<Path>) walk.sorted(Comparator.reverseOrder())::iterator) {
                Files.deleteIfExists(path);
            }
        }
        catch (IOException ignored) {
            // Best effort: a leftover temporary cache is harmless.
        }
    }

    /** Cache outcomes are separate from leases: hits never acquire a lease. */
    private static final class CacheSummary {
        final boolean enabled;
        final JsonObject storeDiagnostics = new JsonObject();
        final JsonObject lookupDiagnostics = new JsonObject();
        long hits;
        long replayed;
        long misses;
        long lookupRejected;
        long stored;
        long storeRejected;

        CacheSummary(boolean enabled) {
            this.enabled = enabled;
        }

        private static void increment(JsonObject counts, String reason) {
            // Bound both the count and length of distinct replay diagnostics.
            if (reason.length() > 240) {
                reason = reason.substring(0, 240) + "...";
            }
            String key = counts.has(reason) || counts.size() < 32 ? reason : "other";
            counts.addProperty(key, (counts.has(key) ? counts.get(key).getAsLong() : 0) + 1);
        }

        synchronized boolean lookup(LiveDecompileCache.Lookup lookup) {
            String rejected = lookup.rejected();
            boolean usable = lookup.kind() != LiveDecompileCache.Kind.MISS &&
                lookup.output() != null && lookup.output().cacheable() && rejected == null;
            if (usable) {
                if (lookup.kind() == LiveDecompileCache.Kind.HIT) {
                    hits++;
                }
                else {
                    replayed++;
                }
            }
            else {
                misses++;
                if (rejected == null && lookup.output() != null) {
                    rejected = "cached output is not cacheable";
                }
                if (rejected != null) {
                    lookupRejected++;
                    increment(lookupDiagnostics, rejected);
                }
            }
            return usable;
        }

        synchronized void store(boolean accepted, String reason) {
            if (accepted) {
                stored++;
            }
            else {
                storeRejected++;
                increment(storeDiagnostics, reason);
            }
        }

        synchronized JsonObject report(LiveDecompileCache cache) throws IOException {
            JsonObject result = new JsonObject();
            result.addProperty("enabled", enabled);
            result.addProperty("hits", hits);
            result.addProperty("replayed", replayed);
            result.addProperty("misses", misses);
            result.addProperty("lookup_rejected", lookupRejected);
            result.addProperty("stored", stored);
            result.addProperty("store_rejected", storeRejected);
            result.add("store_diagnostics", storeDiagnostics.deepCopy());
            result.add("lookup_diagnostics", lookupDiagnostics.deepCopy());
            if (cache != null) {
                result.add("engine_stats", cache.stats());
            }
            return result;
        }
    }

    /** Lease outcomes of one scheduled export, written next to it. */
    private static final class ScheduleSummary {
        final JsonObject leases = new JsonObject();
        final CacheSummary cache;
        long count;
        long runMillis;
        long maxWaitMillis;
        long maxPeakResident;
        long memoryWatched;
        long killed;

        ScheduleSummary(boolean cacheEnabled) {
            cache = new CacheSummary(cacheEnabled);
        }

        synchronized void add(ScheduledDecompiler.Run run) {
            count++;
            String status = run.status();
            leases.addProperty(status, (leases.has(status) ? leases.get(status).getAsLong() : 0) + 1);
            runMillis += run.runMillis();
            maxWaitMillis = Math.max(maxWaitMillis, run.waitedMillis());
            maxPeakResident = Math.max(maxPeakResident, run.peakResidentBytes());
            memoryWatched += run.memoryWatched() ? 1 : 0;
            killed += run.killed() ? 1 : 0;
        }
    }

    private static final class StockParityAudit {
        private final BufferedReader candidate;
        private final JsonArray fallbackSample = new JsonArray();
        private long matches;
        private long fallbacks;

        StockParityAudit(BufferedReader candidate) {
            this.candidate = candidate;
        }

        String select(Address entry, String stock) throws IOException {
            String row = candidate.readLine();
            if (row == null) {
                throw new IOException("Scheduled export ended before stock function " + entry);
            }
            if (row.equals(stock)) {
                matches++;
                return row;
            }
            JsonObject actual = JsonParser.parseString(row).getAsJsonObject();
            if (!entry.getAddressSpace().getName().equals(actual.get("address_space").getAsString()) ||
                    !Long.toUnsignedString(entry.getOffset(), 16).equals(
                        actual.get("address").getAsString())) {
                throw new IOException("Scheduled export function order disagrees at " + entry);
            }
            if (actual.get("timed_out").getAsBoolean() || actual.get("cancelled").getAsBoolean() ||
                    actual.get("failed_to_start").getAsBoolean()) {
                throw new IOException("Scheduled decompiler was interrupted at " + entry);
            }
            fallbacks++;
            if (fallbackSample.size() < 32) {
                fallbackSample.add(entry.toString(true));
            }
            return stock;
        }

        JsonObject finish(byte[] digest) throws IOException {
            if (candidate.readLine() != null) {
                throw new IOException("Scheduled export contains extra functions");
            }
            JsonObject result = new JsonObject();
            result.addProperty("reference", "stock-reused-serial");
            result.addProperty("function_count", matches + fallbacks);
            result.addProperty("scheduled_matches", matches);
            result.addProperty("stock_fallbacks", fallbacks);
            result.add("fallback_sample", fallbackSample);
            result.addProperty("output_sha256", HexFormat.of().formatHex(digest));
            return result;
        }
    }

    private void exportStockVerified(Path output, int workers, int timeout, int chunkSize)
            throws Exception {
        existingOutputs(output, ".parity.json");
        Path workspace = Files.createTempDirectory(output.getParent(), ".binaryrat-parity-");
        try {
            Path candidate = workspace.resolve("scheduled.jsonl");
            export(candidate, Mode.SCHEDULED, workers, timeout, chunkSize);
            if (summary.leases.keySet().stream().anyMatch(status -> !status.equals("completed"))) {
                throw new IOException("Cannot verify interrupted leases: " + summary.leases);
            }
            // Close the pool before starting the stock process. It must see all
            // functions in the original order, even when a scheduled row is cached.
            try (BufferedReader reader = Files.newBufferedReader(candidate, StandardCharsets.UTF_8)) {
                export(output, Mode.SERIAL, workers, timeout, chunkSize, new StockParityAudit(reader));
            }
        }
        finally {
            deleteTree(workspace);
        }
    }

    private void export(Path output, Mode mode, int workers, int timeout, int chunkSize)
            throws Exception {
        export(output, mode, workers, timeout, chunkSize, null);
    }

    private void export(Path output, Mode mode, int workers, int timeout, int chunkSize,
            StockParityAudit audit)
            throws Exception {
        long exportStarted = System.nanoTime();
        checkEpoch();
        String name = mode.name().toLowerCase();
        println("BinaryRat export starting mode=" + name);
        // Keep the temporary file beside its destination so publication can be atomic.
        Path temporary = Files.createTempFile(output.getParent(), ".binaryrat-", ".jsonl.tmp");
        DecompInterface serialDecompiler = null;
        DecompilerCallback<String> callback = null;
        ExecutorService executor = null;
        EngineClient engine = null;
        ScheduledDecompiler scheduler = null;
        ChangeTracker tracker = null;
        LiveDecompileCache liveCache = null;
        boolean persistentCache = false;
        Path engineCache = null;
        boolean temporaryEngineCache = false;
        Path temporarySummary = null;
        JsonObject scheduleReport = null;
        boolean published = false;
        int activeWorkers = 1;
        try {
            if (mode == Mode.PARALLEL) {
                // Reuse the tagged Ghidra pool implementation, with a local executor so
                // requested concurrency does not mutate Ghidra's shared thread-pool settings.
                callback = new DecompilerCallback<String>(currentProgram, this::configure) {
                    @Override
                    public String process(DecompileResults results, TaskMonitor taskMonitor)
                            throws Exception {
                        taskMonitor.checkCancelled();
                        if (results == null || results.getFunction() == null) {
                            throw new IOException("Decompiler returned no function result");
                        }
                        return record(results.getFunction(), results);
                    }
                };
                callback.setTimeout(timeout);
                executor = Executors.newFixedThreadPool(workers);
                activeWorkers = workers;
            }
            else if (mode == Mode.SCHEDULED) {
                String cachePath = System.getenv("BINARYRAT_CACHE_DIR");
                if (cachePath != null && !cachePath.isBlank()) {
                    if (!programId.matches("sha256:[0-9a-fA-F]{64}")) {
                        throw new IOException("Persistent caching requires an executable SHA-256; " +
                            "a Program name is not a safe cross-session identity");
                    }
                    // The engine owns and locks this directory for its complete
                    // session. The bridge must neither create nor delete its files.
                    engineCache = Path.of(cachePath).toAbsolutePath().normalize();
                    persistentCache = true;
                }
                else {
                    engineCache = Files.createTempDirectory(output.getParent(), ".binaryrat-engine-");
                    temporaryEngineCache = true;
                }
                engine = EngineClient.start(EngineClient.findExecutable(), engineCache);
                long leaseTimeout = environment("BINARYRAT_LEASE_TIMEOUT_MS", timeout * 1000L);
                scheduler = new ScheduledDecompiler(engine, currentProgram, this::configure,
                    new ScheduledDecompiler.Limits(workers,
                        environment("BINARYRAT_WORKER_BYTES", 768L << 20),
                        Runtime.getRuntime().maxMemory(),
                        environment("BINARYRAT_OTHER_RESERVE_BYTES", 512L << 20),
                        timeout, environment("BINARYRAT_KILL_GRACE_MS", 5000), leaseTimeout));
                summary = new ScheduleSummary(persistentCache);
                if (persistentCache) {
                    tracker = new ChangeTracker(currentProgram, engine);
                    // Freeze options and registration identity before any jobs can
                    // borrow this sample decompiler or populate its temporary IDs.
                    var sample = scheduler.sample();
                    String registration = sample.registrationDigest();
                    liveCache = new LiveDecompileCache(engine, currentProgram, tracker,
                        sample.getOptions(), programId, registration);
                    checkEpoch();
                    println("BinaryRat persistent cache enabled directory=" + engineCache);
                }
                activeWorkers = scheduler.workers();
                println("BinaryRat engine admitted workers=" + activeWorkers + " requested=" +
                    workers + " configuration=" + scheduler.configuration());
                // More threads than admitted workers only queue in the engine; the
                // engine, not this pool, decides how many decompilations run at once.
                executor = Executors.newFixedThreadPool(workers);
            }
            else {
                serialDecompiler = new DecompInterface();
                configure(serialDecompiler);
                if (!serialDecompiler.openProgram(currentProgram)) {
                    throw new IOException("Cannot start stock decompiler: " + serialDecompiler.getLastMessage());
                }
            }
            FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
            long count = 0;
            long excludedExternal = 0;
            MessageDigest digest = audit == null ? null : MessageDigest.getInstance("SHA-256");
            try (BufferedWriter writer = digest == null ?
                    Files.newBufferedWriter(temporary, StandardCharsets.UTF_8) :
                    new BufferedWriter(new OutputStreamWriter(
                        new DigestOutputStream(Files.newOutputStream(temporary), digest),
                        StandardCharsets.UTF_8))) {
                while (iterator.hasNext()) {
                    checkEpoch();
                    List<Function> functions = new ArrayList<>(chunkSize);
                    while (iterator.hasNext() && functions.size() < chunkSize) {
                        if (sample != null) {
                            checkEpoch();
                        }
                        Function function = iterator.next();
                        if (!exported(function)) {
                            excludedExternal++;
                        }
                        else if (sample == null || sample.contains(function.getEntryPoint())) {
                            functions.add(function);
                        }
                    }
                    // FunctionIterator is forward ordered; consume futures in that same
                    // order, independent of the order in which workers finish.
                    if (executor != null) {
                        DecompilerCallback<String> activeCallback = callback;
                        ScheduledDecompiler activeScheduler = scheduler;
                        LiveDecompileCache activeCache = liveCache;
                        List<Future<String>> futures = new ArrayList<>(functions.size());
                        for (Function function : functions) {
                            futures.add(executor.submit(() -> activeScheduler == null ?
                                activeCallback.process(function, monitor) :
                                scheduledRecord(activeScheduler, activeCache, function)));
                        }
                        for (Future<String> future : futures) {
                            String result = await(future);
                            if (result == null) {
                                throw new IOException("Decompiler cancelled without an export record");
                            }
                            writer.write(result);
                            writer.write('\n');
                            count++;
                        }
                    }
                    else {
                        for (Function function : functions) {
                            checkEpoch();
                            DecompileResults result =
                                serialDecompiler.decompileFunction(function, timeout, monitor);
                            if (audit != null && (result == null || result.isTimedOut() ||
                                    result.isCancelled() || result.failedToStart())) {
                                throw new IOException("Stock decompiler was interrupted at " +
                                    function.getEntryPoint());
                            }
                            String row = record(function, result);
                            writer.write(audit == null ? row : audit.select(function.getEntryPoint(), row));
                            writer.write('\n');
                            count++;
                        }
                    }
                    checkEpoch();
                }
            }
            checkEpoch();
            if (sample != null && count != sample.size()) {
                throw new IOException("Export did not cover every sampled function");
            }
            JsonObject parityReport = audit == null ? null : audit.finish(digest.digest());
            if (scheduler != null) {
                scheduleReport = makeSummary(scheduler, liveCache, workers);
            }
            JsonObject outputReport = audit == null ? scheduleReport : parityReport;
            if (outputReport != null) {
                temporarySummary = Files.createTempFile(output.getParent(), ".binaryrat-schedule-", ".json.tmp");
                Files.writeString(temporarySummary,
                    new GsonBuilder().setPrettyPrinting().create().toJson(outputReport) + "\n",
                    StandardCharsets.UTF_8);
            }
            checkEpoch();
            if (audit != null) {
                existingOutputs(output, ".parity.json");
            }
            publish(temporary, output);
            if (temporarySummary != null) {
                // A summary never announces an export whose publication failed.
                // The two individual renames are atomic where supported; a pair of
                // filesystem paths cannot be committed as one atomic operation.
                publish(temporarySummary, Path.of(output + (audit == null ? ".schedule.json" : ".parity.json")));
            }
            published = true;
            if (scheduleReport != null) {
                println("BinaryRat schedule " + scheduleReport.get("lease_status_counts") + " peak_running=" +
                    scheduleReport.getAsJsonObject("engine_stats").get("peak_running") +
                    " max_peak_resident_bytes=" + summary.maxPeakResident +
                    " memory_watched=" + summary.memoryWatched + " cache=" + scheduleReport.get("cache"));
            }
            if (parityReport != null) {
                println("BinaryRat stock verification passed: " + parityReport);
            }
            println("BinaryRat exported functions=" + count + " mode=" + name +
                " workers=" + activeWorkers + " excluded_external=" + excludedExternal +
                " elapsed_seconds=" + ((System.nanoTime() - exportStarted) / 1_000_000_000.0) +
                " output=" + output);
        }
        finally {
            if (executor != null) {
                if (!published) {
                    // Cancel native requests before disposing the shared callback pool.
                    monitor.cancel();
                    executor.shutdownNow();
                }
                else {
                    executor.shutdown();
                }
                boolean interrupted = false;
                while (!executor.isTerminated()) {
                    try {
                        executor.awaitTermination(1, TimeUnit.SECONDS);
                    }
                    catch (InterruptedException exception) {
                        interrupted = true;
                        monitor.cancel();
                        executor.shutdownNow();
                    }
                }
                if (interrupted) {
                    Thread.currentThread().interrupt();
                }
            }
            try {
                if (callback != null) {
                    callback.dispose();
                }
                if (serialDecompiler != null) {
                    serialDecompiler.dispose();
                }
                if (tracker != null) {
                    tracker.close();
                }
                if (scheduler != null) {
                    scheduler.close();
                }
            }
            finally {
                try {
                    if (engine != null) {
                        engine.close();
                    }
                }
                finally {
                    if (temporaryEngineCache && engineCache != null) {
                        deleteTree(engineCache);
                    }
                    Files.deleteIfExists(temporary);
                    if (temporarySummary != null) {
                        Files.deleteIfExists(temporarySummary);
                    }
                }
            }
        }
    }

    private String scheduledRecord(ScheduledDecompiler scheduler, LiveDecompileCache cache,
            Function function)
            throws Exception {
        checkEpoch();
        long modification = currentProgram.getModificationNumber();
        LiveDecompileCache.Lookup lookup = null;
        if (cache != null) {
            lookup = cache.lookup(function, false);
            checkEpoch();
            if (summary.cache.lookup(lookup)) {
                String result = record(function, lookup.output());
                checkEpoch();
                return result;
            }
        }
        ScheduledDecompiler.Run run = scheduler.decompile(function, monitor);
        summary.add(run);
        checkEpoch();
        if (run.traced() == null) {
            if (cache != null) {
                summary.cache.store(false, "no traced decompilation (lease " + run.status() + ")");
            }
            return record(function, new DecompOutput(false, false, true, false,
                "BinaryRat: the engine did not grant a lease (" + run.status() + ")", "", ""));
        }
        DecompOutput output = DecompOutput.stopped(run.traced().results(), run.status(), run.stopReason());
        if (cache != null) {
            if (!output.cacheable()) {
                summary.cache.store(false, "native output is not cacheable (lease " + run.status() + ")");
            }
            else if (!run.traced().trace().replayable()) {
                summary.cache.store(false, "trace is not replayable");
            }
            else {
                boolean stored = cache.store(function, output, run.traced().trace(), lookup.seq(), modification);
                summary.cache.store(stored, "cache store refused optimistic guard");
            }
            checkEpoch();
        }
        String result = record(function, output);
        checkEpoch();
        return result;
    }

    private static void publish(Path temporary, Path output) throws IOException {
        try {
            Files.move(temporary, output, StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING);
        }
        catch (AtomicMoveNotSupportedException unsupported) {
            Files.move(temporary, output, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private JsonObject makeSummary(ScheduledDecompiler scheduler, LiveDecompileCache cache,
            int requested)
            throws IOException {
        JsonObject report = new JsonObject();
        report.addProperty("requested_workers", requested);
        report.add("engine_configuration", scheduler.configuration());
        report.add("engine_stats", scheduler.stats());
        report.add("lease_status_counts", summary.leases);
        report.addProperty("leases", summary.count);
        report.addProperty("lease_run_millis_total", summary.runMillis);
        report.addProperty("max_wait_millis", summary.maxWaitMillis);
        report.addProperty("max_peak_resident_bytes", summary.maxPeakResident);
        report.addProperty("memory_watched_leases", summary.memoryWatched);
        report.addProperty("killed_processes", summary.killed);
        report.add("cache", summary.cache.report(cache));
        return report;
    }

    private void proveCache(Path output, int timeout) throws Exception {
        List<Function> functions = new ArrayList<>();
        for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
            if (exported(function)) {
                functions.add(function);
            }
        }
        if (functions.isEmpty()) {
            throw new IllegalStateException("No functions to decompile");
        }
        Path cacheDirectory = Files.createTempDirectory(output.getParent(), ".binaryrat-cache-");
        // Scripts run inside one transaction; close it so each probe change is its own
        // transaction that can be undone, and reopen it for the script runner to close.
        end(true);
        try {
            CacheProof proof = new CacheProof(currentProgram, monitor, EngineClient.findExecutable(), cacheDirectory,
                this::configure, programId, functions, timeout, this::println);
            JsonObject report = proof.run();
            Files.writeString(output, new GsonBuilder().setPrettyPrinting().create().toJson(report) +
                "\n", StandardCharsets.UTF_8);
            if (!report.get("passed").getAsBoolean()) {
                throw new IllegalStateException("BinaryRat cache proof FAILED; see " + output);
            }
            println("BinaryRat cache proof passed: " + output);
        }
        finally {
            start();
            deleteTree(cacheDirectory);
        }
    }

    private String await(Future<String> future) throws Exception {
        while (true) {
            checkEpoch();
            try {
                return future.get(100, TimeUnit.MILLISECONDS);
            }
            catch (TimeoutException pending) {
                // Recheck cancellation and the Program epoch while native work runs.
            }
            catch (ExecutionException failure) {
                Throwable cause = failure.getCause();
                if (cause instanceof Exception) {
                    throw (Exception) cause;
                }
                throw new RuntimeException(cause);
            }
        }
    }

    private String record(Function function, DecompileResults results) throws Exception {
        if (results == null) {
            throw new IOException("Decompiler returned null for " + function.getEntryPoint());
        }
        return record(function, DecompOutput.of(results));
    }

    private String record(Function function, DecompOutput output) throws Exception {
        Address entry = function.getEntryPoint();
        StringBuilder json = new StringBuilder(1024);
        json.append("{\"schema_version\":1,\"program_id\":").append(quote(programId));
        if (revision < 0) {
            throw new IOException("Negative Program modification number is unsupported");
        }
        json.append(",\"revision\":").append(revision);
        json.append(",\"address_space\":").append(quote(entry.getAddressSpace().getName()));
        json.append(",\"address\":").append(quote(Long.toUnsignedString(entry.getOffset(), 16)));
        json.append(",\"body_sha256\":").append(quote(bodyHash(function)));
        json.append(",\"body_ranges\":[");
        boolean firstRange = true;
        for (AddressRange range : function.getBody().getAddressRanges(true)) {
            if (!range.getMinAddress().getAddressSpace().equals(entry.getAddressSpace())) {
                throw new IOException("Cross-address-space function body is unsupported: " + entry);
            }
            if (!firstRange) {
                json.append(',');
            }
            firstRange = false;
            json.append('[').append(quote(Long.toUnsignedString(range.getMinAddress().getOffset(), 16)))
                .append(',').append(quote(Long.toUnsignedString(range.getMaxAddress().getOffset(), 16)))
                .append(']');
        }
        json.append(']');
        json.append(",\"name\":").append(quote(function.getName()));
        json.append(",\"completed\":").append(output.completed());
        json.append(",\"timed_out\":").append(output.timedOut());
        json.append(",\"cancelled\":").append(output.cancelled());
        json.append(",\"failed_to_start\":").append(output.failedToStart());
        json.append(",\"error\":").append(quote(output.error()));
        json.append(",\"prototype\":").append(quote(output.prototype()));
        json.append(",\"c\":").append(quote(output.c()));
        return json.append('}').toString();
    }

    private String bodyHash(Function function) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update("binaryrat-body-v1\0".getBytes(StandardCharsets.UTF_8));
        byte[] buffer = new byte[65536];
        for (AddressRange range : function.getBody().getAddressRanges(true)) {
            Address cursor = range.getMinAddress();
            long remaining = range.getLength();
            // Address/length framing distinguishes identical bytes in different or
            // noncontiguous function bodies; this is not a complete semantic cache key.
            String header = cursor.getAddressSpace().getName() + "\0" +
                Long.toUnsignedString(cursor.getOffset(), 16) + "\0" +
                Long.toUnsignedString(remaining) + "\0";
            digest.update(header.getBytes(StandardCharsets.UTF_8));
            while (remaining > 0) {
                monitor.checkCancelled();
                int requested = (int) Math.min(remaining, buffer.length);
                int read = currentProgram.getMemory().getBytes(cursor, buffer, 0, requested);
                if (read <= 0) {
                    throw new IOException("Unreadable function body at " + cursor);
                }
                digest.update(buffer, 0, read);
                remaining -= read;
                if (remaining > 0) {
                    cursor = cursor.addNoWrap(read);
                }
            }
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    private static String quote(String value) {
        if (value == null) {
            return "null";
        }
        char[] hex = "0123456789abcdef".toCharArray();
        StringBuilder result = new StringBuilder(value.length() + 2).append('"');
        for (int index = 0; index < value.length(); index++) {
            char ch = value.charAt(index);
            if (ch == '"' || ch == '\\') {
                result.append('\\').append(ch);
            }
            else if (ch < 0x20 || ch >= 0x7f) {
                // Escaping UTF-16 code units also preserves surrogate pairs without
                // depending on platform encodings or a third-party JSON library.
                result.append("\\u").append(hex[(ch >>> 12) & 15])
                    .append(hex[(ch >>> 8) & 15]).append(hex[(ch >>> 4) & 15])
                    .append(hex[ch & 15]);
            }
            else {
                result.append(ch);
            }
        }
        return result.append('"').toString();
    }
}
