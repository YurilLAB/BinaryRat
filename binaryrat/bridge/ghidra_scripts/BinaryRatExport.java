// Export deterministic stock-decompiler records; optionally run decompilation under the
// C++ engine's admission control, or prove the engine's live cache against fresh output.
// @category BinaryRat
// @menupath
/*
 * Copyright 2026 YurilLAB
 * Licensed under the Apache License, Version 2.0.
 * See the repository LICENSE file for the full license text.
 */

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.stream.Stream;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;

import binaryrat.CacheProof;
import binaryrat.DecompOutput;
import binaryrat.EngineClient;
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
import ghidra.util.task.TaskMonitor;

/**
 * Minimal Ghidra 12.2 bridge. All decompilation remains in Ghidra's native engine.
 * Run as a headless postScript after analysis; there must be no concurrent writer.
 * Every mode except cache-proof leaves the Program unmodified; cache-proof edits it
 * and is meant for throwaway headless projects.
 */
public class BinaryRatExport extends GhidraScript {
    private static final int DEFAULT_CHUNK_SIZE = 128;
    private static final List<String> MODES = List.of("serial", "parallel", "compare",
        "compare-reverse", "scheduled", "compare-scheduled", "cache-proof");
    private long revision;
    private String programId;
    private ScheduleSummary summary;

    private enum Mode { SERIAL, PARALLEL, SCHEDULED }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2 || args.length > 5) {
            throw new IllegalArgumentException("Usage: BinaryRatExport.java OUTPUT " +
                String.join("|", MODES) +
                " [WORKERS=4] [TIMEOUT_SECONDS=60] [CHUNK_SIZE=128]");
        }
        if (!isRunningHeadless() || currentProgram == null) {
            throw new IllegalStateException("A headless postScript with an analyzed Program is required");
        }
        if (AutoAnalysisManager.getAnalysisManager(currentProgram).isAnalyzing()) {
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
        else {
            Mode single = mode.equals("serial") ? Mode.SERIAL :
                mode.equals("parallel") ? Mode.PARALLEL : Mode.SCHEDULED;
            export(output, single, workers, timeout, chunkSize);
        }
        println("BinaryRat export elapsed_seconds=" +
            ((System.nanoTime() - started) / 1_000_000_000.0));
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

    private static Path engineBinary() {
        String value = System.getenv("BINARYRAT_ENGINE");
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(
                "BINARYRAT_ENGINE must name the binaryrat-engine executable for this mode");
        }
        Path engine = Path.of(value).toAbsolutePath().normalize();
        if (!Files.isRegularFile(engine)) {
            throw new IllegalArgumentException("BINARYRAT_ENGINE does not exist: " + engine);
        }
        return engine;
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

    /** Lease outcomes of one scheduled export, written next to it. */
    private static final class ScheduleSummary {
        final JsonObject leases = new JsonObject();
        long count;
        long runMillis;
        long maxWaitMillis;
        long maxPeakResident;
        long memoryWatched;
        long killed;

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

    private void export(Path output, Mode mode, int workers, int timeout, int chunkSize)
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
        Path engineCache = null;
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
                engineCache = Files.createTempDirectory(output.getParent(), ".binaryrat-engine-");
                engine = EngineClient.start(engineBinary(), engineCache);
                long leaseTimeout = environment("BINARYRAT_LEASE_TIMEOUT_MS", timeout * 1000L);
                scheduler = new ScheduledDecompiler(engine, currentProgram, this::configure,
                    new ScheduledDecompiler.Limits(workers,
                        environment("BINARYRAT_WORKER_BYTES", 768L << 20),
                        Runtime.getRuntime().maxMemory(),
                        environment("BINARYRAT_OTHER_RESERVE_BYTES", 512L << 20),
                        timeout, environment("BINARYRAT_KILL_GRACE_MS", 5000), leaseTimeout));
                summary = new ScheduleSummary();
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
            try (BufferedWriter writer = Files.newBufferedWriter(temporary, StandardCharsets.UTF_8)) {
                while (iterator.hasNext()) {
                    checkEpoch();
                    List<Function> functions = new ArrayList<>(chunkSize);
                    while (iterator.hasNext() && functions.size() < chunkSize) {
                        Function function = iterator.next();
                        if (exported(function)) {
                            functions.add(function);
                        }
                        else {
                            excludedExternal++;
                        }
                    }
                    // FunctionIterator is forward ordered; consume futures in that same
                    // order, independent of the order in which workers finish.
                    if (executor != null) {
                        DecompilerCallback<String> activeCallback = callback;
                        ScheduledDecompiler activeScheduler = scheduler;
                        List<Future<String>> futures = new ArrayList<>(functions.size());
                        for (Function function : functions) {
                            futures.add(executor.submit(() -> activeScheduler == null ?
                                activeCallback.process(function, monitor) :
                                scheduledRecord(activeScheduler, function)));
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
                            writer.write(record(function,
                                serialDecompiler.decompileFunction(function, timeout, monitor)));
                            writer.write('\n');
                            count++;
                        }
                    }
                    checkEpoch();
                }
            }
            checkEpoch();
            if (scheduler != null) {
                writeSummary(output, scheduler, workers);
            }
            try {
                Files.move(temporary, output, StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
            }
            catch (AtomicMoveNotSupportedException unsupported) {
                Files.move(temporary, output, StandardCopyOption.REPLACE_EXISTING);
            }
            published = true;
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
            if (callback != null) {
                callback.dispose();
            }
            if (serialDecompiler != null) {
                serialDecompiler.dispose();
            }
            if (scheduler != null) {
                scheduler.close();
            }
            if (engine != null) {
                engine.close();
            }
            if (engineCache != null) {
                deleteTree(engineCache);
            }
            Files.deleteIfExists(temporary);
        }
    }

    private String scheduledRecord(ScheduledDecompiler scheduler, Function function)
            throws Exception {
        ScheduledDecompiler.Run run = scheduler.decompile(function, monitor);
        summary.add(run);
        if (run.traced() == null) {
            return record(function, new DecompOutput(false, false, true, false,
                "BinaryRat: the engine did not grant a lease (" + run.status() + ")", "", ""));
        }
        return record(function,
            DecompOutput.stopped(run.traced().results(), run.status(), run.stopReason()));
    }

    private void writeSummary(Path output, ScheduledDecompiler scheduler, int requested)
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
        Files.writeString(Path.of(output.toString() + ".schedule.json"),
            new GsonBuilder().setPrettyPrinting().create().toJson(report) + "\n",
            StandardCharsets.UTF_8);
        println("BinaryRat schedule " + report.get("lease_status_counts") + " peak_running=" +
            report.getAsJsonObject("engine_stats").get("peak_running") + " max_peak_resident_bytes=" +
            summary.maxPeakResident + " memory_watched=" + summary.memoryWatched);
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
            CacheProof proof = new CacheProof(currentProgram, monitor, engineBinary(), cacheDirectory,
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
