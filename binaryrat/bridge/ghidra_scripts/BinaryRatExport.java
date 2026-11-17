// Export deterministic stock-decompiler records without modifying the Program.
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
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
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
 */
public class BinaryRatExport extends GhidraScript {
    private static final int DEFAULT_CHUNK_SIZE = 128;
    private long revision;
    private String programId;

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2 || args.length > 5) {
            throw new IllegalArgumentException("Usage: BinaryRatExport.java OUTPUT " +
                "serial|parallel|compare|compare-reverse [WORKERS=4] [TIMEOUT_SECONDS=60] [CHUNK_SIZE=128]");
        }
        if (!isRunningHeadless() || currentProgram == null) {
            throw new IllegalStateException("A headless postScript with an analyzed Program is required");
        }
        if (AutoAnalysisManager.getAnalysisManager(currentProgram).isAnalyzing()) {
            throw new IllegalStateException("Auto-analysis must finish before exporting");
        }
        String mode = args[1];
        if (!mode.equals("serial") && !mode.equals("parallel") && !mode.equals("compare") &&
                !mode.equals("compare-reverse")) {
            throw new IllegalArgumentException("Mode must be serial, parallel, compare, or compare-reverse");
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
        if (mode.equals("compare") || mode.equals("compare-reverse")) {
            Path serial = Path.of(output.toString() + ".serial.jsonl");
            Path parallel = Path.of(output.toString() + ".parallel.jsonl");
            if (mode.equals("compare-reverse")) {
                export(parallel, true, workers, timeout, chunkSize);
                export(serial, false, workers, timeout, chunkSize);
            }
            else {
                export(serial, false, workers, timeout, chunkSize);
                export(parallel, true, workers, timeout, chunkSize);
            }
            checkEpoch();
            long mismatch = Files.mismatch(serial, parallel);
            if (mismatch != -1) {
                throw new IOException("Serial/parallel output differs at byte " + mismatch +
                    "; inspect " + serial + " and " + parallel);
            }
            println("BinaryRat exact serial/parallel comparison passed: " + serial);
        }
        else {
            export(output, mode.equals("parallel"), workers, timeout, chunkSize);
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

    private void export(Path output, boolean parallel, int workers, int timeout,
            int chunkSize) throws Exception {
        long exportStarted = System.nanoTime();
        checkEpoch();
        println("BinaryRat export starting mode=" + (parallel ? "parallel" : "serial"));
        // Keep the temporary file beside its destination so publication can be atomic.
        Path temporary = Files.createTempFile(output.getParent(), ".binaryrat-", ".jsonl.tmp");
        DecompInterface serialDecompiler = null;
        DecompilerCallback<String> callback = null;
        ExecutorService executor = null;
        boolean published = false;
        try {
            if (parallel) {
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
                        MemoryBlock entryBlock = currentProgram.getMemory().getBlock(function.getEntryPoint());
                        // ELF imports may represent unresolved externals as functions in
                        // an uninitialized EXTERNAL block in the ordinary RAM space.
                        if (!function.isExternal() && (entryBlock == null || !entryBlock.isExternalBlock())) {
                            functions.add(function);
                        }
                        else {
                            excludedExternal++;
                        }
                    }
                    // FunctionIterator is forward ordered; consume futures in that same
                    // order, independent of the order in which workers finish.
                    if (parallel) {
                        DecompilerCallback<String> activeCallback = callback;
                        List<Future<String>> futures = new ArrayList<>(functions.size());
                        for (Function function : functions) {
                            futures.add(executor.submit(() -> activeCallback.process(function, monitor)));
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
            try {
                Files.move(temporary, output, StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
            }
            catch (AtomicMoveNotSupportedException unsupported) {
                Files.move(temporary, output, StandardCopyOption.REPLACE_EXISTING);
            }
            published = true;
            println("BinaryRat exported functions=" + count + " mode=" +
                (parallel ? "parallel" : "serial") + " workers=" + (parallel ? workers : 1) +
                " excluded_external=" + excludedExternal +
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
            Files.deleteIfExists(temporary);
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
        Address entry = function.getEntryPoint();
        DecompiledFunction decompiled = results.getDecompiledFunction();
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
        json.append(",\"completed\":").append(results.decompileCompleted());
        json.append(",\"timed_out\":").append(results.isTimedOut());
        json.append(",\"cancelled\":").append(results.isCancelled());
        json.append(",\"failed_to_start\":").append(results.failedToStart());
        json.append(",\"error\":").append(quote(orEmpty(results.getErrorMessage())));
        json.append(",\"prototype\":").append(quote(decompiled == null ? "" : orEmpty(decompiled.getSignature())));
        json.append(",\"c\":").append(quote(decompiled == null ? "" : orEmpty(decompiled.getC())));
        return json.append('}').toString();
    }

    private static String orEmpty(String value) {
        return value == null ? "" : value;
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
