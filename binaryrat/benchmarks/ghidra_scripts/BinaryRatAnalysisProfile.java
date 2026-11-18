// Record stock headless auto-analysis timings and an ordered Program inventory.
// @category BinaryRat.Tests
/* Copyright 2026 YurilLAB. SPDX-License-Identifier: Apache-2.0 */

import java.io.BufferedOutputStream;
import java.io.DataOutputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HexFormat;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.StoredAnalyzerTimes;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.util.GhidraProgramUtilities;

/** Benchmark script for both sides of a single, fresh headless import. */
public class BinaryRatAnalysisProfile extends HeadlessScript {
    private static final String START = "binaryrat.analysis-profile.start";
    private static final int INVENTORY_VERSION = 2;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (currentProgram == null || args.length == 0) {
            throw new IllegalArgumentException("Expected one fresh headless import");
        }
        if (args.length == 1 && args[0].equals("begin")) {
            if (GhidraProgramUtilities.isAnalyzed(currentProgram) ||
                !StoredAnalyzerTimes.getStoredAnalyzerTimes(currentProgram).isEmpty()) {
                setHeadlessContinuationOption(HeadlessContinuationOption.ABORT_AND_DELETE);
                throw new IllegalStateException("Profiling requires an unanalysed Program");
            }
            println("BinaryRat analysis profile started");
            storeHeadlessValue(START, System.nanoTime());
            return;
        }
        if (args.length != 2 || !args[0].equals("finish")) {
            throw new IllegalArgumentException("Expected 'begin' or 'finish <report.json>'");
        }
        Object started = getStoredHeadlessValue(START);
        if (!(started instanceof Long start)) {
            throw new IllegalStateException("Analysis start timestamp is missing");
        }
        long elapsed = System.nanoTime() - start;
        println("BinaryRat analysis profile finished");
        setHeadlessContinuationOption(HeadlessContinuationOption.ABORT_AND_DELETE);

        boolean timedOut = analysisTimeoutOccurred();
        boolean analyzed = GhidraProgramUtilities.isAnalyzed(currentProgram);
        var manager = AutoAnalysisManager.getAnalysisManager(currentProgram);
        var times = StoredAnalyzerTimes.getStoredAnalyzerTimes(currentProgram);
        JsonObject report = new JsonObject();
        report.addProperty("schema_version", 1);
        report.addProperty("input_sha256", currentProgram.getExecutableSHA256());
        report.addProperty("language", currentProgram.getLanguageID().getIdAsString());
        report.addProperty("compiler_spec", currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString());
        report.addProperty("image_base", currentProgram.getImageBase().toString());
        report.addProperty("java_version", System.getProperty("java.runtime.version"));
        report.addProperty("heap_max_bytes", Runtime.getRuntime().maxMemory());
        report.addProperty("timed_out", timedOut);
        report.addProperty("program_marked_analyzed", analyzed);
        report.addProperty("analysis_active", manager.isAnalyzing());
        report.addProperty("analysis_wall_ns", elapsed);
        report.addProperty("recorded_task_total_ms", times.getTotalTime());
        var log = manager.getMessageLog();
        String messages = log.toString();
        report.addProperty("analyzer_message_characters", messages.length());
        report.addProperty("analyzer_messages", messages.substring(0, Math.min(messages.length(), 16_384)));
        JsonObject tasks = new JsonObject();
        for (String name : times.getTaskNames()) {
            tasks.addProperty(name, times.getTime(name));
        }
        report.add("task_times_ms", tasks);

        var options = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
        JsonObject settings = new JsonObject();
        for (String name : options.getOptionNames().stream().sorted().toList()) {
            settings.addProperty(name, options.getValueAsString(name));
        }
        report.add("analysis_options", settings);
        JsonObject work = new JsonObject();
        var listing = currentProgram.getListing();
        var functionManager = currentProgram.getFunctionManager();
        var referenceManager = currentProgram.getReferenceManager();
        work.addProperty("initialized_bytes", currentProgram.getMemory().getLoadedAndInitializedAddressSet().getNumAddresses());
        work.addProperty("instructions", listing.getNumInstructions());
        work.addProperty("defined_data", listing.getNumDefinedData());
        work.addProperty("functions", functionManager.getFunctionCount());
        work.addProperty("symbols", currentProgram.getSymbolTable().getNumSymbols());
        work.addProperty("reference_sources", referenceManager.getReferenceSourceCount());
        work.addProperty("reference_destinations", referenceManager.getReferenceDestinationCount());
        if (analyzed && !timedOut && !manager.isAnalyzing()) {
            long inventoryStart = System.nanoTime();
            work.addProperty("inventory_version", INVENTORY_VERSION);
            work.addProperty("inventory_sha256", inventoryDigest());
            report.addProperty("inventory_wall_ns", System.nanoTime() - inventoryStart);
        }
        report.add("work", work);
        Files.writeString(Path.of(args[1]), new GsonBuilder().setPrettyPrinting().create().toJson(report) + "\n");
    }

    protected final String inventoryDigest() throws Exception {
        var digest = MessageDigest.getInstance("SHA-256");
        var listing = currentProgram.getListing();
        var references = currentProgram.getReferenceManager();
        try (var data = new DataOutputStream(new BufferedOutputStream(
            new DigestOutputStream(OutputStream.nullOutputStream(), digest)))) {
            putString(data, "binaryrat/analysis-inventory/" + INVENTORY_VERSION);
            var functionSpaces = new AddressSet(currentProgram.getMemory());
            functionSpaces.addRange(AddressSpace.EXTERNAL_SPACE.getMinAddress(),
                AddressSpace.EXTERNAL_SPACE.getMaxAddress());
            var functions = currentProgram.getFunctionManager().getFunctions(functionSpaces, true);
            while (functions.hasNext()) {
                monitor.checkCancelled();
                var function = functions.next();
                data.writeByte(1);
                putAddress(data, function.getEntryPoint());
                putString(data, function.getName(true));
                putString(data, function.getPrototypeString(true, true));
                data.writeBoolean(function.isThunk());
                data.writeBoolean(function.hasNoReturn());
                data.writeInt(function.getBody().getNumAddressRanges());
                for (var range : function.getBody().getAddressRanges()) {
                    putAddress(data, range.getMinAddress());
                    putAddress(data, range.getMaxAddress());
                }
            }
            var manager = currentProgram.getBookmarkManager();
            var addresses = new AddressSet();
            var bookmarks = manager.getBookmarksIterator();
            while (bookmarks.hasNext()) {
                monitor.checkCancelled();
                addresses.add(bookmarks.next().getAddress());
            }
            // Database IDs and insertion order can differ across fresh imports. Keep only
            // address ranges, then sort and encode the bookmarks at one address at a time.
            for (Address address : addresses.getAddresses(true)) {
                monitor.checkCancelled();
                var atAddress = manager.getBookmarks(address);
                Arrays.sort(atAddress);
                for (var bookmark : atAddress) {
                    data.writeByte(5);
                    putAddress(data, address);
                    putString(data, bookmark.getTypeString());
                    putString(data, bookmark.getCategory());
                    putString(data, bookmark.getComment());
                }
            }
            var instructions = listing.getInstructions(true);
            while (instructions.hasNext()) {
                monitor.checkCancelled();
                var instruction = instructions.next();
                data.writeByte(2);
                putAddress(data, instruction.getMinAddress());
                data.writeInt(instruction.getLength());
                putString(data, instruction.getMnemonicString());
                putString(data, instruction.getFlowOverride().name());
            }
            var items = listing.getDefinedData(true);
            while (items.hasNext()) {
                monitor.checkCancelled();
                var item = items.next();
                data.writeByte(3);
                putAddress(data, item.getMinAddress());
                data.writeInt(item.getLength());
                putString(data, item.getDataType().getPathName());
            }
            var order = Comparator.comparing(Reference::getToAddress)
                .thenComparingInt(Reference::getOperandIndex)
                .thenComparing(reference -> reference.getReferenceType().getName())
                .thenComparing(reference -> reference.getSource().name())
                .thenComparing(Reference::isPrimary);
            var sources = references.getReferenceSourceIterator(currentProgram.getMemory(), true);
            while (sources.hasNext()) {
                monitor.checkCancelled();
                Address source = sources.next();
                var outgoing = references.getReferencesFrom(source);
                Arrays.sort(outgoing, order);
                for (Reference reference : outgoing) {
                    data.writeByte(4);
                    putAddress(data, source);
                    putAddress(data, reference.getToAddress());
                    data.writeInt(reference.getOperandIndex());
                    putString(data, reference.getReferenceType().getName());
                    putString(data, reference.getSource().name());
                    data.writeBoolean(reference.isPrimary());
                }
            }
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    private static void putString(DataOutputStream data, String value) throws Exception {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        data.writeInt(bytes.length);
        data.write(bytes);
    }

    private static void putAddress(DataOutputStream data, Address address) throws Exception {
        putString(data, address.getAddressSpace().getName());
        data.writeLong(address.getOffset());
    }
}
