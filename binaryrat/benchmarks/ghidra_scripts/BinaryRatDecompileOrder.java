// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;

/**
 * Decompiles the join-order fixture in ascending order, descending order and with a new
 * native process per function. Prints each function's C digest for the Python verifier.
 */
public class BinaryRatDecompileOrder extends GhidraScript {
    private static final String[] NAMES = { "g16", "g12", "first16", "first12" };
    private static final long[] ENTRIES = { 0x0, 0xf, 0x36, 0x69 };
    private static final long END = 0x9a;
    private static final int TIMEOUT_SECONDS = 60;

    @Override
    protected void run() throws Exception {
        if (!isRunningHeadless() || currentProgram == null || getScriptArgs().length != 1) {
            throw new IllegalArgumentException("Run headless on the raw fixture with a report path");
        }
        List<Function> functions = new ArrayList<>();
        for (int i = 0; i < NAMES.length; i++) {
            var entry = currentProgram.getImageBase().addNoWrap(ENTRIES[i]);
            long next = i + 1 < ENTRIES.length ? ENTRIES[i + 1] : END;
            var body = new AddressSet(entry, currentProgram.getImageBase().addNoWrap(next - 1));
            var disassemble = new DisassembleCommand(entry, body, true);
            disassemble.enableCodeAnalysis(false);
            if (!disassemble.applyTo(currentProgram, monitor)) {
                throw new IllegalStateException("Cannot disassemble " + NAMES[i]);
            }
            Function function = currentProgram.getFunctionManager().createFunction(NAMES[i], entry,
                body, SourceType.USER_DEFINED);
            if (function == null || !function.getBody().equals(body)) {
                throw new IllegalStateException("Cannot create " + NAMES[i]);
            }
            functions.add(function);
        }
        List<String> report = new ArrayList<>();
        decompileAll("forward", functions, report);
        decompileAll("reverse", functions.reversed(), report);
        for (Function function : functions) {
            decompileAll("fresh", List.of(function), report);
        }
        Files.write(Path.of(getScriptArgs()[0]), report, StandardCharsets.UTF_8);
        println("BINARYRAT_DECOMPILE_ORDER passed " + report.size() + " decompilations");
    }

    /** Decompiles the functions in order through one native process. */
    private void decompileAll(String phase, List<Function> functions, List<String> report)
            throws Exception {
        DecompInterface decompiler = open();
        try {
            for (Function function : functions) {
                report.add(row(phase, function, decompiler));
            }
        }
        finally {
            decompiler.dispose();
        }
    }

    private DecompInterface open() {
        DecompInterface decompiler = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        options.grabFromProgram(currentProgram);
        decompiler.setOptions(options);
        decompiler.setSimplificationStyle("decompile");
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        if (!decompiler.openProgram(currentProgram)) {
            decompiler.dispose();
            throw new IllegalStateException("Cannot start the decompiler: " + decompiler.getLastMessage());
        }
        return decompiler;
    }

    private String row(String phase, Function function, DecompInterface decompiler) throws Exception {
        DecompileResults results = decompiler.decompileFunction(function, TIMEOUT_SECONDS, monitor);
        if (results == null || !results.decompileCompleted() || results.getDecompiledFunction() == null) {
            throw new IllegalStateException("Decompilation failed for " + function.getName() + ": " +
                (results == null ? "no result" : results.getErrorMessage()));
        }
        byte[] text = results.getDecompiledFunction().getC().getBytes(StandardCharsets.UTF_8);
        String digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(text));
        return phase + "\t" + function.getName() + "\t" + digest;
    }
}
