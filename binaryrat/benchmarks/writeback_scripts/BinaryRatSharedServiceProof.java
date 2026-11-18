// Verify the installed decompilation service on a reopened disposable Program.
//@category BinaryRat.Tests

// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0

import java.io.IOException;

import binaryrat.DecompilationSession;
import binaryrat.DecompOutput;
import binaryrat.LiveDecompileCache.Kind;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.BookmarkType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitorAdapter;

public class BinaryRatSharedServiceProof extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (!isRunningHeadless() || currentProgram == null) {
            throw new IllegalArgumentException("Expected a reopened disposable Program");
        }
        end(true);
        var function = getGlobalFunctions("read_packed").getFirst();
        long revision = currentProgram.getModificationNumber();
        DecompOutput stock;
        DecompInterface serial = new DecompInterface();
        try {
            var options = new DecompileOptions();
            options.grabFromProgram(currentProgram);
            serial.setOptions(options);
            serial.setSimplificationStyle("decompile");
            serial.toggleCCode(true);
            serial.toggleSyntaxTree(true);
            require(serial.openProgram(currentProgram), "stock decompiler could not open Program");
            stock = DecompOutput.of(serial.decompileFunction(function, 60, monitor));
            require(stock.completed(), "stock decompilation did not complete");
        }
        finally {
            serial.dispose();
        }
        try (var batch = DecompilationSession.open(currentProgram, 1, 60);
                var foreground = DecompilationSession.open(currentProgram, 1, 60)) {
            require(batch.cacheEnabled() && foreground.cacheEnabled(), "proof requires an owned cache");
            var cold = batch.decompileWithMetrics(function, monitor);
            require(stock.equals(cold.output()) && cold.stored() && cold.lease() != null &&
                cold.lookup().kind() == Kind.MISS, "cold service run did not match and store stock output");
            var warm = foreground.decompileForegroundWithMetrics(function, monitor);
            require(stock.equals(warm.output()) && warm.lease() == null && warm.lookup().usable(),
                "foreground handle did not reuse the batch cache");
            try (var incompatible = DecompilationSession.open(currentProgram, 1, 30)) {
                throw new IllegalStateException("An incompatible session acquired the same cache directory");
            }
            catch (IOException expected) {
                require(expected.getMessage().contains("BINARYRAT_CACHE_DIR already serves"),
                    "unexpected cache ownership failure: " + expected);
            }
            batch.close();
            var cancelled = new TaskMonitorAdapter(true);
            cancelled.cancel();
            try {
                foreground.decompileForeground(function, cancelled);
                throw new IllegalStateException("A cancelled request returned output");
            }
            catch (CancelledException expected) {
                // Cancellation must win even when the output is cached.
            }
            require(stock.equals(foreground.decompileForeground(function, monitor)),
                "closing one handle broke a separate live handle");
        }
        try (var reopened = DecompilationSession.open(currentProgram, 1, 60)) {
            var replay = reopened.decompileWithMetrics(function, monitor);
            require(stock.equals(replay.output()) && replay.lease() == null && replay.lookup().usable(),
                "closed session did not release a reusable cache directory");
        }
        require(currentProgram.getModificationNumber() == revision, "decompilation changed the Program");
        try (var obsolete = DecompilationSession.open(currentProgram, 1, 60)) {
            int change = currentProgram.startTransaction("Test obsolete decompiler context");
            try {
                currentProgram.getBookmarkManager().setBookmark(function.getEntryPoint(),
                    BookmarkType.ANALYSIS, "BinaryRat service test", "temporary edit");
                require(currentProgram.getModificationNumber() != revision, "fixture did not change the Program");
                try {
                    obsolete.decompile(function, monitor);
                    throw new IllegalStateException("An obsolete Program revision returned output");
                }
                catch (IOException expected) {
                    require(expected.getMessage().contains("Program changed"),
                        "unexpected stale Program failure: " + expected);
                }
            }
            finally {
                currentProgram.endTransaction(change, false);
            }
        }
        println("BINARYRAT_SHARED_SERVICE_OK");
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }
}
