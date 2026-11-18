// Run ordinary lease cancellation regressions on an analyzed fixture.
// @category BinaryRat.Tests
/* Copyright 2026 YurilLAB. SPDX-License-Identifier: Apache-2.0 */

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicReference;

import com.google.gson.JsonObject;

import binaryrat.EngineClient;
import binaryrat.DecompOutput;
import binaryrat.ScheduledDecompiler;
import ghidra.app.decompiler.DecompileProcess;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitorAdapter;

/** Checks cancellation ownership against the real engine and stock native decompiler. */
public class BinaryRatLeaseChecks extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (!isRunningHeadless() || currentProgram == null) {
            throw new IllegalStateException("Run as a headless postScript on a benign analyzed fixture");
        }
        Function fixture = null;
        for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
            MemoryBlock block = currentProgram.getMemory().getBlock(function.getEntryPoint());
            if (!function.isExternal() && block != null && block.isInitialized() &&
                    !block.isExternalBlock()) {
                fixture = function;
                break;
            }
        }
        require(fixture != null, "fixture must contain an initialized function");
        Path directory = Files.createTempDirectory("binaryrat-lease-check-");
        try (EngineClient engine = EngineClient.start(Path.of(System.getenv("BINARYRAT_ENGINE")), directory);
                ScheduledDecompiler scheduler = new ScheduledDecompiler(engine, currentProgram, d -> {
                    DecompileOptions options = new DecompileOptions();
                    options.grabFromProgram(currentProgram);
                    d.setOptions(options);
                }, new ScheduledDecompiler.Limits(1, 256L << 20, 0, 0, 60, 5000, 60000))) {
            JsonObject blocker = request("blocker");
            blocker.addProperty("reserve_bytes", 256L << 20);
            blocker.addProperty("timeout_ms", 60000);
            require(engine.call("sched.acquire", blocker).get("granted").getAsBoolean(), "blocker grant");
            AtomicReference<Throwable> failure = new AtomicReference<>();
            Function selected = fixture;
            Thread waiter = new Thread(() -> {
                try {
                    scheduler.decompile(selected, new TaskMonitorAdapter(true));
                    failure.set(new AssertionError("interrupted queued call returned normally"));
                }
                catch (IOException expected) {
                    // An interrupted borrower must relinquish its pending acquire.
                }
                catch (Throwable unexpected) {
                    failure.set(unexpected);
                }
            }, "binaryrat-interrupted-borrower");
            waiter.start();
            waitFor(scheduler, "queued", 1);
            waiter.interrupt();
            waiter.join(5000);
            require(!waiter.isAlive(), "interrupted borrower must finish");
            require(failure.get() == null, "unexpected borrower failure: " + failure.get());
            waitFor(scheduler, "queued", 0);
            engine.call("sched.release", request("blocker"));
            waitFor(scheduler, "running", 0);

            TaskMonitorAdapter cancelled = new TaskMonitorAdapter(true);
            cancelled.cancel();
            ScheduledDecompiler.Run stopped = scheduler.decompile(fixture, cancelled);
            require(stopped.traced() == null && stopped.status().equals("cancelled"),
                "already cancelled monitor must not start native decompilation");
            ScheduledDecompiler.Run next = scheduler.decompile(fixture, new TaskMonitorAdapter(true));
            require(next.traced() != null && next.traced().results().decompileCompleted(),
                "a fresh borrower must still decompile after interrupted/cancelled calls");
            require(next.status().equals("completed"), "fresh lease completion");
            waitFor(scheduler, "running", 0);
            // A deadline or memory stop can arrive just as native output finishes.
            // The lease outcome must prevent that output being published/cached.
            for (String status : new String[] { "memory_exceeded", "timed_out", "cancelled" }) {
                DecompOutput stoppedOutput = DecompOutput.stopped(next.traced().results(), status, null);
                require(!stoppedOutput.completed() && stoppedOutput.c().isEmpty() &&
                    stoppedOutput.prototype().isEmpty() && !stoppedOutput.cacheable(),
                    "stopped lease must discard completed-looking native output: " + status);
                require(stoppedOutput.timedOut() == status.equals("timed_out"), "timeout classification");
                require(stoppedOutput.cancelled() == !status.equals("timed_out"), "cancel classification");
            }
            // A normally released lease need not mean the native decompiler succeeded.
            for (DecompileProcess.DisposeState state : new DecompileProcess.DisposeState[] {
                    DecompileProcess.DisposeState.DISPOSED_ON_TIMEOUT,
                    DecompileProcess.DisposeState.DISPOSED_ON_STARTUP_FAILURE,
                    DecompileProcess.DisposeState.NOT_DISPOSED }) {
                DecompileResults nativeFailure = new DecompileResults(fixture, currentProgram.getLanguage(),
                    currentProgram.getCompilerSpec(), scheduler.sample().getDataTypeManager(),
                    "native fixture failure", null, state);
                require(DecompOutput.stopped(nativeFailure, "completed", null).equals(DecompOutput.of(nativeFailure)),
                    "normal lease must preserve native failure status: " + state);
            }
            println("BinaryRat lease lifecycle checks passed");
        }
    }

    private static JsonObject request(String lease) {
        JsonObject object = new JsonObject();
        object.addProperty("lease", lease);
        return object;
    }

    private static void waitFor(ScheduledDecompiler scheduler, String field, long expected)
            throws Exception {
        long deadline = System.nanoTime() + 5_000_000_000L;
        JsonObject stats;
        do {
            stats = scheduler.stats();
            if (stats.get(field).getAsLong() == expected) {
                return;
            }
            Thread.sleep(10);
        } while (System.nanoTime() < deadline);
        throw new AssertionError(field + " must reach " + expected + ": " + stats);
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
