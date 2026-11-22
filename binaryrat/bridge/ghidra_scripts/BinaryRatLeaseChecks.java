// Run ordinary lease cancellation regressions on an analyzed fixture.
// @category BinaryRat.Tests
/* Copyright 2026 YurilLAB. SPDX-License-Identifier: Apache-2.0 */

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import binaryrat.DecompOutput;
import binaryrat.EngineClient;
import binaryrat.ScheduledDecompiler;
import ghidra.app.decompiler.DecompileProcess;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import utilities.util.FileUtilities;

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
        checkSampleReader();
        checkExportPolicy(fixture.getEntryPoint());
        Path directory = Files.createTempDirectory("binaryrat-lease-check-");
        try (EngineClient engine = EngineClient.start(EngineClient.findExecutable(), directory);
                ScheduledDecompiler scheduler = testScheduler(engine)) {
            JsonObject blocker = request("blocker");
            blocker.addProperty("reserve_bytes", 256L << 20);
            blocker.addProperty("timeout_ms", 60000);
            require(engine.call("sched.acquire", blocker).get("granted").getAsBoolean(), "blocker grant");
            checkRequestDepth(engine, scheduler);
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
            DecompileResults discarded = new DecompileResults(fixture, currentProgram.getLanguage(),
                currentProgram.getCompilerSpec(), scheduler.sample().getDataTypeManager(),
                "native fixture failure", null, DecompileProcess.DisposeState.DISPOSED_ON_CANCEL) {
                @Override
                public DecompiledFunction getDecompiledFunction() {
                    throw new AssertionError("stopped leases must not allocate rendered output");
                }
            };
            for (String status : new String[] { "memory_exceeded", "timed_out", "cancelled", "failed" }) {
                require(!DecompOutput.stopped(discarded, status, null).cacheable(),
                    "stopped lease must not render or cache discarded text: " + status);
            }

            var configured = scheduler.sample();
            String initial = configured.registrationDigest();
            Set<String> registrations = new HashSet<>(Set.of(initial));
            // Exercise toggles after openProgram as well as the default registration.
            require(configured.toggleCCode(false), "disable C");
            require(registrations.add(configured.registrationDigest()), "C output changes cache identity");
            require(configured.toggleCCode(true) && configured.toggleParamMeasures(true), "enable measures");
            require(registrations.add(configured.registrationDigest()), "measures change cache identity");
            require(configured.toggleParamMeasures(false) && configured.toggleJumpLoads(true), "enable jump loads");
            require(registrations.add(configured.registrationDigest()), "jump loads change cache identity");
            require(configured.toggleJumpLoads(false) && configured.toggleSyntaxTree(false), "use C-only output");
            require(registrations.add(configured.registrationDigest()), "syntax tree changes cache identity");
            ScheduledDecompiler.Run cOnly = scheduler.decompileUntraced(fixture, new TaskMonitorAdapter(true));
            require(cOnly.memoryWatched() && cOnly.status().equals("completed") &&
                cOnly.traced() != null && cOnly.traced().trace() == null, "C-only lease must be untraced");
            require(cOnly.traced().results().getHighFunction() != null &&
                !cOnly.traced().results().getHighFunction().getPcodeOps().hasNext(),
                "C-only result must omit the p-code operation tree");
            require(DecompOutput.of(cOnly.traced().results()).equals(DecompOutput.of(next.traced().results())),
                "C-only untraced output must match the traced stock configuration");
            require(configured.toggleSyntaxTree(true) && initial.equals(configured.registrationDigest()),
                "restoring actions must restore the initial cache identity");
            checkCancellationDuringStartup(scheduler, fixture, true);
            checkCancellationDuringStartup(scheduler, fixture, false);
            checkReleaseFailure(fixture, directory.resolve("release-failure"));
        }
        finally {
            if (!FileUtilities.deleteDir(directory)) {
                throw new IOException("Could not remove the lease check cache: " + directory);
            }
        }
        println("BinaryRat lease lifecycle checks passed");
    }

    private static void checkExportPolicy(ghidra.program.model.address.Address entry) throws Exception {
        require(BinaryRatExport.Mode.SERIAL.syntaxTree() && BinaryRatExport.Mode.PARALLEL.syntaxTree() &&
            BinaryRatExport.Mode.SCHEDULED.syntaxTree() && !BinaryRatExport.Mode.VERIFIED_CANDIDATE.syntaxTree(),
            "standalone exports must retain stock response-size semantics");
        JsonObject cOnly = new DecompOutput(true, false, false, false, "", "int f()", "int f() {}").toJson();
        cOnly.addProperty("address_space", entry.getAddressSpace().getName());
        cOnly.addProperty("address", Long.toUnsignedString(entry.getOffset(), 16));
        JsonObject stock = cOnly.deepCopy();
        stock.addProperty("completed", false);
        stock.addProperty("prototype", "");
        stock.addProperty("c", "");
        stock.addProperty("error", "Response buffer size exceeded for: fixture");
        try (var reader = new BufferedReader(new StringReader(cOnly.toString()))) {
            var audit = new BinaryRatExport.StockParityAudit(reader);
            require(audit.select(entry, stock.toString()).equals(stock.toString()) &&
                audit.finish(new byte[32]).get("stock_fallbacks").getAsInt() == 1,
                "stock payload failure must win over a successful C-only candidate");
        }
    }

    private static void checkSampleReader() throws Exception {
        String longName = "x".repeat(2 * 1024 * 1024);
        String records = "0\t1\t" + longName + "\r\nffffffffffffffff\tA\tλ\r2\t1\tz\n3\t1\tq";
        try (var input = new BufferedReader(new StringReader(records))) {
            for (String expected : new String[] { "0", "ffffffffffffffff", "2", "3" }) {
                require(new BigInteger(expected, 16).equals(BinaryRatExport.nextSampleOffset(input,
                    TaskMonitor.DUMMY)), "sample offset with long name or mixed line endings");
            }
            require(BinaryRatExport.nextSampleOffset(input, TaskMonitor.DUMMY) == null, "sample EOF");
        }
        for (String invalid : new String[] { "\n", "0\t0\tx", "0\t1\t\u2003 ", "0\t1\tx\textra",
                "00000000000000000\t1\tx", "\uff10\t1\tx", "0\t1", "\t1\tx", "0\t\tx" }) {
            try (var input = new BufferedReader(new StringReader(invalid))) {
                BinaryRatExport.nextSampleOffset(input, TaskMonitor.DUMMY);
                throw new AssertionError("invalid sample accepted");
            }
            catch (IOException expected) {
                // Each malformed row must fail before producing an offset.
            }
        }
        var cancelling = new TaskMonitorAdapter(true) {
            private int checks;
            @Override
            public void checkCancelled() throws CancelledException {
                if (++checks == 2) {
                    cancel();
                }
                super.checkCancelled();
            }
        };
        try (var input = new BufferedReader(new StringReader(records))) {
            BinaryRatExport.nextSampleOffset(input, cancelling);
            throw new AssertionError("large sample row ignored cancellation");
        }
        catch (CancelledException expected) {
            // Cancellation must be observed inside a single long name.
        }
    }

    private ScheduledDecompiler testScheduler(EngineClient engine) throws IOException {
        return new ScheduledDecompiler(engine, currentProgram, d -> {
            DecompileOptions options = new DecompileOptions();
            options.grabFromProgram(currentProgram);
            d.setOptions(options);
        }, new ScheduledDecompiler.Limits(1, 256L << 20, 0, 0, 60, 5000, 60000));
    }

    private static void checkRequestDepth(EngineClient engine, ScheduledDecompiler scheduler)
            throws Exception {
        var waiting = engine.send("sched.acquire", request("request-depth-fixture"));
        waitFor(scheduler, "queued", 1);

        // The request itself is the 64th container. Brackets in UTF-8 strings do not count.
        JsonElement value = new JsonPrimitive("[{\"name\\with\\escapes\": 1}] α界🐀".repeat(70));
        for (int depth = 1; depth < 64; depth++) {
            if (depth % 2 == 0) {
                JsonObject object = new JsonObject();
                object.add("nested", value);
                value = object;
            }
            else {
                JsonArray array = new JsonArray();
                array.add(value);
                value = array;
            }
        }
        JsonObject fields = new JsonObject();
        fields.add("fixture", value);
        require(engine.call("ping", fields).has("capabilities"), "depth-64 request was not accepted");
        JsonArray extra = new JsonArray();
        extra.add(value);
        fields.add("fixture", extra);
        try {
            engine.call("ping", fields);
            throw new AssertionError("depth-65 request was not rejected");
        }
        catch (IOException expected) {
            require(expected.getMessage().equals("engine request nests deeper than 64 levels"),
                "depth-65 request was not rejected locally");
        }
        require(!waiting.isDone(), "invalid request completed an unrelated queued lease");
        require(engine.call("ping", new JsonObject()).has("capabilities"),
            "depth refusal poisoned the shared engine");
        engine.call("sched.cancel", request("request-depth-fixture"));
        var response = EngineClient.await(waiting, 5);
        require(!response.get("granted").getAsBoolean() && response.get("status").getAsString().equals("cancelled"),
            "the unrelated queued lease lost its response");
        waitFor(scheduler, "queued", 0);
    }

    private void checkCancellationDuringStartup(ScheduledDecompiler pool, Function function,
            boolean trace) throws Exception {
        TaskMonitorAdapter outer = new TaskMonitorAdapter(true);
        AtomicBoolean cancelled = new AtomicBoolean();
        // Stock has installed its cancellation listener when it requests the entry point,
        // but has yet to verify the process to which it will send decompileAt.
        Function duringStartup = (Function) Proxy.newProxyInstance(Function.class.getClassLoader(),
            new Class<?>[] { Function.class }, (proxy, method, args) -> {
                if (method.getName().equals("getEntryPoint") && cancelled.compareAndSet(false, true)) {
                    outer.cancel();
                }
                try {
                    return method.invoke(function, args);
                }
                catch (InvocationTargetException wrapped) {
                    throw wrapped.getCause();
                }
            });
        ScheduledDecompiler.Run stopped = trace ? pool.decompile(duringStartup, outer) :
            pool.decompileUntraced(duringStartup, outer);
        require(cancelled.get() && stopped.memoryWatched() && stopped.status().equals("cancelled") &&
            stopped.traced() != null && !stopped.traced().results().decompileCompleted(),
            "a cancelled lease must not complete native work on an unwatched replacement PID");
        ScheduledDecompiler.Run next = pool.decompileUntraced(function, new TaskMonitorAdapter(true));
        require(next.memoryWatched() && next.status().equals("completed") &&
            next.traced().results().decompileCompleted(), "the next lease can attach a fresh process");
    }

    private void checkReleaseFailure(Function function, Path directory) throws Exception {
        try (EngineClient engine = EngineClient.start(EngineClient.findExecutable(), directory);
                ScheduledDecompiler pool = testScheduler(engine)) {
            // Complete the fresh pool's first lease after attach, before the bridge
            // receives native results. The bridge's own release will now be refused.
            AtomicBoolean released = new AtomicBoolean();
            Function fault = (Function) Proxy.newProxyInstance(Function.class.getClassLoader(),
                new Class<?>[] { Function.class }, (proxy, method, args) -> {
                    if (method.getName().equals("getEntryPoint") && released.compareAndSet(false, true)) {
                        engine.call("sched.release", request("f1"));
                    }
                    try {
                        return method.invoke(function, args);
                    }
                    catch (InvocationTargetException wrapped) {
                        throw wrapped.getCause();
                    }
                });
            try {
                pool.decompileUntraced(fault, new TaskMonitorAdapter(true));
                throw new AssertionError("lost release acknowledgement must fail the export");
            }
            catch (IOException expected) {
                require(released.get() && expected.getMessage().contains("lease release failed"),
                    "fixture must lose the release acknowledgement");
            }
            FutureTask<ScheduledDecompiler.Run> retry = new FutureTask<>(
                () -> pool.decompileUntraced(function, new TaskMonitorAdapter(true)));
            Thread borrower = new Thread(retry, "binaryrat-retired-pool");
            borrower.start();
            try {
                retry.get(5, TimeUnit.SECONDS);
                throw new AssertionError("retired pool reused a decompiler");
            }
            catch (ExecutionException expected) {
                require(expected.getCause() instanceof IOException failure &&
                    failure.getMessage().contains("pool retired"), "retired pool rejects new borrowers");
            }
            finally {
                retry.cancel(true);
                borrower.join(5000);
            }
            waitFor(pool, "running", 0);
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
