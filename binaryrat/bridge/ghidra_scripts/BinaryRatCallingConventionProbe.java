// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
// Verify concurrent first reads of stored calling conventions on a disposable saved Program.
//@category BinaryRat.Tests
import java.lang.management.ManagementFactory;
import java.lang.management.ThreadInfo;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;

import binaryrat.DecompilationSession;
import db.DBHandle;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.data.DataTypeManagerDB;

public class BinaryRatCallingConventionProbe extends GhidraScript {
    @Override
    public void run() throws Exception {
        var database = ((ProgramDB) currentProgram).getDBHandle();
        var manager = (DataTypeManagerDB) currentProgram.getDataTypeManager();
        // Reading the table directly leaves the stock manager's name lookup cold.
        var names = storedNames(database);
        var args = getScriptArgs();
        if (args.length > 0) {
            if (!isRunningHeadless() || args.length != 2 || !args[0].equals("prepare") ||
                    !args[1].equalsIgnoreCase(currentProgram.getExecutableSHA256())) {
                throw new IllegalArgumentException("expected prepare and the disposable fixture's SHA-256");
            }
            if (names.isEmpty()) {
                // Some inputs have no stored ID. Seed a real compiler convention only on the
                // verifier's disposable database, before it saves the cold cache baseline.
                var name = currentProgram.getCompilerSpec().getDefaultCallingConvention().getName();
                manager.getCallingConventionID(name, true);
            }
            if (storedNames(database).isEmpty()) {
                throw new AssertionError("the disposable fixture has no stored calling convention");
            }
            println("BINARYRAT_CONVENTIONS_PREPARED");
            return;
        }
        if (names.isEmpty()) {
            throw new AssertionError("expected a saved fixture with a stored calling convention");
        }
        long revision = currentProgram.getModificationNumber();
        try (var session = DecompilationSession.open(currentProgram, 2, 60)) {
            Callable<Map<Byte, String>> read = () -> {
                var result = new LinkedHashMap<Byte, String>();
                for (var id : names.keySet()) {
                    result.put(id, manager.getCallingConventionName(id));
                }
                return result;
            };
            var first = new FutureTask<>(read);
            var second = new FutureTask<>(read);
            // Table.iterator() acquires this monitor. A cold, unsynchronized 12.2 adapter can
            // publish an empty lookup map to the second reader while the first waits here.
            var readers = Thread.ofPlatform().daemon().name("BinaryRat convention reader ", 1);
            var firstReader = readers.unstarted(first);
            var secondReader = readers.unstarted(second);
            try {
                synchronized (database) {
                    var owner = Thread.currentThread().threadId();
                    startReader(firstReader, first, Set.of(owner));
                    startReader(secondReader, second, Set.of(owner, firstReader.threadId()));
                }
                var actualFirst = first.get(15, TimeUnit.SECONDS);
                var actualSecond = second.get(15, TimeUnit.SECONDS);
                if (!names.equals(actualFirst) || !names.equals(actualSecond)) {
                    throw new AssertionError("stored conventions " + names + ", first reader " +
                        actualFirst + ", second reader " + actualSecond);
                }
            }
            finally {
                firstReader.join(15_000);
                secondReader.join(15_000);
                if (firstReader.isAlive() || secondReader.isAlive()) {
                    throw new AssertionError("convention reader remained active after the database was released");
                }
            }
        }
        if (revision != currentProgram.getModificationNumber()) {
            throw new AssertionError("the read-only convention probe changed the saved Program");
        }
        println("BINARYRAT_CONCURRENT_CONVENTIONS_PASS " + names);
    }

    private static Map<Byte, String> storedNames(DBHandle database) throws Exception {
        var records = database.getTable("Calling Conventions").iterator();
        var names = new LinkedHashMap<Byte, String>();
        while (records.hasNext()) {
            var row = records.next();
            names.put((byte) row.getKey(), row.getString(0));
        }
        return names;
    }

    private static void startReader(Thread thread, FutureTask<?> read, Set<Long> blockers) throws Exception {
        thread.start();
        var threads = ManagementFactory.getThreadMXBean();
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15);
        while (!read.isDone()) {
            ThreadInfo info = threads.getThreadInfo(thread.threadId(), 40);
            if (info != null && blockers.contains(info.getLockOwnerId()) &&
                    Arrays.stream(info.getStackTrace()).anyMatch(
                        frame -> frame.getMethodName().equals("getCallingConventionName"))) {
                break;
            }
            if (System.nanoTime() >= deadline) {
                throw new AssertionError("convention lookup neither finished nor reached its database lock");
            }
            Thread.sleep(1);
        }
    }
}
