/* Copyright 2026 YurilLAB
 * SPDX-License-Identifier: Apache-2.0
 */
package ghidra.program.database.data;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.junit.Assert.*;

import java.lang.management.*;
import java.util.concurrent.*;

import db.DBHandle;

/** Coordinates two cold adapter lookups that read the same database table. */
final class ColdAdapterReaders {

	private ColdAdapterReaders() {
	}

	static <T, U> void assertResults(DBHandle db, Class<?> adapterClass, Callable<T> firstLookup,
			Callable<U> secondLookup, T expectedFirst, U expectedSecond) throws Exception {
		var first = new FutureTask<>(firstLookup);
		var second = new FutureTask<>(secondLookup);
		Thread loader = Thread.ofPlatform().daemon().name("first adapter lookup").unstarted(first);
		Thread observer = Thread.ofPlatform().daemon().name("second adapter lookup").unstarted(second);
		try {
			// Table.iterator() takes the DBHandle monitor. Stop the loader on the real
			// table read and let the observer enter the adapter while that read is pending.
			synchronized (db) {
				loader.start();
				awaitLookup(loader, first, db, adapterClass);
				observer.start();
				awaitLookup(observer, second, null, adapterClass);
			}
			assertEquals(expectedFirst, first.get(10, SECONDS));
			assertEquals("concurrent reader missed a stored value", expectedSecond,
				second.get(10, SECONDS));
		}
		finally {
			first.cancel(true);
			second.cancel(true);
			loader.join(SECONDS.toMillis(10));
			observer.join(SECONDS.toMillis(10));
		}
	}

	private static void awaitLookup(Thread thread, FutureTask<?> result, DBHandle db,
			Class<?> adapterClass) throws Exception {
		ThreadMXBean threads = ManagementFactory.getThreadMXBean();
		long deadline = System.nanoTime() + SECONDS.toNanos(10);
		while (!result.isDone()) {
			ThreadInfo info = threads.getThreadInfo(thread.threadId(), 32);
			if (info != null && (info.getThreadState() == Thread.State.BLOCKED ||
				info.getThreadState() == Thread.State.WAITING)) {
				if (db != null && info.getThreadState() == Thread.State.BLOCKED &&
					info.getLockOwnerId() == Thread.currentThread().threadId() &&
					info.getLockInfo().getIdentityHashCode() == System.identityHashCode(db)) {
					return;
				}
				if (db == null) {
					for (StackTraceElement frame : info.getStackTrace()) {
						if (frame.getClassName().equals(adapterClass.getName())) {
							return;
						}
					}
				}
			}
			if (System.nanoTime() >= deadline) {
				fail("Reader did not reach the cold lookup: " + thread.getName());
			}
			Thread.sleep(1);
		}
		if (db != null) {
			fail("First lookup finished without reading the cold table");
		}
	}
}
