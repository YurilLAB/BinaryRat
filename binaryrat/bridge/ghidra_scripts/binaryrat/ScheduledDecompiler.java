// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package binaryrat;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import com.google.gson.JsonObject;

import ghidra.app.decompiler.DecompInterface;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.data.DataTypeManagerDB;
import ghidra.program.database.data.ProgramBasedDataTypeManagerDB;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.CancelledListener;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * Runs stock Ghidra decompilations under the engine's admission control. Before each
 * decompilation it takes a lease from the C++ scheduler, which grants it only when a
 * worker and the lease's memory reservation fit the machine's CPU and RAM budget. The
 * native decompiler process is attached to the lease so the engine watches its
 * resident memory. When the engine stops the lease (deadline, cancel, memory) the
 * decompilation is cancelled, which stops the native process; a holder that fails to
 * stop has its process killed by the engine.
 */
public final class ScheduledDecompiler implements AutoCloseable {
	/**
	 * Limits handed to the engine; the engine measures CPUs and physical memory itself.
	 * leaseTimeoutMillis is the engine's deadline per decompilation; timeoutSeconds is
	 * the decompiler's own timeout, kept as a backstop behind it.
	 */
	public record Limits(int workerCap, long workerBytes, long jvmReserveBytes,
			long otherReserveBytes, int timeoutSeconds, long killGraceMillis,
			long leaseTimeoutMillis) {
	}

	/** One decompilation and how its lease ended. */
	public record Run(TracingDecompiler.Traced traced, String status, String stopReason,
			long waitedMillis, long runMillis, long peakResidentBytes, boolean killed,
			boolean memoryWatched) {
	}

	private static final int BACKSTOP_SECONDS = 30;

	private final EngineClient engine;
	private final Limits limits;
	private final int workers;
	private final JsonObject configuration;
	private final BlockingQueue<TracingDecompiler> idle = new LinkedBlockingQueue<>();
	private final List<TracingDecompiler> all = new ArrayList<>();
	private final AtomicLong leases = new AtomicLong();
	private volatile IOException releaseFailure;

	/** Prepare stock 12.2's lazy name tables before any callback or cache replay.
	 * In ProgramDB this is the data type manager's own lock. Exclude other readers
	 * only while loading the name indexes; no Program change or transaction. */
	record PreparedProgram(Program program, long revision) {
		static PreparedProgram open(Program program) throws IOException {
			if (program instanceof ProgramDB db) {
				var lock = db.getLock();
				if (lock.getReadHoldCount() != 0 && !lock.isWriteLockedByCurrentThread()) {
					throw new IOException("Open a decompiler session outside the ProgramDB read lock");
				}
				try {
					lock.writeLock().lockInterruptibly();
				}
				catch (InterruptedException interrupted) {
					Thread.currentThread().interrupt();
					throw new IOException("Interrupted while preparing calling conventions", interrupted);
				}
				try {
					prepareSettings(db, DataTypeManagerDB.class, "settingsAdapter");
					prepareSettings(db, ProgramBasedDataTypeManagerDB.class, "instanceSettingsAdapter");
					return readConventions(program);
				}
				finally {
					lock.writeLock().unlock();
				}
			}
			return readConventions(program);
		}

		// 12.2 exposes no Program API for initializing both settings-name indexes.
		// Warm the same adapters used by DataDB.getLong() when reading mutability;
		// choosing a sample Data would miss types or addresses with no stored setting.
		private static void prepareSettings(ProgramDB program, Class<?> owner, String fieldName) throws IOException {
			try {
				var field = owner.getDeclaredField(fieldName);
				if (!field.trySetAccessible()) {
					throw new IOException("Cannot access Ghidra's " + fieldName);
				}
				Object adapter = field.get(program.getDataTypeManager());
				if (adapter == null || adapter.getClass().getSimpleName().equals("SettingsDBAdapterV0")) {
					return; // No instance table, or the older format with inline names.
				}
				if (!adapter.getClass().getSimpleName().equals("SettingsDBAdapterV1")) {
					throw new IOException("Unsupported Ghidra settings adapter: " + adapter.getClass().getName());
				}
				var load = adapter.getClass().getDeclaredMethod("initNameMaps");
				if (!load.trySetAccessible()) {
					throw new IOException("Cannot access Ghidra's settings-name initializer");
				}
				try {
					load.invoke(adapter);
				}
				catch (InvocationTargetException failure) {
					var error = new IOException("Could not initialize Ghidra settings names", failure.getCause());
					// Unpatched V1 can leave partially filled indexes when the table read
					// fails. Reset only those indexes before another session can retry.
					try {
						var clear = adapter.getClass().getDeclaredMethod("invalidateNameCache");
						clear.setAccessible(true);
						clear.invoke(adapter);
					}
					catch (ReflectiveOperationException | RuntimeException cleanupFailure) {
						error.addSuppressed(cleanupFailure);
					}
					throw error;
				}
			}
			catch (ReflectiveOperationException failure) {
				throw new IOException("Cannot locate Ghidra's settings-name index " + fieldName, failure);
			}
		}

		private static PreparedProgram readConventions(Program program) {
			program.getDataTypeManager().getKnownCallingConventionNames();
			return new PreparedProgram(program, program.getModificationNumber());
		}
	}

	public ScheduledDecompiler(EngineClient engine, Program program,
			Consumer<DecompInterface> configure, Limits limits) throws IOException {
		this(engine, PreparedProgram.open(program), configure, limits);
	}

	ScheduledDecompiler(EngineClient engine, PreparedProgram prepared,
			Consumer<DecompInterface> configure, Limits limits) throws IOException {
		Program program = prepared.program();
		if (program.getModificationNumber() != prepared.revision()) {
			throw new IOException("Program changed while preparing the decompiler pool");
		}
		this.engine = engine;
		this.limits = limits;
		JsonObject request = new JsonObject();
		request.addProperty("worker_cap", limits.workerCap());
		request.addProperty("worker_bytes", limits.workerBytes());
		request.addProperty("jvm_reserve_bytes", limits.jvmReserveBytes());
		request.addProperty("other_reserve_bytes", limits.otherReserveBytes());
		request.addProperty("kill_grace_ms", limits.killGraceMillis());
		configuration = engine.call("sched.configure", request);
		workers = configuration.get("workers").getAsInt();
		try {
			for (int index = 0; index < workers; index++) {
				TracingDecompiler decompiler = new TracingDecompiler();
				all.add(decompiler);
				configure.accept(decompiler);
				if (!decompiler.openProgram(program)) {
					throw new IOException("cannot start decompiler: " + decompiler.getLastMessage());
				}
				idle.add(decompiler);
			}
		}
		catch (IOException | RuntimeException | Error exception) {
			close();
			throw exception;
		}
	}

	public int workers() {
		return workers;
	}

	/** One idle candidate yields its physical slot; its next ordinary lease restarts it with
	 * its original registration and recording callback. The stock interface is private to the loan. */
	final class StockLane implements AutoCloseable {
		final TracingDecompiler borrowed;
		final TracingDecompiler stock = new TracingDecompiler(false);
		long expectedPid;

		StockLane(TracingDecompiler borrowed) {
			this.borrowed = borrowed;
		}

		Run decompile(Function function, TaskMonitor monitor) throws IOException {
			return ScheduledDecompiler.this.decompile(function, monitor, false, this);
		}

		@Override
		public void close() throws IOException {
			try {
				stock.suspendNativeProcess();
			}
			catch (IOException failure) {
				// Without proof of exit another native process must not use this budget.
				releaseFailure = failure;
				throw failure;
			}
			finally {
				try {
					stock.dispose();
				}
				finally {
					idle.add(borrowed);
				}
			}
		}
	}

	StockLane borrowStockReference(Program program, TaskMonitor monitor) throws IOException, CancelledException {
		checkPool();
		TracingDecompiler borrowed;
		try {
			do {
				monitor.checkCancelled();
				borrowed = idle.poll(50, TimeUnit.MILLISECONDS);
			} while (borrowed == null);
		}
		catch (InterruptedException interrupted) {
			Thread.currentThread().interrupt();
			throw new CancelledException();
		}
		var lane = new StockLane(borrowed);
		try {
			try {
				borrowed.suspendNativeProcess();
			}
			catch (IOException failure) {
				releaseFailure = failure;
				throw failure;
			}
			monitor.checkCancelled();
			DecompilationSession.configureDecompiler(lane.stock, program, true);
			if (!lane.stock.openProgram(program) || (lane.expectedPid = lane.stock.readyProcessId()) <= 0) {
				throw new IOException("cannot start ordered stock reference: " + lane.stock.getLastMessage());
			}
			monitor.checkCancelled();
			return lane;
		}
		catch (IOException | CancelledException | RuntimeException | Error failure) {
			try {
				lane.close();
			}
			catch (IOException cleanup) {
				failure.addSuppressed(cleanup);
			}
			throw failure;
		}
	}

	/** What the engine decided: worker count, measured CPUs and memory, pool size. */
	public JsonObject configuration() {
		return configuration.deepCopy();
	}

	/** Any one decompiler, for registration digests. */
	public TracingDecompiler sample() {
		return all.get(0);
	}

	public JsonObject stats() throws IOException {
		return engine.call("sched.stats", new JsonObject());
	}

	/**
	 * Decompiles under a lease. Blocks until the engine admits it. Callers may call this
	 * from up to {@link #workers()} threads at once and more; extra callers queue in
	 * the engine.
	 */
	public Run decompile(Function function, TaskMonitor outer) throws IOException {
		return decompile(function, outer, true, null);
	}

	/** Runs without collecting query traces. Requires the engine to watch process memory. */
	public Run decompileUntraced(Function function, TaskMonitor outer) throws IOException {
		return decompile(function, outer, false, null);
	}

	private Run decompile(Function function, TaskMonitor outer, boolean recordQueries, StockLane lane)
			throws IOException {
		checkPool();
		// TaskMonitorAdapter does not notify a listener added after cancellation.
		if (outer.isCancelled()) {
			return new Run(null, "cancelled", "cancelled", 0, 0, 0, false, false);
		}
		String lease = "f" + leases.incrementAndGet();
		TaskMonitorAdapter monitor = new TaskMonitorAdapter(true);
		AtomicReference<String> stopReason = new AtomicReference<>();
		engine.onLease(lease, event -> {
			if ("lease.stop".equals(event.get("event").getAsString())) {
				stopReason.compareAndSet(null, event.get("reason").getAsString());
				monitor.cancel();
			}
		});
		AtomicBoolean acquireSent = new AtomicBoolean();
		AtomicBoolean cancelSent = new AtomicBoolean();
		Runnable cancel = () -> {
			monitor.cancel();
			if (acquireSent.get() && cancelSent.compareAndSet(false, true)) {
				engine.send("sched.cancel", leaseRequest(lease));
			}
		};
		CancelledListener forward = cancel::run;
		outer.addCancelledListener(forward);
		try {
			JsonObject request = new JsonObject();
			request.addProperty("lease", lease);
			request.addProperty("reserve_bytes", limits.workerBytes());
			request.addProperty("timeout_ms", limits.leaseTimeoutMillis());
			CompletableFuture<JsonObject> pending = engine.send("sched.acquire", request);
			acquireSent.set(true);
			if (outer.isCancelled()) {
				cancel.run();
			}
			JsonObject grant = awaitGrant(lease, pending, outer, cancel);
			if (!grant.get("granted").getAsBoolean()) {
				return new Run(null, grant.get("status").getAsString(), null, 0, 0, 0, false, false);
			}
			TracingDecompiler decompiler;
			try {
				// A preceding holder releases its lease before returning its process;
				// a newly admitted holder may have to wait for that handoff.
				decompiler = lane == null ? idle.take() : lane.stock;
			}
			catch (InterruptedException exception) {
				cancel.run();
				engine.send("sched.release", leaseRequest(lease));
				Thread.currentThread().interrupt();
				throw new IOException("interrupted while borrowing a decompiler", exception);
			}
			TracingDecompiler.Traced traced;
			boolean watched = false;
			JsonObject ended;
			try {
				checkPool();
				long pid = lane != null && lane.expectedPid > 0 ?
					decompiler.readyProcessId() : decompiler.processId();
				if (lane != null && lane.expectedPid > 0 && pid != lane.expectedPid) {
					throw new IOException("Ordered stock decompiler lost its process history between requests");
				}
				if (pid > 0) {
					JsonObject attach = new JsonObject();
					attach.addProperty("lease", lease);
					attach.addProperty("pid", pid);
					watched = engine.call("sched.attach", attach).get("attached").getAsBoolean();
				}
				int timeout = limits.timeoutSeconds() + (lane == null ? BACKSTOP_SECONDS : 0);
				if (!watched) {
					throw new IOException("cannot watch decompiler process memory");
				}
				traced = decompiler.decompileAttached(function, timeout, monitor, pid, recordQueries);
				if (lane != null) {
					// A completed stock request may dispose its own process, e.g. after an I/O
					// failure. Only in that case may the next call perform Ghidra's normal restart.
					lane.expectedPid = decompiler.readyProcessId();
				}
			}
			finally {
				// Once a process is reused, its old lease must no longer watch or kill
				// that PID. Await release before making the process available again.
				try {
					ended = release(lease);
				}
				catch (IOException failure) {
					releaseFailure = failure;
					throw failure;
				}
				finally {
					// Wake any borrower waiting for the handoff, even after a failed
					// release. checkPool() prevents it from touching that process.
					if (lane == null) {
						idle.add(decompiler);
					}
				}
			}
			return new Run(traced, ended.get("status").getAsString(), stopReason.get(),
				grant.get("waited_ms").getAsLong(), ended.get("run_ms").getAsLong(),
				ended.get("peak_resident_bytes").getAsLong(), ended.get("killed").getAsBoolean(),
				watched);
		}
		finally {
			outer.removeCancelledListener(forward);
			engine.forgetLease(lease);
		}
	}

	private void checkPool() throws IOException {
		if (releaseFailure != null) {
			throw new IOException("decompiler pool retired because native process ownership could not be confirmed",
				releaseFailure);
		}
	}

	private void abandonGrant(String lease, CompletableFuture<JsonObject> pending, Runnable cancel) {
		cancel.run();
		// Cancellation can race a grant. Release any slot granted to this waiter.
		pending.thenAccept(grant -> {
			if (grant.get("granted").getAsBoolean()) {
				engine.send("sched.release", leaseRequest(lease));
			}
		});
	}

	private JsonObject awaitGrant(String lease, CompletableFuture<JsonObject> pending,
			TaskMonitor outer, Runnable cancel) throws IOException {
		while (true) {
			if (releaseFailure != null) {
				abandonGrant(lease, pending, cancel);
				checkPool();
			}
			if (outer.isCancelled()) {
				cancel.run();
			}
			try {
				return pending.get(100, TimeUnit.MILLISECONDS);
			}
			catch (TimeoutException waiting) {
				// Check cancellation again while the engine queues this request.
			}
			catch (InterruptedException exception) {
				abandonGrant(lease, pending, cancel);
				Thread.currentThread().interrupt();
				throw new IOException("interrupted while waiting for a lease", exception);
			}
			catch (ExecutionException exception) {
				throw new IOException("lease request failed", exception.getCause());
			}
		}
	}

	private JsonObject release(String lease) throws IOException {
		CompletableFuture<JsonObject> pending = engine.send("sched.release", leaseRequest(lease));
		long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(60);
		boolean interrupted = Thread.interrupted();
		try {
			while (true) {
				try {
					long remaining = deadline - System.nanoTime();
					if (remaining <= 0) {
						throw new TimeoutException();
					}
					return pending.get(remaining, TimeUnit.NANOSECONDS);
				}
				catch (InterruptedException exception) {
					// Complete ownership cleanup, then restore the caller's interrupt.
					interrupted = true;
				}
				catch (ExecutionException exception) {
					throw new IOException("lease release failed", exception.getCause());
				}
				catch (TimeoutException exception) {
					throw new IOException("engine did not release lease within 60 seconds", exception);
				}
			}
		}
		finally {
			if (interrupted) {
				Thread.currentThread().interrupt();
			}
		}
	}

	private static JsonObject leaseRequest(String lease) {
		JsonObject request = new JsonObject();
		request.addProperty("lease", lease);
		return request;
	}

	@Override
	public void close() {
		for (TracingDecompiler decompiler : all) {
			decompiler.dispose();
		}
		all.clear();
		idle.clear();
	}
}
