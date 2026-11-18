// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package binaryrat;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import com.google.gson.JsonObject;

import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.CancelledListener;
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

	public ScheduledDecompiler(EngineClient engine, Program program,
			Consumer<DecompInterface> configure, Limits limits) throws IOException {
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
		catch (IOException | RuntimeException exception) {
			close();
			throw exception;
		}
	}

	public int workers() {
		return workers;
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
		return decompile(function, outer, true);
	}

	/** Runs without collecting query traces. Requires the engine to watch process memory. */
	public Run decompileUntraced(Function function, TaskMonitor outer) throws IOException {
		return decompile(function, outer, false);
	}

	private Run decompile(Function function, TaskMonitor outer, boolean recordQueries)
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
				decompiler = idle.take();
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
				long pid = decompiler.processId();
				if (pid > 0) {
					JsonObject attach = new JsonObject();
					attach.addProperty("lease", lease);
					attach.addProperty("pid", pid);
					watched = engine.call("sched.attach", attach).get("attached").getAsBoolean();
				}
				int timeout = limits.timeoutSeconds() + BACKSTOP_SECONDS;
				if (!watched) {
					throw new IOException("cannot watch decompiler process memory");
				}
				traced = decompiler.decompileAttached(function, timeout, monitor, pid, recordQueries);
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
					idle.add(decompiler);
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
			throw new IOException("decompiler pool retired after an unacknowledged lease release",
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
