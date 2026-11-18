// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package binaryrat;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;
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
		String lease = "f" + leases.incrementAndGet();
		TaskMonitorAdapter monitor = new TaskMonitorAdapter(true);
		AtomicReference<String> stopReason = new AtomicReference<>();
		engine.onLease(lease, event -> {
			if ("lease.stop".equals(event.get("event").getAsString())) {
				stopReason.compareAndSet(null, event.get("reason").getAsString());
				monitor.cancel();
			}
		});
		CancelledListener forward = monitor::cancel;
		outer.addCancelledListener(forward);
		try {
			JsonObject request = new JsonObject();
			request.addProperty("lease", lease);
			request.addProperty("reserve_bytes", limits.workerBytes());
			request.addProperty("timeout_ms", limits.leaseTimeoutMillis());
			CompletableFuture<JsonObject> pending = engine.send("sched.acquire", request);
			JsonObject grant = awaitGrant(lease, pending, outer);
			if (!grant.get("granted").getAsBoolean()) {
				return new Run(null, grant.get("status").getAsString(), null, 0, 0, 0, false, false);
			}
			TracingDecompiler decompiler = idle.poll();
			if (decompiler == null) {
				release(lease);
				throw new IOException("engine granted more leases than decompilers");
			}
			TracingDecompiler.Traced traced;
			boolean watched = false;
			JsonObject ended;
			try {
				long pid = decompiler.processId();
				if (pid > 0) {
					JsonObject attach = new JsonObject();
					attach.addProperty("lease", lease);
					attach.addProperty("pid", pid);
					watched = engine.call("sched.attach", attach).get("attached").getAsBoolean();
				}
				traced = decompiler.decompile(function,
					limits.timeoutSeconds() + BACKSTOP_SECONDS, monitor);
			}
			finally {
				// Hand the decompiler back before the lease, so the next grant finds it.
				idle.add(decompiler);
				ended = release(lease);
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

	private JsonObject awaitGrant(String lease, CompletableFuture<JsonObject> pending,
			TaskMonitor outer) throws IOException {
		boolean cancelSent = false;
		while (true) {
			try {
				return pending.get(100, TimeUnit.MILLISECONDS);
			}
			catch (TimeoutException waiting) {
				if (outer.isCancelled() && !cancelSent) {
					JsonObject cancel = new JsonObject();
					cancel.addProperty("lease", lease);
					engine.send("sched.cancel", cancel);
					cancelSent = true;
				}
			}
			catch (InterruptedException exception) {
				Thread.currentThread().interrupt();
				throw new IOException("interrupted while waiting for a lease", exception);
			}
			catch (ExecutionException exception) {
				throw new IOException("lease request failed", exception.getCause());
			}
		}
	}

	private JsonObject release(String lease) throws IOException {
		JsonObject request = new JsonObject();
		request.addProperty("lease", lease);
		return engine.call("sched.release", request);
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
