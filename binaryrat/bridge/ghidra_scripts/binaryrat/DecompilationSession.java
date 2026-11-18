// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0

package binaryrat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.IdentityHashMap;
import java.util.List;

import com.google.gson.JsonObject;

import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Read-only access to the native BinaryRat scheduler and decompilation cache.
 * Compatible sessions in one JVM share the same Program, pool, cache and admission queue.
 * A session observes one Program revision. Reopen it after edits or auto-analysis.
 * Call from a worker, pass a cancellable monitor, and close the handle when done.
 */
public final class DecompilationSession implements AutoCloseable {
	public static final int DEFAULT_WORKERS = 4;
	public static final int DEFAULT_TIMEOUT_SECONDS = 60;

	private static final IdentityHashMap<Program, List<Backend>> OPEN = new IdentityHashMap<>();

	private record Options(int workers, int timeout, boolean syntaxTree, Path cache) {}

	/** Output and the corresponding cache lookup and lease, for export diagnostics. */
	public record Result(DecompOutput output, ScheduledDecompiler.Run lease,
			LiveDecompileCache.Lookup lookup, boolean stored, String storeRejection) {}

	private final Backend backend;
	private boolean closed;

	private DecompilationSession(Backend backend) {
		this.backend = backend;
	}

	public static DecompilationSession open(Program program, int workers, int timeoutSeconds)
			throws IOException {
		return open(program, workers, timeoutSeconds, true);
	}

	public static DecompilationSession open(Program program, int workers, int timeoutSeconds,
			boolean syntaxTree) throws IOException {
		if (program == null || workers < 1 || workers > 256 ||
				timeoutSeconds < 1 || timeoutSeconds > 86_400) {
			throw new IllegalArgumentException("Expected a Program, 1–256 workers and timeout 1–86400 seconds");
		}
		String configured = System.getenv("BINARYRAT_CACHE_DIR");
		Path cache = configured == null || configured.isBlank() ? null :
			Path.of(configured).toAbsolutePath().normalize();
		var options = new Options(workers, timeoutSeconds, syntaxTree, cache);
		synchronized (OPEN) {
			var existing = OPEN.get(program);
			long revision = program.getModificationNumber();
			if (existing != null) {
				for (Backend backend : existing) {
					if (backend.revision == revision && backend.options.equals(options)) {
						backend.checkEpoch();
						backend.references++;
						return new DecompilationSession(backend);
					}
				}
			}
			if (cache != null && OPEN.values().stream().flatMap(List::stream)
					.anyMatch(backend -> cache.equals(backend.options.cache()))) {
				throw new IOException("BINARYRAT_CACHE_DIR already serves another Program, revision, or " +
					"decompilation configuration. Close that session before opening another");
			}
			Backend backend = create(program, revision, options);
			OPEN.computeIfAbsent(program, ignored -> new ArrayList<>()).add(backend);
			return new DecompilationSession(backend);
		}
	}

	/** Reuses the call's cancellation monitor for both queue waiting and native decompilation. */
	public DecompOutput decompile(Function function, TaskMonitor monitor)
			throws IOException, CancelledException {
		return decompileWithMetrics(function, monitor).output();
	}

	/** Enters before queued batch requests. Running requests retain their leases. */
	public DecompOutput decompileForeground(Function function, TaskMonitor monitor)
			throws IOException, CancelledException {
		return decompileForegroundWithMetrics(function, monitor).output();
	}

	public Result decompileForegroundWithMetrics(Function function, TaskMonitor monitor)
			throws IOException, CancelledException {
		return decompile(function, monitor, true);
	}

	public Result decompileWithMetrics(Function function, TaskMonitor monitor)
			throws IOException, CancelledException {
		return decompile(function, monitor, false);
	}

	private Result decompile(Function function, TaskMonitor monitor, boolean foreground)
			throws IOException, CancelledException {
		try (var use = retain()) {
			monitor.checkCancelled();
			backend.checkEpoch();
			if (function == null || function.getProgram() != backend.program || function.isExternal() ||
					!function.equals(backend.program.getFunctionManager().getFunctionAt(function.getEntryPoint()))) {
				throw new IllegalArgumentException("Expected a current local function from this Program");
			}
			backend.queue.enter(foreground, monitor);
			try {
				return backend.run(function, monitor);
			}
			finally {
				backend.queue.leave();
			}
		}
	}

	public int workers() {
		return backend.scheduler.workers();
	}

	public boolean cacheEnabled() {
		return backend.cache != null;
	}

	public JsonObject configuration() {
		return backend.scheduler.configuration();
	}

	public JsonObject stats() throws IOException {
		try (var use = retain()) {
			return backend.scheduler.stats();
		}
	}

	public JsonObject cacheStats() throws IOException {
		try (var use = retain()) {
			return backend.cache == null ? null : backend.cache.stats();
		}
	}

	/** Requests pin the backend so a concurrent close cannot dispose a running decompiler. */
	private DecompilationSession retain() throws IOException {
		synchronized (OPEN) {
			if (closed) {
				throw new IOException("BinaryRat decompilation session is closed");
			}
			backend.references++;
			return new DecompilationSession(backend);
		}
	}

	@Override
	public void close() throws IOException {
		synchronized (OPEN) {
			if (closed) {
				return;
			}
			closed = true;
			if (--backend.references == 0) {
				var backends = OPEN.get(backend.program);
				backends.remove(backend);
				if (backends.isEmpty()) {
					OPEN.remove(backend.program);
				}
				// The engine releases its directory lock before another open can use it.
				backend.close();
			}
		}
	}

	private static Backend create(Program program, long revision, Options options) throws IOException {
		Object consumer = new Object();
		if (!program.addConsumer(consumer)) {
			throw new IOException("Program closed before the decompilation session started");
		}
		Path directory = options.cache();
		EngineClient engine = null;
		ScheduledDecompiler scheduler = null;
		ChangeTracker tracker = null;
		try {
			AutoAnalysisManager analysis = AutoAnalysisManager.getAnalysisManager(program);
			if (analysis.isAnalyzing()) {
				throw new IOException("Auto-analysis is running. Wait for analysis to finish before decompiling");
			}
			String executableHash = program.getExecutableSHA256();
			if (directory != null && (executableHash == null || !executableHash.matches("[0-9a-fA-F]{64}"))) {
				throw new IOException("Persistent caching requires an executable SHA-256; " +
					"a Program name is not a safe cross-session identity");
			}
			if (directory == null) {
				directory = Files.createTempDirectory("binaryrat-engine-");
			}
			engine = EngineClient.start(EngineClient.findExecutable(), directory);
			int timeout = options.timeout();
			var limits = new ScheduledDecompiler.Limits(options.workers(),
				environment("BINARYRAT_WORKER_BYTES", 768L << 20), Runtime.getRuntime().maxMemory(),
				environment("BINARYRAT_OTHER_RESERVE_BYTES", 512L << 20), timeout,
				environment("BINARYRAT_KILL_GRACE_MS", 5000),
				environment("BINARYRAT_LEASE_TIMEOUT_MS", timeout * 1_000L));
			scheduler = new ScheduledDecompiler(engine, program, decompiler -> {
				DecompileOptions decompileOptions = new DecompileOptions();
				decompileOptions.grabFromProgram(program);
				decompiler.setOptions(decompileOptions);
				decompiler.setSimplificationStyle("decompile");
				decompiler.toggleCCode(true);
				decompiler.toggleSyntaxTree(options.syntaxTree());
			}, limits);
			if (scheduler.workers() < 1) {
				throw new IOException("The memory budget admits no native decompiler workers. " +
					"Reduce the JVM heap or adjust the BinaryRat memory reservations");
			}
			LiveDecompileCache cache = null;
			if (options.cache() != null) {
				tracker = new ChangeTracker(program, engine);
				var sample = scheduler.sample();
				cache = new LiveDecompileCache(engine, program, tracker, sample.getOptions(),
					"sha256:" + executableHash, sample.registrationDigest());
			}
			var backend = new Backend(program, revision, options, analysis, consumer, directory,
				engine, scheduler, tracker, cache);
			backend.checkEpoch();
			return backend;
		}
		catch (IOException | RuntimeException | Error failure) {
			try {
				cleanup(program, consumer, engine, scheduler, tracker,
					options.cache() == null ? directory : null);
			}
			catch (IOException | RuntimeException cleanupFailure) {
				failure.addSuppressed(cleanupFailure);
			}
			throw failure;
		}
	}

	private static long environment(String name, long fallback) {
		String value = System.getenv(name);
		long parsed = value == null || value.isBlank() ? fallback : Long.parseLong(value.trim());
		if (parsed < 0) {
			throw new IllegalArgumentException(name + " must not be negative");
		}
		return parsed;
	}

	private static void cleanup(Program program, Object consumer, EngineClient engine,
			ScheduledDecompiler scheduler, ChangeTracker tracker, Path temporary) throws IOException {
		// Resources borrowed by the cache close before the engine and Program owners.
		try (EngineClient ignoredEngine = engine;
			 ScheduledDecompiler ignoredScheduler = scheduler;
			 ChangeTracker ignoredTracker = tracker) {
			// Close in reverse declaration order.
		}
		finally {
			try {
				if (temporary != null) {
					try (var paths = Files.walk(temporary)) {
						for (Path path : (Iterable<Path>) paths.sorted(Comparator.reverseOrder())::iterator) {
							Files.deleteIfExists(path);
						}
					}
				}
			}
			finally {
				program.release(consumer);
			}
		}
	}

	private static final class Backend implements AutoCloseable {
		final Program program;
		final long revision;
		final Options options;
		final AutoAnalysisManager analysis;
		final Object consumer;
		final Path directory;
		final EngineClient engine;
		final ScheduledDecompiler scheduler;
		final ChangeTracker tracker;
		final LiveDecompileCache cache;
		final AdmissionQueue queue;
		int references = 1;

		Backend(Program program, long revision, Options options, AutoAnalysisManager analysis,
				Object consumer, Path directory, EngineClient engine, ScheduledDecompiler scheduler,
				ChangeTracker tracker, LiveDecompileCache cache) {
			this.program = program;
			this.revision = revision;
			this.options = options;
			this.analysis = analysis;
			this.consumer = consumer;
			this.directory = directory;
			this.engine = engine;
			this.scheduler = scheduler;
			this.tracker = tracker;
			this.cache = cache;
			queue = new AdmissionQueue(scheduler.workers());
		}

		void checkEpoch() throws IOException {
			if (program.isClosed() || revision != program.getModificationNumber() || analysis.isAnalyzing()) {
				throw new IOException("Program changed or is being analyzed. Open a fresh BinaryRat session");
			}
		}

		Result run(Function function, TaskMonitor monitor) throws IOException, CancelledException {
			monitor.checkCancelled();
			checkEpoch();
			LiveDecompileCache.Lookup lookup = cache == null ? null : cache.lookup(function, false);
			monitor.checkCancelled();
			checkEpoch();
			if (lookup != null && lookup.usable()) {
				return new Result(lookup.output(), null, lookup, false, null);
			}
			var lease = cache == null ? scheduler.decompileUntraced(function, monitor) :
				scheduler.decompile(function, monitor);
			monitor.checkCancelled();
			checkEpoch();
			if (lease.traced() == null) {
				var output = new DecompOutput(false, false, true, false,
					"BinaryRat: the engine did not grant a lease (" + lease.status() + ")", "", "");
				return new Result(output, lease, lookup, false,
					"no traced decompilation (lease " + lease.status() + ")");
			}
			var output = DecompOutput.stopped(lease.traced().results(), lease.status(), lease.stopReason());
			boolean stored = false;
			String rejection = null;
			if (cache != null) {
				if (!output.cacheable()) {
					rejection = "native output is not cacheable (lease " + lease.status() + ")";
				}
				else if (!lease.traced().trace().replayable()) {
					rejection = "trace is not replayable";
				}
				else {
					stored = cache.store(function, output, lease.traced().trace(), lookup.seq(), revision);
					if (!stored) {
						rejection = "cache entry exceeded storage limits or failed optimistic validation";
					}
				}
			}
			monitor.checkCancelled();
			checkEpoch();
			return new Result(output, lease, lookup, stored, rejection);
		}

		@Override
		public void close() throws IOException {
			cleanup(program, consumer, engine, scheduler, tracker, options.cache() == null ? directory : null);
		}
	}

	/** Bound pending native work so an interactive request can precede queued batch requests. */
	static final class AdmissionQueue {
		private final int capacity;
		private final ArrayDeque<Object> interactive = new ArrayDeque<>();
		private final ArrayDeque<Object> batch = new ArrayDeque<>();
		private int running;

		AdmissionQueue(int capacity) {
			if (capacity < 1) {
				throw new IllegalArgumentException("The admission queue needs an available worker");
			}
			this.capacity = capacity;
		}

		synchronized void enter(boolean foreground, TaskMonitor monitor) throws CancelledException {
			ArrayDeque<Object> queue = foreground ? interactive : batch;
			Object ticket = new Object();
			queue.add(ticket);
			try {
				while (running == capacity || queue.peek() != ticket ||
						(!foreground && !interactive.isEmpty())) {
					monitor.checkCancelled();
					wait(50);
				}
				monitor.checkCancelled();
				running++;
			}
			catch (InterruptedException cancelled) {
				Thread.currentThread().interrupt();
				throw new CancelledException();
			}
			finally {
				queue.remove(ticket);
				notifyAll();
			}
		}

		synchronized void leave() {
			running--;
			notifyAll();
		}
	}
}
