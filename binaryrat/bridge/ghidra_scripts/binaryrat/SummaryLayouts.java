// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package binaryrat;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import generic.hash.HashUtilities;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.util.task.TaskMonitor;

/**
 * Summary-based layout evidence, shared by the headless script, PyGhidra and the live
 * service. Each reached (function, pointer parameter) is decompiled once and summarized; the
 * engine's {@code types.solve} op propagates the summaries along calls that pass the parameter
 * plus an exact constant, through cycles, without a depth limit. Read-only: the Program's
 * modification number is checked around every step and any change fails the run.
 */
public final class SummaryLayouts {
	public static final String ANALYSIS_MODE = "read_only_summary_layout_evidence";
	public static final int DEFAULT_SUMMARIES = 32;
	public static final int MAXIMUM_SUMMARIES = 256;
	public static final int MAXIMUM_TIMEOUT_SECONDS = 600;
	private static final long MAXIMUM_FUNCTION_BYTES = 65_536;
	private static final int MAXIMUM_EDGES = 1_024;
	private static final int MAXIMUM_REFUSED_CALLS = 1_024;
	private static final int MAXIMUM_TOTAL_OPS = 8 * LayoutEvidence.MAXIMUM_OPS;
	private static final int MAXIMUM_SOLVER_STATES = 4_096;
	private static final String UNSUPPORTED_PARAMETER =
		"callee parameter is not a pointer-sized default-prototype register input";

	private record Key(Address entry, int parameter) {
	}

	private record Summary(String id, Function function, int parameter, Address storage,
			JsonArray accesses, List<LayoutEvidence.SummaryCall> calls, String callRefusal) {
	}

	private SummaryLayouts() {
	}

	/** Whether a function can be summarized: local, not a thunk, initialized, at most 64 KiB. */
	public static boolean supportedFunction(Program program, Function function) {
		if (function == null || function.isExternal() || function.isThunk()) {
			return false;
		}
		MemoryBlock block = program.getMemory().getBlock(function.getEntryPoint());
		long size = function.getBody().getNumAddresses();
		return block != null && !block.isExternalBlock() && block.isInitialized() &&
			size > 0 && size <= MAXIMUM_FUNCTION_BYTES;
	}

	/** Recovers a report and returns it as JSON text (for PyGhidra callers). */
	public static String recoverJson(Program program, Function function, int parameter,
			int timeoutSeconds, int maximumSummaries, TaskMonitor monitor) throws Exception {
		return new GsonBuilder().serializeNulls().create()
			.toJson(recover(program, function, parameter, timeoutSeconds, maximumSummaries, monitor));
	}

	/**
	 * Recovers summary layout evidence for one analyst-selected pointer parameter. The engine
	 * runs in a private temporary directory that is removed afterwards.
	 */
	public static JsonObject recover(Program program, Function function, int parameter,
			int timeoutSeconds, int maximumSummaries, TaskMonitor monitor) throws Exception {
		if (parameter < 0) {
			throw new IllegalArgumentException("parameter index must be nonnegative");
		}
		if (timeoutSeconds < 1 || timeoutSeconds > MAXIMUM_TIMEOUT_SECONDS) {
			throw new IllegalArgumentException("timeout must be 1-600 seconds");
		}
		if (maximumSummaries < 1 || maximumSummaries > MAXIMUM_SUMMARIES) {
			throw new IllegalArgumentException("summary limit must be between 1 and " + MAXIMUM_SUMMARIES);
		}
		if (!supportedFunction(program, function) || function.getProgram() != program) {
			throw new IOException("select a local non-thunk function within the 64 KiB body limit");
		}
		Path workspace = Files.createTempDirectory("binaryrat-summary-");
		try {
			return new Run(program, monitor, maximumSummaries).recover(workspace, function, parameter,
				timeoutSeconds);
		}
		finally {
			try (Stream<Path> files = Files.walk(workspace)) {
				for (Path file : (Iterable<Path>) files.sorted(Comparator.reverseOrder())::iterator) {
					Files.deleteIfExists(file);
				}
			}
			catch (IOException | UncheckedIOException leftover) {
				// A scanner can still hold a temporary file; the finished result matters more.
			}
		}
	}

	/** State of one recovery; never shared between threads. */
	private static final class Run {
		private final Program program;
		private final TaskMonitor monitor;
		private final int maximumSummaries;
		private final long revision;
		private final String programId;
		private int decompileAttempts;
		private int pcodeOps;
		private int unresolved;
		private int accessRows;

		Run(Program program, TaskMonitor monitor, int maximumSummaries) throws Exception {
			this.program = program;
			this.monitor = monitor;
			this.maximumSummaries = maximumSummaries;
			this.revision = program.getModificationNumber();
			String hash = program.getExecutableSHA256();
			if (hash == null || !hash.matches("[0-9a-fA-F]{64}")) {
				throw new IOException("layout evidence requires a valid executable SHA-256");
			}
			this.programId = "sha256:" + hash.toLowerCase(Locale.ROOT);
			checkCurrent();
		}

		JsonObject recover(Path workspace, Function function, int parameter, int timeout)
				throws Exception {
			try (EngineClient engine = EngineClient.start(EngineClient.findExecutable(), workspace)) {
				checkCurrent();
				var limits = new ScheduledDecompiler.Limits(1, reserve("BINARYRAT_WORKER_BYTES", 768L << 20),
					Runtime.getRuntime().maxMemory(), reserve("BINARYRAT_OTHER_RESERVE_BYTES", 512L << 20),
					timeout, 5_000, timeout * 1_000L);
				Map<Key, Summary> summaries = new LinkedHashMap<>();
				JsonArray edges = new JsonArray();
				JsonArray refused = new JsonArray();
				JsonArray variable = new JsonArray();
				Summary root;
				try (ScheduledDecompiler decompiler = new ScheduledDecompiler(engine, program,
						this::configure, limits)) {
					root = summarize(decompiler, function, parameter, true, variable);
					summaries.put(new Key(function.getEntryPoint(), parameter), root);
					traverse(decompiler, root, summaries, edges, refused, variable);
				}
				checkCurrent();
				JsonObject solved = engine.call("types.solve", solveRequest(root, summaries, edges));
				JsonObject solution = solved.getAsJsonArray("roots").get(0).getAsJsonObject();
				if (!"solved".equals(solution.get("status").getAsString())) {
					throw new IOException("summary solution exceeds the solver limit: " +
						solution.get("status").getAsString());
				}
				checkCurrent();
				return report(function, parameter, root, summaries, edges, refused, variable, solved,
					solution);
			}
		}

		private static JsonObject solveRequest(Summary root, Map<Key, Summary> summaries,
				JsonArray edges) {
			JsonArray summaryInput = new JsonArray();
			for (Summary summary : summaries.values()) {
				JsonObject item = new JsonObject();
				item.addProperty("id", summary.id());
				item.add("accesses", summary.accesses());
				summaryInput.add(item);
			}
			JsonObject rootRequest = new JsonObject();
			rootRequest.addProperty("summary", root.id());
			rootRequest.addProperty("object_id", root.id());
			JsonArray roots = new JsonArray();
			roots.add(rootRequest);
			JsonObject request = new JsonObject();
			request.add("summaries", summaryInput);
			request.add("edges", edges);
			request.add("roots", roots);
			request.addProperty("maximum_extent", LayoutEvidence.MAXIMUM_EXTENT);
			request.addProperty("maximum_states", MAXIMUM_SOLVER_STATES);
			request.addProperty("maximum_derived", LayoutEvidence.MAXIMUM_ACCESSES);
			return request;
		}

		private JsonObject report(Function function, int parameter, Summary root,
				Map<Key, Summary> summaries, JsonArray edges, JsonArray refused, JsonArray variable,
				JsonObject solved, JsonObject solution) {
			JsonObject target = new JsonObject();
			Address entry = function.getEntryPoint();
			target.addProperty("address_space", entry.getAddressSpace().getName());
			target.addProperty("address", hex(entry));
			target.addProperty("name", function.getName(true));
			JsonObject report = new JsonObject();
			report.addProperty("schema_version", 1);
			report.addProperty("analysis_mode", ANALYSIS_MODE);
			report.addProperty("assumption", "analyst_selected_object_start");
			report.addProperty("score_kind", solved.get("score_kind").getAsString());
			report.add("function", target);
			report.addProperty("revision", revision);
			report.addProperty("program_id", programId);
			report.addProperty("language_id", program.getLanguageID().toString());
			report.addProperty("compiler_spec_id", program.getCompilerSpec().getCompilerSpecID().toString());
			report.addProperty("parameter_index", parameter);
			report.addProperty("object_id", root.id());
			report.addProperty("summary_limit", maximumSummaries);
			report.addProperty("decompile_attempts", decompileAttempts);
			report.addProperty("pcode_ops", pcodeOps);
			report.addProperty("unresolved_accesses", unresolved);
			JsonArray records = new JsonArray();
			for (Summary summary : summaries.values()) {
				records.add(summaryRecord(summary));
			}
			report.add("summaries", records);
			report.add("edges", edges);
			report.add("refused_calls", refused);
			report.add("variable_accesses", variable);
			report.add("components", solved.getAsJsonArray("components"));
			report.add("solution", solution);
			return report;
		}

		private void traverse(ScheduledDecompiler decompiler, Summary root, Map<Key, Summary> summaries,
				JsonArray edges, JsonArray refused, JsonArray variable) throws Exception {
			Map<Key, String> refusedTargets = new HashMap<>();
			// A summary is expanded only once an accepted edge reaches it.
			Set<String> expanded = new HashSet<>();
			var pending = new ArrayDeque<Summary>();
			pending.add(root);
			expanded.add(root.id());
			while (!pending.isEmpty()) {
				Summary caller = pending.removeFirst();
				for (LayoutEvidence.SummaryCall call : caller.calls()) {
					checkCurrent();
					Key key = new Key(call.callee(), call.argumentIndex());
					Summary callee = summaries.get(key);
					String refusal = refusedTargets.get(key);
					if (callee == null && refusal == null) {
						Function target = program.getFunctionManager().getFunctionAt(call.callee());
						if (!supportedFunction(program, target)) {
							refusal = "callee is missing, external, a thunk, uninitialized or above 64 KiB";
						}
						else {
							if (summaries.size() >= maximumSummaries) {
								throw new IOException("summary traversal exceeds the summary limit of " +
									maximumSummaries);
							}
							callee = summarize(decompiler, target, key.parameter(), false, variable);
							if (callee == null) {
								refusal = UNSUPPORTED_PARAMETER;
							}
						}
						if (refusal != null) {
							refusedTargets.put(key, refusal);
						}
						else {
							summaries.put(key, callee);
						}
					}
					if (callee != null && callee.storage() == null) {
						// Only the root can lack register storage: it is summarized regardless.
						refusal = UNSUPPORTED_PARAMETER;
					}
					if (refusal != null) {
						if (refused.size() >= MAXIMUM_REFUSED_CALLS) {
							throw new IOException("summary traversal exceeds the refused call limit");
						}
						refused.add(callRecord(caller, call, refusal));
						continue;
					}
					if (edges.size() >= MAXIMUM_EDGES) {
						throw new IOException("summary traversal exceeds the forwarding edge limit");
					}
					JsonObject edge = callRecord(caller, call, null);
					edge.addProperty("caller", caller.id());
					edge.addProperty("callee", callee.id());
					edges.add(edge);
					if (expanded.add(callee.id())) {
						pending.addLast(callee);
					}
				}
			}
		}

		/** Decompiles and summarizes one parameter, or returns null if it cannot be followed. */
		private Summary summarize(ScheduledDecompiler decompiler, Function function, int parameter,
				boolean root, JsonArray variable) throws Exception {
			if (++decompileAttempts > 2 * maximumSummaries) {
				throw new IOException("summary traversal exceeds the decompilation attempt limit");
			}
			HighFunction high = readHighFunction(decompiler, function);
			Address storage = LayoutEvidence.parameterStorage(program, high, parameter);
			if (!root && storage == null) {
				return null;
			}
			if (pcodeOps >= MAXIMUM_TOTAL_OPS) {
				throw new IOException("summary traversal exceeds the total p-code operation limit");
			}
			var capture = LayoutEvidence.collect(program, high, parameter, false, monitor,
				MAXIMUM_TOTAL_OPS - pcodeOps);
			var calls = LayoutEvidence.summaryCalls(program, high, parameter, monitor);
			pcodeOps += capture.pcodeOps();
			unresolved += capture.unresolvedAccesses();
			accessRows += capture.accesses().size();
			if (accessRows > LayoutEvidence.MAXIMUM_ACCESSES) {
				throw new IOException("summary traversal exceeds the total evidence limit");
			}
			Address entry = function.getEntryPoint();
			String id = programId + "/" + entry.getAddressSpace().getName() + "/" + hex(entry) +
				"/param/" + parameter;
			JsonArray accesses = new JsonArray();
			for (LayoutEvidence.Access access : capture.accesses()) {
				monitor.checkCancelled();
				JsonObject row = accessRecord(id, access);
				if (access.offset() != access.maximumOffset()) {
					// A range is not an observed field: kept for review, never solved.
					row.addProperty("summary", id);
					variable.add(row);
				}
				else {
					accesses.add(row);
				}
			}
			return new Summary(id, function, parameter, storage, accesses, calls.calls(), calls.refusal());
		}

		private JsonObject accessRecord(String summary, LayoutEvidence.Access access) {
			JsonObject row = new JsonObject();
			Address site = access.address();
			boolean exact = access.offset() == access.maximumOffset();
			if (exact) {
				row.addProperty("offset", access.offset());
			}
			else {
				row.addProperty("minimum_offset", access.offset());
				row.addProperty("maximum_offset", access.maximumOffset());
				row.addProperty("stride", access.stride());
			}
			row.addProperty("width", access.width());
			row.addProperty("evidence_id", summary + "/" + site.getAddressSpace().getName() + "/" +
				hex(site) + "/" + access.pcodeOrder());
			var use = access.typedUse();
			if (exact && use != null) {
				row.addProperty("storage_view", use.kind());
				JsonObject typedUse = new JsonObject();
				typedUse.addProperty("address_space", use.address().getAddressSpace().getName());
				typedUse.addProperty("address", hex(use.address()));
				typedUse.addProperty("pcode_order", use.pcodeOrder());
				typedUse.addProperty("operation", use.operation());
				addInstructionDigest(typedUse, use.address());
				row.add("typed_use", typedUse);
			}
			row.addProperty("address_space", site.getAddressSpace().getName());
			row.addProperty("address", hex(site));
			row.addProperty("pcode_order", access.pcodeOrder());
			row.addProperty("operation", access.operation());
			addInstructionDigest(row, site);
			return row;
		}

		private JsonObject callRecord(Summary caller, LayoutEvidence.SummaryCall call, String refusal) {
			JsonObject record = new JsonObject();
			record.addProperty("offset", call.offset());
			record.addProperty("evidence_id", caller.id() + "/call/" +
				call.address().getAddressSpace().getName() + "/" + hex(call.address()) + "/" +
				call.pcodeOrder() + "/arg/" + call.argumentIndex());
			record.addProperty("address_space", call.address().getAddressSpace().getName());
			record.addProperty("address", hex(call.address()));
			record.addProperty("pcode_order", call.pcodeOrder());
			record.addProperty("callee_address_space", call.callee().getAddressSpace().getName());
			record.addProperty("callee_address", hex(call.callee()));
			record.addProperty("argument_index", call.argumentIndex());
			record.addProperty("argument_value_storage", call.argumentStorage().toString());
			addInstructionDigest(record, call.address());
			if (refusal != null) {
				record.addProperty("caller", caller.id());
				record.addProperty("reason", refusal);
			}
			return record;
		}

		private static JsonObject summaryRecord(Summary summary) {
			JsonObject record = new JsonObject();
			Address entry = summary.function().getEntryPoint();
			record.addProperty("id", summary.id());
			record.addProperty("function_address_space", entry.getAddressSpace().getName());
			record.addProperty("function_address", hex(entry));
			record.addProperty("function_name", summary.function().getName(true));
			record.addProperty("parameter_index", summary.parameter());
			record.addProperty("parameter_storage",
				summary.storage() == null ? null : summary.storage().toString());
			record.addProperty("call_refusal", summary.callRefusal());
			record.add("accesses", summary.accesses());
			return record;
		}

		private HighFunction readHighFunction(ScheduledDecompiler decompiler, Function function)
				throws Exception {
			ScheduledDecompiler.Run run = decompiler.decompileUntraced(function, monitor);
			checkCurrent();
			if (!"completed".equals(run.status()) || !run.memoryWatched()) {
				throw new IOException("layout decompilation did not complete under a memory-watched lease: " +
					run.status());
			}
			DecompileResults decompiled = run.traced() == null ? null : run.traced().results();
			if (decompiled == null || !decompiled.decompileCompleted() ||
					decompiled.getHighFunction() == null) {
				throw new IOException("unable to read high p-code: " +
					(decompiled == null ? "no results" : decompiled.getErrorMessage()));
			}
			return decompiled.getHighFunction();
		}

		private void addInstructionDigest(JsonObject row, Address site) {
			var instruction = program.getListing().getInstructionAt(site);
			if (instruction == null) {
				return;
			}
			int length = instruction.getParsedLength();
			if (length <= 0 || length > MAXIMUM_FUNCTION_BYTES) {
				return;
			}
			try {
				byte[] bytes = instruction.getParsedBytes();
				if (bytes.length == length) {
					row.addProperty("instruction_sha256", HashUtilities.getHash("SHA-256", bytes));
				}
			}
			catch (MemoryAccessException unavailable) {
				// Some synthetic p-code sites have no readable instruction bytes.
			}
		}

		private void configure(DecompInterface decompiler) {
			DecompileOptions options = new DecompileOptions();
			options.grabFromProgram(program);
			options.setMaxPayloadMBytes(Math.min(options.getMaxPayloadMBytes(), 8));
			options.setMaxInstructions(Math.min(options.getMaxInstructions(), 16_384));
			decompiler.setOptions(options);
			decompiler.setSimplificationStyle("decompile");
			decompiler.toggleCCode(false);
			decompiler.toggleSyntaxTree(true);
		}

		private void checkCurrent() throws Exception {
			monitor.checkCancelled();
			if (program.isClosed() || revision != program.getModificationNumber()) {
				throw new IllegalStateException("Program changed during layout evidence extraction");
			}
		}
	}

	private static long reserve(String name, long fallback) {
		String configured = System.getenv(name);
		long value = configured == null || configured.isBlank() ? fallback : Long.parseLong(configured);
		if (value < 0) {
			throw new IllegalArgumentException(name + " must be nonnegative");
		}
		return value;
	}

	private static String hex(Address address) {
		return Long.toUnsignedString(address.getOffset(), 16);
	}
}
