// Propagate read-only layout evidence over direct calls with the engine's summary solver.
// @category BinaryRat
// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
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

import binaryrat.EngineClient;
import binaryrat.LayoutEvidence;
import binaryrat.ScheduledDecompiler;
import generic.hash.HashUtilities;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolType;

/**
 * Headless entrypoint for summary-based layout evidence. Each reached (function, pointer
 * parameter) is decompiled once and summarized; the engine's {@code types.solve} op then
 * propagates the summaries along calls that pass the parameter plus an exact constant,
 * through cycles (strongly connected components) without a depth limit. Read-only.
 */
public class BinaryRatSolveLayouts extends GhidraScript {
	private static final long MAXIMUM_FUNCTION_BYTES = 65_536;
	private static final int MAXIMUM_SYMBOL_MATCHES = 4_096;
	private static final int DEFAULT_SUMMARIES = 32;
	private static final int MAXIMUM_SUMMARIES = 256;
	private static final int MAXIMUM_EDGES = 1_024;
	private static final int MAXIMUM_REFUSED_CALLS = 1_024;
	private static final int MAXIMUM_TOTAL_OPS = 8 * LayoutEvidence.MAXIMUM_OPS;
	private static final int MAXIMUM_SOLVER_STATES = 4_096;
	private long revision;
	private String programId;
	private int decompileAttempts;
	private int pcodeOps;
	private int unresolved;
	private int accessRows;

	private record Key(Address entry, int parameter) {
	}

	private record Summary(String id, Function function, int parameter, Address storage,
			JsonArray accesses, List<LayoutEvidence.SummaryCall> calls, String callRefusal) {
	}

	@Override
	protected void run() throws Exception {
		if (currentProgram == null) {
			throw new IllegalStateException("Open an analyzed Program before solving layout evidence");
		}
		end(true);
		revision = currentProgram.getModificationNumber();
		if (!isRunningHeadless()) {
			throw new IllegalStateException("BinaryRatSolveLayouts.java runs as a headless postScript");
		}
		if (AutoAnalysisManager.getAnalysisManager(currentProgram).isAnalyzing()) {
			throw new IllegalStateException("auto-analysis must finish before layout extraction");
		}
		String[] args = getScriptArgs();
		if (args.length < 3 || args.length > 5) {
			throw new IllegalArgumentException("Use as a headless postScript: BinaryRatSolveLayouts.java " +
				"OUTPUT_JSON ENTRY_HEX|name:FUNCTION PARAM_INDEX [TIMEOUT_SECONDS [MAX_SUMMARIES]]");
		}
		int parameter = Integer.parseInt(args[2]);
		int timeout = args.length >= 4 ? Integer.parseInt(args[3]) : 30;
		int maximumSummaries = args.length == 5 ? Integer.parseInt(args[4]) : DEFAULT_SUMMARIES;
		if (parameter < 0) {
			throw new IllegalArgumentException("parameter index must be nonnegative");
		}
		if (timeout < 1 || timeout > 600) {
			throw new IllegalArgumentException("timeout must be 1-600 seconds");
		}
		if (maximumSummaries < 1 || maximumSummaries > MAXIMUM_SUMMARIES) {
			throw new IllegalArgumentException("summary limit must be between 1 and " + MAXIMUM_SUMMARIES);
		}
		Function function = selectFunction(args[1]);
		if (!supportedFunction(function)) {
			throw new IOException("select a local non-thunk function within the 64 KiB body limit");
		}
		Path output = Path.of(args[0]).toAbsolutePath().normalize();
		if (Files.exists(output, LinkOption.NOFOLLOW_LINKS)) {
			throw new IOException("layout evidence destination already exists: " + output);
		}
		String hash = currentProgram.getExecutableSHA256();
		if (hash == null || !hash.matches("[0-9a-fA-F]{64}")) {
			throw new IOException("layout evidence requires a valid executable SHA-256");
		}
		programId = "sha256:" + hash.toLowerCase(Locale.ROOT);
		checkCurrent();

		Path workspace = Files.createTempDirectory(output.getParent(), ".binaryrat-summary-");
		try {
			JsonObject report = solve(workspace, function, parameter, timeout, maximumSummaries);
			Path staged = workspace.resolve("report.json");
			String content = new GsonBuilder().serializeNulls().setPrettyPrinting().create().toJson(report);
			Files.writeString(staged, content + "\n", StandardCharsets.UTF_8);
			checkCurrent();
			// A hard link publishes the complete report and refuses an existing destination.
			try {
				Files.createLink(output, staged);
			}
			catch (UnsupportedOperationException failure) {
				throw new IOException("layout publication requires hard-link support in the output directory",
					failure);
			}
			println("BinaryRat summary layout evidence written: " + output);
		}
		finally {
			try (Stream<Path> files = Files.walk(workspace)) {
				for (Path file : (Iterable<Path>) files.sorted(Comparator.reverseOrder())::iterator) {
					Files.deleteIfExists(file);
				}
			}
			catch (IOException cleanup) {
				printerr("Unable to clean up temporary layout workspace: " + cleanup.getMessage());
			}
		}
	}

	private JsonObject solve(Path workspace, Function function, int parameter, int timeout,
			int maximumSummaries) throws Exception {
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
			try (ScheduledDecompiler decompiler = new ScheduledDecompiler(engine, currentProgram,
					this::configure, limits)) {
				root = summarize(decompiler, function, parameter, true, maximumSummaries, variable);
				summaries.put(new Key(function.getEntryPoint(), parameter), root);
				traverse(decompiler, root, summaries, edges, refused, variable, maximumSummaries);
			}
			checkCurrent();

			JsonObject request = new JsonObject();
			JsonArray summaryInput = new JsonArray();
			for (Summary summary : summaries.values()) {
				JsonObject item = new JsonObject();
				item.addProperty("id", summary.id());
				item.add("accesses", summary.accesses());
				summaryInput.add(item);
			}
			JsonArray roots = new JsonArray();
			JsonObject rootRequest = new JsonObject();
			rootRequest.addProperty("summary", root.id());
			rootRequest.addProperty("object_id", root.id());
			roots.add(rootRequest);
			request.add("summaries", summaryInput);
			request.add("edges", edges);
			request.add("roots", roots);
			request.addProperty("maximum_extent", LayoutEvidence.MAXIMUM_EXTENT);
			request.addProperty("maximum_states", MAXIMUM_SOLVER_STATES);
			request.addProperty("maximum_derived", LayoutEvidence.MAXIMUM_ACCESSES);
			JsonObject solved = engine.call("types.solve", request);
			JsonObject solution = solved.getAsJsonArray("roots").get(0).getAsJsonObject();
			if (!"solved".equals(solution.get("status").getAsString())) {
				throw new IOException("summary solution exceeds the solver limit: " +
					solution.get("status").getAsString());
			}

			JsonObject target = new JsonObject();
			Address entry = function.getEntryPoint();
			target.addProperty("address_space", entry.getAddressSpace().getName());
			target.addProperty("address", hex(entry));
			target.addProperty("name", function.getName(true));
			JsonObject report = new JsonObject();
			report.addProperty("schema_version", 1);
			report.addProperty("analysis_mode", "read_only_summary_layout_evidence");
			report.addProperty("assumption", "analyst_selected_object_start");
			report.addProperty("score_kind", solved.get("score_kind").getAsString());
			report.add("function", target);
			report.addProperty("revision", revision);
			report.addProperty("program_id", programId);
			report.addProperty("language_id", currentProgram.getLanguageID().toString());
			report.addProperty("compiler_spec_id",
				currentProgram.getCompilerSpec().getCompilerSpecID().toString());
			report.addProperty("parameter_index", parameter);
			report.addProperty("object_id", root.id());
			report.addProperty("summary_limit", maximumSummaries);
			report.addProperty("decompile_attempts", decompileAttempts);
			report.addProperty("pcode_ops", pcodeOps);
			report.addProperty("unresolved_accesses", unresolved);
			JsonArray summaryRecords = new JsonArray();
			for (Summary summary : summaries.values()) {
				summaryRecords.add(summaryRecord(summary));
			}
			report.add("summaries", summaryRecords);
			report.add("edges", edges);
			report.add("refused_calls", refused);
			report.add("variable_accesses", variable);
			report.add("components", solved.getAsJsonArray("components"));
			report.add("solution", solution);
			return report;
		}
	}

	private void traverse(ScheduledDecompiler decompiler, Summary root, Map<Key, Summary> summaries,
			JsonArray edges, JsonArray refused, JsonArray variable, int maximumSummaries) throws Exception {
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
					Function target = currentProgram.getFunctionManager().getFunctionAt(call.callee());
					if (!supportedFunction(target)) {
						refusal = "callee is missing, external, a thunk, uninitialized or above 64 KiB";
					}
					else {
						if (summaries.size() >= maximumSummaries) {
							throw new IOException("summary traversal exceeds the summary limit of " +
								maximumSummaries);
						}
						callee = summarize(decompiler, target, key.parameter(), false, maximumSummaries,
							variable);
						if (callee == null) {
							refusal = "callee parameter is not a pointer-sized default-prototype register input";
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
					refusal = "callee parameter is not a pointer-sized default-prototype register input";
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

	/** Decompiles one function and summarizes one parameter, or returns null if it cannot be followed. */
	private Summary summarize(ScheduledDecompiler decompiler, Function function, int parameter,
			boolean root, int maximumSummaries, JsonArray variable) throws Exception {
		if (++decompileAttempts > 2 * maximumSummaries) {
			throw new IOException("summary traversal exceeds the decompilation attempt limit");
		}
		HighFunction high = readHighFunction(decompiler, function);
		Address storage = LayoutEvidence.parameterStorage(currentProgram, high, parameter);
		if (!root && storage == null) {
			return null;
		}
		if (pcodeOps >= MAXIMUM_TOTAL_OPS) {
			throw new IOException("summary traversal exceeds the total p-code operation limit");
		}
		var capture = LayoutEvidence.collect(currentProgram, high, parameter, false, monitor,
			MAXIMUM_TOTAL_OPS - pcodeOps);
		var calls = LayoutEvidence.summaryCalls(currentProgram, high, parameter, monitor);
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

	private JsonObject summaryRecord(Summary summary) {
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
		if (decompiled == null || !decompiled.decompileCompleted() || decompiled.getHighFunction() == null) {
			throw new IOException("unable to read high p-code: " +
				(decompiled == null ? "no results" : decompiled.getErrorMessage()));
		}
		return decompiled.getHighFunction();
	}

	private Function selectFunction(String selector) throws Exception {
		if (selector.startsWith("name:")) {
			String name = selector.substring("name:".length());
			if (name.isBlank() || name.length() > 1024) {
				throw new IllegalArgumentException("invalid function name selector");
			}
			Function match = null;
			int visited = 0;
			SymbolIterator symbols = currentProgram.getSymbolTable().getSymbols(name);
			while (symbols.hasNext()) {
				checkCurrent();
				if (++visited > MAXIMUM_SYMBOL_MATCHES) {
					throw new IOException("too many symbols with that name; select a function entry");
				}
				Symbol symbol = symbols.next();
				if (symbol.getSymbolType() != SymbolType.FUNCTION &&
						symbol.getSymbolType() != SymbolType.LABEL) {
					continue;
				}
				Function candidate = currentProgram.getFunctionManager().getFunctionAt(symbol.getAddress());
				if (candidate != null) {
					if (match != null && !match.getEntryPoint().equals(candidate.getEntryPoint())) {
						throw new IOException("ambiguous function name; select a function entry");
					}
					match = candidate;
				}
			}
			if (match != null) {
				return match;
			}
		}
		else {
			if (!selector.matches("[a-fA-F0-9]{1,16}")) {
				throw new IllegalArgumentException("function entry must be hexadecimal");
			}
			long offset = Long.parseUnsignedLong(selector, 16);
			Address address = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
			if (address.getOffset() != offset) {
				throw new IllegalArgumentException("function entry does not fit the default address space");
			}
			Function match = currentProgram.getFunctionManager().getFunctionAt(address);
			if (match != null) {
				return match;
			}
		}
		throw new IOException("no function matches " + selector);
	}

	private boolean supportedFunction(Function function) {
		if (function == null || function.isExternal() || function.isThunk()) {
			return false;
		}
		MemoryBlock block = currentProgram.getMemory().getBlock(function.getEntryPoint());
		long size = function.getBody().getNumAddresses();
		return block != null && !block.isExternalBlock() && block.isInitialized() &&
			size > 0 && size <= MAXIMUM_FUNCTION_BYTES;
	}

	private void addInstructionDigest(JsonObject row, Address site) {
		var instruction = currentProgram.getListing().getInstructionAt(site);
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

	private static long reserve(String name, long fallback) {
		String configured = System.getenv(name);
		long value = configured == null || configured.isBlank() ? fallback : Long.parseLong(configured);
		if (value < 0) {
			throw new IllegalArgumentException(name + " must be nonnegative");
		}
		return value;
	}

	private void configure(DecompInterface decompiler) {
		DecompileOptions options = new DecompileOptions();
		options.grabFromProgram(currentProgram);
		options.setMaxPayloadMBytes(Math.min(options.getMaxPayloadMBytes(), 8));
		options.setMaxInstructions(Math.min(options.getMaxInstructions(), 16_384));
		decompiler.setOptions(options);
		decompiler.setSimplificationStyle("decompile");
		decompiler.toggleCCode(false);
		decompiler.toggleSyntaxTree(true);
	}

	private void checkCurrent() throws Exception {
		monitor.checkCancelled();
		if (currentProgram.isClosed() || revision != currentProgram.getModificationNumber()) {
			throw new IllegalStateException("Program changed during layout evidence extraction");
		}
	}

	private static String hex(Address address) {
		return Long.toUnsignedString(address.getOffset(), 16);
	}
}
