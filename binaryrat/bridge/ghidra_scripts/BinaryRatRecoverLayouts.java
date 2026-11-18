// Collect read-only layout evidence from a selected Ghidra function parameter.
// @category BinaryRat
// @menupath Tools.BinaryRat.Recover Layout at Cursor
// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
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
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ProgramManager;
import ghidra.features.base.values.GhidraValuesMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.MessageType;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;

/** CodeBrowser and headless entrypoints for the read-only C++ layout evidence solver. */
public class BinaryRatRecoverLayouts extends GhidraScript {
	private static final long MAXIMUM_FUNCTION_BYTES = 65_536;
	private static final int MAXIMUM_SYMBOL_MATCHES = 4_096;
	private static final int MAXIMUM_FOLLOW_DEPTH = 4;
	private static final int MAXIMUM_FORWARDED_CALLEES = 4;
	private static final int MAXIMUM_CALLEE_TARGETS = 12;
	private static final int MAXIMUM_DECOMPILE_ATTEMPTS = 12;
	private static final int MAXIMUM_FORWARDED_EDGES = 128;
	private static final int MAXIMUM_TOTAL_OPS = (MAXIMUM_FORWARDED_CALLEES + 1) * LayoutEvidence.MAXIMUM_OPS;
	private static final int NOT_VISITED = -1;
	private static final String PARAMETER = "Parameter index";
	private static final String DEPTH = "Direct-call depth";
	private static final String OUTPUT = "Output JSON path";
	private long revision;

	private record Request(Function function, int parameter, int timeout, int depth, Path output) {
	}

	private record Visit(Address entry, int depth, List<LayoutEvidence.ForwardedCall> calls) {
	}

	private record CalleeInput(Address storage, int firstDepth) {
	}

	private record TraversalStats(int pcodeOps, int unresolved, int decompileAttempts) {
	}

	@Override
	protected void run() throws Exception {
		if (currentProgram == null) {
			throw new IllegalStateException("Open an analyzed Program before recovering layout evidence");
		}
		// Release the script's empty transaction before reading the Program or prompting.
		end(true);
		revision = currentProgram.getModificationNumber();
		var analysis = AutoAnalysisManager.getAnalysisManager(currentProgram);
		if (analysis.isAnalyzing()) {
			throw new IllegalStateException("auto-analysis must finish before layout extraction");
		}
		Request request = isRunningHeadless() ? headlessRequest() : desktopRequest();
		checkCurrent();
		if (analysis.isAnalyzing()) {
			throw new IllegalStateException("auto-analysis must finish before layout extraction");
		}
		Path output = request.output().toAbsolutePath().normalize();
		if (Files.exists(output, LinkOption.NOFOLLOW_LINKS)) {
			throw new IOException("layout evidence destination already exists: " + output);
		}

		String hash = currentProgram.getExecutableSHA256();
		if (hash == null || !hash.matches("[0-9a-fA-F]{64}")) {
			throw new IOException("layout evidence requires a valid executable SHA-256");
		}
		String programId = "sha256:" + hash.toLowerCase(Locale.ROOT);
		Path workspace = Files.createTempDirectory(output.getParent(), ".binaryrat-layout-");
		try {
			JsonObject result = recover(workspace, request.function(), request.parameter(),
				request.timeout(), request.depth(), programId);
			Path staged = workspace.resolve("report.json");
			String content = new GsonBuilder().serializeNulls().setPrettyPrinting().create().toJson(result);
			Files.writeString(staged, content + "\n", StandardCharsets.UTF_8);
			checkCurrent();
			// A hard link publishes the complete report and rejects an existing
			// destination atomically, even if another exporter won after our check.
			try {
				Files.createLink(output, staged);
			}
			catch (UnsupportedOperationException failure) {
				throw new IOException("layout publication requires hard-link support in the output directory",
					failure);
			}
			println("BinaryRat layout evidence written: " + output);
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

	private Request headlessRequest() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 3 || args.length > 5) {
			throw new IllegalArgumentException("Use as a headless postScript: " +
				"BinaryRatRecoverLayouts.java OUTPUT_JSON ENTRY_HEX|name:FUNCTION " +
				"PARAM_INDEX [TIMEOUT_SECONDS [FOLLOW_DEPTH]]");
		}
		int index = Integer.parseInt(args[2]);
		int timeout = args.length >= 4 ? Integer.parseInt(args[3]) : 30;
		int depth = args.length == 5 ? Integer.parseInt(args[4]) : 0;
		if (timeout < 1 || timeout > 600) {
			throw new IllegalArgumentException("timeout must be 1–600 seconds");
		}
		String error = parameterError(index, depth);
		if (error != null) {
			throw new IllegalArgumentException(error);
		}
		return new Request(requireSupported(selectFunction(args[1])), index, timeout, depth, Path.of(args[0]));
	}

	private Request desktopRequest() throws Exception {
		Address cursor = currentAddress;
		checkCursor(cursor);
		Function function = requireSupported(getFunctionContaining(cursor));
		Address entry = function.getEntryPoint();
		GhidraValuesMap values = new GhidraValuesMap();
		values.defineInt(PARAMETER, 0);
		values.defineInt(DEPTH, 0);
		values.defineString(OUTPUT, Path.of(System.getProperty("user.home"),
			"layout-" + hex(entry) + ".json").toString());
		values.setValidator((input, status) -> {
			String error = input.hasValue(PARAMETER) && input.hasValue(DEPTH) ?
				parameterError(input.getInt(PARAMETER), input.getInt(DEPTH)) : "Enter both numbers";
			if (error == null && (!input.hasValue(OUTPUT) || input.getString(OUTPUT).isBlank())) {
				error = "Enter a path for the new JSON report";
			}
			if (error != null) {
				status.setStatusText(error, MessageType.ERROR);
			}
			return error == null;
		});
		setReusePreviousChoices(false);
		askValues("Recover Layout at Cursor",
			"Function " + function.getName(true) + " at " + entry +
			"\nSelect a zero-based decompiler parameter index. Use depth 0 for this function only.",
			values);
		checkCursor(cursor);
		return new Request(function, values.getInt(PARAMETER), 30, values.getInt(DEPTH),
			Path.of(values.getString(OUTPUT)));
	}

	private Function requireSupported(Function function) throws IOException {
		if (!supportedFunction(function)) {
			throw new IOException("select a local non-thunk function within the 64 KiB body limit");
		}
		return function;
	}

	private static String parameterError(int index, int depth) {
		if (index < 0) {
			return "parameter index must be nonnegative";
		}
		return depth < 0 || depth > MAXIMUM_FOLLOW_DEPTH ?
			"follow depth must be between 0 and " + MAXIMUM_FOLLOW_DEPTH : null;
	}

	private void checkCursor(Address cursor) throws Exception {
		checkCurrent();
		// The script's state is a snapshot. Read the connected Listing on the EDT to
		// detect a tab switch or cursor movement while either dialog was open.
		Boolean matches = Swing.runNow(() -> {
			var tool = state.getTool();
			var viewer = tool == null ? null : tool.getService(CodeViewerService.class);
			var manager = tool == null ? null : tool.getService(ProgramManager.class);
			var location = viewer == null ? null : viewer.getCurrentLocation();
			return cursor != null && manager != null && manager.getCurrentProgram() == currentProgram &&
				location != null && location.getProgram() == currentProgram && cursor.equals(location.getAddress());
		});
		checkCurrent();
		if (!Boolean.TRUE.equals(matches)) {
			throw new IllegalStateException("Select the function in the active Listing and run recovery again");
		}
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

	private JsonObject recover(Path workspace, Function function, int parameterIndex, int timeout,
			int followDepth, String programId) throws Exception {
		try (EngineClient engine = EngineClient.start(EngineClient.findExecutable(), workspace)) {
			checkCurrent();
			var limits = new ScheduledDecompiler.Limits(1, reserve("BINARYRAT_WORKER_BYTES", 768L << 20),
				Runtime.getRuntime().maxMemory(), reserve("BINARYRAT_OTHER_RESERVE_BYTES", 512L << 20),
				timeout, 5_000, timeout * 1_000L);
			Address entry = function.getEntryPoint();
			String space = entry.getAddressSpace().getName();
			String offset = hex(entry);
			String object = programId + "/" + space + "/" + offset + "/param/" + parameterIndex;
			JsonArray observations = new JsonArray();
			JsonArray variableAccesses = new JsonArray();
			JsonArray calls = new JsonArray();
			TraversalStats stats;
			try (ScheduledDecompiler decompiler = new ScheduledDecompiler(engine, currentProgram,
					this::configure, limits)) {
				stats = collectLayouts(decompiler, function, parameterIndex, followDepth, object,
					observations, variableAccesses, calls);
			}
			checkCurrent();
			JsonObject request = new JsonObject();
			request.add("observations", observations);
			request.addProperty("maximum_extent", LayoutEvidence.MAXIMUM_EXTENT);
			JsonObject report = engine.call("types.recover", request);
			JsonObject target = new JsonObject();
			target.addProperty("address_space", space);
			target.addProperty("address", offset);
			target.addProperty("name", function.getName(true));
			report.add("function", target);
			report.addProperty("schema_version", 1);
			report.addProperty("revision", revision);
			report.addProperty("program_id", programId);
			report.addProperty("language_id", currentProgram.getLanguageID().toString());
			report.addProperty("compiler_spec_id", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
			report.addProperty("parameter_index", parameterIndex);
			report.addProperty("assumption", "analyst_selected_object_start");
			report.addProperty("analysis_mode", "read_only_layout_evidence");
			report.addProperty("pcode_ops", stats.pcodeOps());
			report.addProperty("unresolved_accesses", stats.unresolved());
			report.addProperty("follow_depth", followDepth);
			if (followDepth > 1) {
				report.addProperty("decompile_attempts", stats.decompileAttempts());
			}
			report.add("forwarded_calls", calls);
			report.add("observations", observations);
			report.add("variable_accesses", variableAccesses);
			return report;
		}
	}

	private TraversalStats collectLayouts(ScheduledDecompiler decompiler, Function function,
			int parameterIndex, int followDepth, String object, JsonArray observations,
			JsonArray variableAccesses, JsonArray calls) throws Exception {
		Address entry = function.getEntryPoint();
		var root = LayoutEvidence.collect(currentProgram, readHighFunction(decompiler, function),
			parameterIndex, followDepth > 0, monitor);
		int pcodeOps = root.pcodeOps();
		int unresolved = root.unresolvedAccesses();
		appendObservations(observations, variableAccesses, root, object, entry, false);
		var pending = new ArrayDeque<Visit>();
		pending.add(new Visit(entry, 0, root.calls()));
		Map<Address, CalleeInput> inputs = new HashMap<>();
		int decompileAttempts = 1;
		while (!pending.isEmpty()) {
			var parent = pending.removeFirst();
			int depth = parent.depth() + 1;
			for (var target : groupCallees(parent, entry).entrySet()) {
				checkCurrent();
				Address address = target.getKey();
				CalleeInput known = inputs.get(address);
				if (known != null && known.firstDepth() != NOT_VISITED) {
					// Keep alternate equally short paths, with one copy of each function's
					// evidence. Omitting longer paths also keeps cycles out of provenance.
					if (known.firstDepth() == depth) {
						appendCalls(calls, parent, target.getValue(), known.storage(), followDepth);
					}
					continue;
				}
				if (known != null && target.getValue().stream().noneMatch(
						call -> call.argumentStorage().equals(known.storage()))) {
					continue;
				}
				if (known == null && inputs.size() >= MAXIMUM_CALLEE_TARGETS) {
					throw new IOException("layout traversal exceeds the distinct callee limit");
				}
				Function callee = currentProgram.getFunctionManager().getFunctionAt(address);
				if (!supportedFunction(callee)) {
					inputs.put(address, new CalleeInput(null, NOT_VISITED));
					continue;
				}
				if (++decompileAttempts > MAXIMUM_DECOMPILE_ATTEMPTS) {
					throw new IOException("layout traversal exceeds the decompilation attempt limit");
				}
				HighFunction high = readHighFunction(decompiler, callee);
				Address storage = LayoutEvidence.forwardedInputStorage(currentProgram, high);
				if (!appendCalls(calls, parent, target.getValue(), storage, followDepth)) {
					// A later caller may agree with the storage. Retain only its address,
					// then decompile again if needed rather than pinning HighFunction state.
					inputs.put(address, new CalleeInput(storage, NOT_VISITED));
					continue;
				}
				var capture = LayoutEvidence.collect(currentProgram, high, 0, depth < followDepth,
					monitor, MAXIMUM_TOTAL_OPS - pcodeOps);
				pcodeOps += capture.pcodeOps();
				unresolved += capture.unresolvedAccesses();
				appendObservations(observations, variableAccesses, capture, object, address, true);
				inputs.put(address, new CalleeInput(storage, depth));
				if (!capture.calls().isEmpty()) {
					pending.addLast(new Visit(address, depth, capture.calls()));
				}
			}
		}
		return new TraversalStats(pcodeOps, unresolved, decompileAttempts);
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

	private static Map<Address, List<LayoutEvidence.ForwardedCall>> groupCallees(Visit parent,
			Address root) throws IOException {
		Map<Address, List<LayoutEvidence.ForwardedCall>> byCallee = new LinkedHashMap<>();
		for (var call : parent.calls()) {
			if (call.callee().equals(root) || call.callee().equals(parent.entry())) {
				continue;
			}
			byCallee.computeIfAbsent(call.callee(), ignored -> new ArrayList<>()).add(call);
			if (byCallee.size() > MAXIMUM_FORWARDED_CALLEES) {
				throw new IOException("function exceeds the four direct-callee layout limit");
			}
		}
		return byCallee;
	}

	private void appendObservations(JsonArray observations, JsonArray variableAccesses,
			LayoutEvidence.Capture capture, String object, Address function, boolean forwarded)
			throws Exception {
		if (observations.size() + variableAccesses.size() + capture.accesses().size() >
				LayoutEvidence.MAXIMUM_ACCESSES) {
			throw new IOException("layout report exceeds the total evidence limit");
		}
		for (LayoutEvidence.Access access : capture.accesses()) {
			monitor.checkCancelled();
			JsonObject observation = new JsonObject();
			Address site = access.address();
			observation.addProperty("object_id", object);
			observation.addProperty("object_start_known", true);
			observation.addProperty("width", access.width());
			boolean variableOffset = access.offset() != access.maximumOffset();
			if (variableOffset) {
				// A possible offset is not an observed field. Keep range evidence off
				// the exact-field solver input and distinguish its lower bound in JSON.
				observation.addProperty("minimum_offset", access.offset());
				observation.addProperty("stride", access.stride());
				observation.addProperty("maximum_offset", access.maximumOffset());
			}
			else {
				observation.addProperty("offset", access.offset());
				var use = access.typedUse();
				if (use != null) {
					observation.addProperty("storage_view", use.kind());
					JsonObject typedUse = new JsonObject();
					typedUse.addProperty("address_space", use.address().getAddressSpace().getName());
					typedUse.addProperty("address", hex(use.address()));
					typedUse.addProperty("pcode_order", use.pcodeOrder());
					typedUse.addProperty("operation", use.operation());
					addInstructionDigest(typedUse, use.address());
					observation.add("typed_use", typedUse);
				}
			}
			String prefix = forwarded ? object + "/callee/" + hex(function) : object;
			addInstructionDigest(observation, site);
			observation.addProperty("evidence_id", prefix + "/" + site.getAddressSpace().getName() +
				"/" + hex(site) + "/" + access.pcodeOrder());
			observation.addProperty("function_address", hex(function));
			observation.addProperty("function_address_space", function.getAddressSpace().getName());
			observation.addProperty("address_space", site.getAddressSpace().getName());
			observation.addProperty("address", hex(site));
			observation.addProperty("pcode_order", access.pcodeOrder());
			observation.addProperty("operation", access.operation());
			(variableOffset ? variableAccesses : observations).add(observation);
		}
	}

	private boolean appendCalls(JsonArray calls, Visit parent,
			List<LayoutEvidence.ForwardedCall> candidates, Address storage, int followDepth)
			throws IOException {
		boolean accepted = false;
		for (var call : candidates) {
			if (!call.argumentStorage().equals(storage)) {
				continue;
			}
			if (calls.size() >= MAXIMUM_FORWARDED_EDGES) {
				throw new IOException("layout report exceeds the total forwarding call limit");
			}
			calls.add(callRecord(call, parent, followDepth));
			accepted = true;
		}
		return accepted;
	}

	private JsonObject callRecord(LayoutEvidence.ForwardedCall call, Visit parent, int followDepth) {
		JsonObject record = new JsonObject();
		addInstructionDigest(record, call.address());
		record.addProperty("address_space", call.address().getAddressSpace().getName());
		record.addProperty("address", hex(call.address()));
		record.addProperty("pcode_order", call.pcodeOrder());
		record.addProperty("callee_address_space", call.callee().getAddressSpace().getName());
		record.addProperty("callee_address", hex(call.callee()));
		record.addProperty("callee_parameter_index", 0);
		if (followDepth > 1) {
			record.addProperty("caller_address_space", parent.entry().getAddressSpace().getName());
			record.addProperty("caller_address", hex(parent.entry()));
			record.addProperty("hop", parent.depth() + 1);
		}
		return record;
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
			// Parsed bytes include a tail that a Listing length override may hide.
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
