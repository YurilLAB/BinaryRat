// Collect read-only layout evidence from a selected Ghidra function parameter.
// @category BinaryRat
// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
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
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolType;

/** Headless entrypoint for the C++ layout evidence solver. It makes no Program edits. */
public class BinaryRatRecoverLayouts extends GhidraScript {
	private static final long MAXIMUM_FUNCTION_BYTES = 65_536;
	private static final int MAXIMUM_SYMBOL_MATCHES = 4_096;
	private static final int MAXIMUM_FORWARDED_CALLEES = 4;
	private long revision;

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (!isRunningHeadless() || currentProgram == null || args.length < 3 || args.length > 5) {
			throw new IllegalArgumentException("Use as a headless postScript: " +
				"BinaryRatRecoverLayouts.java OUTPUT_JSON ENTRY_HEX|name:FUNCTION " +
				"PARAM_INDEX [TIMEOUT_SECONDS [FOLLOW_DEPTH]]");
		}
		// Release GhidraScript's empty transaction before taking any analysis inputs.
		end(true);
		if (AutoAnalysisManager.getAnalysisManager(currentProgram).isAnalyzing()) {
			throw new IllegalStateException("auto-analysis must finish before layout extraction");
		}
		int parameterIndex = Integer.parseInt(args[2]);
		int timeout = args.length >= 4 ? Integer.parseInt(args[3]) : 30;
		int followDepth = args.length == 5 ? Integer.parseInt(args[4]) : 0;
		if (parameterIndex < 0 || timeout < 1 || timeout > 600) {
			throw new IllegalArgumentException("parameter index must be nonnegative and timeout 1–600 seconds");
		}
		if (followDepth < 0 || followDepth > 1) {
			throw new IllegalArgumentException("follow depth must be 0 or 1");
		}
		Path output = Path.of(args[0]).toAbsolutePath().normalize();
		if (Files.exists(output, LinkOption.NOFOLLOW_LINKS)) {
			throw new IOException("layout evidence destination already exists: " + output);
		}
		revision = currentProgram.getModificationNumber();
		checkCurrent();
		Function function = selectFunction(args[1]);
		if (!supportedFunction(function)) {
			throw new IOException("select a local non-thunk function within the 64 KiB body limit");
		}

		String hash = currentProgram.getExecutableSHA256();
		if (hash == null || !hash.matches("[0-9a-fA-F]{64}")) {
			throw new IOException("layout evidence requires a valid executable SHA-256");
		}
		String programId = "sha256:" + hash.toLowerCase(Locale.ROOT);
		Path workspace = Files.createTempDirectory(output.getParent(), ".binaryrat-layout-");
		try {
			JsonObject result = recover(workspace, function, parameterIndex, timeout, followDepth, programId);
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
			int pcodeOps;
			int unresolved;
			try (ScheduledDecompiler decompiler = new ScheduledDecompiler(engine, currentProgram,
					this::configure, limits)) {
				var root = LayoutEvidence.collect(currentProgram, readHighFunction(decompiler, function),
					parameterIndex, followDepth > 0, monitor);
				pcodeOps = root.pcodeOps();
				unresolved = root.unresolvedAccesses();
				appendObservations(observations, variableAccesses, root, object, entry, false);
				for (var target : groupCallees(root.calls(), entry).entrySet()) {
					checkCurrent();
					Function callee = currentProgram.getFunctionManager().getFunctionAt(target.getKey());
					if (!supportedFunction(callee)) {
						continue;
					}
					HighFunction high = readHighFunction(decompiler, callee);
					var accepted = target.getValue().stream().filter(call ->
						LayoutEvidence.acceptsForwardedInput(currentProgram, high, call.argumentStorage())).toList();
					if (accepted.isEmpty()) {
						continue;
					}
					var capture = LayoutEvidence.collect(currentProgram, high, 0, false, monitor);
					pcodeOps += capture.pcodeOps();
					unresolved += capture.unresolvedAccesses();
					appendObservations(observations, variableAccesses, capture, object, target.getKey(), true);
					for (var call : accepted) {
						calls.add(callRecord(call));
					}
				}
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
			report.addProperty("pcode_ops", pcodeOps);
			report.addProperty("unresolved_accesses", unresolved);
			report.addProperty("follow_depth", followDepth);
			report.add("forwarded_calls", calls);
			report.add("observations", observations);
			report.add("variable_accesses", variableAccesses);
			return report;
		}
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

	private static Map<Address, List<LayoutEvidence.ForwardedCall>> groupCallees(
			List<LayoutEvidence.ForwardedCall> calls, Address root) throws IOException {
		Map<Address, List<LayoutEvidence.ForwardedCall>> byCallee = new LinkedHashMap<>();
		for (var call : calls) {
			// At depth 1 a self-call is the only cycle that would re-extract the root.
			if (call.callee().equals(root)) {
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
			}
			String prefix = forwarded ? object + "/callee/" + hex(function) : object;
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

	private static JsonObject callRecord(LayoutEvidence.ForwardedCall call) {
		JsonObject record = new JsonObject();
		record.addProperty("address_space", call.address().getAddressSpace().getName());
		record.addProperty("address", hex(call.address()));
		record.addProperty("pcode_order", call.pcodeOrder());
		record.addProperty("callee_address_space", call.callee().getAddressSpace().getName());
		record.addProperty("callee_address", hex(call.callee()));
		record.addProperty("callee_parameter_index", 0);
		return record;
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
		if (revision != currentProgram.getModificationNumber()) {
			throw new IllegalStateException("Program changed during layout evidence extraction");
		}
	}

	private static String hex(Address address) {
		return Long.toUnsignedString(address.getOffset(), 16);
	}
}
