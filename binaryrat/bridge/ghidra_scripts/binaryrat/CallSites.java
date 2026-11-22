// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package binaryrat;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Stream;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;

import generic.hash.HashUtilities;
import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangStatement;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighConstant;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Every call to a function, each shown as its caller's decompiled C statement with the
 * argument values the decompiler proved constant. Calls through thunks of the function count
 * as calls to it. Each caller is decompiled once under a memory-watched lease. The report keeps
 * whole sites in address order within its limits. The Program's modification number is checked
 * around every step and any change fails the run.
 */
public final class CallSites {
	public static final String ANALYSIS_MODE = "read_only_call_sites";
	public static final int DEFAULT_SITES = 64;
	public static final int MAXIMUM_SITES = 1_024;
	public static final int DEFAULT_CALLERS = 32;
	public static final int MAXIMUM_CALLERS = 256;
	public static final int MAXIMUM_TIMEOUT_SECONDS = 600;
	/** Incoming references examined before the scan stops and the report says it is truncated. */
	public static final int MAXIMUM_REFERENCES = 100_000;
	public static final int MAXIMUM_STATEMENT = 1_024;
	public static final int MAXIMUM_ARGUMENTS = 64;
	public static final int MAXIMUM_STRING = 120;
	// The Python report decoder enforces the same UTF-8 byte limit.
	private static final int MAXIMUM_REPORT_BYTES = 8 * 1024 * 1024;
	private static final int MAXIMUM_REASON = 300;
	private static final long MAXIMUM_INSTRUCTION_BYTES = 64;
	private static final Gson JSON = new GsonBuilder().serializeNulls().create();

	public static final String DECOMPILED = "decompiled";
	public static final String NO_FUNCTION = "no_function";
	public static final String UNSUPPORTED_CALLER = "unsupported_caller";
	public static final String DECOMPILE_FAILED = "decompile_failed";
	public static final String NOT_IN_DECOMPILATION = "not_in_decompilation";
	public static final String CALLER_LIMIT = "caller_limit";

	private CallSites() {
	}

	/** Recovers a report and returns it as JSON text (for PyGhidra callers). */
	public static String recoverJson(Program program, Function function, int timeoutSeconds,
			int maximumSites, int maximumCallers, TaskMonitor monitor) throws Exception {
		return encodeReport(recover(program, function, timeoutSeconds, maximumSites, maximumCallers, monitor));
	}

	/** Encodes the report with the same JSON format used to measure its byte limit. */
	public static String encodeReport(JsonObject report) {
		return JSON.toJson(report);
	}

	private static int encodedBytes(JsonObject object) {
		return encodeReport(object).getBytes(StandardCharsets.UTF_8).length;
	}

	/**
	 * Finds the calls to {@code function} (or, for a thunk, to the function it reaches) and
	 * decompiles their callers. The engine runs in a private temporary directory that is removed
	 * afterwards; no engine starts when no caller needs decompiling.
	 */
	public static JsonObject recover(Program program, Function function, int timeoutSeconds,
			int maximumSites, int maximumCallers, TaskMonitor monitor) throws Exception {
		if (timeoutSeconds < 1 || timeoutSeconds > MAXIMUM_TIMEOUT_SECONDS) {
			throw new IllegalArgumentException("timeout must be 1-" + MAXIMUM_TIMEOUT_SECONDS + " seconds");
		}
		if (maximumSites < 1 || maximumSites > MAXIMUM_SITES) {
			throw new IllegalArgumentException("site limit must be between 1 and " + MAXIMUM_SITES);
		}
		if (maximumCallers < 1 || maximumCallers > MAXIMUM_CALLERS) {
			throw new IllegalArgumentException("caller limit must be between 1 and " + MAXIMUM_CALLERS);
		}
		if (program == null || function == null || function.getProgram() != program) {
			throw new IOException("select a function of the open Program");
		}
		return new Run(program, monitor, timeoutSeconds, maximumSites, maximumCallers).recover(function);
	}

	/** One incoming call reference: where the call is and which target address it reaches. */
	private record Site(Address address, Address target) {
	}

	/** Keep a prefix within the byte budget, even when records arrive grouped by caller. */
	private static final class SiteRecords {
		private record SizedSite(JsonObject record, int bytes, Address attemptedCaller) {
		}

		private final TreeMap<Address, SizedSite> entries = new TreeMap<>();
		private int available;
		private Address firstOmitted;

		SiteRecords(int available) {
			this.available = available;
		}

		boolean mayInclude(Site site) {
			return firstOmitted == null || site.address().compareTo(firstOmitted) < 0;
		}

		void add(Site site, JsonObject record, Address attemptedCaller) {
			// Charge one byte per site for its separator, including one spare byte for the first site.
			int bytes = encodedBytes(record) + 1;
			entries.put(site.address(), new SizedSite(record, bytes, attemptedCaller));
			available -= bytes;
			while (available < 0) {
				var last = entries.pollLastEntry();
				available += last.getValue().bytes();
				firstOmitted = last.getKey();
			}
		}

		void finish(JsonObject report) {
			JsonArray sites = report.getAsJsonArray("sites");
			Set<Address> callers = new LinkedHashSet<>();
			for (SizedSite site : entries.values()) {
				sites.add(site.record());
				if (site.attemptedCaller() != null) {
					callers.add(site.attemptedCaller());
				}
			}
			if (firstOmitted != null) {
				report.addProperty("truncated", true);
			}
			report.addProperty("decompiled_callers", callers.size());
		}
	}

	/** State of one recovery; never shared between threads. */
	private static final class Run {
		private final Program program;
		private final TaskMonitor monitor;
		private final int timeout;
		private final int maximumSites;
		private final int maximumCallers;
		private final long revision;

		Run(Program program, TaskMonitor monitor, int timeout, int maximumSites, int maximumCallers)
				throws Exception {
			this.program = program;
			this.monitor = monitor;
			this.timeout = timeout;
			this.maximumSites = maximumSites;
			this.maximumCallers = maximumCallers;
			this.revision = program.getModificationNumber();
			checkCurrent();
		}

		JsonObject recover(Function selected) throws Exception {
			Function root = selected.isThunk() ? selected.getThunkedFunction(true) : selected;
			if (root == null) {
				root = selected;
			}
			Set<Address> targets = new LinkedHashSet<>();
			targets.add(root.getEntryPoint());
			Address[] thunks = root.getFunctionThunkAddresses(true);
			if (thunks != null) {
				for (Address thunk : thunks) {
					targets.add(thunk);
				}
			}

			Map<Address, Site> found = new TreeMap<>();
			int scanned = 0;
			int other = 0;
			boolean truncated = false;
			scan:
			for (Address target : targets) {
				for (Reference reference : program.getReferenceManager().getReferencesTo(target)) {
					checkCurrent();
					if (++scanned > MAXIMUM_REFERENCES) {
						truncated = true;
						break scan;
					}
					Address from = reference.getFromAddress();
					if (!reference.getReferenceType().isCall() || from == null || !from.isMemoryAddress()) {
						other++;
						continue;
					}
					found.putIfAbsent(from, new Site(from, target));
				}
			}
			int callReferences = found.size();
			List<Site> sites = new ArrayList<>(found.values());
			if (sites.size() > maximumSites) {
				sites = new ArrayList<>(sites.subList(0, maximumSites));
				truncated = true;
			}

			JsonObject report = new JsonObject();
			report.addProperty("schema_version", 1);
			report.addProperty("analysis_mode", ANALYSIS_MODE);
			report.add("function", functionRecord(selected));
			report.add("root_function", functionRecord(root));
			report.addProperty("revision", revision);
			String hash = program.getExecutableSHA256();
			report.addProperty("program_id", hash != null && hash.matches("[0-9a-fA-F]{64}") ?
				"sha256:" + hash.toLowerCase(Locale.ROOT) : null);
			report.addProperty("language_id", program.getLanguageID().toString());
			report.addProperty("compiler_spec_id", program.getCompilerSpec().getCompilerSpecID().toString());
			JsonArray targetRecords = new JsonArray();
			report.add("targets", targetRecords);
			report.addProperty("timeout_seconds", timeout);
			report.addProperty("site_limit", maximumSites);
			report.addProperty("caller_limit", maximumCallers);
			report.addProperty("references_scanned", Math.min(scanned, MAXIMUM_REFERENCES));
			report.addProperty("call_references", callReferences);
			report.addProperty("other_references", other);
			report.addProperty("truncated", false);
			report.addProperty("decompiled_callers", maximumCallers);
			report.add("sites", new JsonArray());
			// Reserve the widest count and boolean above, plus the headless file's final newline.
			int available = MAXIMUM_REPORT_BYTES - encodedBytes(report) - 1;
			report.addProperty("truncated", truncated);
			for (Address target : targets) {
				checkCurrent();
				JsonObject record = new JsonObject();
				record.addProperty("address_space", target.getAddressSpace().getName());
				record.addProperty("address", hex(target));
				Function at = program.getFunctionManager().getFunctionAt(target);
				record.addProperty("name", at == null ? null : text(at.getName(true)));
				record.addProperty("thunk", !target.equals(root.getEntryPoint()));
				available -= encodedBytes(record) + (targetRecords.isEmpty() ? 0 : 1);
				if (available < 0) {
					throw new IOException("call-site target metadata exceeds the 8 MiB report limit");
				}
				targetRecords.add(record);
			}
			SiteRecords records = new SiteRecords(available);
			// Each caller is decompiled once for all of its sites, in order of its first site.
			Map<Function, List<Site>> byCaller = new LinkedHashMap<>();
			for (Site site : sites) {
				if (!records.mayInclude(site)) {
					break;
				}
				Function caller = program.getFunctionManager().getFunctionContaining(site.address());
				if (caller == null) {
					records.add(site, siteRecord(site, null, NO_FUNCTION,
						"the call is not inside a defined function"), null);
				}
				else if (!SummaryLayouts.supportedFunction(program, caller)) {
					records.add(site, siteRecord(site, caller, UNSUPPORTED_CALLER,
						"the caller is external, a thunk, uninitialized or above 64 KiB"), null);
				}
				else {
					byCaller.computeIfAbsent(caller, key -> new ArrayList<>()).add(site);
				}
			}
			if (!byCaller.isEmpty()) {
				decompileCallers(byCaller, targets, records);
			}
			records.finish(report);
			checkCurrent();
			return report;
		}

		private void decompileCallers(Map<Function, List<Site>> byCaller, Set<Address> targets,
				SiteRecords records) throws Exception {
			Path workspace = Files.createTempDirectory("binaryrat-callsites-");
			int decompiled = 0;
			try (EngineClient engine = EngineClient.start(EngineClient.findExecutable(), workspace)) {
				checkCurrent();
				var limits = new ScheduledDecompiler.Limits(1, reserve("BINARYRAT_WORKER_BYTES", 768L << 20),
					Runtime.getRuntime().maxMemory(), reserve("BINARYRAT_OTHER_RESERVE_BYTES", 512L << 20),
					timeout, 5_000, timeout * 1_000L);
				try (ScheduledDecompiler decompiler = new ScheduledDecompiler(engine, program,
						this::configure, limits)) {
					for (Map.Entry<Function, List<Site>> entry : byCaller.entrySet()) {
						checkCurrent();
						if (!records.mayInclude(entry.getValue().get(0))) {
							break;
						}
						Function caller = entry.getKey();
						if (decompiled >= maximumCallers) {
							for (Site site : entry.getValue()) {
								monitor.checkCancelled();
								if (!records.mayInclude(site)) {
									break;
								}
								records.add(site, siteRecord(site, caller, CALLER_LIMIT,
									"the caller decompile limit of " + maximumCallers + " was reached"), null);
							}
							continue;
						}
						decompiled++;
						ScheduledDecompiler.Run run = decompiler.decompileUntraced(caller, monitor);
						checkCurrent();
						DecompileResults results = run.traced() == null ? null : run.traced().results();
						String failure = failure(run, results);
						for (Site site : entry.getValue()) {
							monitor.checkCancelled();
							if (!records.mayInclude(site)) {
								break;
							}
							records.add(site, failure != null ?
								siteRecord(site, caller, DECOMPILE_FAILED, failure) :
								decompiledSite(site, caller, results, targets), caller.getEntryPoint());
						}
					}
				}
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

		/** Why a caller's decompilation cannot be read, or null when it completed. */
		private String failure(ScheduledDecompiler.Run run, DecompileResults results)
				throws CancelledException {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			if (!"completed".equals(run.status()) || !run.memoryWatched()) {
				return clip(text("decompilation lease ended " + run.status() +
					(run.stopReason() == null ? "" : " (" + run.stopReason() + ")")), MAXIMUM_REASON);
			}
			if (results == null || !results.decompileCompleted() || results.getHighFunction() == null ||
					results.getCCodeMarkup() == null) {
				String message = results == null ? "no results" : results.getErrorMessage();
				return clip(text("decompiler failed: " + (message == null || message.isBlank() ?
					"no output" : message)), MAXIMUM_REASON);
			}
			return null;
		}

		private JsonObject decompiledSite(Site site, Function caller, DecompileResults results,
				Set<Address> targets) {
			HighFunction high = results.getHighFunction();
			PcodeOpAST call = null;
			boolean otherTarget = false;
			var ops = high.getPcodeOps(site.address());
			while (ops.hasNext()) {
				PcodeOpAST op = ops.next();
				int code = op.getOpcode();
				if (code == PcodeOp.CALL) {
					if (targets.contains(op.getInput(0).getAddress())) {
						call = op;
						break;
					}
					otherTarget = true;
				}
				else if (code == PcodeOp.CALLIND && call == null) {
					// An indirect call reaches the target through a reference the analyst or
					// analysis recorded at this instruction.
					call = op;
				}
			}
			if (call == null) {
				return siteRecord(site, caller, NOT_IN_DECOMPILATION, otherTarget ?
					"the decompiled call at this address has another target" :
					"the decompiler emitted no call at this address");
			}
			JsonObject record = siteRecord(site, caller, DECOMPILED, null);
			record.addProperty("operation", call.getMnemonic());
			record.addProperty("statement", statement(results.getCCodeMarkup(), call));
			JsonArray arguments = new JsonArray();
			int count = Math.min(call.getNumInputs() - 1, MAXIMUM_ARGUMENTS);
			for (int index = 0; index < count; index++) {
				arguments.add(argument(index, call.getInput(index + 1)));
			}
			record.add("arguments", arguments);
			record.addProperty("arguments_truncated", call.getNumInputs() - 1 > MAXIMUM_ARGUMENTS);
			return record;
		}

		/** The C statement that contains the call, or its line if it is part of a condition. */
		private static String statement(ClangTokenGroup markup, PcodeOp call) {
			List<ClangNode> tokens = new ArrayList<>();
			markup.flatten(tokens);
			ClangToken found = null;
			for (ClangNode node : tokens) {
				if (node instanceof ClangToken token && token.getPcodeOp() != null &&
						token.getPcodeOp().getSeqnum().equals(call.getSeqnum())) {
					found = token;
					break;
				}
			}
			if (found == null) {
				return null;
			}
			for (ClangNode node = found.Parent(); node != null; node = node.Parent()) {
				if (node instanceof ClangStatement statement) {
					String text = text(statement.toString());
					return text.isEmpty() ? null : text;
				}
			}
			for (var line : DecompilerUtils.toLines(markup)) {
				if (line.getAllTokens().contains(found)) {
					StringBuilder builder = new StringBuilder();
					for (ClangToken token : line.getAllTokens()) {
						builder.append(token.getText());
					}
					String text = text(builder.toString());
					return text.isEmpty() ? null : text;
				}
			}
			return null;
		}

		private JsonObject argument(int index, Varnode input) {
			JsonObject record = new JsonObject();
			record.addProperty("index", index);
			record.addProperty("size", input.getSize());
			Varnode value = input;
			boolean pointer = false;
			// Look through copies and casts; PTRSUB(0, c) is the decompiler's global address c.
			for (int step = 0; step < 8 && value != null && !value.isConstant(); step++) {
				PcodeOp definition = value.getDef();
				if (definition == null) {
					break;
				}
				int code = definition.getOpcode();
				if (code == PcodeOp.COPY || code == PcodeOp.CAST) {
					value = definition.getInput(0);
					continue;
				}
				if (code == PcodeOp.PTRSUB && definition.getNumInputs() == 2 &&
						definition.getInput(0).isConstant() && definition.getInput(0).getOffset() == 0 &&
						definition.getInput(1).isConstant()) {
					pointer = true;
					value = definition.getInput(1);
				}
				break;
			}
			if (value == null || !value.isConstant()) {
				record.addProperty("kind", "unknown");
				record.add("value", JsonNull.INSTANCE);
				record.add("signed", JsonNull.INSTANCE);
				record.addProperty("variable", variable(input));
				record.add("symbol", JsonNull.INSTANCE);
				record.add("string", JsonNull.INSTANCE);
				record.add("string_source", JsonNull.INSTANCE);
				return record;
			}
			int size = input.getSize();
			long bits = value.getOffset();
			if (size > 0 && size < 8) {
				bits &= (1L << (8 * size)) - 1;
			}
			record.addProperty("value", Long.toUnsignedString(bits, 16));
			if (size > 0 && size <= 8) {
				int shift = 64 - 8 * size;
				record.addProperty("signed", (bits << shift) >> shift);
			}
			else {
				record.add("signed", JsonNull.INSTANCE);
			}
			record.add("variable", JsonNull.INSTANCE);
			AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
			Address target = null;
			if (size <= 8) {
				try {
					target = space.getAddress(bits);
				}
				catch (AddressOutOfBoundsException outside) {
					target = null;
				}
			}
			MemoryBlock block = target == null ? null : program.getMemory().getBlock(target);
			Symbol symbol = block == null ? null : program.getSymbolTable().getPrimarySymbol(target);
			Data data = block == null ? null : program.getListing().getDefinedDataAt(target);
			boolean address = block != null && (pointer ||
				size == space.getPointerSize() && (symbol != null || data != null));
			if (!address) {
				record.addProperty("kind", "constant");
				record.add("symbol", JsonNull.INSTANCE);
				record.add("string", JsonNull.INSTANCE);
				record.add("string_source", JsonNull.INSTANCE);
				return record;
			}
			record.addProperty("kind", "address");
			record.addProperty("symbol", symbol == null ? null : text(symbol.getName(true)));
			String string = null;
			String source = null;
			if (data != null && data.hasStringValue()) {
				string = clip(printable(data.getDefaultValueRepresentation()), MAXIMUM_STRING);
				source = "defined_data";
			}
			else if (data == null && block.isInitialized() && !block.isExecute()) {
				string = scanAscii(target);
				source = string == null ? null : "memory_scan";
			}
			record.addProperty("string", string);
			record.addProperty("string_source", source);
			return record;
		}

		/**
		 * A NUL-terminated printable ASCII string at an address, quoted and escaped, or null. The
		 * quoted text is at most {@link #MAXIMUM_STRING} characters; a longer string ends in "...
		 */
		private String scanAscii(Address start) {
			StringBuilder builder = new StringBuilder("\"");
			Address at = start;
			try {
				while (true) {
					byte value = program.getMemory().getByte(at);
					if (value == 0) {
						return builder.length() == 1 ? null : builder.append('"').toString();
					}
					String piece = switch (value) {
						case '\n' -> "\\n";
						case '\t' -> "\\t";
						case '\r' -> "\\r";
						case '"' -> "\\\"";
						case '\\' -> "\\\\";
						default -> value < 0x20 || value > 0x7e ? null : String.valueOf((char) value);
					};
					if (piece == null) {
						return null;
					}
					if (builder.length() + piece.length() > MAXIMUM_STRING - 4) {
						return builder.append("\"...").toString();
					}
					builder.append(piece);
					at = at.addNoWrap(1);
				}
			}
			catch (MemoryAccessException | ghidra.program.model.address.AddressOverflowException end) {
				return null;
			}
		}

		private static String variable(Varnode input) {
			// Locals, parameters, globals and named temporaries: the name the C statement shows.
			HighVariable high = input.getHigh();
			if (high == null || high instanceof HighConstant) {
				return null;
			}
			String name = high.getName();
			return name == null || name.isBlank() || name.equals("UNNAMED") ? null : text(name);
		}

		private JsonObject siteRecord(Site site, Function caller, String status, String reason) {
			JsonObject record = new JsonObject();
			record.addProperty("address_space", site.address().getAddressSpace().getName());
			record.addProperty("address", hex(site.address()));
			record.addProperty("target_address_space", site.target().getAddressSpace().getName());
			record.addProperty("target_address", hex(site.target()));
			record.add("caller", caller == null ? JsonNull.INSTANCE : functionRecord(caller));
			record.addProperty("status", status);
			record.addProperty("reason", reason);
			record.add("operation", JsonNull.INSTANCE);
			record.add("statement", JsonNull.INSTANCE);
			record.add("arguments", new JsonArray());
			record.addProperty("arguments_truncated", false);
			record.addProperty("instruction_sha256", instructionDigest(site.address()));
			return record;
		}

		private static JsonObject functionRecord(Function function) {
			JsonObject record = new JsonObject();
			Address entry = function.getEntryPoint();
			record.addProperty("address_space", entry.getAddressSpace().getName());
			record.addProperty("address", hex(entry));
			record.addProperty("name", text(function.getName(true)));
			return record;
		}

		private String instructionDigest(Address site) {
			var instruction = program.getListing().getInstructionAt(site);
			if (instruction == null) {
				return null;
			}
			int length = instruction.getParsedLength();
			if (length <= 0 || length > MAXIMUM_INSTRUCTION_BYTES) {
				return null;
			}
			try {
				byte[] bytes = instruction.getParsedBytes();
				return bytes.length == length ? HashUtilities.getHash("SHA-256", bytes) : null;
			}
			catch (MemoryAccessException unavailable) {
				return null;
			}
		}

		private void configure(DecompInterface decompiler) {
			DecompileOptions options = new DecompileOptions();
			options.grabFromProgram(program);
			options.setMaxPayloadMBytes(Math.min(options.getMaxPayloadMBytes(), 16));
			options.setMaxInstructions(Math.min(options.getMaxInstructions(), 16_384));
			decompiler.setOptions(options);
			decompiler.setSimplificationStyle("decompile");
			decompiler.toggleCCode(true);
			decompiler.toggleSyntaxTree(true);
		}

		private void checkCurrent() throws Exception {
			monitor.checkCancelled();
			if (program.isClosed() || revision != program.getModificationNumber()) {
				throw new IllegalStateException("Program changed during call-site recovery");
			}
		}
	}

	/** Collapses whitespace, replaces control characters and bounds the length. */
	private static String text(String value) {
		return clip(printable(value.replaceAll("\\s+", " ").strip()), MAXIMUM_STATEMENT);
	}

	private static String printable(String value) {
		StringBuilder builder = new StringBuilder(value.length());
		value.codePoints().forEach(point -> builder.appendCodePoint(
			Character.isISOControl(point) || point >= Character.MIN_SURROGATE &&
				point <= Character.MAX_SURROGATE ? '?' : point));
		return builder.toString();
	}

	private static String clip(String value, int limit) {
		if (value.length() <= limit) {
			return value;
		}
		int end = limit - 3;
		if (Character.isHighSurrogate(value.charAt(end - 1)) && Character.isLowSurrogate(value.charAt(end))) {
			end--;
		}
		return value.substring(0, end) + "...";
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
