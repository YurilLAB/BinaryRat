// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import binaryrat.CallSites;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * Edge cases of the call-site service on a disposable x86-64 Program: direct, thunk, recursive
 * and indirect calls, a call outside any function, a thunk caller, references the decompiler
 * does not show as a call, limits, cancellation and a Program change during the run. Runs as a
 * headless project-only preScript, from a checkout or against the installed extension.
 */
public class BinaryRatCallSitesProof extends GhidraScript {
	private static final String TABLE = "binaryrat.desktop.CallSitesTable";
	private static final long HUGE_ENTRY = 0x20000;
	private static final int HUGE_INSTRUCTIONS = 17_000;
	private static final String HUGE_CALL = Long.toHexString(HUGE_ENTRY + 2 * HUGE_INSTRUCTIONS);
	private ProgramDB program;
	private Function callee;
	private Function thunk;
	private Function lonely;
	private Function takesPointer;

	@Override
	protected void run() throws Exception {
		if (!isRunningHeadless() || currentProgram != null) {
			throw new IllegalStateException("Run as a headless project-only preScript");
		}
		String[] args = getScriptArgs();
		Path output = args.length == 1 ? Path.of(args[0]).toAbsolutePath().normalize() : null;
		if (args.length > 1 || output != null && Files.exists(output, LinkOption.NOFOLLOW_LINKS)) {
			throw new IllegalArgumentException("optional argument: a new REPORT_JSON path");
		}
		var language = DefaultLanguageService.getLanguageService()
			.getLanguage(new LanguageID("x86:LE:64:default"));
		program = new ProgramDB("BinaryRat disposable call-site fixture", language,
			language.getCompilerSpecByID(new CompilerSpecID("gcc")), this);
		try {
			setup();
			JsonObject report = CallSites.recover(program, callee, 60, CallSites.DEFAULT_SITES,
				CallSites.DEFAULT_CALLERS, monitor);
			full(report);
			viaThunk(report);
			globalPointer();
			JsonObject callerLimited = limits();
			Set<String> statuses = new TreeSet<>();
			for (JsonObject seen : List.of(report, callerLimited)) {
				for (JsonElement site : seen.getAsJsonArray("sites")) {
					statuses.add(site.getAsJsonObject().get("status").getAsString());
				}
			}
			require(statuses.size() == 6, "statuses exercised: " + statuses);
			require(CallSites.recover(program, callee, 60, CallSites.DEFAULT_SITES,
				CallSites.DEFAULT_CALLERS, monitor).equals(report), "a second run gave a different report");
			boolean table = table(report);
			rejected();
			CountingMonitor counter = new CountingMonitor(Integer.MAX_VALUE, () -> {
			});
			CallSites.recover(program, callee, 60, 64, 32, counter);
			int checks = counter.checks;
			require(checks > 20, "too few cancellation checks: " + checks);
			cancellation(checks);
			programChange(checks);
			if (output != null) {
				Files.writeString(output, new GsonBuilder().serializeNulls().setPrettyPrinting().create()
					.toJson(report) + "\n", StandardCharsets.UTF_8);
			}
			println("BINARYRAT_CALL_SITES_OK sites=" + report.getAsJsonArray("sites").size() +
				" statuses=" + statuses.size() + " thunk=true limits=true checks=" + checks +
				" cancellation=true program_change=true" +
				" deterministic=true table=" + table);
		}
		finally {
			program.release(this);
		}
	}

	private void setup() throws Exception {
		var space = program.getAddressFactory().getDefaultAddressSpace();
		var flat = new FlatProgramAPI(program, monitor);
		int transaction = program.startTransaction("Build disposable call-site fixture");
		boolean commit = false;
		try {
			var memory = program.getMemory();
			var text = memory.createInitializedBlock(".text", space.getAddress(0x1000), 0x400, (byte) 0xcc,
				monitor, false);
			text.setExecute(true);
			var rodata = memory.createInitializedBlock(".rodata", space.getAddress(0x3000), 0x40, (byte) 0,
				monitor, false);
			rodata.setWrite(false);
			rodata.setExecute(false);
			memory.setBytes(space.getAddress(0x3000), "hello\0".getBytes(StandardCharsets.US_ASCII));
			memory.setBytes(space.getAddress(0x3010), "raw text\0".getBytes(StandardCharsets.US_ASCII));
			// caller: callee(7, "hello"); thunk(-1, raw_label); callee(result, 0)
			bytes(0x1000, "bf07000000be00300000e871000000bfffffffffbe10300000e8a200000089c731f6e859000000c3");
			// callee: if (a > 0) return callee(a - 1, s); return a
			bytes(0x1080, "85ff7e0cffcfe8f5ffffffc3cccccccc89f8c3");
			bytes(0x10c0, "e9bbffffff");                  // thunk: jmp callee
			bytes(0x1140, "e83bffffffc3");                // a call outside any function
			bytes(0x1180, "48c7c080100000bf05000000ffd0c3"); // mov rax, callee; call rax
			bytes(0x11c0, "e8bbfeffffc3");                // a thunk whose body calls callee
			bytes(0x1200, "31c0c3");                      // callee2
			bytes(0x1240, "e8bbffffffc3");                // other_caller: call callee2
			bytes(0x1280, "31c0c3");                      // lonely: never called
			bytes(0x12c0, "8b07c3");                      // takes_pointer: return *p
			bytes(0x1300, "bf20300000e8b6ffffffc3");      // pointer_caller: takes_pointer(&global_count)
			// huge_caller: 17,000 two-byte "add al, imm8", then call callee. The service caps the
			// decompiler at 16,384 instructions, so this caller's decompilation fails while its body
			// stays under 64 KiB. The immediates vary: Ghidra's disassembler stops at long runs of
			// identical instructions.
			memory.createInitializedBlock(".text.huge", space.getAddress(HUGE_ENTRY), 2 * HUGE_INSTRUCTIONS + 16,
				(byte) 0xcc, monitor, false).setExecute(true);
			byte[] body = new byte[2 * HUGE_INSTRUCTIONS];
			for (int index = 0; index < HUGE_INSTRUCTIONS; index++) {
				body[2 * index] = 0x04;
				body[2 * index + 1] = (byte) index;
			}
			memory.setBytes(space.getAddress(HUGE_ENTRY), body);
			long call = HUGE_ENTRY + 2 * HUGE_INSTRUCTIONS;
			int relative = (int) (0x1080 - (call + 5));
			bytes(call, String.format("e8%02x%02x%02x%02xc3", relative & 0xff, relative >>> 8 & 0xff,
				relative >>> 16 & 0xff, relative >>> 24 & 0xff));
			flat.createAsciiString(space.getAddress(0x3000));
			program.getSymbolTable().createLabel(space.getAddress(0x3010), "raw_label", SourceType.USER_DEFINED);
			flat.createData(space.getAddress(0x3020), IntegerDataType.dataType);
			program.getSymbolTable().createLabel(space.getAddress(0x3020), "global_count", SourceType.USER_DEFINED);

			callee = function(flat, 0x1080, "callee");
			callee.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
			callee.replaceParameters(FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true,
				SourceType.USER_DEFINED, new ParameterImpl("a", IntegerDataType.dataType, program),
				new ParameterImpl("s", new PointerDataType(CharDataType.dataType), program));
			function(flat, 0x1000, "caller");
			thunk = function(flat, 0x10c0, "callee_thunk");
			thunk.setThunkedFunction(callee);
			require(flat.disassemble(space.getAddress(0x1140)), "could not disassemble the orphan call");
			function(flat, 0x1180, "indirect_caller");
			function(flat, 0x11c0, "call_thunk").setThunkedFunction(callee);
			function(flat, 0x1200, "callee2");
			function(flat, 0x1240, "other_caller");
			lonely = function(flat, 0x1280, "lonely");
			takesPointer = function(flat, 0x12c0, "takes_pointer");
			takesPointer.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
			takesPointer.replaceParameters(FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true,
				SourceType.USER_DEFINED, new ParameterImpl("p", new PointerDataType(IntegerDataType.dataType), program));
			function(flat, 0x1300, "pointer_caller");
			function(flat, HUGE_ENTRY, "huge_caller");

			var references = program.getReferenceManager();
			references.addMemoryReference(space.getAddress(0x118c), callee.getEntryPoint(),
				RefType.COMPUTED_CALL, SourceType.USER_DEFINED, 0);
			// Call references the decompiled code does not show as a call to callee.
			references.addMemoryReference(space.getAddress(0x1000), callee.getEntryPoint(),
				RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0);
			references.addMemoryReference(space.getAddress(0x1240), callee.getEntryPoint(),
				RefType.COMPUTED_CALL, SourceType.USER_DEFINED, 0);
			commit = true;
		}
		finally {
			program.endTransaction(transaction, commit);
		}
		program.clearUndo();
	}

	private void bytes(long offset, String hex) throws Exception {
		program.getMemory().setBytes(program.getAddressFactory().getDefaultAddressSpace().getAddress(offset),
			HexFormat.of().parseHex(hex));
	}

	private Function function(FlatProgramAPI flat, long offset, String name) throws Exception {
		Address entry = program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
		require(flat.disassemble(entry), "could not disassemble " + name);
		Function created = flat.createFunction(entry, name);
		require(created != null, "could not create " + name);
		return created;
	}

	private void full(JsonObject report) throws Exception {
		require(report.get("schema_version").getAsInt() == 1 &&
			report.get("analysis_mode").getAsString().equals(CallSites.ANALYSIS_MODE) &&
			report.get("revision").getAsLong() == program.getModificationNumber() &&
			report.get("program_id").isJsonNull(), "report header");
		require(report.get("call_references").getAsInt() == 10 && !report.get("truncated").getAsBoolean() &&
			report.get("decompiled_callers").getAsInt() == 5, "counts: " + report.get("call_references") +
			" calls, " + report.get("decompiled_callers") + " callers");
		Set<String> targets = new TreeSet<>();
		for (JsonElement element : report.getAsJsonArray("targets")) {
			JsonObject target = element.getAsJsonObject();
			targets.add(target.get("address").getAsString() + ":" + target.get("thunk").getAsBoolean());
		}
		require(targets.equals(Set.of("1080:false", "10c0:true", "11c0:true")), "targets " + targets);
		expectSite(report, "1000", CallSites.NOT_IN_DECOMPILATION, "caller", "emitted no call");
		JsonObject first = expectSite(report, "100a", CallSites.DECOMPILED, "caller", null);
		require(first.get("operation").getAsString().equals("CALL") &&
			first.get("statement").getAsString().contains("callee(7,") &&
			first.get("instruction_sha256").getAsString().matches("[0-9a-f]{64}"), "direct call " + first);
		expectArgument(first, 0, "constant", "7", 7);
		JsonObject hello = expectArgument(first, 1, "address", "3000", null);
		require(hello.get("string").getAsString().equals("\"hello\"") &&
			hello.get("string_source").getAsString().equals("defined_data"), "defined string " + hello);
		JsonObject viaThunk = expectSite(report, "1019", CallSites.DECOMPILED, "caller", null);
		require(viaThunk.get("target_address").getAsString().equals("10c0"), "thunk call target");
		expectArgument(viaThunk, 0, "constant", "ffffffff", -1);
		JsonObject raw = expectArgument(viaThunk, 1, "address", "3010", null);
		require(raw.get("symbol").getAsString().equals("raw_label") &&
			raw.get("string").getAsString().equals("\"raw text\"") &&
			raw.get("string_source").getAsString().equals("memory_scan"), "scanned string " + raw);
		JsonObject third = expectSite(report, "1022", CallSites.DECOMPILED, "caller", null);
		expectArgument(third, 0, "unknown", null, null);
		expectArgument(third, 1, "constant", "0", 0);
		JsonObject recursive = expectSite(report, "1086", CallSites.DECOMPILED, "callee", null);
		expectArgument(recursive, 0, "unknown", null, null);
		require(expectArgument(recursive, 1, "unknown", null, null).get("variable").getAsString().equals("s"),
			"forwarded parameter name");
		expectSite(report, "1140", CallSites.NO_FUNCTION, null, "not inside a defined function");
		JsonObject indirect = expectSite(report, "118c", CallSites.DECOMPILED, "indirect_caller", null);
		require(Set.of("CALL", "CALLIND").contains(indirect.get("operation").getAsString()), "indirect op");
		if (indirect.get("operation").getAsString().equals("CALL")) {
			expectArgument(indirect, 0, "constant", "5", 5);
		}
		expectSite(report, "11c0", CallSites.UNSUPPORTED_CALLER, "call_thunk", "a thunk");
		expectSite(report, "1240", CallSites.NOT_IN_DECOMPILATION, "other_caller", "another target");
		expectSite(report, HUGE_CALL, CallSites.DECOMPILE_FAILED, "huge_caller", "decompiler failed");
		require(report.getAsJsonArray("sites").size() == 10, "site rows");
	}

	/** The address of a typed global: the decompiler writes it as PTRSUB(0, address). */
	private void globalPointer() throws Exception {
		JsonObject report = CallSites.recover(program, takesPointer, 60, CallSites.DEFAULT_SITES,
			CallSites.DEFAULT_CALLERS, monitor);
		JsonObject site = expectSite(report, "1305", CallSites.DECOMPILED, "pointer_caller", null);
		JsonObject pointer = expectArgument(site, 0, "address", "3020", 0x3020);
		require(pointer.get("symbol").getAsString().equals("global_count") && pointer.get("string").isJsonNull(),
			"global pointer " + pointer + " in " + site.get("statement"));
	}

	private void viaThunk(JsonObject direct) throws Exception {
		JsonObject report = CallSites.recover(program, thunk, 60, CallSites.DEFAULT_SITES,
			CallSites.DEFAULT_CALLERS, monitor);
		// Ghidra names a thunk after the function it reaches, so the addresses tell them apart.
		require(report.getAsJsonObject("function").get("address").getAsString().equals("10c0") &&
			report.getAsJsonObject("root_function").get("address").getAsString().equals("1080") &&
			report.get("sites").equals(direct.get("sites")), "a thunk did not resolve to its function's calls: " +
			report.get("function") + " " + report.get("root_function") + " " +
			report.get("sites").equals(direct.get("sites")));
		JsonObject none = CallSites.recover(program, lonely, 60, CallSites.DEFAULT_SITES,
			CallSites.DEFAULT_CALLERS, monitor);
		require(none.getAsJsonArray("sites").isEmpty() && none.get("call_references").getAsInt() == 0 &&
			none.get("decompiled_callers").getAsInt() == 0, "uncalled function");
	}

	private JsonObject limits() throws Exception {
		JsonObject sites = CallSites.recover(program, callee, 60, 2, CallSites.DEFAULT_CALLERS, monitor);
		require(sites.get("truncated").getAsBoolean() && sites.get("call_references").getAsInt() == 10 &&
			sites.getAsJsonArray("sites").size() == 2 && sites.get("decompiled_callers").getAsInt() == 1,
			"site limit");
		JsonObject callers = CallSites.recover(program, callee, 60, CallSites.DEFAULT_SITES, 1, monitor);
		require(callers.get("decompiled_callers").getAsInt() == 1, "caller limit count");
		expectSite(callers, "100a", CallSites.DECOMPILED, "caller", null);
		expectSite(callers, "1086", CallSites.CALLER_LIMIT, "callee", "limit of 1");
		expectSite(callers, "118c", CallSites.CALLER_LIMIT, "indirect_caller", "limit of 1");
		expectSite(callers, "1240", CallSites.CALLER_LIMIT, "other_caller", "limit of 1");
		expectSite(callers, HUGE_CALL, CallSites.CALLER_LIMIT, "huge_caller", "limit of 1");
		return callers;
	}

	private void rejected() throws Exception {
		int[][] bad = { { 0, 1, 1 }, { 601, 1, 1 }, { 1, 0, 1 }, { 1, 1_025, 1 }, { 1, 1, 0 }, { 1, 1, 257 } };
		for (int[] limits : bad) {
			expect(IllegalArgumentException.class, () ->
				CallSites.recover(program, callee, limits[0], limits[1], limits[2], monitor));
		}
		expect(IOException.class, () -> CallSites.recover(program, null, 1, 1, 1, monitor));
		expect(IOException.class, () -> CallSites.recover(null, callee, 1, 1, 1, monitor));
	}

	private void cancellation(int checks) throws Exception {
		TaskMonitorAdapter cancelled = new TaskMonitorAdapter(true);
		cancelled.cancel();
		expect(CancelledException.class, () -> CallSites.recover(program, callee, 60, 64, 32, cancelled));
		// Cancel at successive points, through the scan and the decompilations.
		for (int after = 1; after <= checks; after += 2) {
			CountingMonitor late = new CountingMonitor(after, () -> {
			});
			expect(CancelledException.class, () -> CallSites.recover(program, callee, 60, 64, 32, late));
		}
	}

	private void programChange(int checks) throws Exception {
		for (int after = 1; after <= checks; after += 3) {
			CountingMonitor changing = new CountingMonitor(after, () -> {
				int transaction = program.startTransaction("Change during call-site recovery");
				try {
					program.getSymbolTable().createLabel(program.getAddressFactory().getDefaultAddressSpace()
						.getAddress(0x3020), "late_" + program.getModificationNumber(), SourceType.USER_DEFINED);
				}
				catch (Exception failure) {
					throw new IllegalStateException(failure);
				}
				finally {
					program.endTransaction(transaction, true);
				}
			});
			changing.cancelInstead = false;
			expect(IllegalStateException.class, () -> CallSites.recover(program, callee, 60, 64, 32, changing));
		}
	}

	/** Checks the desktop formatting when BinaryRat.jar is installed; a checkout run has no table. */
	private boolean table(JsonObject report) throws Exception {
		Class<?> table;
		try {
			table = Class.forName(TABLE, true, ClassLoader.getSystemClassLoader());
		}
		catch (ClassNotFoundException missing) {
			println("Call-site table formatting skipped: BinaryRat.jar is not installed");
			return false;
		}
		List<?> rows;
		try {
			rows = (List<?>) table.getMethod("rows", Program.class, JsonObject.class)
				.invoke(null, program, report);
		}
		catch (InvocationTargetException failure) {
			throw new IOException("call-site table rows failed", failure.getCause());
		}
		require(rows.size() == 10, "table rows");
		String first = String.valueOf(rows.get(1));
		String second = String.valueOf(rows.get(2));
		require(first.contains("arguments=7, \"hello\"") && second.contains("arguments=-1, \"raw text\"") &&
			String.valueOf(rows.get(5)).contains("caller=(no function)"), "table formatting: " + rows);
		return true;
	}

	private JsonObject expectSite(JsonObject report, String address, String status, String caller,
			String reason) throws IOException {
		for (JsonElement element : report.getAsJsonArray("sites")) {
			JsonObject site = element.getAsJsonObject();
			if (!site.get("address").getAsString().equals(address)) {
				continue;
			}
			String name = site.get("caller").isJsonNull() ? null :
				site.getAsJsonObject("caller").get("name").getAsString();
			require(site.get("status").getAsString().equals(status) &&
				(caller == null ? name == null : caller.equals(name)) &&
				(reason == null ? site.get("reason").isJsonNull() :
					site.get("reason").getAsString().contains(reason)) &&
				(status.equals(CallSites.DECOMPILED) || site.get("statement").isJsonNull() &&
					site.getAsJsonArray("arguments").isEmpty()), "site " + address + ": " + site);
			return site;
		}
		throw new IOException("missing site " + address);
	}

	private static JsonObject expectArgument(JsonObject site, int index, String kind, String value,
			Integer signed) throws IOException {
		var arguments = site.getAsJsonArray("arguments");
		require(arguments.size() > index, "missing argument " + index + " in " + site);
		JsonObject argument = arguments.get(index).getAsJsonObject();
		require(argument.get("index").getAsInt() == index && argument.get("kind").getAsString().equals(kind) &&
			(value == null ? argument.get("value").isJsonNull() : argument.get("value").getAsString().equals(value)) &&
			(signed == null || argument.get("signed").getAsLong() == signed), "argument " + index + ": " + argument +
			" in " + site.get("statement"));
		return argument;
	}

	private interface Action {
		void run() throws Exception;
	}

	private static void expect(Class<? extends Throwable> type, Action action) throws IOException {
		try {
			action.run();
		}
		catch (Throwable thrown) {
			if (type.isInstance(thrown)) {
				return;
			}
			throw new IOException("expected " + type.getSimpleName() + " but got " + thrown, thrown);
		}
		throw new IOException("expected " + type.getSimpleName());
	}

	private static void require(boolean condition, String message) throws IOException {
		if (!condition) {
			throw new IOException("call-site proof failed: " + message);
		}
	}

	/** Cancels, or runs a change, on the Nth cancellation check. */
	private static final class CountingMonitor extends TaskMonitorAdapter {
		private final int trigger;
		private final Runnable change;
		private int checks;
		boolean cancelInstead = true;

		CountingMonitor(int trigger, Runnable change) {
			super(true);
			this.trigger = trigger;
			this.change = change;
		}

		@Override
		public void checkCancelled() throws CancelledException {
			if (++checks == trigger) {
				if (cancelInstead) {
					cancel();
				}
				else {
					change.run();
				}
			}
			super.checkCancelled();
		}
	}
}
