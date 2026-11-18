// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package binaryrat;

import java.io.IOException;
import java.nio.file.Path;
import java.util.*;
import java.util.function.Consumer;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

/**
 * Proves that live-cached decompiler output equals fresh decompilation while the
 * program changes. Every round applies one change, then looks every function up in
 * the cache with auditing on and decompiles it fresh with a stock decompiler:
 * <ul>
 * <li>every result the cache serves must equal the fresh output byte for byte;</li>
 * <li>an entry the engine vouched for must also replay cleanly, or a change was
 * missed (a stale result would have been served without the audit);</li>
 * <li>a negative control drops the change reports for one change and must be caught.</li>
 * </ul>
 */
public final class CacheProof {
	private final Program program;
	private final TaskMonitor monitor;
	private final Path engineBinary;
	private final Path cacheDirectory;
	private final Consumer<DecompInterface> configure;
	private final String programId;
	private final List<Function> functions;
	private final int timeoutSeconds;
	private final Consumer<String> log;

	private EngineClient engine;
	private ChangeTracker tracker;
	private LiveDecompileCache cache;
	private TracingDecompiler fresh;
	private final Map<Address, DecompOutput> previous = new HashMap<>();
	private final Set<Address> cached = new HashSet<>();
	private final JsonArray rounds = new JsonArray();
	private int failures;
	private int counter;

	public CacheProof(Program program, TaskMonitor monitor, Path engineBinary, Path cacheDirectory,
			Consumer<DecompInterface> configure, String programId, List<Function> functions,
			int timeoutSeconds, Consumer<String> log) {
		this.program = program;
		this.monitor = monitor;
		this.engineBinary = engineBinary;
		this.cacheDirectory = cacheDirectory;
		this.configure = configure;
		this.programId = programId;
		this.functions = functions;
		this.timeoutSeconds = timeoutSeconds;
		this.log = log;
	}

	private void open() throws IOException {
		engine = EngineClient.start(engineBinary, cacheDirectory);
		tracker = new ChangeTracker(program, engine);
		DecompileOptions options = fresh.getOptions();
		cache = new LiveDecompileCache(engine, program, tracker, options, programId,
			fresh.registrationDigest());
	}

	private void shut() throws IOException {
		if (tracker != null) {
			tracker.close();
			tracker = null;
		}
		if (engine != null) {
			engine.close();
			engine = null;
		}
	}

	/** Runs every round and returns the report; report.passed says whether the proof holds. */
	public JsonObject run() throws Exception {
		fresh = new TracingDecompiler();
		configure.accept(fresh);
		if (!fresh.openProgram(program)) {
			throw new IOException("cannot start decompiler: " + fresh.getLastMessage());
		}
		JsonObject report = new JsonObject();
		report.addProperty("functions", functions.size());
		try {
			open();
			round("populate", null, false, Expect.ANY);
			round("no change", null, false, Expect.ALL_HITS);
			round("bookmark (never read by the decompiler)", () -> {
				Function first = functions.get(0);
				program.getBookmarkManager().setBookmark(first.getEntryPoint(),
					BookmarkType.NOTE, "BinaryRat", "probe");
			}, false, Expect.ALL_HITS);
			round("comment outside every function", this::commentOutsideFunctions, false, Expect.ANY);
			round("rename a called function", this::renameCallee, false, Expect.ANY);
			round("change a called function's return type", this::retypeCallee, false, Expect.ANY);
			round("comment inside a function body", this::commentInBody, false, Expect.ANY);
			round("rename a parameter", this::renameParameter, false, Expect.ANY);
			round("retype referenced global data", this::retypeGlobal, false, Expect.ANY);
			round("add an unused data type (reach unknown)", () -> program.getDataTypeManager()
					.addDataType(new StructureDataType("binaryrat_probe_" + (++counter), 8),
						DataTypeConflictHandler.DEFAULT_HANDLER),
				false, Expect.NO_MISSES);
			round("patch an instruction's immediate", this::patchImmediate, false, Expect.ANY);
			undoRedo();
			round("set a register value across several functions", this::contextAcrossFunctions,
				false, Expect.ANY);
			round("add a label inside a function body", this::labelInBody, false, Expect.ANY);
			round("override a call's flow to a branch", this::overrideCallFlow, false, Expect.ANY);
			round("edit a data type a function uses (reach unknown)", this::editUsedType, false,
				Expect.ANY);
			round("delete a called function", this::deleteCallee, false, Expect.ANY);
			offlineEdit();
			negativeControl();
			JsonObject timing = timing();
			report.add("timing", timing);
		}
		finally {
			shut();
			fresh.dispose();
		}
		report.add("rounds", rounds);
		report.addProperty("failures", failures);
		report.addProperty("passed", failures == 0);
		return report;
	}

	private enum Expect {
		ANY, ALL_HITS, NO_MISSES
	}

	@FunctionalInterface
	private interface Change {
		void apply() throws Exception;
	}

	/** Undo and redo must run outside any transaction. */
	@FunctionalInterface
	private interface Undoing extends Change {
	}

	private boolean change(String name, Change change) throws Exception {
		if (change instanceof Undoing) {
			change.apply();
			return true;
		}
		int transaction = program.startTransaction("BinaryRat cache proof: " + name);
		boolean applied = false;
		try {
			change.apply();
			applied = true;
		}
		catch (Skip skip) {
			log.accept("BinaryRat cache proof skipped change: " + name + " (" + skip.getMessage() + ")");
		}
		finally {
			program.endTransaction(transaction, applied);
		}
		return applied;
	}

	private static final class Skip extends Exception {
		Skip(String why) {
			super(why);
		}
	}

	private JsonObject round(String name, Change change, boolean blind, Expect expect)
			throws Exception {
		JsonObject result = new JsonObject();
		result.addProperty("name", name);
		ChangeTracker.Counts before = snapshot(tracker.counts());
		if (change != null) {
			if (blind) {
				tracker.setBlind(true);
			}
			boolean applied;
			try {
				applied = change(name, change);
				program.flushEvents();
			}
			finally {
				if (blind) {
					// Read the events away while still blind, then restore reporting.
					tracker.sync();
					tracker.setBlind(false);
				}
			}
			if (!applied) {
				result.addProperty("skipped", true);
				rounds.add(result);
				return result;
			}
		}
		int hits = 0, replayed = 0, misses = 0, rejectedReplays = 0, staleVouched = 0,
				servedWrong = 0, changedOutputs = 0, missedButUnchanged = 0, stored = 0,
				lostEntries = 0;
		Set<Address> expected = new HashSet<>(cached);
		List<String> examples = new ArrayList<>();
		for (Function function : functions) {
			monitor.checkCancelled();
			long modification = program.getModificationNumber();
			LiveDecompileCache.Lookup lookup = cache.lookup(function, true);
			TracingDecompiler.Traced decompiled = fresh.decompile(function, timeoutSeconds, monitor);
			DecompOutput now = DecompOutput.of(decompiled.results());
			DecompOutput before0 = previous.put(function.getEntryPoint(), now);
			boolean changed = before0 != null && !before0.equals(now);
			if (changed) {
				changedOutputs++;
			}
			switch (lookup.kind()) {
				case HIT -> {
					hits++;
					if (lookup.rejected() != null) {
						staleVouched++;
						example(examples, function, "vouched entry failed replay: " + lookup.rejected());
					}
				}
				case REPLAYED -> replayed++;
				case MISS -> {
					misses++;
					cached.remove(function.getEntryPoint());
					if (expected.contains(function.getEntryPoint())) {
						lostEntries++;
					}
					if (lookup.rejected() != null) {
						rejectedReplays++;
					}
					if (!changed && before0 != null) {
						missedButUnchanged++;
					}
				}
			}
			if (lookup.output() != null && !lookup.output().equals(now)) {
				servedWrong++;
				example(examples, function, "cached output differs from fresh decompilation");
			}
			if (lookup.kind() == LiveDecompileCache.Kind.MISS || lookup.rejected() != null) {
				if (cache.store(function, now, decompiled.trace(), lookup.seq(), modification)) {
					stored++;
					cached.add(function.getEntryPoint());
				}
			}
		}
		ChangeTracker.Counts after = tracker.counts();
		result.addProperty("hits", hits);
		result.addProperty("replayed_hits", replayed);
		result.addProperty("misses", misses);
		result.addProperty("rejected_by_replay", rejectedReplays);
		result.addProperty("vouched_but_stale", staleVouched);
		result.addProperty("served_different_from_fresh", servedWrong);
		result.addProperty("outputs_changed", changedOutputs);
		result.addProperty("removed_but_unchanged", missedButUnchanged);
		result.addProperty("stored", stored);
		result.addProperty("change_records", after.records - before.records);
		result.addProperty("precise_records", after.precise - before.precise);
		result.addProperty("unknown_reach_records", after.unknownReach - before.unknownReach);
		result.addProperty("ignored_records", after.ignored - before.ignored);
		result.addProperty("entries_removed_by_changes", after.removed - before.removed);
		JsonArray shown = new JsonArray();
		examples.forEach(shown::add);
		result.add("examples", shown);
		result.addProperty("cached_entries_lost", lostEntries);
		boolean ok = blind ? staleVouched > 0 : staleVouched == 0 && servedWrong == 0;
		if (ok && expect != Expect.ANY) {
			// Precision: a change that cannot affect a decompilation must not cost its entry.
			ok = lostEntries == 0;
		}
		if (ok && expect == Expect.ALL_HITS) {
			ok = after.removed == before.removed && after.unknownReach == before.unknownReach;
		}
		result.addProperty("passed", ok);
		if (!ok) {
			failures++;
		}
		rounds.add(result);
		log.accept("BinaryRat cache proof round \"" + name + "\" " + (ok ? "passed" : "FAILED") +
			": hits=" + hits + " replayed=" + replayed + " misses=" + misses + " changed=" +
			changedOutputs + " stale_vouched=" + staleVouched + " served_wrong=" + servedWrong);
		return result;
	}

	private static ChangeTracker.Counts snapshot(ChangeTracker.Counts counts) {
		ChangeTracker.Counts copy = new ChangeTracker.Counts();
		copy.records = counts.records;
		copy.precise = counts.precise;
		copy.unknownReach = counts.unknownReach;
		copy.ignored = counts.ignored;
		copy.removed = counts.removed;
		return copy;
	}

	private static void example(List<String> examples, Function function, String what) {
		if (examples.size() < 5) {
			examples.add(function.getName() + "@" + function.getEntryPoint() + ": " + what);
		}
	}

	// ---- the changes -----------------------------------------------------------------

	private Function calledFunction() throws Skip {
		for (Function function : functions) {
			if (!function.isThunk() && !function.getCallingFunctions(monitor).isEmpty()) {
				return function;
			}
		}
		throw new Skip("no function with callers");
	}

	private void renameCallee() throws Exception {
		calledFunction().setName("binaryrat_renamed_" + (++counter), SourceType.USER_DEFINED);
	}

	private void retypeCallee() throws Exception {
		Function callee = calledFunction();
		DataType current = callee.getReturnType();
		DataType replacement = current.getLength() == 8 ? IntegerDataType.dataType :
			LongLongDataType.dataType;
		callee.setReturnType(replacement, SourceType.USER_DEFINED);
	}

	private void commentInBody() throws Exception {
		for (Function function : functions) {
			Address entry = function.getEntryPoint();
			for (Instruction instruction : program.getListing().getInstructions(function.getBody(), true)) {
				if (!instruction.getAddress().equals(entry)) {
					program.getListing().setComment(instruction.getAddress(), CommentType.PRE,
						"BinaryRat probe " + (++counter));
					return;
				}
			}
		}
		throw new Skip("no multi-instruction function");
	}

	private void commentOutsideFunctions() throws Exception {
		Memory memory = program.getMemory();
		for (MemoryBlock block : memory.getBlocks()) {
			if (!block.isInitialized() || block.isExecute()) {
				continue;
			}
			Address candidate = block.getEnd();
			if (program.getFunctionManager().getFunctionContaining(candidate) == null) {
				program.getListing().setComment(candidate, CommentType.EOL, "BinaryRat probe");
				return;
			}
		}
		throw new Skip("no initialized non-executable block");
	}

	private void renameParameter() throws Exception {
		for (Function function : functions) {
			if (function.getParameterCount() > 0 && !function.isThunk()) {
				function.getParameter(0).setName("binaryrat_arg" + (++counter), SourceType.USER_DEFINED);
				return;
			}
		}
		throw new Skip("no function with parameters");
	}

	private void retypeGlobal() throws Exception {
		Listing listing = program.getListing();
		ReferenceManager references = program.getReferenceManager();
		for (Function function : functions) {
			for (Address from : references.getReferenceSourceIterator(function.getBody(), true)) {
				for (Reference reference : references.getReferencesFrom(from)) {
					Data data = listing.getDefinedDataAt(reference.getToAddress());
					if (data == null || data.hasStringValue() || data.isPointer() ||
						(data.getLength() != 4 && data.getLength() != 8)) {
						continue;
					}
					DataType replacement = data.getLength() == 4 ? FloatDataType.dataType :
						DoubleDataType.dataType;
					if (data.getDataType().isEquivalent(replacement)) {
						replacement = data.getLength() == 4 ? UnsignedIntegerDataType.dataType :
							UnsignedLongLongDataType.dataType;
					}
					Address start = data.getMinAddress();
					listing.clearCodeUnits(start, data.getMaxAddress(), false);
					listing.createData(start, replacement);
					return;
				}
			}
		}
		throw new Skip("no referenced 4- or 8-byte global data");
	}

	/**
	 * Adds one to a MOV's trailing 32-bit immediate and re-disassembles it, preferring
	 * a constant that appears in the function's current C so the output must change.
	 */
	private void patchImmediate() throws Exception {
		Listing listing = program.getListing();
		Instruction chosen = null;
		search: for (boolean mustBeVisible : new boolean[] { true, false }) {
			for (Function function : functions) {
				DecompOutput current = previous.get(function.getEntryPoint());
				for (Instruction instruction : listing.getInstructions(function.getBody(), true)) {
					Integer value = trailingImmediate(instruction);
					if (value == null) {
						continue;
					}
					boolean visible = current != null &&
						(current.c().contains("0x" + Integer.toHexString(value)) ||
							current.c().matches("(?s).*\\b" + value + "\\b.*"));
					if (visible || !mustBeVisible) {
						chosen = instruction;
						break search;
					}
				}
			}
		}
		if (chosen == null) {
			throw new Skip("no MOV with a trailing 32-bit immediate");
		}
		Address start = chosen.getAddress();
		Address end = chosen.getMaxAddress();
		int patched = trailingImmediate(chosen) + 1;
		listing.clearCodeUnits(start, end, false);
		program.getMemory().setBytes(start.add(chosen.getLength() - 4), new byte[] { (byte) patched,
			(byte) (patched >>> 8), (byte) (patched >>> 16), (byte) (patched >>> 24) });
		new DisassembleCommand(start, new AddressSet(start, end), false).applyTo(program, monitor);
		if (listing.getInstructionAt(start) == null) {
			throw new IOException("re-disassembly failed at " + start);
		}
	}

	/**
	 * One change whose range spans many dependency lines: a register value set from the
	 * second function's entry to the end of the sixth. Every function entry inside
	 * the range answers its tracked-register query differently afterwards.
	 */
	private void contextAcrossFunctions() throws Exception {
		if (functions.size() < 6) {
			throw new Skip("fewer than six functions");
		}
		Address start = functions.get(1).getEntryPoint();
		Address end = functions.get(5).getBody().getMaxAddress();
		ProgramContext context = program.getProgramContext();
		for (ghidra.program.model.lang.Register register : context.getRegisters()) {
			if (register.isProcessorContext() || register.getBitLength() > 8 ||
				context.getValue(register, start, false) != null) {
				continue;
			}
			context.setValue(register, start, end, java.math.BigInteger.ONE);
			return;
		}
		throw new Skip("no unset small register");
	}

	private void labelInBody() throws Exception {
		for (Function function : functions) {
			for (Instruction instruction : program.getListing().getInstructions(function.getBody(), true)) {
				if (instruction.getFlowType().isJump() && instruction.getFlows().length == 1) {
					program.getSymbolTable().createLabel(instruction.getFlows()[0],
						"binaryrat_label_" + (++counter), function, SourceType.USER_DEFINED);
					return;
				}
			}
		}
		throw new Skip("no jump target inside a function");
	}

	private void overrideCallFlow() throws Exception {
		Function callee = calledFunction();
		for (Function caller : callee.getCallingFunctions(monitor)) {
			for (Instruction instruction : program.getListing().getInstructions(caller.getBody(), true)) {
				if (instruction.getFlowType().isCall() &&
					instruction.getFlowOverride() == FlowOverride.NONE) {
					instruction.setFlowOverride(FlowOverride.BRANCH);
					return;
				}
			}
		}
		throw new Skip("no call instruction in a caller");
	}

	private void editUsedType() throws Exception {
		for (Function function : functions) {
			for (Parameter parameter : function.getParameters()) {
				DataType type = parameter.getDataType();
				if (type instanceof Pointer pointer && pointer.getDataType() instanceof Structure structure &&
					structure.getDataTypeManager() == program.getDataTypeManager()) {
					structure.add(IntegerDataType.dataType, "binaryrat_field_" + (++counter), null);
					return;
				}
			}
		}
		// No structure parameters: retype a parameter through a new typedef instead.
		for (Function function : functions) {
			if (function.getParameterCount() > 0 && !function.isThunk()) {
				Parameter parameter = function.getParameter(0);
				DataType typedef = program.getDataTypeManager().addDataType(
					new TypedefDataType("binaryrat_t" + (++counter), parameter.getDataType()),
					DataTypeConflictHandler.DEFAULT_HANDLER);
				parameter.setDataType(typedef, SourceType.USER_DEFINED);
				return;
			}
		}
		throw new Skip("no parameter to retype");
	}

	private void deleteCallee() throws Exception {
		Function callee = calledFunction();
		program.getFunctionManager().removeFunction(callee.getEntryPoint());
		functions.remove(callee);
		previous.remove(callee.getEntryPoint());
		cached.remove(callee.getEntryPoint());
	}

	/** The value of a MOV whose last four bytes encode its small positive immediate. */
	private static Integer trailingImmediate(Instruction instruction) throws Exception {
		if (!instruction.getMnemonicString().equalsIgnoreCase("MOV") ||
			instruction.getNumOperands() != 2) {
			return null;
		}
		Scalar scalar = instruction.getScalar(1);
		if (scalar == null || scalar.getValue() <= 1 || scalar.getValue() > 0xffff) {
			return null;
		}
		byte[] bytes = instruction.getBytes();
		int offset = bytes.length - 4;
		if (offset < 1) {
			return null;
		}
		int encoded = (bytes[offset] & 0xff) | (bytes[offset + 1] & 0xff) << 8 |
			(bytes[offset + 2] & 0xff) << 16 | (bytes[offset + 3] & 0xff) << 24;
		return encoded == scalar.getValue() ? encoded : null;
	}

	private void undoRedo() throws Exception {
		if (!program.canUndo()) {
			rounds.add(skipped("undo", "nothing to undo (is a transaction still open?)"));
			failures++;
			return;
		}
		round("undo the previous change (reach unknown)", (Undoing) program::undo, false, Expect.ANY);
		if (program.canRedo()) {
			round("redo it (reach unknown)", (Undoing) program::redo, false, Expect.ANY);
		}
	}

	/** Changes made while no engine was watching must be caught by replay. */
	private void offlineEdit() throws Exception {
		shut();
		boolean applied = change("rename while the engine is down", this::renameCallee);
		open();
		JsonObject result = round(applied ? "restart after an unwatched rename" :
			"restart", null, false, Expect.ANY);
		if (result.get("hits").getAsInt() != 0) {
			failures++;
			result.addProperty("passed", false);
			log.accept("BinaryRat cache proof: a new session vouched for entries it never checked");
		}
	}

	/** Changes hidden from the cache must be detected, or the audit proves nothing. */
	private void negativeControl() throws Exception {
		round("NEGATIVE CONTROL: rename a called function with change reports dropped",
			this::renameCallee, true, Expect.ANY);
		// The dropped changes are still unknown to the engine; recover soundness.
		JsonObject all = new JsonObject();
		all.addProperty("all", true);
		engine.call("cache.changed", all);
	}

	/** Fresh decompilation versus the cache's fast path, after everything is cached. */
	private JsonObject timing() throws Exception {
		for (Function function : functions) {
			LiveDecompileCache.Lookup lookup = cache.lookup(function, false);
			if (lookup.kind() == LiveDecompileCache.Kind.MISS) {
				long modification = program.getModificationNumber();
				TracingDecompiler.Traced decompiled = fresh.decompile(function, timeoutSeconds, monitor);
				cache.store(function, DecompOutput.of(decompiled.results()), decompiled.trace(),
					lookup.seq(), modification);
			}
		}
		long started = System.nanoTime();
		int hits = 0;
		for (Function function : functions) {
			if (cache.lookup(function, false).kind() != LiveDecompileCache.Kind.MISS) {
				hits++;
			}
		}
		long cached = System.nanoTime() - started;
		started = System.nanoTime();
		for (Function function : functions) {
			fresh.decompile(function, timeoutSeconds, monitor);
		}
		long decompiled = System.nanoTime() - started;
		JsonObject all = new JsonObject();
		all.addProperty("all", true);
		engine.call("cache.changed", all);
		started = System.nanoTime();
		int replayed = 0;
		for (Function function : functions) {
			if (cache.lookup(function, false).kind() == LiveDecompileCache.Kind.REPLAYED) {
				replayed++;
			}
		}
		long verifying = System.nanoTime() - started;
		JsonObject timing = new JsonObject();
		timing.addProperty("fresh_decompile_seconds", decompiled / 1e9);
		timing.addProperty("cache_hit_seconds", cached / 1e9);
		timing.addProperty("cache_hits", hits);
		timing.addProperty("replay_verify_seconds", verifying / 1e9);
		timing.addProperty("replay_verified", replayed);
		timing.add("engine_cache", cache.stats());
		return timing;
	}

	private static JsonObject skipped(String name, String why) {
		JsonObject result = new JsonObject();
		result.addProperty("name", name);
		result.addProperty("skipped", true);
		result.addProperty("why", why);
		return result;
	}
}
