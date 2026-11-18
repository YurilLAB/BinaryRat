// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
//@category BinaryRat

import java.nio.file.Files;
import java.nio.file.Path;

import com.google.gson.JsonObject;

import binaryrat.ChangeTracker;
import binaryrat.DecompOutput;
import binaryrat.EngineClient;
import binaryrat.LiveDecompileCache;
import binaryrat.TracingDecompiler;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;

/**
 * A real x86-64 ProgramDB with cache dependencies on distinct address lines. The
 * stock decompiler first calls the redirected target, then suppresses the
 * redirect when the original target acquires a call fixup, and restores it when
 * the fixup is cleared.
 */
public class BinaryRatRedirectedCallCheck extends GhidraScript {
	private static final int TIMEOUT_SECONDS = 60;
	private static final String FIXUP = "fentry";

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length != 3) {
			throw new IllegalArgumentException("expected ENGINE CACHE_DIRECTORY REPORT");
		}
		Path engineBinary = Path.of(args[0]);
		Path cacheDirectory = Path.of(args[1]);
		Language language = DefaultLanguageService.getLanguageService()
				.getLanguage(new LanguageID("x86:LE:64:default"));
		Program program = new ProgramDB("redirected call cache check", language,
			language.getCompilerSpecByID(new CompilerSpecID("gcc")), this);
		try {
			JsonObject report = new JsonObject();
			report.add("primary_call", prove(program, engineBinary,
				cacheDirectory, 0x1000, RefType.UNCONDITIONAL_CALL, false));
			report.add("explicit_call_override", prove(program, engineBinary,
				cacheDirectory, 0x2000, RefType.CALL_OVERRIDE_UNCONDITIONAL, false));
			report.add("inherited_thunk_fixup", prove(program, engineBinary,
				cacheDirectory, 0x3000, RefType.UNCONDITIONAL_CALL, true));
			report.addProperty("passed", true);
			Files.writeString(Path.of(args[2]), report + "\n");
			println("BinaryRat redirected call cache checks passed");
		}
		finally {
			program.release(this);
		}
	}

	private JsonObject prove(Program program, Path engineBinary, Path cacheDirectory,
			long base, RefType refType, boolean throughThunks) throws Exception {
		Address callerEntry = program.getAddressFactory().getDefaultAddressSpace().getAddress(base);
		Address originalEntry = callerEntry.add(0x200);
		Address redirectedEntry = callerEntry.add(0x400);
		FlatProgramAPI api = new FlatProgramAPI(program, monitor);
		Function caller;
		Function redirected;
		Function fixupTarget;
		try (var transaction = program.openTransaction("Build the redirected call fixture")) {
			var block = program.getMemory().createInitializedBlock("fixture_" + base, callerEntry,
				0xa00, (byte) 0xcc, monitor, false);
			block.setExecute(true);
			// CALL rel32 to originalEntry, ADD EAX,1, RET.
			program.getMemory().setBytes(callerEntry,
				new byte[] { (byte) 0xe8, (byte) 0xfb, 1, 0, 0, (byte) 0x83, (byte) 0xc0, 1, (byte) 0xc3 });
			returnConstant(program, originalEntry, (byte) 7);
			returnConstant(program, redirectedEntry, (byte) 9);
			Function original = disassembleFunction(api, originalEntry, "original_target_" + base);
			redirected = disassembleFunction(api, redirectedEntry, "redirected_target_" + base);
			caller = disassembleFunction(api, callerEntry, "caller_" + base);
			if (throughThunks) {
				Address hopEntry = callerEntry.add(0x600);
				Address targetEntry = callerEntry.add(0x800);
				returnConstant(program, hopEntry, (byte) 7);
				returnConstant(program, targetEntry, (byte) 7);
				Function hop = disassembleFunction(api, hopEntry, "thunk_hop_" + base);
				fixupTarget = disassembleFunction(api, targetEntry, "thunk_leaf_" + base);
				hop.setThunkedFunction(fixupTarget);
				original.setThunkedFunction(hop);
			}
			else {
				fixupTarget = original;
			}

			// Prepare the existing call-fixup property map before enabling the tracker.
			// Its first creation has unknown reach and would hide a missing dependency.
			fixupTarget.setCallFixup(FIXUP);
			fixupTarget.setCallFixup(null);
			ReferenceManager references = program.getReferenceManager();
			Reference redirect = references.addMemoryReference(callerEntry, redirectedEntry,
				refType, SourceType.USER_DEFINED, 0);
			references.setPrimary(redirect, true);
		}
		program.flushEvents();
		Instruction call = program.getListing().getInstructionAt(callerEntry);
		require(callTarget(call, false).equals(originalEntry), "fixture's original call target");
		require(callTarget(call, true).equals(redirectedEntry), "fixture's redirected call target");

		TracingDecompiler traced = new TracingDecompiler();
		DecompInterface stock = new DecompInterface();
		try (EngineClient engine = EngineClient.start(engineBinary, cacheDirectory);
				ChangeTracker tracker = new ChangeTracker(program, engine)) {
			traced.setOptions(new DecompileOptions());
			stock.setOptions(new DecompileOptions());
			require(traced.openProgram(program), "open tracing decompiler");
			require(stock.openProgram(program), "open stock decompiler");
			LiveDecompileCache cache = new LiveDecompileCache(engine, program, tracker,
				traced.getOptions(), "binaryrat-redirected-call-" + base, traced.registrationDigest());
			DecompOutput before = compute(program, caller, traced, stock, cache);
			DecompOutput unaffected = compute(program, redirected, traced, stock, cache);
			require(before.c().contains(redirected.getName()), "stock C shows redirected call");
			requireHot(cache, caller, before);
			requireHot(cache, redirected, unaffected);
			long unknownChanges = tracker.counts().unknownReach;
			long resyncs = tracker.counts().resyncs;

			setFixup(program, fixupTarget, FIXUP);
			require(callTarget(call, true).equals(originalEntry), "fixup suppresses redirection");
			// Comparison must use the ordinary fast-path lookup, without audit replay.
			LiveDecompileCache.Lookup set = cache.lookup(caller, false);
			DecompOutput changed = stock(stock, caller);
			require(!before.equals(changed) && !changed.c().contains(redirected.getName()),
				"changing only the original call fixup changes fresh stock output");
			require(set.kind() == LiveDecompileCache.Kind.MISS && set.output() == null,
				"adding original call fixup must invalidate the caller, got " + set.kind());
			require(compute(program, caller, traced, stock, cache).equals(changed),
				"regenerated output matches stock after adding the fixup");
			requireHot(cache, caller, changed);
			requireHot(cache, redirected, unaffected);

			setFixup(program, fixupTarget, null);
			require(callTarget(call, true).equals(redirectedEntry), "clearing fixup restores redirection");
			LiveDecompileCache.Lookup cleared = cache.lookup(caller, false);
			require(cleared.kind() == LiveDecompileCache.Kind.MISS && cleared.output() == null,
				"clearing original call fixup must invalidate the caller, got " + cleared.kind());
			require(compute(program, caller, traced, stock, cache).equals(before),
				"fresh stock matches the initial redirected call after clearing fixup");
			requireHot(cache, caller, before);
			requireHot(cache, redirected, unaffected);
			require(tracker.counts().unknownReach == unknownChanges &&
				tracker.counts().resyncs == resyncs, "edits must use precise invalidation");

			JsonObject evidence = new JsonObject();
			evidence.addProperty("stock_output_changed", true);
			evidence.addProperty("add_fixup", set.kind().name());
			evidence.addProperty("clear_fixup", cleared.kind().name());
			evidence.addProperty("unrelated_entry_unchanged", true);
			evidence.addProperty("precise_invalidation", true);
			return evidence;
		}
		finally {
			stock.dispose();
			traced.dispose();
		}
	}

	private static void returnConstant(Program program, Address address, byte immediate)
			throws Exception {
		// MOV EAX,imm32, RET.
		program.getMemory().setBytes(address,
			new byte[] { (byte) 0xb8, immediate, 0, 0, 0, (byte) 0xc3 });
	}

	private static Function disassembleFunction(FlatProgramAPI api, Address address, String name)
			throws Exception {
		require(api.disassemble(address), "disassemble " + name);
		Function function = api.createFunction(address, name);
		require(function != null, "create " + name);
		return function;
	}

	private static Address callTarget(Instruction call, boolean overrides) {
		for (PcodeOp op : call.getPcode(overrides)) {
			if (op.getOpcode() == PcodeOp.CALL) {
				return op.getInput(0).getAddress();
			}
		}
		throw new IllegalStateException("fixture instruction must emit a direct CALL");
	}

	private static void setFixup(Program program, Function original, String value) {
		try (var transaction = program.openTransaction("Edit the original target's call fixup")) {
			original.setCallFixup(value);
		}
	}

	private DecompOutput compute(Program program, Function function, TracingDecompiler traced,
			DecompInterface stock, LiveDecompileCache cache) throws Exception {
		long modification = program.getModificationNumber();
		LiveDecompileCache.Lookup lookup = cache.lookup(function, false);
		require(lookup.kind() == LiveDecompileCache.Kind.MISS, "expected a cold cache entry");
		TracingDecompiler.Traced current = traced.decompile(function, TIMEOUT_SECONDS, monitor);
		DecompOutput output = DecompOutput.of(current.results());
		require(output.cacheable() && !output.c().isEmpty() && output.equals(stock(stock, function)),
			"recorded output exactly matches a successful stock decompilation");
		require(current.trace().unpredictable().isEmpty(), "fixture must exercise cache fast hits");
		require(cache.store(function, output, current.trace(), lookup.seq(), modification),
			"store a verified cache entry");
		return output;
	}

	private DecompOutput stock(DecompInterface decompiler, Function function) {
		return DecompOutput.of(decompiler.decompileFunction(function, TIMEOUT_SECONDS, monitor));
	}

	private static void requireHot(LiveDecompileCache cache, Function function, DecompOutput output)
			throws Exception {
		LiveDecompileCache.Lookup found = cache.lookup(function, false);
		require(found.kind() == LiveDecompileCache.Kind.HIT && output.equals(found.output()),
			"expected an exact fast hit for " + function.getName() + ", got " + found.kind());
	}

	private static void require(boolean predicate, String detail) {
		if (!predicate) {
			throw new IllegalStateException("Redirected call cache check: " + detail);
		}
	}
}
