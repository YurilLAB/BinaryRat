// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
// Proves two live-cache defences on a disposable x86-64 program and a real engine.
// Aliases: a byte write changes what byte-mapped (1:1 and 2:4), bit-mapped and file-sharing
// blocks show elsewhere, and Ghidra reports it only where it was written; the cache must still
// never serve the old decompilation, while untouched functions stay fast hits.
// Refusals: when the engine cannot write, read or remove a cache record (a directory in its
// place, a scanner holding the file), decompilation goes on uncached and nothing stale is
// served; a lost engine connection is still an error.
// Headless project-only preScript: BinaryRatCacheEdgeProof.java [REPORT_JSON]
// @category BinaryRat
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.util.*;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import binaryrat.*;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.mem.ByteMappingScheme;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.util.DefaultLanguageService;

public class BinaryRatCacheEdgeProof extends GhidraScript {
	private static final int TIMEOUT = 30;

	private ProgramDB program;
	private final Map<String, Function> functions = new LinkedHashMap<>();
	private TracingDecompiler fresh;
	private Path engineBinary;
	private Path directory;
	private EngineClient engine;
	private ChangeTracker tracker;
	private LiveDecompileCache cache;
	private final JsonObject report = new JsonObject();

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
		engineBinary = EngineClient.findExecutable();
		var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:64:default"));
		program = new ProgramDB("BinaryRat disposable cache-edge fixture", language,
			language.getCompilerSpecByID(new CompilerSpecID("gcc")), this);
		Path root = Files.createTempDirectory("binaryrat-cache-edges-");
		try {
			setup();
			fresh = new TracingDecompiler();
			DecompileOptions options = new DecompileOptions();
			options.grabFromProgram(program);
			fresh.setOptions(options);
			fresh.setSimplificationStyle("decompile");
			fresh.toggleCCode(true);
			fresh.toggleSyntaxTree(true);
			require(fresh.openProgram(program), "decompiler did not start: " + fresh.getLastMessage());
			directory = root.resolve("alias cache");
			open();
			int aliases = aliases();
			shut();
			directory = root.resolve("refusal cache");
			open();
			String pinning = pinning();
			int refusals = refusals();
			report.addProperty("alias_cases", aliases);
			report.addProperty("refusal_cases", refusals);
			report.addProperty("pinning", pinning);
			report.addProperty("passed", true);
			if (output != null) {
				Files.writeString(output, new GsonBuilder().serializeNulls().setPrettyPrinting().create()
					.toJson(report) + "\n", StandardCharsets.UTF_8);
			}
			println("BINARYRAT_CACHE_EDGES_OK aliases=" + aliases + " refusals=" + refusals +
				" pinning=" + pinning + " stale_served=0 export_safe=true");
		}
		finally {
			try {
				shut();
			}
			finally {
				if (fresh != null) {
					fresh.dispose();
				}
				program.release(this);
				deleteTree(root);
			}
		}
	}

	// ------------------------------------------------------------------ fixture

	private Address at(long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	/**
	 * .text holds one function per alias kind, each returning a dword or byte it loads from
	 * read-only memory, which the decompiler folds into a constant:
	 * f_mirror [0x3000] (1:1 view of rom 0x2000), f_half [0x3900] (2:4 view: rom 0x2200,
	 * 0x2201, 0x2204, 0x2205), f_bits [0x4100] (bit 0 of rom 0x2020), f_copy [0x6030] (file
	 * bytes shared with block "image" at 0x5000), f_plain [0x2800] (rom itself, no alias).
	 * f_half and f_bits read 0x100 into their views, so a write mapped as if it were 1:1
	 * would land on another 256-byte dependency line and leave them stale.
	 * f_late's code at 0x1050 reads [0x7000], a view created during the proof.
	 */
	private void setup() throws Exception {
		int transaction = program.startTransaction("Build disposable cache-edge fixture");
		boolean commit = false;
		try {
			Memory memory = program.getMemory();
			var text = memory.createInitializedBlock(".text", at(0x1000), 0x100, (byte) 0xcc, monitor, false);
			text.setWrite(false);
			text.setExecute(true);
			var rom = memory.createInitializedBlock("rom", at(0x2000), 0x1000, (byte) 0, monitor, false);
			rom.setWrite(false);
			memory.setBytes(at(0x2000), HexFormat.of().parseHex("44332211"));
			memory.setBytes(at(0x2200), HexFormat.of().parseHex("443322116655"));
			memory.setBytes(at(0x2020), new byte[] { 1 });
			memory.setBytes(at(0x2800), HexFormat.of().parseHex("efbeadde"));
			memory.createByteMappedBlock("mirror", at(0x3000), at(0x2000), 0x800, false).setWrite(false);
			memory.createByteMappedBlock("half", at(0x3800), at(0x2000), 0x400, new ByteMappingScheme(2, 4), false)
				.setWrite(false);
			memory.createBitMappedBlock("bits", at(0x4000), at(0x2000), 0x800, false).setWrite(false);
			byte[] image = new byte[0x100];
			System.arraycopy(HexFormat.of().parseHex("78563412"), 0, image, 0x30, 4);
			var shared = memory.createFileBytes("shared.bin", 0, image.length, new ByteArrayInputStream(image), monitor);
			memory.createInitializedBlock("image", at(0x5000), shared, 0, image.length, false).setWrite(false);
			memory.createInitializedBlock("copy", at(0x6000), shared, 0, image.length, false).setWrite(false);
			memory.setBytes(at(0x1000), HexFormat.of().parseHex(
				"8b042500300000c3" + "cccccccccccccccc" +    // f_mirror: mov eax,[0x3000]; ret
				"8b042500390000c3" + "cccccccccccccccc" +    // f_half:   mov eax,[0x3900]; ret
				"0fb6042500410000c3" + "cccccccccccccc" +    // f_bits:   movzx eax,byte [0x4100]; ret
				"8b042530600000c3" + "cccccccccccccccc" +    // f_copy:   mov eax,[0x6030]; ret
				"8b042500280000c3" + "cccccccccccccccc" +    // f_plain:  mov eax,[0x2800]; ret
				"8b042500700000c3"));                        // f_late:   mov eax,[0x7000]; ret
			var flat = new FlatProgramAPI(program, monitor);
			String[] names = { "f_mirror", "f_half", "f_bits", "f_copy", "f_plain" };
			for (int index = 0; index < names.length; index++) {
				functions.put(names[index], function(flat, 0x1000 + 0x10L * index, names[index]));
			}
			commit = true;
		}
		finally {
			program.endTransaction(transaction, commit);
		}
		program.clearUndo();
	}

	private Function function(FlatProgramAPI flat, long offset, String name) throws IOException {
		Address entry = at(offset);
		require(flat.disassemble(entry), "could not disassemble " + name);
		Function created = flat.createFunction(entry, name);
		require(created != null, "could not create " + name);
		return created;
	}

	// ------------------------------------------------------------------ cache session

	private void open() throws IOException {
		Files.createDirectories(directory);
		engine = EngineClient.start(engineBinary, directory);
		tracker = new ChangeTracker(program, engine);
		cache = new LiveDecompileCache(engine, program, tracker, fresh.getOptions(), "sha256:binaryrat-cache-edges",
			fresh.registrationDigest());
	}

	private void shut() throws IOException {
		try {
			if (tracker != null) {
				tracker.close();
			}
		}
		finally {
			tracker = null;
			cache = null;
			if (engine != null) {
				EngineClient closing = engine;
				engine = null;
				closing.close();
			}
		}
	}

	private DecompOutput decompile(String name) throws Exception {
		return DecompOutput.of(fresh.decompile(functions.get(name), TIMEOUT, monitor).results());
	}

	/** Decompiles fresh and stores it; returns the output. */
	private DecompOutput populate(String name) throws Exception {
		Function function = functions.get(name);
		LiveDecompileCache.Lookup lookup = cache.lookup(function, false);
		long modification = program.getModificationNumber();
		TracingDecompiler.Traced traced = fresh.decompile(function, TIMEOUT, monitor);
		DecompOutput output = DecompOutput.of(traced.results());
		String why = cache.put(function, output, traced.trace(), lookup.seq(), modification);
		require(why == null, name + " was not stored: " + why);
		require(cache.lookup(function, false).kind() == LiveDecompileCache.Kind.HIT, name + " is not a hit after storing");
		return output;
	}

	private void write(long address, String hex) throws Exception {
		int transaction = program.startTransaction("BinaryRat cache-edge write");
		try {
			program.getMemory().setBytes(at(address), HexFormat.of().parseHex(hex));
		}
		finally {
			program.endTransaction(transaction, true);
		}
		program.flushEvents();
	}

	private static String folded(DecompOutput output) {
		if (output == null) {
			return "(nothing)";
		}
		String c = output.c().replaceAll("\\s+", " ");
		int body = c.indexOf('{');
		return body < 0 ? c : c.substring(body);
	}

	// ------------------------------------------------------------------ aliases

	private int aliases() throws Exception {
		Map<String, DecompOutput> stored = new LinkedHashMap<>();
		for (String name : functions.keySet()) {
			stored.put(name, populate(name));
		}
		require(folded(stored.get("f_mirror")).contains("0x11223344") &&
			folded(stored.get("f_half")).contains("0x55663344") && folded(stored.get("f_bits")).contains("return 1") &&
			folded(stored.get("f_copy")).contains("0x12345678") && folded(stored.get("f_plain")).contains("0xdeadbeef"),
			"the fixture's loads were not folded into constants: " + stored.values().stream().map(
				BinaryRatCacheEdgeProof::folded).toList());
		Object[][] cases = {
			{ "byte-mapped 1:1", "f_mirror", 0x2000L, "aabbccdd", "0xddccbbaa" },
			{ "byte-mapped 2:4", "f_half", 0x2204L, "0102", "0x2013344" },
			{ "bit-mapped", "f_bits", 0x2020L, "00", "return 0" },
			{ "shared file bytes", "f_copy", 0x5030L, "efcdab90", "0x90abcdef" },
		};
		com.google.gson.JsonArray rows = new com.google.gson.JsonArray();
		for (Object[] row : cases) {
			String kind = (String) row[0];
			String name = (String) row[1];
			rows.add(aliasCase(kind, name, (Long) row[2], (String) row[3], (String) row[4], stored));
		}
		// Control: a write through the mirror itself is reported at both ends by Ghidra.
		rows.add(aliasCase("write through the mirror", "f_mirror", 0x3000L, "01020304", "0x4030201", stored));
		// Control: a write to rom outside every view must keep every entry a fast hit.
		refreshAll(stored);
		ChangeTracker.Counts before = copy(tracker.counts());
		write(0x2c00, "11223344");
		for (String name : functions.keySet()) {
			require(cache.lookup(functions.get(name), false).kind() == LiveDecompileCache.Kind.HIT,
				"a write outside every alias removed " + name);
		}
		require(tracker.counts().unknownReach == before.unknownReach, "a plain write was reported with unknown reach");
		// A view created after the alias index was built must be followed too.
		int transaction = program.startTransaction("BinaryRat late view");
		try {
			program.getMemory().createByteMappedBlock("late", at(0x7000), at(0x2c00), 0x100, false).setWrite(false);
			functions.put("f_late", function(new FlatProgramAPI(program, monitor), 0x1050, "f_late"));
		}
		finally {
			program.endTransaction(transaction, true);
		}
		program.flushEvents();
		stored.put("f_late", populate("f_late"));
		require(folded(stored.get("f_late")).contains("0x44332211"), "f_late: " + folded(stored.get("f_late")));
		rows.add(aliasCase("view created during the session", "f_late", 0x2c00L, "55667788", "0x88776655", stored));
		report.add("aliases", rows);
		return rows.size();
	}

	private JsonObject aliasCase(String kind, String name, long address, String bytes, String expected,
			Map<String, DecompOutput> stored) throws Exception {
		Function function = functions.get(name);
		// Writes reach whole 256-byte lines, so earlier cases may have removed this entry.
		refreshAll(stored);
		require(cache.lookup(function, false).kind() == LiveDecompileCache.Kind.HIT, kind + ": " + name +
			" is not a hit before the write");
		ChangeTracker.Counts before = copy(tracker.counts());
		write(address, bytes);
		LiveDecompileCache.Lookup lookup = cache.lookup(function, false);
		DecompOutput now = decompile(name);
		JsonObject row = new JsonObject();
		row.addProperty("kind", kind);
		row.addProperty("function", name);
		row.addProperty("write", Long.toHexString(address));
		row.addProperty("lookup", lookup.kind().name());
		row.addProperty("fresh", folded(now));
		require(folded(now).contains(expected) && !now.equals(stored.get(name)),
			kind + ": the write did not change " + name + "'s decompilation: " + folded(now));
		require(lookup.output() == null || lookup.output().equals(now),
			kind + ": STALE " + name + " served as " + lookup.kind() + ": " + folded(lookup.output()) +
				" while a fresh decompilation gives " + folded(now));
		require(lookup.kind() == LiveDecompileCache.Kind.MISS, kind + ": " + name + " was " + lookup.kind() +
			", not removed by the reported change");
		ChangeTracker.Counts after = tracker.counts();
		require(after.unknownReach == before.unknownReach && after.precise > before.precise,
			kind + ": the write was not reported precisely");
		require(cache.lookup(functions.get("f_plain"), false).kind() == LiveDecompileCache.Kind.HIT,
			kind + ": the untouched f_plain lost its entry");
		stored.put(name, populate(name));
		return row;
	}

	/** Makes every function a fast hit again, so each case starts from vouched entries. */
	private void refreshAll(Map<String, DecompOutput> stored) throws Exception {
		for (String name : functions.keySet()) {
			if (cache.lookup(functions.get(name), false).kind() != LiveDecompileCache.Kind.HIT) {
				stored.put(name, populate(name));
			}
		}
	}

	private static ChangeTracker.Counts copy(ChangeTracker.Counts counts) {
		ChangeTracker.Counts copy = new ChangeTracker.Counts();
		copy.records = counts.records;
		copy.precise = counts.precise;
		copy.unknownReach = counts.unknownReach;
		return copy;
	}

	// ------------------------------------------------------------------ refusals

	/** Keeps the engine from removing or replacing one record, as a scanner holding it would. */
	private interface Pin extends AutoCloseable {
		@Override
		void close() throws IOException;
	}

	private Pin pin(Path record) throws IOException {
		if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
			// POSIX removes an open file; a directory without write permission keeps it.
			Set<PosixFilePermission> previous = Files.getPosixFilePermissions(directory);
			Files.setPosixFilePermissions(directory, EnumSet.of(PosixFilePermission.OWNER_READ,
				PosixFilePermission.OWNER_EXECUTE));
			return () -> Files.setPosixFilePermissions(directory, previous);
		}
		// java.io opens without FILE_SHARE_DELETE, so Windows refuses to delete or replace it.
		FileInputStream held = new FileInputStream(record.toFile());
		return held::close;
	}

	/** Checks that pinning works here (it does not for root); returns how it pins. */
	private String pinning() throws IOException {
		Path probe = directory.resolve("pin-probe.tmp");
		Files.writeString(probe, "probe");
		boolean removed;
		try (Pin pinned = pin(probe)) {
			try {
				Files.delete(probe);
				removed = true;
			}
			catch (IOException expected) {
				removed = false;
			}
		}
		Files.deleteIfExists(probe);
		require(!removed, "cannot make a file undeletable here, so engine refusals cannot be exercised " +
			"(running as root?)");
		return FileSystems.getDefault().supportedFileAttributeViews().contains("posix") ? "directory-permissions" :
			"open-handle";
	}

	/** The record file of a function's entry, found by the key inside it. */
	private Path record(String name) throws IOException {
		String address = Long.toUnsignedString(functions.get(name).getEntryPoint().getOffset(), 16);
		Path found = null;
		try (DirectoryStream<Path> files = Files.newDirectoryStream(directory, "*.json")) {
			for (Path file : files) {
				if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) || !file.getFileName().toString()
						.matches("[0-9a-f]{64}\\.json")) {
					continue;
				}
				JsonObject key = JsonParser.parseString(Files.readString(file)).getAsJsonObject()
					.getAsJsonObject("payload").getAsJsonObject("key");
				if (key.get("address").getAsString().equals(address)) {
					require(found == null, "two records for " + name);
					found = file;
				}
			}
		}
		require(found != null, "no record for " + name);
		return found;
	}

	private void refused(String what, String why, String operation) throws IOException {
		require(why != null && why.startsWith("engine refused " + operation + " (operation_failed): "),
			what + ": expected a refused " + operation + ", got " + why);
	}

	private int refusals() throws Exception {
		com.google.gson.JsonArray rows = new com.google.gson.JsonArray();
		for (String name : functions.keySet()) {
			populate(name);
		}
		Function plain = functions.get("f_plain");

		// 1. A directory where a record must go: every write of that key fails.
		Path squatted = record("f_plain");
		Files.delete(squatted);
		Files.createDirectory(squatted);
		Files.writeString(squatted.resolve("occupied.txt"), "x");
		LiveDecompileCache.Lookup lookup = cache.lookup(plain, false);
		require(lookup.kind() == LiveDecompileCache.Kind.MISS && lookup.output() == null, "squatted lookup " + lookup);
		long modification = program.getModificationNumber();
		TracingDecompiler.Traced traced = fresh.decompile(plain, TIMEOUT, monitor);
		DecompOutput output = DecompOutput.of(traced.results());
		String why = cache.put(plain, output, traced.trace(), lookup.seq(), modification);
		refused("record path occupied by a directory", why, "cache.put");
		require(!output.c().isEmpty() && output.completed(), "the refused store damaged the decompilation");
		require(cache.lookup(plain, false).output() == null, "a refused store left something to serve");
		rows.add(row("write refused: a directory holds the record's name", why));
		deleteTree(squatted);
		populate("f_plain");

		// 2. An unreadable record the engine cannot remove must not keep it from starting.
		Path corrupt = record("f_mirror");
		shut();
		Files.writeString(corrupt, "{partial");
		try (Pin pinned = pin(corrupt)) {
			open();
			lookup = cache.lookup(functions.get("f_mirror"), false);
			require(lookup.kind() == LiveDecompileCache.Kind.MISS && lookup.output() == null,
				"a corrupt record was served: " + lookup);
			traced = fresh.decompile(functions.get("f_mirror"), TIMEOUT, monitor);
			why = cache.put(functions.get("f_mirror"), DecompOutput.of(traced.results()), traced.trace(),
				lookup.seq(), program.getModificationNumber());
			refused("corrupt record held open", why, "cache.put");
		}
		rows.add(row("engine started beside an undeletable corrupt record; its replacement was refused", why));
		populate("f_mirror");

		// 3. A readable record the engine has not indexed and cannot remove: cache.get fails.
		Path unindexed = record("f_bits");
		Path aside = unindexed.resolveSibling(unindexed.getFileName() + ".aside");
		shut();
		Files.move(unindexed, aside);
		open();
		Files.move(aside, unindexed);
		try (Pin pinned = pin(unindexed)) {
			lookup = cache.lookup(functions.get("f_bits"), false);
			refused("unindexed record held open", lookup.rejected(), "cache.get");
			require(lookup.kind() == LiveDecompileCache.Kind.MISS && lookup.output() == null, "refused get " + lookup);
		}
		rows.add(row("read refused: an unindexed record could not be dropped", lookup.rejected()));
		require(cache.lookup(functions.get("f_bits"), false).kind() == LiveDecompileCache.Kind.MISS,
			"the unindexed record was served once it could be dropped");
		populate("f_bits");

		// 4. An entry the engine vouches for, made stale by a change nobody reported, whose
		// removal the engine refuses: the engine must stop vouching for every entry.
		populate("f_copy");
		tracker.setBlind(true);
		try {
			write(0x5030, "21436587");
		}
		finally {
			tracker.sync();
			tracker.setBlind(false);
		}
		Function copy = functions.get("f_copy");
		DecompOutput now = decompile("f_copy");
		try (Pin pinned = pin(record("f_copy"))) {
			LiveDecompileCache.Lookup audited = cache.lookup(copy, true);
			require(audited.kind() == LiveDecompileCache.Kind.HIT && audited.rejected() != null &&
				audited.rejected().contains("engine refused cache.evict (operation_failed): "),
				"audit of the stale entry " + audited);
			lookup = cache.lookup(copy, false);
			require(lookup.output() == null && lookup.kind() == LiveDecompileCache.Kind.MISS,
				"STALE f_copy served after a refused removal: " + lookup.kind() + " " + folded(lookup.output()) +
					" vs fresh " + folded(now));
			LiveDecompileCache.Lookup other = cache.lookup(plain, false);
			require(other.kind() == LiveDecompileCache.Kind.REPLAYED && other.output().equals(decompile("f_plain")),
				"other entries must be replayed once the engine stops vouching: " + other.kind());
		}
		rows.add(row("removal refused for a stale vouched entry: every entry replayed", lookup.rejected()));
		require(cache.lookup(copy, false).kind() == LiveDecompileCache.Kind.MISS, "f_copy after its removal");
		populate("f_copy");
		require(cache.disabledReason() == null, "the cache disabled itself: " + cache.disabledReason());

		// 5. A lost connection is not a refusal: callers must still see the failure.
		LiveDecompileCache orphan = cache;
		EngineClient gone = engine;
		gone.close();
		IOException lost = null;
		try {
			orphan.lookup(plain, false);
		}
		catch (IOException expected) {
			lost = expected;
		}
		require(lost != null && !(lost instanceof EngineClient.Refused),
			"a lookup on a closed engine must throw a connection failure, got " + lost);
		rows.add(row("connection lost: lookup throws", String.valueOf(lost.getMessage())));
		report.add("refusals", rows);
		return rows.size();
	}

	private static JsonObject row(String name, String reason) {
		JsonObject row = new JsonObject();
		row.addProperty("case", name);
		row.addProperty("reason", reason);
		return row;
	}

	// ------------------------------------------------------------------ helpers

	private static void deleteTree(Path root) throws IOException {
		if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) {
			return;
		}
		try (var paths = Files.walk(root)) {
			for (Path path : (Iterable<Path>) paths.sorted(Comparator.reverseOrder())::iterator) {
				Files.deleteIfExists(path);
			}
		}
	}

	private static void require(boolean condition, String message) throws IOException {
		if (!condition) {
			throw new IOException("cache-edge proof failed: " + message);
		}
	}
}
