// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import binaryrat.EntryAddress;
import binaryrat.StackStrings;
import ghidra.app.cmd.function.NewFunctionStackAnalysisCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * Edge cases of the stack-string service on a disposable x86-64 Program: immediates of every
 * width, a 64-bit immediate, UTF-16, a rewritten slot, an XOR-decoded constant, vector loads
 * from read-only and writable memory, sub-registers, a call that clobbers registers, branches,
 * a loop join, limits, cancellation and a Program change during the run. Includes fall-through
 * controls for x86-64 and AArch64. Runs as a headless project-only preScript, from a checkout
 * or against the installed extension.
 */
public class BinaryRatStackStringsProof extends GhidraScript {
	private static final String TABLE = "binaryrat.desktop.StackStringsTable";
	private ProgramDB program;
	private Function builder;
	private Function brancher;
	private Function thunk;

	@Override
	protected void run() throws Exception {
		if (!isRunningHeadless() || currentProgram != null) {
			throw new IllegalStateException("Run as a headless project-only preScript");
		}
		String[] args = getScriptArgs();
		Path output = args.length == 1 ? Path.of(args[0]).toAbsolutePath().normalize() : null;
		// The overlay-bank report goes beside it, for the Python decoder to check as well.
		Path overlayOutput = output == null ? null : output.resolveSibling(output.getFileName() + ".overlays.json");
		if (args.length > 1 || output != null && (Files.exists(output, LinkOption.NOFOLLOW_LINKS) ||
			Files.exists(overlayOutput, LinkOption.NOFOLLOW_LINKS))) {
			throw new IllegalArgumentException("optional argument: a new REPORT_JSON path (and no REPORT_JSON.overlays.json)");
		}
		var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:64:default"));
		program = new ProgramDB("BinaryRat disposable stack-string fixture", language,
			language.getCompilerSpecByID(new CompilerSpecID("gcc")), this);
		try {
			setup();
			JsonObject report = StackStrings.recover(program, null, 4, StackStrings.DEFAULT_FUNCTIONS, monitor);
			whole(report);
			selected();
			limits();
			require(StackStrings.recover(program, null, 4, StackStrings.DEFAULT_FUNCTIONS, monitor).equals(report),
				"a second run gave a different report");
			boolean table = table(report);
			rejected();
			CountingMonitor counter = new CountingMonitor(Integer.MAX_VALUE, () -> {
			});
			StackStrings.recover(program, null, 4, 100, counter);
			int checks = counter.checks;
			require(checks > 20, "too few cancellation checks: " + checks);
			cancellation(checks);
			programChange(checks);
			JsonObject overlay = overlays(report);
			fallThrough();
			if (output != null) {
				var gson = new GsonBuilder().serializeNulls().setPrettyPrinting().create();
				Files.writeString(output, gson.toJson(report) + "\n", StandardCharsets.UTF_8);
				Files.writeString(overlayOutput, gson.toJson(overlay) + "\n", StandardCharsets.UTF_8);
			}
			println("BINARYRAT_STACK_STRINGS_OK strings=" + report.getAsJsonArray("strings").size() +
				" checks=" + checks + " joins=true calls=true read_only=true limits=true cancellation=true" +
				" program_change=true deterministic=true overlays=true table=" + table +
				" fall_through_x86_64=true fall_through_aarch64=true");
		}
		finally {
			program.release(this);
		}
	}

	/** Builds x86-64 code, computing rip-relative displacements from the instruction address. */
	private static final class Code {
		private final long base;
		private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();

		Code(long base) {
			this.base = base;
		}

		Code emit(String hex) {
			bytes.writeBytes(HexFormat.of().parseHex(hex.replace(" ", "")));
			return this;
		}

		/** movups xmm0, [rip + target]. */
		Code loadXmm0(long target) {
			return relative("0f1005", target);
		}

		/** call target. */
		Code call(long target) {
			return relative("e8", target);
		}

		private Code relative(String opcode, long target) {
			emit(opcode);
			int displacement = (int) (target - (base + bytes.size() + 4));
			for (int shift = 0; shift < 32; shift += 8) {
				bytes.write(displacement >>> shift & 0xff);
			}
			return this;
		}

		byte[] bytes() {
			return bytes.toByteArray();
		}
	}

	private void setup() throws Exception {
		var space = program.getAddressFactory().getDefaultAddressSpace();
		var flat = new FlatProgramAPI(program, monitor);
		int transaction = program.startTransaction("Build disposable stack-string fixture");
		boolean commit = false;
		try {
			var memory = program.getMemory();
			memory.createInitializedBlock(".text", space.getAddress(0x1000), 0x400, (byte) 0xcc, monitor, false)
				.setExecute(true);
			var rodata = memory.createInitializedBlock(".rodata", space.getAddress(0x3000), 0x20, (byte) 0,
				monitor, false);
			rodata.setWrite(false);
			rodata.setExecute(false);
			var data = memory.createInitializedBlock(".data", space.getAddress(0x4000), 0x20, (byte) 0,
				monitor, false);
			data.setWrite(true);
			data.setExecute(false);
			memory.setBytes(space.getAddress(0x3000), "fromrodata12345\0".getBytes(StandardCharsets.US_ASCII));
			memory.setBytes(space.getAddress(0x4000), "writable_text!!\0".getBytes(StandardCharsets.US_ASCII));

			// builder: rbp-relative stores; Ghidra's stack offsets are 8 lower (push rbp).
			Code code = new Code(0x1000)
				.emit("55 4889e5 4881ec00010000")          // push rbp; mov rbp,rsp; sub rsp,0x100
				.emit("c745f868656c6c")                    // mov dword [rbp-0x08], "hell"
				.emit("66c745fc6f00")                      // mov word [rbp-0x04], "o\0"
				.emit("48b8736563726574 0000")             // movabs rax, "secret\0\0"
				.emit("488945e8")                          // mov [rbp-0x18], rax
				.emit("c745d877006900")                    // mov dword [rbp-0x28], u"wi"
				.emit("c745dc64006500")                    // mov dword [rbp-0x24], u"de"
				.emit("c745e000000000")                    // mov dword [rbp-0x20], 0
				.emit("c745c858585858")                    // mov dword [rbp-0x38], "XXXX"
				.emit("c745cc58585858")                    // mov dword [rbp-0x34], "XXXX"
				.emit("c745c861626364")                    // mov dword [rbp-0x38], "abcd" (rewrite)
				.emit("b87a746862 3511111111")             // mov eax, 0x6268747a; xor eax, 0x11111111
				.emit("8945c0")                            // mov [rbp-0x40], eax ("keys")
				.emit("c645c400")                          // mov byte [rbp-0x3c], 0
				.loadXmm0(0x3000)                          // movups xmm0, [read-only "fromrodata12345"]
				.emit("0f1145a0")                          // movups [rbp-0x60], xmm0
				.loadXmm0(0x4000)                          // movups xmm0, [writable "writable_text!!"]
				.emit("0f114580")                          // movups [rbp-0x80], xmm0
				.emit("c78570ffffff64000000")              // mov dword [rbp-0x90], 100 (a number)
				.emit("66b84142 66898560ffffff")           // mov ax, "AB"; mov [rbp-0xa0], ax
				.emit("66b84344 66898562ffffff")           // mov ax, "CD"; mov [rbp-0x9e], ax
				.emit("c68564ffffff00")                    // mov byte [rbp-0x9c], 0
				.emit("c9c3");                             // leave; ret
			memory.setBytes(space.getAddress(0x1000), code.bytes());
			// clobbered: eax is unknown after the call, so only "efgh" is a string.
			memory.setBytes(space.getAddress(0x1100), HexFormat.of().parseHex(
				"554889e54883ec20" + "b861626364" + "e8eefeffff" + "8945f0" + "c745f465666768" + "c9c3"));
			// brancher: "AAAA" and, on one path, "BBBB" in the same slot; then a loop whose head is
			// a join, so the eax stored there is unknown.
			memory.setBytes(space.getAddress(0x1200), HexFormat.of().parseHex(
				"554889e5" + "b841424344" + "c745f041414141" + "85ff" + "7407" + "c745f042424242" +
				"8945f4" + "b8575859 5a".replace(" ", "") + "8945e0" + "ffc9" + "75f9" + "5dc3"));
			memory.setBytes(space.getAddress(0x1300), HexFormat.of().parseHex("e9fbfcffff")); // jmp builder
			// reuser: values and bytes that are not known must not be reported as text.
			memory.setBytes(space.getAddress(0x1310), new Code(0x1310)
				.emit("55 4889e5 4883ec40")                // push rbp; mov rbp,rsp; sub rsp,0x40
				.emit("b861616161 b962626262")             // mov eax, "aaaa"; mov ecx, "bbbb"
				.emit("85ff 0f44c1")                       // test edi,edi; cmovz eax,ecx
				.emit("8945f0")                            // mov [rbp-0x10], eax (either text)
				.emit("c745e061626364")                    // mov dword [rbp-0x20], "abcd"
				.emit("c745e465666768")                    // mov dword [rbp-0x1c], "efgh"
				.emit("897de0")                            // mov [rbp-0x20], edi (unknown over "abcd")
				.emit("c745d06b65726e")                    // mov dword [rbp-0x30], "kern"
				.emit("c745d4656c3332")                    // mov dword [rbp-0x2c], "el32"
				.emit("c745d82e646c6c")                    // mov dword [rbp-0x28], ".dll"
				.emit("c645dc00")                          // mov byte [rbp-0x24], 0
				.call(0x1000)                              // the callee is given the buffer
				.emit("c745d075736572")                    // mov dword [rbp-0x30], "user" (buffer reused)
				.emit("c645d400")                          // mov byte [rbp-0x2c], 0
				.emit("c9c3").bytes());                    // leave; ret

			builder = function(flat, 0x1000, "builder");
			function(flat, 0x1100, "clobbered");
			brancher = function(flat, 0x1200, "brancher");
			thunk = function(flat, 0x1300, "builder_thunk");
			thunk.setThunkedFunction(builder);
			function(flat, 0x1310, "reuser");
			for (long entry : new long[] { 0x1000, 0x1100, 0x1200, 0x1310 }) {
				require(new NewFunctionStackAnalysisCmd(space.getAddress(entry), true).applyTo(program, monitor),
					"stack analysis failed at " + Long.toHexString(entry));
			}
			commit = true;
		}
		finally {
			program.endTransaction(transaction, commit);
		}
		program.clearUndo();
	}

	private Function function(FlatProgramAPI flat, long offset, String name) throws Exception {
		Address entry = program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
		require(flat.disassemble(entry), "could not disassemble " + name);
		Function created = flat.createFunction(entry, name);
		require(created != null, "could not create " + name);
		return created;
	}

	/** Every string, in report order: function, stack offset, text, encoding, terminated. */
	private static List<String> strings(JsonObject report) {
		List<String> found = new ArrayList<>();
		for (JsonElement element : report.getAsJsonArray("strings")) {
			JsonObject item = element.getAsJsonObject();
			found.add(item.getAsJsonObject("function").get("name").getAsString() + " " +
				item.get("stack_offset").getAsLong() + " " + item.get("text").getAsString() + " " +
				item.get("encoding").getAsString() + " " + item.get("terminated").getAsBoolean());
		}
		return found;
	}

	private void whole(JsonObject report) throws Exception {
		require(report.get("schema_version").getAsInt() == 1 &&
			report.get("analysis_mode").getAsString().equals(StackStrings.ANALYSIS_MODE) &&
			report.get("revision").getAsLong() == program.getModificationNumber() &&
			report.get("function").isJsonNull() && report.get("functions_scanned").getAsInt() == 4 &&
			report.get("functions_skipped").getAsInt() == 1 && report.get("functions_partial").getAsInt() == 0 &&
			!report.get("truncated").getAsBoolean(), "report header " + report);
		List<String> expected = List.of(
			"builder -168 ABCD ascii true",
			"builder -104 fromrodata12345 ascii true",
			"builder -72 keys ascii true",
			"builder -64 abcdXXXX ascii false",
			"builder -48 wide utf16le true",
			"builder -32 secret ascii true",
			"builder -16 hello ascii true",
			"clobbered -20 efgh ascii false",
			"brancher -24 AAAA ascii false",
			"brancher -24 BBBB ascii false",
			// Not "bbbb" at -24 (a conditional move), not "abcdefgh" (its first half was
			// overwritten), and not the "l32.dll" left under "user" from before the call.
			"reuser -56 kernel32.dll ascii true",
			"reuser -36 efgh ascii false",
			"reuser -56 user ascii true");
		require(strings(report).equals(expected), "strings " + strings(report));
		for (JsonElement element : report.getAsJsonArray("strings")) {
			JsonObject item = element.getAsJsonObject();
			require(!item.getAsJsonArray("writes").isEmpty() && item.get("address").getAsString().equals(
				item.getAsJsonArray("writes").get(0).getAsJsonObject().get("address").getAsString()),
				"write citations " + item);
		}
		// "hello" cites both of its stores; "abcdXXXX" cites the rewrite and the untouched store.
		require(writes(report, "hello").equals(List.of("100b", "1012")),
			"hello writes " + writes(report, "hello"));
		require(writes(report, "abcdXXXX").size() == 2, "rewrite writes " + writes(report, "abcdXXXX"));
		JsonObject shortest = StackStrings.recover(program, builder, 1, 1, monitor);
		require(strings(shortest).contains("builder -152 d utf16le true"), "minimum length 1: " + strings(shortest));
	}

	private static List<String> writes(JsonObject report, String text) {
		List<String> addresses = new ArrayList<>();
		for (JsonElement element : report.getAsJsonArray("strings")) {
			JsonObject item = element.getAsJsonObject();
			if (item.get("text").getAsString().equals(text)) {
				for (JsonElement write : item.getAsJsonArray("writes")) {
					addresses.add(write.getAsJsonObject().get("address").getAsString());
				}
			}
		}
		return addresses;
	}

	private void selected() throws Exception {
		JsonObject report = StackStrings.recover(program, brancher, 4, 1, monitor);
		require(report.getAsJsonObject("function").get("name").getAsString().equals("brancher") &&
			report.get("functions_scanned").getAsInt() == 1 &&
			strings(report).equals(List.of("brancher -24 AAAA ascii false", "brancher -24 BBBB ascii false")),
			"selected function " + strings(report));
		expect(IOException.class, () -> StackStrings.recover(program, thunk, 4, 1, monitor));
	}

	private void limits() throws Exception {
		JsonObject first = StackStrings.recover(program, null, 4, 1, monitor);
		require(first.get("truncated").getAsBoolean() && first.get("functions_scanned").getAsInt() == 1 &&
			strings(first).size() == 7, "function limit " + strings(first));
		JsonObject longer = StackStrings.recover(program, null, 9, StackStrings.DEFAULT_FUNCTIONS, monitor);
		require(strings(longer).equals(List.of("builder -104 fromrodata12345 ascii true",
			"reuser -56 kernel32.dll ascii true")),
			"minimum length 9 " + strings(longer));
	}

	private void rejected() throws Exception {
		int[][] bad = { { 0, 1 }, { 65, 1 }, { 4, 0 }, { 4, 200_001 } };
		for (int[] limits : bad) {
			expect(IllegalArgumentException.class, () -> StackStrings.recover(program, null, limits[0], limits[1],
				monitor));
		}
		expect(IOException.class, () -> StackStrings.recover(null, null, 4, 1, monitor));
	}

	private void cancellation(int checks) throws Exception {
		TaskMonitorAdapter cancelled = new TaskMonitorAdapter(true);
		cancelled.cancel();
		expect(CancelledException.class, () -> StackStrings.recover(program, null, 4, 100, cancelled));
		for (int after = 1; after <= checks; after += 2) {
			CountingMonitor late = new CountingMonitor(after, () -> {
			});
			expect(CancelledException.class, () -> StackStrings.recover(program, null, 4, 100, late));
		}
	}

	private void programChange(int checks) throws Exception {
		for (int after = 1; after <= checks; after += 3) {
			CountingMonitor changing = new CountingMonitor(after, () -> {
				int transaction = program.startTransaction("Change during stack-string recovery");
				try {
					program.getSymbolTable().createLabel(program.getAddressFactory().getDefaultAddressSpace()
						.getAddress(0x3010), "late_" + program.getModificationNumber(), SourceType.USER_DEFINED);
				}
				catch (Exception failure) {
					throw new IllegalStateException(failure);
				}
				finally {
					program.endTransaction(transaction, true);
				}
			});
			changing.cancelInstead = false;
			expect(IllegalStateException.class, () -> StackStrings.recover(program, null, 4, 100, changing));
		}
	}

	private void fallThrough() throws Exception {
		// mov dword [rbp-8], "ABCD"; mov dword [rbp-4], "WXYZ"; ret
		assertFallThrough("x86:LE:64:default", "gcc", "c745f841424344", "c745fc5758595ac3",
			0, 0, -8, (byte) 0xcc);
		// movz/movk w8, "ABCD"; str w8, [sp]; movz/movk w8, "WXYZ"; str w8, [sp,#4]; ret
		assertFallThrough("AARCH64:LE:64:v8A", "default", "284888526888a872e80300b9",
			"e80a8b52284bab72e80700b9c0035fd6", 8, 1, 0, (byte) 0);
	}

	private void assertFallThrough(String languageId, String compilerId, String firstCode, String secondCode,
			int storeOffset, int stackOperand, int stackOffset, byte fill) throws Exception {
		var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(languageId));
		var fixture = new ProgramDB("Stack string fall-through fixture", language,
			language.getCompilerSpecByID(new CompilerSpecID(compilerId)), this);
		try {
			byte[] firstBytes = HexFormat.of().parseHex(firstCode);
			byte[] secondBytes = HexFormat.of().parseHex(secondCode);
			var ram = fixture.getAddressFactory().getDefaultAddressSpace();
			var memory = fixture.getMemory();
			var flat = new FlatProgramAPI(fixture, monitor);
			int transaction = fixture.startTransaction("Create disconnected and contiguous stack stores");
			boolean commit = false;
			List<Function> functions = new ArrayList<>();
			try {
				memory.createInitializedBlock(".text", ram.getAddress(0x1000), 0x3000, fill, monitor, false)
					.setExecute(true);
				for (boolean contiguous : new boolean[] { false, true }) {
					Address first = ram.getAddress(contiguous ? 0x3000 : 0x1000);
					Address second = contiguous ? first.add(firstBytes.length) : ram.getAddress(0x2000);
					memory.setBytes(first, firstBytes);
					memory.setBytes(second, secondBytes);
					flat.disassemble(first);
					if (!contiguous) {
						flat.disassemble(second);
					}
					Address firstStore = first.add(storeOffset);
					Address secondStore = second.add(storeOffset);
					var instruction = fixture.getListing().getInstructionAt(firstStore);
					require(instruction != null && fixture.getListing().getInstructionAt(secondStore) != null &&
						second.equals(instruction.getFallThrough()) == contiguous, languageId + " fixture flow");
					AddressSet body = new AddressSet(first, first.add(firstBytes.length - 1));
					body.addRange(second, second.add(secondBytes.length - 1));
					Function function = fixture.getFunctionManager().createFunction(
						contiguous ? "contiguous" : "disconnected", first, body, SourceType.USER_DEFINED);
					fixture.getReferenceManager().addStackReference(firstStore, stackOperand,
						stackOffset, RefType.WRITE, SourceType.USER_DEFINED);
					fixture.getReferenceManager().addStackReference(secondStore, stackOperand,
						stackOffset + 4, RefType.WRITE, SourceType.USER_DEFINED);
					functions.add(function);
				}
				commit = true;
			}
			finally {
				fixture.endTransaction(transaction, commit);
			}
			List<String> disconnected = strings(StackStrings.recover(fixture, functions.get(0), 4, 1, monitor));
			require(disconnected.equals(List.of("disconnected " + stackOffset + " ABCD ascii false",
				"disconnected " + (stackOffset + 4) + " WXYZ ascii false")),
				languageId + " disconnected stack stores: " + disconnected);
			List<String> contiguous = strings(StackStrings.recover(fixture, functions.get(1), 4, 1, monitor));
			require(contiguous.equals(List.of("contiguous " + stackOffset + " ABCDWXYZ ascii false")),
				languageId + " contiguous stack stores: " + contiguous);
		}
		finally {
			fixture.release(this);
		}
	}

	/**
	 * Overlay spaces hold the same offsets as each other and as the default space: builder at
	 * ram:1000, bankA::1000 and bankB::1000 must be three separate engine groups in one batch,
	 * each string credited to its own function and space. Runs last: it adds two functions.
	 */
	private JsonObject overlays(JsonObject plain) throws Exception {
		var flat = new FlatProgramAPI(program, monitor);
		var ram = program.getAddressFactory().getDefaultAddressSpace();
		String[] texts = { "north", "south" };
		Function[] banked = new Function[texts.length];
		int transaction = program.startTransaction("Add overlay banks at the builder's offset");
		boolean commit = false;
		try {
			for (int index = 0; index < texts.length; index++) {
				var block = program.getMemory().createInitializedBlock("bank" + (char) ('A' + index),
					ram.getAddress(0x1000), 0x40, (byte) 0xcc, monitor, true);
				block.setExecute(true);
				Address entry = block.getStart();
				require(block.isOverlay() && entry.getOffset() == builder.getEntryPoint().getOffset() &&
					!entry.getAddressSpace().equals(ram), "bank " + index + " is not an overlay at 0x1000: " + entry);
				byte[] text = texts[index].getBytes(StandardCharsets.US_ASCII);
				program.getMemory().setBytes(entry, HexFormat.of().parseHex(
					"554889e5" +                                                   // push rbp; mov rbp,rsp
					"c745f0" + HexFormat.of().formatHex(text, 0, 4) +             // mov dword [rbp-0x10]
					"66c745f4" + HexFormat.of().formatHex(text, 4, 5) + "00" +    // mov word [rbp-0x0c], "h\0"
					"5dc3"));                                                      // pop rbp; ret
				require(flat.disassemble(entry), "could not disassemble bank " + index);
				banked[index] = flat.createFunction(entry, "banked_" + texts[index]);
				require(banked[index] != null &&
					new NewFunctionStackAnalysisCmd(entry, true).applyTo(program, monitor),
					"could not create the function in bank " + index);
			}
			commit = true;
		}
		finally {
			program.endTransaction(transaction, commit);
		}
		// The headless scripts' entry selector: HEX is the default space, SPACE:HEX (or SPACE::HEX,
		// as Ghidra shows overlay addresses) any memory space; banked code may repeat names too.
		String bankA = banked[0].getEntryPoint().getAddressSpace().getName();
		String bankB = banked[1].getEntryPoint().getAddressSpace().getName();
		var functions = program.getFunctionManager();
		require(functions.getFunctionAt(EntryAddress.parse(program, "1000")) == builder &&
			functions.getFunctionAt(EntryAddress.parse(program, ram.getName() + ":0x1000")) == builder &&
			functions.getFunctionAt(EntryAddress.parse(program, bankA + ":1000")) == banked[0] &&
			functions.getFunctionAt(EntryAddress.parse(program, bankA + "::00001000")) == banked[0] &&
			functions.getFunctionAt(EntryAddress.parse(program, bankB + ":0X1000")) == banked[1] &&
			EntryAddress.parse(program, "ffffffffffffffff").getOffset() == -1L,
			"entry selectors in overlay spaces");
		for (String bad : new String[] { "nosuch:1000", "register:0", "unique:1000", bankA + ":", ":1000",
			bankA + ":1000:", bankA + ":::1000", "bank A:1000", "10000000000000000", "name:x", "", "0x" }) {
			expect(IllegalArgumentException.class, () -> EntryAddress.parse(program, bad));
		}
		JsonObject report = StackStrings.recover(program, null, 4, StackStrings.DEFAULT_FUNCTIONS, monitor);
		require(report.get("functions_scanned").getAsInt() == plain.get("functions_scanned").getAsInt() + 2,
			"overlay functions not scanned: " + report.get("functions_scanned"));
		require(StackStrings.recover(program, null, 4, StackStrings.DEFAULT_FUNCTIONS, monitor).equals(report),
			"a second overlay run gave a different report");
		List<String> found = strings(report);
		require(found.containsAll(strings(plain)) && found.size() == strings(plain).size() + texts.length,
			"overlay functions changed the default-space strings: " + found);
		for (int index = 0; index < texts.length; index++) {
			String space = banked[index].getEntryPoint().getAddressSpace().getName();
			int matches = 0;
			for (JsonElement element : report.getAsJsonArray("strings")) {
				JsonObject item = element.getAsJsonObject();
				if (!item.get("text").getAsString().equals(texts[index])) {
					continue;
				}
				matches++;
				JsonObject function = item.getAsJsonObject("function");
				require(function.get("name").getAsString().equals("banked_" + texts[index]) &&
					function.get("address_space").getAsString().equals(space) &&
					function.get("address").getAsString().equals("1000") &&
					item.get("address_space").getAsString().equals(space) &&
					item.get("address").getAsString().equals("1004") && item.get("terminated").getAsBoolean(),
					"\"" + texts[index] + "\" credited to the wrong function or space: " + item);
				for (JsonElement write : item.getAsJsonArray("writes")) {
					require(write.getAsJsonObject().get("address_space").getAsString().equals(space),
						"\"" + texts[index] + "\" cites a write outside " + space + ": " + item);
				}
			}
			require(matches == 1, "\"" + texts[index] + "\" found " + matches + " times");
			JsonObject one = StackStrings.recover(program, banked[index], 4, 1, monitor);
			require(one.getAsJsonObject("function").get("address_space").getAsString().equals(space) &&
				strings(one).equals(List.of("banked_" + texts[index] + " -24 " + texts[index] + " ascii true")),
				"selected overlay function " + index + ": " + strings(one));
		}
		// The installed table resolves each row's address in the string's own space.
		Class<?> table;
		try {
			table = Class.forName(TABLE, true, ClassLoader.getSystemClassLoader());
		}
		catch (ClassNotFoundException missing) {
			return report;
		}
		List<?> rows;
		try {
			rows = (List<?>) table.getMethod("rows", Program.class, JsonObject.class).invoke(null, program, report);
		}
		catch (InvocationTargetException failure) {
			throw new IOException("overlay table rows failed", failure.getCause());
		}
		for (int index = 0; index < texts.length; index++) {
			Address expected = banked[index].getEntryPoint().add(4);
			int matches = 0;
			for (Object row : rows) {
				if (String.valueOf(row).contains("text=\"" + texts[index] + "\"")) {
					matches++;
					require(row.getClass().getMethod("address").invoke(row).equals(expected),
						"overlay table row at the wrong address: " + row);
				}
			}
			require(matches == 1, "overlay table rows for \"" + texts[index] + "\": " + matches);
		}
		return report;
	}

	/** Checks the desktop formatting when BinaryRat.jar is installed; a checkout run has no table. */
	private boolean table(JsonObject report) throws Exception {
		Class<?> table;
		try {
			table = Class.forName(TABLE, true, ClassLoader.getSystemClassLoader());
		}
		catch (ClassNotFoundException missing) {
			println("Stack-string table formatting skipped: BinaryRat.jar is not installed");
			return false;
		}
		List<?> rows;
		try {
			rows = (List<?>) table.getMethod("rows", Program.class, JsonObject.class).invoke(null, program, report);
		}
		catch (InvocationTargetException failure) {
			throw new IOException("stack-string table rows failed", failure.getCause());
		}
		// One row per reported string, in report order (whole() pins that list).
		require(rows.size() == report.getAsJsonArray("strings").size(),
			"table rows: " + rows.size() + " for " + report.getAsJsonArray("strings").size() + " strings");
		String hello = String.valueOf(rows.get(6));
		String wide = String.valueOf(rows.get(4));
		String reused = String.valueOf(rows.get(rows.size() - 1));
		require(hello.contains("text=\"hello\"") && hello.contains("stackOffset=-0x10") &&
			hello.contains("encoding=ASCII") && hello.contains("terminated=yes") &&
			wide.contains("encoding=UTF-16") && reused.contains("text=\"user\"") &&
			reused.contains("stackOffset=-0x38"), "table formatting: " + rows);
		return true;
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
			throw new IOException("stack-string proof failed: " + message);
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
