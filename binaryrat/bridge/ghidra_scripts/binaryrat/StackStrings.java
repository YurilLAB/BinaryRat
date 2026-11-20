// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package binaryrat;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Stream;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.StackReference;
import ghidra.util.task.TaskMonitor;

/**
 * Strings a function builds on its stack with constant stores, assembled by the engine's
 * {@code strings.stack} op. Read-only and without the decompiler: each function's
 * instructions are read in address order, register constants are followed through each
 * straight-line run (moves, extensions, constant arithmetic and loads from read-only
 * memory), and every store that Ghidra's stack analysis marked as a stack write with a
 * known value becomes one write. A run ends at a jump target and after a jump or a call, so
 * strings from different paths, or from before and after a callee used a buffer, are never
 * mixed. A stack store of an unknown value removes the bytes it covers, and p-code that an
 * instruction runs conditionally (a conditional move) yields unknown values. The Program's
 * modification number is checked around every step and any change fails the run.
 */
public final class StackStrings {
	public static final String ANALYSIS_MODE = "read_only_stack_strings";
	public static final int DEFAULT_MINIMUM_LENGTH = 4;
	public static final int DEFAULT_FUNCTIONS = 10_000;
	public static final int MAXIMUM_FUNCTIONS = 200_000;
	public static final int MAXIMUM_STRINGS = 10_000;
	private static final long MAXIMUM_FUNCTION_BYTES = 1 << 20;
	private static final int MAXIMUM_INSTRUCTIONS = 65_536;
	private static final int MAXIMUM_VALUE_BYTES = 64;
	private static final int BATCH_WRITES = 32_768;
	// The engine assembles at most 1 MiB of distinct stack bytes per group.
	private static final long MAXIMUM_GROUP_BYTES = (1 << 20) - MAXIMUM_VALUE_BYTES;
	private static final int MAXIMUM_TEXT = 1_024;
	// Earlier writes examined per function when stores of unknown values overwrite them;
	// past it such a store ends the run instead.
	private static final long FORGET_BUDGET = 1L << 22;

	private StackStrings() {
	}

	/** One constant stack store. */
	private record Write(long offset, byte[] bytes, long order, Address address) {
	}

	/** Writes of one straight-line run of one function. */
	private record Group(String id, Function function, List<Write> writes) {
	}

	/** Recovers a report and returns it as JSON text (for PyGhidra callers). */
	public static String recoverJson(Program program, Function function, int minimumLength, int maximumFunctions,
			TaskMonitor monitor) throws Exception {
		return new GsonBuilder().serializeNulls().create()
			.toJson(recover(program, function, minimumLength, maximumFunctions, monitor));
	}

	/**
	 * Recovers stack strings in one function, or in every eligible function of the Program when
	 * {@code function} is null (at most {@code maximumFunctions}, in entry order).
	 */
	public static JsonObject recover(Program program, Function function, int minimumLength, int maximumFunctions,
			TaskMonitor monitor) throws Exception {
		if (minimumLength < 1 || minimumLength > 64) {
			throw new IllegalArgumentException("minimum length must be 1 to 64 characters");
		}
		if (maximumFunctions < 1 || maximumFunctions > MAXIMUM_FUNCTIONS) {
			throw new IllegalArgumentException("function limit must be between 1 and " + MAXIMUM_FUNCTIONS);
		}
		if (program == null || function != null && function.getProgram() != program) {
			throw new IOException("select a function of the open Program");
		}
		return new Run(program, monitor, minimumLength, maximumFunctions).recover(function);
	}

	/** Whether a function's stores can be read: local, not a thunk, initialized, at most 1 MiB. */
	public static boolean supportedFunction(Program program, Function function) {
		if (function == null || function.isExternal() || function.isThunk()) {
			return false;
		}
		MemoryBlock block = program.getMemory().getBlock(function.getEntryPoint());
		long size = function.getBody().getNumAddresses();
		return block != null && !block.isExternalBlock() && block.isInitialized() && size > 0 &&
			size <= MAXIMUM_FUNCTION_BYTES;
	}

	private static final class Run {
		private final Program program;
		private final TaskMonitor monitor;
		private final int minimumLength;
		private final int maximumFunctions;
		private final long revision;
		private final boolean bigEndian;

		Run(Program program, TaskMonitor monitor, int minimumLength, int maximumFunctions) throws Exception {
			this.program = program;
			this.monitor = monitor;
			this.minimumLength = minimumLength;
			this.maximumFunctions = maximumFunctions;
			this.revision = program.getModificationNumber();
			this.bigEndian = program.getLanguage().isBigEndian();
			checkCurrent();
		}

		JsonObject recover(Function selected) throws Exception {
			List<Group> groups = new ArrayList<>();
			int scanned = 0;
			int skipped = 0;
			int partial = 0;
			boolean truncated = false;
			Iterator<Function> functions = selected != null ? List.of(selected).iterator() :
				program.getFunctionManager().getFunctions(true);
			while (functions.hasNext()) {
				checkCurrent();
				Function function = functions.next();
				if (!supportedFunction(program, function)) {
					if (selected != null) {
						throw new IOException("select a local non-thunk function within the 1 MiB body limit");
					}
					skipped += function.isExternal() ? 0 : 1;
					continue;
				}
				if (scanned == maximumFunctions) {
					truncated = true;
					break;
				}
				scanned++;
				if (!extract(function, groups)) {
					partial++;
				}
			}
			JsonArray strings = new JsonArray();
			int writeCount = groups.stream().mapToInt(group -> group.writes().size()).sum();
			if (writeCount > 0) {
				truncated |= assemble(groups, strings);
			}
			checkCurrent();

			JsonObject report = new JsonObject();
			report.addProperty("schema_version", 1);
			report.addProperty("analysis_mode", ANALYSIS_MODE);
			report.addProperty("revision", revision);
			String hash = program.getExecutableSHA256();
			report.addProperty("program_id", hash != null && hash.matches("[0-9a-fA-F]{64}") ?
				"sha256:" + hash.toLowerCase(Locale.ROOT) : null);
			report.addProperty("language_id", program.getLanguageID().toString());
			report.addProperty("compiler_spec_id", program.getCompilerSpec().getCompilerSpecID().toString());
			report.add("function", selected == null ? JsonNull.INSTANCE : functionRecord(selected));
			report.addProperty("minimum_length", minimumLength);
			report.addProperty("function_limit", maximumFunctions);
			report.addProperty("functions_scanned", scanned);
			report.addProperty("functions_skipped", skipped);
			report.addProperty("functions_partial", partial);
			report.addProperty("stack_writes", writeCount);
			report.addProperty("truncated", truncated);
			report.add("strings", strings);
			return report;
		}

		/**
		 * Reads one function's constant stack stores into groups. Returns false when the function
		 * has more instructions than are read; the stores before the limit are kept.
		 */
		private boolean extract(Function function, List<Group> groups) throws Exception {
			var references = program.getReferenceManager();
			TreeMap<Long, byte[]> registers = new TreeMap<>();
			List<Write> current = new ArrayList<>();
			long groupBytes = 0;
			Address groupStart = null;
			boolean endAfter = false;
			long forgetBudget = FORGET_BUDGET;
			int index = 0;
			for (Instruction instruction : program.getListing().getInstructions(function.getBody(), true)) {
				monitor.checkCancelled();
				if (++index > MAXIMUM_INSTRUCTIONS) {
					finish(function, groupStart, current, groups);
					return false;
				}
				Address address = instruction.getAddress();
				boolean join = references.hasReferencesTo(address) && isJoin(references.getReferencesTo(address));
				if (groupStart == null || endAfter || join || groupBytes > MAXIMUM_GROUP_BYTES) {
					finish(function, groupStart, current, groups);
					current = new ArrayList<>();
					groupBytes = 0;
					registers.clear();
					groupStart = address;
				}
				FlowType flow = instruction.getFlowType();
				// A callee may read or rewrite the buffers built so far, so a call ends the run too.
				endAfter = flow.isJump() || flow.isTerminal() || flow.isCall();
				StackReference destination = null;
				int stackWrites = 0;
				for (Reference reference : references.getReferencesFrom(address)) {
					if (reference instanceof StackReference stack && reference.getReferenceType().isWrite()) {
						destination = stack;
						stackWrites++;
					}
				}
				TreeMap<Long, byte[]> uniques = new TreeMap<>();
				PcodeOp[] ops = instruction.getPcode();
				int stores = 0;
				// P-code after a branch inside the instruction (a conditional move, a repeated
				// string operation) runs zero or several times, so nothing it computes is known.
				boolean conditional = false;
				for (int position = 0; position < ops.length; position++) {
					int opcode = ops[position].getOpcode();
					stores += opcode == PcodeOp.STORE ? 1 : 0;
					conditional |= position < ops.length - 1 && (opcode == PcodeOp.BRANCH ||
						opcode == PcodeOp.CBRANCH || opcode == PcodeOp.BRANCHIND);
				}
				boolean oneStackStore = stores == 1 && stackWrites == 1;
				if (stackWrites > 0 ? !oneStackStore : conditional && stores > 0) {
					// Memory changes here, but not which bytes: what follows starts afresh.
					endAfter = true;
				}
				for (int position = 0; position < ops.length; position++) {
					PcodeOp op = ops[position];
					if (op.getOpcode() == PcodeOp.STORE) {
						if (oneStackStore) {
							Varnode stored = op.getInput(2);
							byte[] value = conditional ? null : value(stored, registers, uniques);
							long offset = destination.getStackOffset();
							if (value != null) {
								current.add(new Write(offset, value, (long) index * 256 + position, address));
								groupBytes += value.length;
							}
							else if ((forgetBudget -= current.size()) < 0) {
								endAfter = true;
							}
							else {
								forget(current, offset, stored.getSize());
							}
						}
						continue;
					}
					if (op.getOpcode() == PcodeOp.CALL || op.getOpcode() == PcodeOp.CALLIND) {
						registers.clear();
						uniques.clear();
					}
					Varnode output = op.getOutput();
					if (output != null) {
						assign(output, conditional ? null : evaluate(op, registers, uniques), registers, uniques);
					}
				}
			}
			finish(function, groupStart, current, groups);
			return true;
		}

		/** A jump or call (not a fall-through) reaches this instruction: values may differ. */
		private static boolean isJoin(Iterable<Reference> incoming) {
			for (Reference reference : incoming) {
				var type = reference.getReferenceType();
				if (type.isFlow() && !type.isFallthrough()) {
					return true;
				}
			}
			return false;
		}

		/**
		 * Drops the bytes [offset, offset + size) from the writes so far: a store of an unknown
		 * value replaced them, so no string may be read across them.
		 */
		private static void forget(List<Write> writes, long offset, int size) {
			long end = offset + size;
			for (int index = 0; index < writes.size(); index++) {
				Write write = writes.get(index);
				long start = write.offset();
				long stop = start + write.bytes().length;
				if (stop <= offset || start >= end) {
					continue;
				}
				writes.remove(index--);
				if (start < offset) {
					writes.add(++index, new Write(start,
						Arrays.copyOfRange(write.bytes(), 0, (int) (offset - start)), write.order(), write.address()));
				}
				if (stop > end) {
					writes.add(++index, new Write(end, Arrays.copyOfRange(write.bytes(), (int) (end - start),
						write.bytes().length), write.order(), write.address()));
				}
			}
		}

		private void finish(Function function, Address start, List<Write> writes, List<Group> groups) {
			if (start != null && !writes.isEmpty()) {
				groups.add(new Group(hex(function.getEntryPoint()) + "/" + hex(start), function, writes));
			}
		}

		/** The bytes an op computes when every input is known, or null. */
		private byte[] evaluate(PcodeOp op, TreeMap<Long, byte[]> registers, TreeMap<Long, byte[]> uniques) {
			int size = op.getOutput().getSize();
			if (size <= 0 || size > MAXIMUM_VALUE_BYTES) {
				return null;
			}
			switch (op.getOpcode()) {
				case PcodeOp.COPY:
					return value(op.getInput(0), registers, uniques);
				case PcodeOp.INT_ZEXT:
				case PcodeOp.INT_SEXT: {
					byte[] input = value(op.getInput(0), registers, uniques);
					if (input == null || input.length > size) {
						return null;
					}
					boolean negative = op.getOpcode() == PcodeOp.INT_SEXT &&
						(input[bigEndian ? 0 : input.length - 1] & 0x80) != 0;
					return bytes(integer(input).add(negative ? BigInteger.ONE.shiftLeft(8 * size)
						.subtract(BigInteger.ONE.shiftLeft(8 * input.length)) : BigInteger.ZERO), size);
				}
				case PcodeOp.LOAD: {
					byte[] pointer = value(op.getInput(1), registers, uniques);
					AddressSpace space = program.getAddressFactory().getAddressSpace((int) op.getInput(0).getOffset());
					return pointer == null || space == null || pointer.length > 8 ? null :
						readOnly(space, integer(pointer).longValue(), size);
				}
				case PcodeOp.SUBPIECE: {
					byte[] input = value(op.getInput(0), registers, uniques);
					long drop = op.getInput(1).getOffset();
					if (input == null || drop < 0 || drop + size > input.length) {
						return null;
					}
					return bytes(integer(input).shiftRight((int) (8 * drop)), size);
				}
				case PcodeOp.PIECE: {
					byte[] high = value(op.getInput(0), registers, uniques);
					byte[] low = value(op.getInput(1), registers, uniques);
					return high == null || low == null || high.length + low.length != size ? null :
						bytes(integer(high).shiftLeft(8 * low.length).or(integer(low)), size);
				}
				case PcodeOp.INT_ADD:
				case PcodeOp.INT_SUB:
				case PcodeOp.INT_XOR:
				case PcodeOp.INT_AND:
				case PcodeOp.INT_OR:
				case PcodeOp.INT_LEFT:
				case PcodeOp.INT_RIGHT: {
					if (op.getOpcode() == PcodeOp.INT_XOR && op.getInput(0).equals(op.getInput(1))) {
						return new byte[size];
					}
					byte[] left = value(op.getInput(0), registers, uniques);
					byte[] right = value(op.getInput(1), registers, uniques);
					if (left == null || right == null || size > 8) {
						return null;
					}
					BigInteger a = integer(left);
					BigInteger b = integer(right);
					BigInteger result = switch (op.getOpcode()) {
						case PcodeOp.INT_ADD -> a.add(b);
						case PcodeOp.INT_SUB -> a.subtract(b);
						case PcodeOp.INT_XOR -> a.xor(b);
						case PcodeOp.INT_AND -> a.and(b);
						case PcodeOp.INT_OR -> a.or(b);
						case PcodeOp.INT_LEFT -> b.compareTo(BigInteger.valueOf(64)) >= 0 ? BigInteger.ZERO :
							a.shiftLeft(b.intValue());
						default -> b.compareTo(BigInteger.valueOf(64)) >= 0 ? BigInteger.ZERO : a.shiftRight(b.intValue());
					};
					return bytes(result, size);
				}
				default:
					return null;
			}
		}

		/** A known value of a varnode, in memory byte order, or null. */
		private byte[] value(Varnode varnode, TreeMap<Long, byte[]> registers, TreeMap<Long, byte[]> uniques) {
			int size = varnode.getSize();
			if (size <= 0 || size > MAXIMUM_VALUE_BYTES) {
				return null;
			}
			if (varnode.isConstant()) {
				return size > 8 ? null : bytes(BigInteger.valueOf(varnode.getOffset()), size);
			}
			if (varnode.isUnique()) {
				return compose(uniques, varnode.getOffset(), size);
			}
			if (varnode.isRegister()) {
				return compose(registers, varnode.getOffset(), size);
			}
			if (varnode.isAddress()) {
				return readOnly(varnode.getAddress().getAddressSpace(), varnode.getOffset(), size);
			}
			return null;
		}

		/** Bytes from initialized memory that no write can change, or null. */
		private byte[] readOnly(AddressSpace space, long offset, int size) {
			try {
				Address start = space.getAddress(offset);
				MemoryBlock block = program.getMemory().getBlock(start);
				if (block == null || !block.isInitialized() || block.isWrite() || block.isVolatile() ||
						!block.contains(start.addNoWrap(size - 1))) {
					return null;
				}
				byte[] bytes = new byte[size];
				return program.getMemory().getBytes(start, bytes) == size ? bytes : null;
			}
			catch (MemoryAccessException | ghidra.program.model.address.AddressOverflowException |
					ghidra.program.model.address.AddressOutOfBoundsException unreadable) {
				return null;
			}
		}

		private void assign(Varnode output, byte[] value, TreeMap<Long, byte[]> registers,
				TreeMap<Long, byte[]> uniques) {
			TreeMap<Long, byte[]> storage = output.isUnique() ? uniques : output.isRegister() ? registers : null;
			if (storage == null) {
				return;
			}
			long start = output.getOffset();
			long end = start + output.getSize();
			// Known pieces never overlap: a write replaces every piece it touches, so the
			// untouched bytes of a partly overwritten piece become unknown.
			storage.entrySet().removeIf(entry -> entry.getKey() < end && entry.getKey() + entry.getValue().length > start);
			if (value != null) {
				storage.put(start, value);
			}
		}

		/**
		 * The bytes [offset, offset + size) of a register or temporary, assembled from adjacent
		 * known pieces, or null if any byte is unknown. Pieces are kept in address order, so a
		 * sub-register (AL in RAX) or a slice of a temporary reads the right bytes on either
		 * byte order.
		 */
		private static byte[] compose(TreeMap<Long, byte[]> storage, long offset, int size) {
			byte[] out = new byte[size];
			long position = offset;
			long end = offset + size;
			while (position < end) {
				var entry = storage.floorEntry(position);
				if (entry == null || entry.getKey() + entry.getValue().length <= position) {
					return null;
				}
				int from = (int) (position - entry.getKey());
				int take = (int) Math.min(entry.getValue().length - from, end - position);
				System.arraycopy(entry.getValue(), from, out, (int) (position - offset), take);
				position += take;
			}
			return out;
		}

		/** An unsigned integer from bytes in memory order. */
		private BigInteger integer(byte[] bytes) {
			byte[] big = bytes.clone();
			if (!bigEndian) {
				for (int low = 0, high = big.length - 1; low < high; low++, high--) {
					byte swap = big[low];
					big[low] = big[high];
					big[high] = swap;
				}
			}
			return new BigInteger(1, big);
		}

		/** The low {@code size} bytes of a value, in memory order. */
		private byte[] bytes(BigInteger value, int size) {
			byte[] out = new byte[size];
			for (int index = 0; index < size; index++) {
				byte digit = value.shiftRight(8 * index).byteValue();
				out[bigEndian ? size - 1 - index : index] = digit;
			}
			return out;
		}

		/** Sends the groups to the engine in batches; returns true when the string limit cut the list. */
		private boolean assemble(List<Group> groups, JsonArray strings) throws Exception {
			Path workspace = Files.createTempDirectory("binaryrat-stackstrings-");
			try (EngineClient engine = EngineClient.start(EngineClient.findExecutable(), workspace)) {
				JsonObject ping = engine.call("ping", new JsonObject());
				boolean supported = false;
				for (JsonElement capability : ping.getAsJsonArray("capabilities")) {
					supported |= capability.getAsString().equals("stack-strings");
				}
				if (!supported) {
					throw new IOException("the BinaryRat engine is too old for stack strings; update the extension");
				}
				Map<String, Group> byId = new LinkedHashMap<>();
				JsonArray batch = new JsonArray();
				int batchWrites = 0;
				for (Group group : groups) {
					checkCurrent();
					if (batchWrites > 0 && batchWrites + group.writes().size() > BATCH_WRITES) {
						if (send(engine, batch, byId, strings)) {
							return true;
						}
						batch = new JsonArray();
						byId.clear();
						batchWrites = 0;
					}
					byId.put(group.id(), group);
					batch.add(groupRequest(group));
					batchWrites += group.writes().size();
				}
				return send(engine, batch, byId, strings);
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

		private JsonObject groupRequest(Group group) {
			JsonArray writes = new JsonArray();
			for (Write write : group.writes()) {
				JsonObject item = new JsonObject();
				item.addProperty("offset", write.offset());
				item.addProperty("bytes", HexFormat.of().formatHex(write.bytes()));
				item.addProperty("order", write.order());
				writes.add(item);
			}
			JsonObject request = new JsonObject();
			request.addProperty("id", group.id());
			request.add("writes", writes);
			return request;
		}

		private boolean send(EngineClient engine, JsonArray batch, Map<String, Group> byId, JsonArray strings)
				throws Exception {
			checkCurrent();
			JsonObject request = new JsonObject();
			request.add("groups", batch);
			request.addProperty("minimum_length", minimumLength);
			JsonObject result = engine.call("strings.stack", request);
			checkCurrent();
			for (JsonElement element : result.getAsJsonArray("groups")) {
				JsonObject answer = element.getAsJsonObject();
				Group group = byId.get(answer.get("id").getAsString());
				if (group == null) {
					throw new IOException("engine answered an unknown stack-string group");
				}
				Map<Long, Address> addresses = new TreeMap<>();
				for (Write write : group.writes()) {
					addresses.put(write.order(), write.address());
				}
				for (JsonElement found : answer.getAsJsonArray("strings")) {
					if (strings.size() == MAXIMUM_STRINGS) {
						return true;
					}
					strings.add(stringRecord(group, found.getAsJsonObject(), addresses));
				}
			}
			return false;
		}

		private JsonObject stringRecord(Group group, JsonObject found, Map<Long, Address> addresses)
				throws IOException {
			JsonArray writes = new JsonArray();
			Address first = null;
			java.util.Set<Address> seen = new java.util.TreeSet<>();
			for (JsonElement order : found.getAsJsonArray("orders")) {
				Address address = addresses.get(order.getAsLong());
				if (address == null) {
					throw new IOException("engine cited an unknown stack write");
				}
				seen.add(address);
			}
			for (Address address : seen) {
				JsonObject item = new JsonObject();
				item.addProperty("address_space", address.getAddressSpace().getName());
				item.addProperty("address", hex(address));
				writes.add(item);
				first = first == null ? address : first;
			}
			String text = found.get("text").getAsString();
			JsonObject record = new JsonObject();
			record.add("function", functionRecord(group.function()));
			record.addProperty("address_space", first.getAddressSpace().getName());
			record.addProperty("address", hex(first));
			record.addProperty("stack_offset", found.get("offset").getAsLong());
			record.addProperty("byte_length", found.get("byte_length").getAsLong());
			record.addProperty("encoding", found.get("encoding").getAsString());
			record.addProperty("text", text.length() > MAXIMUM_TEXT ? text.substring(0, MAXIMUM_TEXT) : text);
			record.addProperty("text_truncated", text.length() > MAXIMUM_TEXT);
			record.addProperty("terminated", found.get("terminated").getAsBoolean());
			record.add("writes", writes);
			return record;
		}

		private static JsonObject functionRecord(Function function) {
			JsonObject record = new JsonObject();
			Address entry = function.getEntryPoint();
			record.addProperty("address_space", entry.getAddressSpace().getName());
			record.addProperty("address", hex(entry));
			String name = function.getName(true).replaceAll("\\s+", " ").strip();
			StringBuilder printable = new StringBuilder();
			name.codePoints().forEach(point -> printable.appendCodePoint(Character.isISOControl(point) ? '?' : point));
			record.addProperty("name", printable.length() > 1_024 ? printable.substring(0, 1_024) : printable.toString());
			return record;
		}

		private void checkCurrent() throws Exception {
			monitor.checkCancelled();
			if (program.isClosed() || revision != program.getModificationNumber()) {
				throw new IllegalStateException("Program changed during stack-string recovery");
			}
		}
	}

	private static String hex(Address address) {
		return Long.toUnsignedString(address.getOffset(), 16);
	}
}
