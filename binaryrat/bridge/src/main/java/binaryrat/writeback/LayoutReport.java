// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package binaryrat.writeback;

import java.io.IOException;
import java.io.StringReader;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

import com.google.gson.*;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Common version-1 layout report decoding, identity and live forwarding checks. */
final class LayoutReport {
	private static final int MAXIMUM_FUNCTIONS = 32;
	private static final int MAXIMUM_FOLLOW_DEPTH = 4;
	private static final int MAXIMUM_FORWARDING_EDGES = 128;

	private LayoutReport() {
	}

	record Target(Function function, String reportedName, String objectId, int parameter) {
	}

	static Target target(Program program, JsonObject artifact, int maximumParameter) throws IOException {
		return target(program, artifact, maximumParameter, "read_only_layout_evidence");
	}

	static Target target(Program program, JsonObject artifact, int maximumParameter,
			String analysisMode) throws IOException {
		integer(artifact.get("schema_version"), 1, 1, "schema_version");
		if (!analysisMode.equals(string(artifact.get("analysis_mode"), "analysis_mode")) ||
				!"analyst_selected_object_start".equals(string(artifact.get("assumption"), "assumption"))) {
			throw new IOException("Expected a BinaryRat read-only layout report");
		}

		String executableHash = program.getExecutableSHA256();
		if (executableHash == null || !executableHash.matches("[0-9a-fA-F]{64}")) {
			throw new IOException("Review requires a Program with an executable SHA-256");
		}
		String programId = "sha256:" + executableHash.toLowerCase(Locale.ROOT);
		if (!programId.equals(string(artifact.get("program_id"), "program_id")) ||
				!program.getLanguageID().toString().equals(
					string(artifact.get("language_id"), "language_id")) ||
				!program.getCompilerSpec().getCompilerSpecID().toString().equals(
					string(artifact.get("compiler_spec_id"), "compiler_spec_id"))) {
			throw new IOException("Layout report is from a different executable or architecture");
		}

		JsonObject functionJson = object(artifact.get("function"), "function");
		String spaceName = string(functionJson.get("address_space"), "address_space");
		String offsetText = string(functionJson.get("address"), "address");
		Function function = findFunction(program, spaceName, offsetText);
		String reportedName = string(functionJson.get("name"), "function name");
		int parameter = integer(artifact.get("parameter_index"), 0, maximumParameter, "parameter_index");
		String objectId = programId + "/" + spaceName + "/" + offsetText + "/param/" + parameter;
		return new Target(function, reportedName, objectId, parameter);
	}

	static void checkRevision(Program program, long revision) throws IOException {
		if (program.isClosed() || program.getModificationNumber() != revision) {
			throw new IOException("The reviewed Program changed or closed; prepare a fresh review");
		}
	}

	static Function findFunction(Program program, String spaceName, String offsetText)
			throws IOException {
		Address entry = readAddress(program, spaceName, offsetText);
		Function function = program.getFunctionManager().getFunctionAt(entry);
		if (function == null || function.isExternal() || function.isThunk()) {
			throw new IOException("Report target must identify a local, non-thunk function");
		}
		return function;
	}

	static Address readAddress(Program program, String spaceName, String offsetText)
			throws IOException {
		if (!offsetText.matches("0|[1-9a-f][0-9a-f]{0,15}")) {
			throw new IOException("Invalid layout report address");
		}
		var space = program.getAddressFactory().getAddressSpace(spaceName);
		if (space == null || !space.isMemorySpace()) {
			throw new IOException("Unknown function address space");
		}
		long offset = Long.parseUnsignedLong(offsetText, 16);
		Address entry;
		try {
			entry = space.getAddressInThisSpaceOnly(offset);
		}
		catch (AddressOutOfBoundsException failure) {
			throw new IOException("Function address exceeds its space", failure);
		}
		if (entry.getOffset() != offset) {
			throw new IOException("Report address exceeds its selected space");
		}
		return entry;
	}

	/** Validate every reported transfer, including intermediate functions with no field accesses. */
	static Map<Address, Function> forwardingPath(Program program, JsonObject report,
			Function root, TaskMonitor monitor) throws IOException, CancelledException {
		int limit = integer(report.get("follow_depth"), 0, MAXIMUM_FOLLOW_DEPTH, "follow_depth");
		JsonArray calls = array(report.get("forwarded_calls"), "forwarded_calls");
		if (calls.size() > MAXIMUM_FORWARDING_EDGES || limit == 0 && !calls.isEmpty()) {
			throw new IOException("Forwarded calls exceed the report's traversal limits");
		}
		Map<Address, Function> functions = new TreeMap<>();
		functions.put(root.getEntryPoint(), root);
		Map<Address, Integer> depths = new HashMap<>();
		depths.put(root.getEntryPoint(), 0);
		var reached = new HashSet<Address>();
		reached.add(root.getEntryPoint());
		for (var element : calls) {
			monitor.checkCancelled();
			JsonObject edge = object(element, "forwarded call");
			int hop = limit == 1 ? 1 : integer(edge.get("hop"), 1, limit, "hop");
			Function caller = limit == 1 ? root : findFunction(program,
				string(edge.get("caller_address_space"), "caller address space"),
				string(edge.get("caller_address"), "caller address"));
			Function callee = findFunction(program,
				string(edge.get("callee_address_space"), "callee address space"),
				string(edge.get("callee_address"), "callee address"));
			Address site = readAddress(program, string(edge.get("address_space"), "call address space"),
				string(edge.get("address"), "call address"));
			integer(edge.get("callee_parameter_index"), 0, 0, "callee_parameter_index");
			if ((hop == 1 && !caller.equals(root)) ||
					depths.computeIfAbsent(caller.getEntryPoint(), k -> hop - 1) != hop - 1 ||
					depths.computeIfAbsent(callee.getEntryPoint(), k -> hop) != hop) {
				throw new IOException("Inconsistent forwarded call path");
			}
			if (!caller.getBody().contains(site) ||
					!caller.equals(program.getFunctionManager().getFunctionContaining(site)) ||
					!currentDirectCall(program, site, callee)) {
				throw new IOException("Forwarded call no longer matches the reviewed instruction");
			}
			verifyInstructionBytes(edge, program.getListing().getInstructionAt(site));
			functions.put(caller.getEntryPoint(), caller);
			functions.put(callee.getEntryPoint(), callee);
			if (functions.size() > MAXIMUM_FUNCTIONS) {
				throw new IOException("Reviewed functions exceed the review limit");
			}
			reached.add(callee.getEntryPoint());
		}
		// Every non-root caller needs a validated incoming edge at the preceding depth.
		if (!reached.containsAll(functions.keySet())) {
			throw new IOException("Disconnected forwarded call path");
		}
		return functions;
	}

	private static boolean currentDirectCall(Program program, Address site, Function callee) {
		var instruction = program.getListing().getInstructionAt(site);
		if (instruction == null || instruction.getFlowOverride() != FlowOverride.NONE ||
				!instruction.getFlowType().isCall() || instruction.getFlowType().isComputed() ||
				callee.getCallFixup() != null) {
			return false;
		}
		Address target = callee.getEntryPoint();
		Address[] decoded = instruction.getDefaultFlows();
		if (decoded == null || decoded.length != 1 || !target.equals(decoded[0])) {
			return false;
		}
		// The effective p-code includes primary call-reference overrides. They can
		// redirect a call without changing its bytes, prototype, or decoded flow.
		for (PcodeOp op : instruction.getPcode(true)) {
			if (op.getOpcode() == PcodeOp.CALL && target.equals(op.getInput(0).getAddress())) {
				return true;
			}
		}
		return false;
	}

	/** A v1 witness, when present, covers all parsed bytes, including a length override's tail. */
	static boolean verifyInstructionBytes(JsonObject witness, Instruction instruction) throws IOException {
		if (!witness.has("instruction_sha256")) {
			return false;
		}
		String expected = string(witness.get("instruction_sha256"), "instruction_sha256");
		if (!expected.matches("[0-9a-f]{64}")) {
			throw new IOException("Invalid instruction SHA-256");
		}
		int length = instruction == null ? 0 : instruction.getParsedLength();
		if (length <= 0 || length > 65_536) {
			throw new IOException("No verifiable parsed instruction at the cited address");
		}
		try {
			byte[] bytes = instruction.getParsedBytes();
			if (bytes == null || bytes.length != length ||
					!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)).equals(expected)) {
				throw new IOException("Instruction bytes differ from the layout evidence");
			}
		}
		catch (MemoryAccessException e) {
			throw new IOException("Cannot read the complete cited instruction", e);
		}
		catch (NoSuchAlgorithmException impossible) {
			throw new IllegalStateException("SHA-256 is unavailable", impossible);
		}
		return true;
	}

	static byte[] readReport(Path path, int maximumBytes) throws IOException {
		if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
			throw new IOException("Choose a regular BinaryRat layout report file");
		}
		try (var input = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS)) {
			byte[] bytes = input.readNBytes(maximumBytes + 1);
			if (bytes.length > maximumBytes) {
				throw new IOException("Layout report exceeds the review byte limit");
			}
			return bytes;
		}
	}

	static JsonObject parseReport(byte[] bytes, TaskMonitor monitor) throws IOException, CancelledException {
		String text = StandardCharsets.UTF_8.newDecoder()
			.onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
			.decode(ByteBuffer.wrap(bytes)).toString();
		try (JsonReader reader = new JsonReader(new StringReader(text))) {
			reader.setStrictness(Strictness.STRICT);
			reader.setNestingLimit(32);
			var budget = new ReadBudget(monitor);
			JsonObject report = object(readJson(reader, budget), "report");
			if (reader.peek() != JsonToken.END_DOCUMENT) {
				throw new IOException("Extra content after layout report");
			}
			return report;
		}
	}

	private static final class ReadBudget {
		private final TaskMonitor monitor;
		private int values;

		private ReadBudget(TaskMonitor monitor) {
			this.monitor = monitor;
		}

		void next() throws IOException, CancelledException {
			if ((values & 255) == 0) {
				monitor.checkCancelled();
			}
			if (++values > 262_144) {
				throw new IOException("Too many JSON values in layout report");
			}
		}
	}

	private static JsonElement readJson(JsonReader reader, ReadBudget budget)
			throws IOException, CancelledException {
		budget.next();
		return switch (reader.peek()) {
			case BEGIN_OBJECT -> {
				JsonObject result = new JsonObject();
				reader.beginObject();
				while (reader.hasNext()) {
					String name = reader.nextName();
					if (result.has(name)) {
						throw new IOException("Duplicate layout report property");
					}
					result.add(name, readJson(reader, budget));
				}
				reader.endObject();
				yield result;
			}
			case BEGIN_ARRAY -> {
				JsonArray result = new JsonArray();
				reader.beginArray();
				while (reader.hasNext()) {
					result.add(readJson(reader, budget));
				}
				reader.endArray();
				yield result;
			}
			case BOOLEAN -> new JsonPrimitive(reader.nextBoolean());
			case NUMBER -> JsonParser.parseString(reader.nextString());
			case STRING -> new JsonPrimitive(reader.nextString());
			case NULL -> {
				reader.nextNull();
				yield JsonNull.INSTANCE;
			}
			default -> throw new IOException("Invalid layout report JSON value");
		};
	}

	static JsonObject object(JsonElement value, String name) throws IOException {
		if (value == null || !value.isJsonObject()) {
			throw new IOException("Expected a JSON object for " + name);
		}
		return value.getAsJsonObject();
	}

	static JsonArray array(JsonElement value, String name) throws IOException {
		if (value == null || !value.isJsonArray()) {
			throw new IOException("Expected a JSON array for " + name);
		}
		return value.getAsJsonArray();
	}

	static boolean flag(JsonElement value, String name) throws IOException {
		if (!(value instanceof JsonPrimitive primitive) || !primitive.isBoolean()) {
			throw new IOException("Expected a JSON boolean for " + name);
		}
		return primitive.getAsBoolean();
	}

	static String string(JsonElement value, String name) throws IOException {
		if (!(value instanceof JsonPrimitive primitive) || !primitive.isString() ||
				primitive.getAsString().isBlank() || primitive.getAsString().length() > 1024) {
			throw new IOException("Invalid string for " + name);
		}
		return primitive.getAsString();
	}

	static int integer(JsonElement value, int minimum, int maximum, String name)
			throws IOException {
		if (!(value instanceof JsonPrimitive primitive) || !primitive.isNumber() ||
				!primitive.getAsString().matches("0|[1-9][0-9]{0,9}")) {
			throw new IOException("Expected an unsigned decimal integer for " + name);
		}
		long number = Long.parseLong(primitive.getAsString());
		if (number < minimum || number > maximum) {
			throw new IOException("Out-of-range layout value for " + name);
		}
		return (int) number;
	}

}
