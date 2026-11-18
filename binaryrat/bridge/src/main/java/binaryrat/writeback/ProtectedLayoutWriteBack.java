// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package binaryrat.writeback;

import java.io.IOException;
import java.io.StringReader;
import java.lang.reflect.InvocationTargetException;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import com.google.gson.Strictness;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;

import ghidra.app.plugin.core.analysis.AnalysisWorker;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Explicitly review and create a new structure in an exclusively owned, saved headless Program.
 * Imported layout reports are analyst-reviewed data. A review code binds the exact report,
 * destination Program and current target state. The prepared handle also guards live edits.
 */
public final class ProtectedLayoutWriteBack {
	private static final CategoryPath CATEGORY = new CategoryPath("/BinaryRat/Reviewed");
	private static final String JOURNAL = "BinaryRat Reviewed Layouts";
	private static final String TRANSACTION = "Create reviewed BinaryRat layout";
	private static final int MAXIMUM_REPORT_BYTES = 1 << 20;
	private static final int MAXIMUM_EXTENT = 65_536;
	private static final int MAXIMUM_FIELDS = 128;
	private static final int MAXIMUM_OBSERVATIONS = 4096;
	private static final int MAXIMUM_EVIDENCE_PER_FIELD = 512;
	private static final int MAXIMUM_FUNCTIONS = 32;
	private static final int MAXIMUM_FUNCTION_BYTES = 65_536;
	private static final HexFormat HEX = HexFormat.of();
	private static final ReentrantLock WRITE = new ReentrantLock();

	private ProtectedLayoutWriteBack() {
	}

	public record Evidence(String id, String function, String address, String operation) {
	}

	/** A field records the width of a reviewed access and the cited observations. */
	public record Field(int offset, int width, List<Evidence> evidence) {
		public Field {
			evidence = List.copyOf(evidence);
		}
	}

	public record Review(String programName, String functionName, String reportedFunctionName,
			int parameterIndex,
			String destination, int minimumExtent, List<Field> fields,
			String reportSha256, String approvalCode) {
		public Review {
			fields = List.copyOf(fields);
		}
	}

	/** A one-use handle bound to this exact open Program and its modification number. */
	public static final class Prepared {
		private final Program program;
		private final long revision;
		private final DataTypePath path;
		private final Review review;
		private final AtomicBoolean consumed = new AtomicBoolean();

		private Prepared(Program program, long revision, DataTypePath path, Review review) {
			this.program = program;
			this.revision = revision;
			this.path = path;
			this.review = review;
		}

		public Review review() {
			return review;
		}
	}

	public record Result(String dataTypePath, boolean committedAfterCancellation) {
	}

	/** Prepare a read-only review against the currently opened Program. */
	public static Prepared prepare(Program program, Path report, String name, TaskMonitor monitor)
			throws IOException, CancelledException {
		Objects.requireNonNull(program, "program");
		Objects.requireNonNull(report, "report");
		Objects.requireNonNull(monitor, "monitor");
		if (name == null || !name.matches("[A-Za-z_][A-Za-z0-9_]{0,63}")) {
			throw new IllegalArgumentException("Use a 1–64 character ASCII structure identifier");
		}
		monitor.checkCancelled();
		long revision = program.getModificationNumber();
		DataTypePath destination = new DataTypePath(CATEGORY, name);
		checkAvailable(program, destination);
		byte[] input = readReport(report);
		String reportHash = HEX.formatHex(digest().digest(input));
		JsonObject artifact = parseReport(input);
		integer(artifact.get("schema_version"), 1, 1, "schema_version");
		if (!"read_only_layout_evidence".equals(string(artifact.get("analysis_mode"), "analysis_mode")) ||
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
		int parameter = integer(artifact.get("parameter_index"), 0, 255, "parameter_index");
		if (artifact.has("variable_accesses") &&
				!array(artifact.get("variable_accesses"), "variable_accesses").isEmpty()) {
			throw new IOException("Variable-offset accesses require further review");
		}
		JsonArray layouts = array(artifact.get("layouts"), "layouts");
		if (layouts.size() != 1) {
			throw new IOException("Review requires exactly one layout");
		}
		JsonObject layout = object(layouts.get(0), "layout");
		String objectId = programId + "/" + spaceName + "/" + offsetText + "/param/" + parameter;
		if (!objectId.equals(string(layout.get("object_id"), "object_id"))) {
			throw new IOException("Layout object id does not identify its declared target");
		}
		int extent = integer(layout.get("minimum_extent"), 1, MAXIMUM_EXTENT, "minimum_extent");
		Map<Address, Function> citedFunctions = new TreeMap<>();
		citedFunctions.put(function.getEntryPoint(), function);
		List<Field> fields = fields(program, layout, extent, objectId,
			array(artifact.get("observations"), "observations"), citedFunctions, monitor);
		String code = approvalCode(program, destination, reportHash, citedFunctions, monitor);
		Review review = new Review(program.getName(), function.getName(true), reportedName,
			parameter, destination.getPath(), extent, fields, reportHash, code);
		monitor.checkCancelled();
		checkRevision(program, revision);
		return new Prepared(program, revision, destination, review);
	}

	/**
	 * Create a fresh reviewed structure. The caller must own the writable headless Program,
	 * and explicitly provide the approval code from its review. The Program's normal save
	 * lifecycle and native undo/redo apply to the result.
	 */
	public static Result accept(Program program, Prepared prepared, String approvalCode,
			TaskMonitor monitor) throws Exception {
		Objects.requireNonNull(monitor, "monitor");
		if (prepared == null || !prepared.consumed.compareAndSet(false, true) ||
				prepared.program != program || !prepared.review.approvalCode().equals(approvalCode)) {
			throw new IOException("A fresh review of this Program and its approval code are required");
		}
		if (!SystemUtilities.isInHeadlessMode() || !program.canSave() ||
				!program.getDomainFile().isInWritableProject()) {
			throw new IOException("Write-back requires an exclusively owned, writable headless project");
		}
		if (!WRITE.tryLock()) {
			throw new IOException("Another BinaryRat write-back is in progress");
		}
		try {
			AutoAnalysisManager analysis = AutoAnalysisManager.getAnalysisManager(program);
			monitor.checkCancelled();
			if (analysis.isAnalyzing() || program.getCurrentTransactionInfo() != null) {
				throw new IOException("Write-back requires idle analysis and no other Program transaction");
			}
			checkRevision(program, prepared.revision);
			checkAvailable(program, prepared.path);
			return submit(program, analysis, prepared, monitor);
		}
		finally {
			WRITE.unlock();
		}
	}

	private static Result submit(Program program, AutoAnalysisManager analysis, Prepared prepared,
			TaskMonitor monitor) throws Exception {
		boolean[] completed = { false };
		CancelledException[] workerCancellation = { null };
		try {
			if (!analysis.scheduleWorker(new AnalysisWorker() {
				@Override
				public String getWorkerName() {
					return TRANSACTION;
				}

				@Override
				public boolean analysisWorkerCallback(Program target, Object ignored,
						TaskMonitor workerMonitor) throws Exception {
					try {
						workerMonitor.checkCancelled();
						var scope = target.getCurrentTransactionInfo();
						if (target != prepared.program || analysis.isAnalyzing() || scope == null ||
								!scope.getOpenSubTransactions().equals(List.of(TRANSACTION))) {
							throw new IOException("Write-back did not acquire its managed Program transaction");
						}
						checkRevision(target, prepared.revision);
						checkAvailable(target, prepared.path);
						int transaction = target.startTransaction(TRANSACTION);
						boolean commit = false;
						try {
							createStructure(target, prepared, workerMonitor);
							workerMonitor.checkCancelled();
							commit = true;
						}
						finally {
							target.endTransaction(transaction, commit);
						}
						completed[0] = true;
						return true;
					}
					catch (CancelledException cancellation) {
						// The worker wrapper catches callback cancellation and reports false.
						workerCancellation[0] = cancellation;
						return false;
					}
				}
			}, null, true, monitor)) {
				if (workerCancellation[0] != null) {
					throw workerCancellation[0];
				}
				throw new IOException("Write-back worker did not complete");
			}
		}
		catch (InvocationTargetException failure) {
			if (failure.getCause() instanceof Exception cause) {
				throw cause;
			}
			throw failure;
		}
		catch (CancelledException cancellation) {
			// scheduleWorker can report cancellation after its managed transaction commits.
			if (completed[0] && hasApplied(program, prepared)) {
				return new Result(prepared.path.getPath(), true);
			}
			throw cancellation;
		}
		if (!completed[0] || !hasApplied(program, prepared)) {
			throw new IOException("Write-back result did not commit");
		}
		return new Result(prepared.path.getPath(), false);
	}

	private static void createStructure(Program program, Prepared prepared, TaskMonitor monitor)
			throws IOException, CancelledException {
		var types = program.getDataTypeManager();
		StructureDataType structure = new StructureDataType(CATEGORY, prepared.path.getDataTypeName(),
			prepared.review.minimumExtent(), types);
		structure.setDescription("Reviewed BinaryRat layout evidence. Extent is a lower bound.");
		for (Field field : prepared.review.fields()) {
			monitor.checkCancelled();
			structure.replaceAtOffset(field.offset(), Undefined.getUndefinedDataType(field.width()),
				field.width(), "field_" + Integer.toHexString(field.offset()), null);
		}
		DataType inserted = types.addDataType(structure, DataTypeConflictHandler.KEEP_HANDLER);
		if (!(inserted instanceof Structure installed) ||
				!inserted.getDataTypePath().equals(prepared.path) ||
				installed.getLength() != prepared.review.minimumExtent() ||
				installed.getNumDefinedComponents() != prepared.review.fields().size()) {
			throw new IOException("Ghidra resolved the reviewed layout to an unexpected destination");
		}
		for (Field field : prepared.review.fields()) {
			var component = installed.getDefinedComponentAtOrAfterOffset(field.offset());
			if (component == null || component.getOffset() != field.offset() ||
					component.getLength() != field.width() ||
					!Undefined.isUndefined(component.getDataType())) {
				throw new IOException("Ghidra changed a reviewed field's layout");
			}
		}
		monitor.checkCancelled();
		program.getOptions(JOURNAL).setString(prepared.path.getDataTypeName(),
			journalValue(prepared.review));
	}

	private static String journalValue(Review review) {
		return review.approvalCode() + " " + review.reportSha256();
	}

	private static boolean hasApplied(Program program, Prepared prepared) {
		return program.getCurrentTransactionInfo() == null &&
			program.getDataTypeManager().getDataType(prepared.path) instanceof Structure &&
			journalValue(prepared.review).equals(program.getOptions(JOURNAL)
				.getString(prepared.path.getDataTypeName(), null));
	}

	private static void checkAvailable(Program program, DataTypePath path) throws IOException {
		if (program.isClosed()) {
			throw new IOException("The reviewed Program is closed");
		}
		if (program.getDataTypeManager().getDataType(path) != null ||
				program.getOptions(JOURNAL).getString(path.getDataTypeName(), null) != null) {
			throw new IOException("The destination type or its prior review record already exists");
		}
	}

	private static void checkRevision(Program program, long revision) throws IOException {
		if (program.isClosed() || program.getModificationNumber() != revision) {
			throw new IOException("The reviewed Program changed or closed; prepare a fresh review");
		}
	}

	private static Function findFunction(Program program, String spaceName, String offsetText)
			throws IOException {
		Address entry = readAddress(program, spaceName, offsetText);
		Function function = program.getFunctionManager().getFunctionAt(entry);
		if (function == null || function.isExternal() || function.isThunk()) {
			throw new IOException("Report target must identify a local, non-thunk function");
		}
		return function;
	}

	private static Address readAddress(Program program, String spaceName, String offsetText)
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

	private static String approvalCode(Program program, DataTypePath destination, String reportHash,
			Map<Address, Function> citedFunctions, TaskMonitor monitor) throws IOException, CancelledException {
		var file = program.getDomainFile();
		var locator = file.getProjectLocator();
		if (locator == null || file.getFileID() == null || file.getFileID().isBlank()) {
			throw new IOException("Review requires a saved Program identity");
		}
		MessageDigest hash = digest();
		for (String value : List.of("binaryrat-reviewed-layout-v1", reportHash, destination.getPath(),
				locator.getLocation(), locator.getName(), file.getPathname(), file.getFileID(),
				Long.toUnsignedString(program.getUniqueProgramID()), Integer.toString(citedFunctions.size()))) {
			frame(hash, value);
		}
		long remaining = MAXIMUM_FUNCTION_BYTES;
		for (Function function : citedFunctions.values()) {
			monitor.checkCancelled();
			var body = function.getBody();
			long size = body.getNumAddresses();
			if (size < 1 || size > remaining) {
				throw new IOException("Reviewed function bodies exceed the byte limit");
			}
			remaining -= size;
			frame(hash, function.getEntryPoint().toString(true));
			frame(hash, function.getName(true));
			frame(hash, function.getPrototypeString(false, true));
			frame(hash, function.getSignatureSource().name());
			frame(hash, Integer.toString(body.getNumAddressRanges()));
			for (AddressRange range : body.getAddressRanges()) {
				monitor.checkCancelled();
				frame(hash, range.getMinAddress().toString(true));
				frame(hash, readFunctionRange(program, range));
			}
		}
		return HEX.formatHex(hash.digest());
	}

	private static byte[] readFunctionRange(Program program, AddressRange range) throws IOException {
		byte[] bytes = new byte[(int) range.getLength()];
		try {
			int read = 0;
			while (read < bytes.length) {
				int count = program.getMemory().getBytes(range.getMinAddress().add(read),
					bytes, read, bytes.length - read);
				if (count <= 0) {
					throw new IOException("Incomplete target function bytes");
				}
				read += count;
			}
		}
		catch (MemoryAccessException failure) {
			throw new IOException("Unable to verify target function bytes", failure);
		}
		return bytes;
	}

	private static List<Field> fields(Program program, JsonObject layout, int extent,
			String objectId, JsonArray observations, Map<Address, Function> citedFunctions, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (flag(layout.get("has_overlaps"), "has_overlaps") ||
				flag(layout.get("has_stride_conflicts"), "has_stride_conflicts") ||
				flag(layout.get("has_overlapping_stride"), "has_overlapping_stride") ||
				(layout.has("union_candidates") &&
					!array(layout.get("union_candidates"), "union_candidates").isEmpty())) {
			throw new IOException("Only unambiguous structures can be written back");
		}
		JsonArray input = array(layout.get("fields"), "fields");
		if (input.isEmpty() || input.size() > MAXIMUM_FIELDS) {
			throw new IOException("Layout field count is outside the review limit");
		}
		if (observations.isEmpty() || observations.size() > MAXIMUM_OBSERVATIONS) {
			throw new IOException("Observation count is outside the review limit");
		}
		Map<String, JsonObject> byId = new HashMap<>();
		for (JsonElement element : observations) {
			JsonObject observation = object(element, "observation");
			String id = string(observation.get("evidence_id"), "observation evidence id");
			if (byId.putIfAbsent(id, observation) != null) {
				throw new IOException("Duplicate layout observation");
			}
		}
		List<Field> fields = new ArrayList<>();
		var unique = new HashSet<String>();
		for (JsonElement element : input) {
			JsonObject field = object(element, "field");
			int offset = integer(field.get("offset"), 0, extent - 1, "offset");
			int width = integer(field.get("width"), 1, extent - offset, "width");
			JsonElement stride = field.get("stride");
			if (stride == null || !stride.isJsonNull() ||
					flag(field.get("overlaps_other_fields"), "overlaps_other_fields") ||
					flag(field.get("stride_conflict"), "stride_conflict") ||
					flag(field.get("stride_overlaps_access"), "stride_overlaps_access")) {
				throw new IOException("Only exact, non-overlapping field accesses can be written back");
			}
			JsonArray ids = array(field.get("evidence_ids"), "evidence_ids");
			if (ids.isEmpty() || ids.size() > MAXIMUM_EVIDENCE_PER_FIELD) {
				throw new IOException("Field evidence count is outside the review limit");
			}
			var evidence = new ArrayList<Evidence>();
			for (JsonElement id : ids) {
				monitor.checkCancelled();
				String key = string(id, "evidence id");
				if (!unique.add(key)) {
					throw new IOException("Duplicate field evidence");
				}
				evidence.add(evidence(program, byId.get(key), key, objectId, offset, width, citedFunctions));
			}
			fields.add(new Field(offset, width, evidence));
		}
		fields.sort(Comparator.comparingInt(Field::offset));
		int end = 0;
		for (Field field : fields) {
			if (field.offset() < end) {
				throw new IOException("Overlapping fields cannot be written back");
			}
			end = field.offset() + field.width();
		}
		if (end != extent) {
			throw new IOException("Layout extent must match the minimum observed extent");
		}
		return List.copyOf(fields);
	}

	private static Evidence evidence(Program program, JsonObject observation, String id,
			String objectId, int offset, int width, Map<Address, Function> citedFunctions)
			throws IOException {
		if (observation == null || !objectId.equals(string(observation.get("object_id"), "object_id")) ||
				!flag(observation.get("object_start_known"), "object_start_known") ||
				integer(observation.get("offset"), 0, MAXIMUM_EXTENT - 1, "observation offset") != offset ||
				integer(observation.get("width"), 1, MAXIMUM_EXTENT, "observation width") != width) {
			throw new IOException("Field evidence must cite a matching observed access");
		}
		String operation = string(observation.get("operation"), "operation");
		if (!operation.equals("LOAD") && !operation.equals("STORE")) {
			throw new IOException("Field evidence must be a LOAD or STORE observation");
		}
		Function function = findFunction(program,
			string(observation.get("function_address_space"), "function_address_space"),
			string(observation.get("function_address"), "function_address"));
		Address address = readAddress(program, string(observation.get("address_space"), "address_space"),
			string(observation.get("address"), "address"));
		if (!function.getBody().contains(address) || program.getListing().getInstructionAt(address) == null) {
			throw new IOException("Field evidence must cite a current instruction in its reported function");
		}
		citedFunctions.putIfAbsent(function.getEntryPoint(), function);
		if (citedFunctions.size() > MAXIMUM_FUNCTIONS) {
			throw new IOException("Reviewed functions exceed the review limit");
		}
		return new Evidence(id, function.getEntryPoint().toString(true), address.toString(true), operation);
	}

	private static byte[] readReport(Path path) throws IOException {
		if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
			throw new IOException("Choose a regular BinaryRat layout report file");
		}
		try (var input = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS)) {
			byte[] bytes = input.readNBytes(MAXIMUM_REPORT_BYTES + 1);
			if (bytes.length > MAXIMUM_REPORT_BYTES) {
				throw new IOException("Layout report exceeds the review byte limit");
			}
			return bytes;
		}
	}

	private static JsonObject parseReport(byte[] bytes) throws IOException {
		String text = StandardCharsets.UTF_8.newDecoder()
			.onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
			.decode(ByteBuffer.wrap(bytes)).toString();
		try (JsonReader reader = new JsonReader(new StringReader(text))) {
			reader.setStrictness(Strictness.STRICT);
			reader.setNestingLimit(32);
			JsonObject report = object(readJson(reader), "report");
			if (reader.peek() != JsonToken.END_DOCUMENT) {
				throw new IOException("Extra content after layout report");
			}
			return report;
		}
	}

	private static JsonElement readJson(JsonReader reader) throws IOException {
		return switch (reader.peek()) {
			case BEGIN_OBJECT -> {
				JsonObject result = new JsonObject();
				reader.beginObject();
				while (reader.hasNext()) {
					String name = reader.nextName();
					if (result.has(name)) {
						throw new IOException("Duplicate layout report property");
					}
					result.add(name, readJson(reader));
				}
				reader.endObject();
				yield result;
			}
			case BEGIN_ARRAY -> {
				JsonArray result = new JsonArray();
				reader.beginArray();
				while (reader.hasNext()) {
					result.add(readJson(reader));
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

	private static JsonObject object(JsonElement value, String name) throws IOException {
		if (value == null || !value.isJsonObject()) {
			throw new IOException("Expected a JSON object for " + name);
		}
		return value.getAsJsonObject();
	}

	private static JsonArray array(JsonElement value, String name) throws IOException {
		if (value == null || !value.isJsonArray()) {
			throw new IOException("Expected a JSON array for " + name);
		}
		return value.getAsJsonArray();
	}

	private static boolean flag(JsonElement value, String name) throws IOException {
		if (!(value instanceof JsonPrimitive primitive) || !primitive.isBoolean()) {
			throw new IOException("Expected a JSON boolean for " + name);
		}
		return primitive.getAsBoolean();
	}

	private static String string(JsonElement value, String name) throws IOException {
		if (!(value instanceof JsonPrimitive primitive) || !primitive.isString() ||
				primitive.getAsString().isBlank() || primitive.getAsString().length() > 1024) {
			throw new IOException("Invalid string for " + name);
		}
		return primitive.getAsString();
	}

	private static int integer(JsonElement value, int minimum, int maximum, String name)
			throws IOException {
		if (!(value instanceof JsonPrimitive primitive) || !primitive.isNumber() ||
				!primitive.getAsString().matches("0|[1-9][0-9]{0,8}")) {
			throw new IOException("Expected an unsigned decimal integer for " + name);
		}
		int number = Integer.parseInt(primitive.getAsString());
		if (number < minimum || number > maximum) {
			throw new IOException("Out-of-range layout value for " + name);
		}
		return number;
	}

	private static MessageDigest digest() {
		try {
			return MessageDigest.getInstance("SHA-256");
		}
		catch (NoSuchAlgorithmException impossible) {
			throw new IllegalStateException("SHA-256 is unavailable", impossible);
		}
	}

	private static void frame(MessageDigest hash, String value) {
		frame(hash, value.getBytes(StandardCharsets.UTF_8));
	}

	private static void frame(MessageDigest hash, byte[] bytes) {
		hash.update(ByteBuffer.allocate(Integer.BYTES).putInt(bytes.length).array());
		hash.update(bytes);
	}
}
