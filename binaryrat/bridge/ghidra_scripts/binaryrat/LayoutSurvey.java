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
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Stream;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import generic.hash.HashUtilities;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.HighFunction;
import ghidra.util.task.TaskMonitor;

/**
 * Program-wide local layout evidence. Every supported function is decompiled once, and each
 * pointer-sized register parameter is treated as a possible object start: its own exact
 * accesses are aggregated by the engine's {@code types.recover} op. Nothing is followed into
 * callees, so each access supports exactly one parameter of one function. The survey says
 * what the code does with each parameter; it does not claim that a parameter is a structure
 * pointer. Read-only: the Program's modification number is checked around every step.
 */
public final class LayoutSurvey {
	public static final String ANALYSIS_MODE = "read_only_layout_survey";
	public static final int MAXIMUM_FUNCTIONS = 65_536;
	public static final int MAXIMUM_PARAMETERS = 8;
	public static final int MAXIMUM_TIMEOUT_SECONDS = 600;
	public static final int MAXIMUM_DEADLINE_SECONDS = 14_400;
	private static final long MAXIMUM_FUNCTION_BYTES = 65_536;

	private LayoutSurvey() {
	}

	/** Surveys a Program and returns the report as JSON text (for PyGhidra callers). */
	public static String surveyJson(Program program, int timeoutSeconds, int deadlineSeconds,
			int maximumFunctions, TaskMonitor monitor) throws Exception {
		return new GsonBuilder().serializeNulls().create()
			.toJson(survey(program, timeoutSeconds, deadlineSeconds, maximumFunctions, monitor));
	}

	/**
	 * Surveys every supported function. A function that cannot be decompiled or exceeds an
	 * evidence limit is reported with its reason and no parameters; exceeding the function
	 * limit or the overall deadline fails the whole survey.
	 */
	public static JsonObject survey(Program program, int timeoutSeconds, int deadlineSeconds,
			int maximumFunctions, TaskMonitor monitor) throws Exception {
		if (timeoutSeconds < 1 || timeoutSeconds > MAXIMUM_TIMEOUT_SECONDS) {
			throw new IllegalArgumentException("timeout must be 1-600 seconds");
		}
		if (deadlineSeconds < 1 || deadlineSeconds > MAXIMUM_DEADLINE_SECONDS) {
			throw new IllegalArgumentException("deadline must be 1-14400 seconds");
		}
		if (maximumFunctions < 1 || maximumFunctions > MAXIMUM_FUNCTIONS) {
			throw new IllegalArgumentException("function limit must be between 1 and " + MAXIMUM_FUNCTIONS);
		}
		Path workspace = Files.createTempDirectory("binaryrat-survey-");
		try {
			return new Run(program, monitor, deadlineSeconds).survey(workspace, timeoutSeconds,
				maximumFunctions);
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

	private record Surveyed(int slot, Register register, Address storage, int exact, int variable,
			String object) {
	}

	/** State of one survey; never shared between threads. */
	private static final class Run {
		private final Program program;
		private final TaskMonitor monitor;
		private final long revision;
		private final long deadline;
		private final String programId;

		Run(Program program, TaskMonitor monitor, int deadlineSeconds) throws Exception {
			this.program = program;
			this.monitor = monitor;
			this.revision = program.getModificationNumber();
			this.deadline = System.nanoTime() + deadlineSeconds * 1_000_000_000L;
			String hash = program.getExecutableSHA256();
			if (hash == null || !hash.matches("[0-9a-fA-F]{64}")) {
				throw new IOException("layout evidence requires a valid executable SHA-256");
			}
			this.programId = "sha256:" + hash.toLowerCase(Locale.ROOT);
			checkCurrent();
		}

		JsonObject survey(Path workspace, int timeout, int maximumFunctions) throws Exception {
			JsonArray functions = new JsonArray();
			int unsupported = 0;
			int surveyed = 0;
			try (EngineClient engine = EngineClient.start(EngineClient.findExecutable(), workspace)) {
				checkCurrent();
				var limits = new ScheduledDecompiler.Limits(1, reserve("BINARYRAT_WORKER_BYTES", 768L << 20),
					Runtime.getRuntime().maxMemory(), reserve("BINARYRAT_OTHER_RESERVE_BYTES", 512L << 20),
					timeout, 5_000, timeout * 1_000L);
				try (ScheduledDecompiler decompiler = new ScheduledDecompiler(engine, program,
						this::configure, limits)) {
					for (Function function : program.getFunctionManager().getFunctions(true)) {
						checkCurrent();
						if (!SummaryLayouts.supportedFunction(program, function)) {
							unsupported++;
							continue;
						}
						if (functions.size() >= maximumFunctions) {
							throw new IOException("layout survey exceeds the function limit of " +
								maximumFunctions);
						}
						JsonObject record = surveyFunction(engine, decompiler, function);
						if ("surveyed".equals(record.get("status").getAsString())) {
							surveyed++;
						}
						functions.add(record);
					}
				}
			}
			checkCurrent();
			JsonObject report = new JsonObject();
			report.addProperty("schema_version", 1);
			report.addProperty("analysis_mode", ANALYSIS_MODE);
			report.addProperty("assumption", "each_register_parameter_as_object_start");
			report.addProperty("score_kind", "uncalibrated_evidence_strength");
			report.addProperty("follow_depth", 0);
			report.addProperty("revision", revision);
			report.addProperty("program_id", programId);
			report.addProperty("language_id", program.getLanguageID().toString());
			report.addProperty("compiler_spec_id", program.getCompilerSpec().getCompilerSpecID().toString());
			report.addProperty("image_base", hex(program.getImageBase()));
			Long original = ElfLoader.getElfOriginalImageBase(program);
			report.addProperty("original_image_base",
				original == null ? null : Long.toUnsignedString(original, 16));
			report.addProperty("maximum_parameters", MAXIMUM_PARAMETERS);
			report.addProperty("unsupported_functions", unsupported);
			report.addProperty("surveyed_functions", surveyed);
			report.add("functions", functions);
			return report;
		}

		private JsonObject surveyFunction(EngineClient engine, ScheduledDecompiler decompiler,
				Function function) throws Exception {
			Address entry = function.getEntryPoint();
			String space = entry.getAddressSpace().getName();
			JsonObject record = new JsonObject();
			record.addProperty("address_space", space);
			record.addProperty("address", hex(entry));
			record.addProperty("name", function.getName(true));
			addIdentity(record, function);
			JsonArray parameters = new JsonArray();
			record.add("parameters", parameters);

			ScheduledDecompiler.Run run = decompiler.decompileUntraced(function, monitor);
			checkCurrent();
			DecompileResults decompiled = run.traced() == null ? null : run.traced().results();
			if (!"completed".equals(run.status()) || !run.memoryWatched() || decompiled == null ||
					!decompiled.decompileCompleted() || decompiled.getHighFunction() == null) {
				monitor.checkCancelled();
				return refused(record, "decompilation did not complete under a memory-watched lease: " +
					run.status());
			}
			HighFunction high = decompiled.getHighFunction();
			int declared = high.getLocalSymbolMap().getNumParams();
			record.addProperty("decompiler_parameters", declared);

			JsonArray observations = new JsonArray();
			List<Surveyed> surveyed = new ArrayList<>();
			Map<Integer, Integer> owner = new HashMap<>();
			for (int slot = 0; slot < Math.min(declared, MAXIMUM_PARAMETERS); slot++) {
				monitor.checkCancelled();
				Address storage = LayoutEvidence.parameterStorage(program, high, slot);
				Register register = storage == null ? null :
					program.getRegister(storage, program.getDefaultPointerSize());
				if (register == null) {
					continue;
				}
				LayoutEvidence.Capture capture;
				try {
					capture = LayoutEvidence.collect(program, high, slot, false, monitor);
				}
				catch (IOException limit) {
					return refused(record, limit.getMessage());
				}
				String object = programId + "/" + space + "/" + hex(entry) + "/param/" + slot;
				int exact = 0;
				int variable = 0;
				for (LayoutEvidence.Access access : capture.accesses()) {
					if (access.offset() != access.maximumOffset()) {
						// A possible offset is not an observed field.
						variable++;
						continue;
					}
					exact++;
					if (observations.size() >= MAXIMUM_PARAMETERS * LayoutEvidence.MAXIMUM_ACCESSES) {
						return refused(record, "function exceeds the layout evidence limit");
					}
					owner.put(observations.size(), surveyed.size());
					observations.add(observation(object, access));
				}
				surveyed.add(new Surveyed(slot, register, storage, exact, variable, object));
			}

			Map<String, JsonObject> layouts = new HashMap<>();
			int[] rejected = new int[surveyed.size()];
			if (!observations.isEmpty()) {
				JsonObject request = new JsonObject();
				request.add("observations", observations);
				request.addProperty("maximum_extent", LayoutEvidence.MAXIMUM_EXTENT);
				JsonObject solved = engine.call("types.recover", request);
				for (JsonElement layout : solved.getAsJsonArray("layouts")) {
					JsonObject item = layout.getAsJsonObject();
					layouts.put(item.get("object_id").getAsString(), item);
				}
				for (JsonElement refusal : solved.getAsJsonArray("rejected")) {
					rejected[owner.get(refusal.getAsJsonObject().get("observation_index").getAsInt())]++;
				}
			}
			for (int index = 0; index < surveyed.size(); index++) {
				Surveyed item = surveyed.get(index);
				JsonObject parameter = new JsonObject();
				parameter.addProperty("index", item.slot());
				parameter.addProperty("register", item.register().getName());
				parameter.addProperty("storage", item.storage().toString());
				parameter.addProperty("object_id", item.object());
				parameter.addProperty("exact_accesses", item.exact());
				parameter.addProperty("variable_accesses", item.variable());
				parameter.addProperty("rejected_accesses", rejected[index]);
				parameter.add("layout", layouts.get(item.object()));
				parameters.add(parameter);
			}
			record.addProperty("status", "surveyed");
			return record;
		}

		private static JsonObject refused(JsonObject record, String reason) {
			record.add("parameters", new JsonArray());
			record.addProperty("status", "refused");
			record.addProperty("reason", reason);
			return record;
		}

		private static JsonObject observation(String object, LayoutEvidence.Access access) {
			JsonObject row = new JsonObject();
			Address site = access.address();
			row.addProperty("object_id", object);
			row.addProperty("object_start_known", true);
			row.addProperty("offset", access.offset());
			row.addProperty("width", access.width());
			row.addProperty("evidence_id", object + "/" + site.getAddressSpace().getName() + "/" +
				hex(site) + "/" + access.pcodeOrder());
			if (access.typedUse() != null) {
				row.addProperty("storage_view", access.typedUse().kind());
			}
			return row;
		}

		/**
		 * Two identities for finding the same function in several programs: the exact body
		 * bytes, and the instructions with every linked address masked. The second ignores
		 * where the code and its callees were placed, but keeps registers, constants and
		 * displacements, so two setters of different fields stay different functions.
		 */
		private void addIdentity(JsonObject record, Function function) throws Exception {
			long size = function.getBody().getNumAddresses();
			record.addProperty("body_bytes", size);
			String bodyHash = null;
			StringBuilder code = new StringBuilder();
			int instructions = 0;
			for (Instruction instruction : program.getListing().getInstructions(function.getBody(), true)) {
				monitor.checkCancelled();
				instructions++;
				code.append(instruction.getMnemonicString());
				for (int operand = 0; operand < instruction.getNumOperands(); operand++) {
					code.append(' ');
					for (Object part : instruction.getOpObjects(operand)) {
						code.append(part instanceof Address ? "@" : part.toString()).append(',');
					}
				}
				code.append('\n');
			}
			record.addProperty("instructions", instructions);
			record.addProperty("code_sha256", instructions == 0 ? null :
				HashUtilities.getHash("SHA-256", code.toString().getBytes(StandardCharsets.UTF_8)));
			try {
				byte[] bytes = new byte[(int) Math.min(size, MAXIMUM_FUNCTION_BYTES)];
				int filled = 0;
				for (AddressRange range : function.getBody()) {
					monitor.checkCancelled();
					int length = (int) range.getLength();
					if (program.getMemory().getBytes(range.getMinAddress(), bytes, filled, length) != length) {
						throw new MemoryAccessException("short read");
					}
					filled += length;
				}
				bodyHash = HashUtilities.getHash("SHA-256", bytes);
			}
			catch (MemoryAccessException unreadable) {
				// The function stays in the survey; its instruction identity still applies.
			}
			record.addProperty("body_sha256", bodyHash);
		}

		private void configure(DecompInterface decompiler) {
			DecompileOptions options = new DecompileOptions();
			options.grabFromProgram(program);
			options.setMaxPayloadMBytes(Math.min(options.getMaxPayloadMBytes(), 8));
			options.setMaxInstructions(Math.min(options.getMaxInstructions(), 16_384));
			decompiler.setOptions(options);
			decompiler.setSimplificationStyle("decompile");
			decompiler.toggleCCode(false);
			decompiler.toggleSyntaxTree(true);
		}

		private void checkCurrent() throws Exception {
			monitor.checkCancelled();
			if (program.isClosed() || revision != program.getModificationNumber()) {
				throw new IllegalStateException("Program changed during the layout survey");
			}
			if (System.nanoTime() - deadline > 0) {
				throw new IOException("layout survey exceeds its deadline");
			}
		}
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
