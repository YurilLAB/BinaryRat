// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package binaryrat.writeback;

import static binaryrat.writeback.LayoutReport.*;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.SwingUtilities;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import binaryrat.SummaryLayouts;
import generic.hash.HashUtilities;
import ghidra.app.plugin.core.analysis.AnalysisWorker;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.model.TransactionInfo;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Review live summary evidence and apply a fresh layout to one existing generic parameter. */
public final class SummaryLayoutWriteBack {
	private static final CategoryPath CATEGORY = new CategoryPath("/BinaryRat/ReviewedSummaryLayouts");
	private static final String JOURNAL = "BinaryRat Reviewed Summary Layouts";
	private static final String TRANSACTION = "Apply BinaryRat summary layout";
	private static final int MAXIMUM_PARAMETER = 255;
	private static final int MAXIMUM_EXTENT = 65_536;
	private static final int MAXIMUM_FIELDS = 128;
	private static final int COMMENT_SITES = 8;

	private SummaryLayoutWriteBack() {
	}

	/** Opaque storage widths and the first contributing instruction sites. */
	public record Field(int offset, int width, int support, List<String> sites) {
		public Field {
			sites = List.copyOf(sites);
		}
	}

	/** Everything the analyst needs to identify the specific pending edit. */
	public record Review(long revision, String functionName, int parameterIndex, String originalType,
			String destination, int minimumExtent, List<Field> fields) {
		public Review {
			fields = List.copyOf(fields);
		}
	}

	/** A one-use handle issued only from current, live recovery. */
	public static final class Prepared {
		private final Program program;
		private final Address functionEntry;
		private final DataTypePath path;
		private final Review review;
		private final String reportHash;
		private final AtomicBoolean consumed = new AtomicBoolean();

		private Prepared(Program program, Address functionEntry, DataTypePath path,
				Review review, String reportHash) {
			this.program = program;
			this.functionEntry = functionEntry;
			this.path = path;
			this.review = review;
			this.reportHash = reportHash;
		}

		public Review review() {
			return review;
		}
	}

	/** The report can be browsed when a guarded application is unavailable. */
	public record Recovery(JsonObject report, Prepared proposal, String refusal) {
	}

	public record Result(String dataTypePath, boolean committedAfterCancellation) {
	}

	/** Recover live evidence and prepare an explicit edit when the source and layout allow it. */
	public static Recovery recover(Program program, Function function, int parameterIndex,
			int timeoutSeconds, int maximumSummaries, TaskMonitor monitor) throws Exception {
		Object consumer = retain(program);
		try {
			JsonObject report = SummaryLayouts.recover(program, function, parameterIndex, timeoutSeconds,
				maximumSummaries, monitor);
			long revision = report.get("revision").getAsLong();
			checkRevision(program, revision);
			monitor.checkCancelled();
			try {
				return new Recovery(report, prepare(program, report, revision, monitor), null);
			}
			catch (IOException refusal) {
				checkRevision(program, revision);
				return new Recovery(report, null, refusal.getMessage());
			}
		}
		finally {
			program.release(consumer);
		}
	}

	private static Prepared prepare(Program program, JsonObject report, long revision,
			TaskMonitor monitor) throws IOException, CancelledException {
		requireWritable(program);
		var target = target(program, report, MAXIMUM_PARAMETER, SummaryLayouts.ANALYSIS_MODE);
		Function function = target.function();
		Parameter parameter = eligibleParameter(program, function, target.parameter());
		Address entry = function.getEntryPoint();
		DataTypePath path = new DataTypePath(CATEGORY,
			"BR_" + Long.toUnsignedString(entry.getOffset(), 16) + "_p" + target.parameter());
		checkAvailable(program, path);
		JsonObject solution = object(report.get("solution"), "solution");
		if (!flag(solution.get("complete"), "solution completeness") ||
				report.get("unresolved_accesses").getAsInt() != 0 ||
				!array(solution.get("rejected"), "rejected accesses").isEmpty() ||
				!array(report.get("refused_calls"), "refused calls").isEmpty() ||
				!array(report.get("variable_accesses"), "variable accesses").isEmpty()) {
			throw new IOException("Apply requires complete, fixed-offset evidence");
		}
		Map<String, String> sites = new HashMap<>();
		boolean rootMatches = false;
		for (JsonElement item : array(report.get("summaries"), "summaries")) {
			monitor.checkCancelled();
			JsonObject summary = object(item, "summary");
			if (!summary.get("call_refusal").isJsonNull()) {
				throw new IOException("Apply requires a complete default-convention call path");
			}
			if (target.objectId().equals(string(summary.get("id"), "summary id"))) {
				rootMatches = !summary.get("parameter_storage").isJsonNull() &&
					parameter.getVariableStorage().getMinAddress().toString().equals(
						string(summary.get("parameter_storage"), "parameter storage"));
			}
			for (JsonElement witness : array(summary.get("accesses"), "accesses")) {
				monitor.checkCancelled();
				JsonObject access = object(witness, "access");
				if (access.has("instruction_sha256")) {
					String site = string(access.get("address_space"), "access space") + ":" +
						string(access.get("address"), "access address");
					sites.put(string(access.get("evidence_id"), "evidence id"), site);
				}
			}
		}
		if (!rootMatches) {
			throw new IOException("Recovered parameter storage differs from the current function");
		}
		JsonElement proposed = solution.get("layout");
		if (proposed.isJsonNull()) {
			throw new IOException("No fixed fields were recovered");
		}
		JsonObject layout = object(proposed, "layout");
		int extent = integer(layout.get("minimum_extent"), 1, MAXIMUM_EXTENT, "minimum extent");
		List<Field> fields = fields(layout, sites, extent, monitor);
		Review review = new Review(revision, function.getName(true), target.parameter(),
			parameter.getFormalDataType().getDisplayName(), path.getPath(), extent, fields);
		String hash = hashReport(report);
		monitor.checkCancelled();
		checkRevision(program, revision);
		return new Prepared(program, entry, path, review, hash);
	}

	private static List<Field> fields(JsonObject layout, Map<String, String> sites, int extent,
			TaskMonitor monitor) throws IOException, CancelledException {
		if (flag(layout.get("has_overlaps"), "overlapping fields") ||
				flag(layout.get("has_stride_conflicts"), "conflicting strides") ||
				flag(layout.get("has_overlapping_stride"), "overlapping strides") ||
				!array(layout.get("union_candidates"), "union candidates").isEmpty()) {
			throw new IOException("Apply requires an unambiguous structure");
		}
		var input = array(layout.get("fields"), "fields");
		if (input.isEmpty() || input.size() > MAXIMUM_FIELDS) {
			throw new IOException("Layout field count is outside the review limit");
		}
		List<Field> fields = new ArrayList<>();
		int end = 0;
		for (JsonElement element : input) {
			monitor.checkCancelled();
			JsonObject row = object(element, "field");
			int offset = integer(row.get("offset"), end, extent - 1, "offset");
			int width = integer(row.get("width"), 1, extent - offset, "width");
			if (!row.get("stride").isJsonNull()) {
				throw new IOException("Apply requires fixed fields without a stride");
			}
			var evidence = array(row.get("evidence_ids"), "field evidence");
			if (evidence.isEmpty()) {
				throw new IOException("A field has no cited instruction");
			}
			List<String> cited = new ArrayList<>();
			for (JsonElement item : evidence) {
				monitor.checkCancelled();
				String site = sites.get(string(item, "evidence id"));
				if (site == null) {
					throw new IOException("A field has no verified instruction site");
				}
				if (cited.size() < COMMENT_SITES && !cited.contains(site)) {
					cited.add(site);
				}
			}
			fields.add(new Field(offset, width, evidence.size(), cited));
			end = offset + width;
		}
		if (end != extent) {
			throw new IOException("The final field does not match the minimum extent");
		}
		return fields;
	}

	private static String hashReport(JsonObject report) {
		return HashUtilities.getHash("SHA-256", report.toString().getBytes(StandardCharsets.UTF_8));
	}

	private static Object retain(Program program) throws IOException {
		Objects.requireNonNull(program, "program");
		Object consumer = new Object();
		if (!program.addConsumer(consumer)) {
			throw new IOException("The selected Program is closed");
		}
		return consumer;
	}

	private static void requireWritable(Program program) throws IOException {
		if (!(program instanceof ProgramDB) || !program.isChangeable() || !program.canSave() ||
				!program.getDomainFile().isInWritableProject()) {
			throw new IOException("Apply requires an open writable Program database");
		}
	}

	private static Parameter eligibleParameter(Program program, Function function, int index)
			throws IOException {
		if (!SummaryLayouts.supportedFunction(program, function) || function.getProgram() != program ||
				!function.getEntryPoint().getAddressSpace().equals(
					program.getAddressFactory().getDefaultAddressSpace())) {
			throw new IOException("Apply requires a local non-thunk function in the default address space");
		}
		var defaultConvention = program.getCompilerSpec().getDefaultCallingConvention();
		var declared = function.getCallingConvention();
		if (function.hasCustomVariableStorage() || function.hasVarArgs() || function.getCallFixup() != null ||
				function.getAutoParameterCount() != 0 || defaultConvention == null ||
				declared != null && !defaultConvention.getName().equals(declared.getName())) {
			throw new IOException("Apply requires standard fixed-argument storage");
		}
		if (protectedSource(function.getSignatureSource())) {
			throw new IOException("This function signature is user-defined or imported");
		}
		Parameter parameter = function.getParameter(index);
		if (parameter == null || parameter.isAutoParameter() || parameter.isForcedIndirect()) {
			throw new IOException("Apply requires an existing explicit Program parameter");
		}
		if (protectedSource(parameter.getSource())) {
			throw new IOException("This parameter is user-defined or imported");
		}
		int pointerSize = program.getDefaultPointerSize();
		VariableStorage storage = parameter.getVariableStorage();
		if (!storage.isRegisterStorage() || storage.size() != pointerSize ||
				parameter.getFormalDataType().getLength() != pointerSize ||
				!(parameter.getFormalDataType() instanceof Pointer pointer)) {
			throw new IOException("Apply requires a pointer-width parameter in one register");
		}
		DataType pointed = pointer.getDataType();
		// A named typedef can denote an opaque object even when its base is void.
		if (pointed != null && !(pointed instanceof VoidDataType) &&
				(!Undefined.isUndefined(pointed) || Undefined.isUndefinedArray(pointed))) {
			throw new IOException("This parameter already has a specific pointer type");
		}
		return parameter;
	}

	private static boolean protectedSource(SourceType source) {
		return source.isHigherPriorityThan(SourceType.ANALYSIS);
	}

	private static void checkAvailable(Program program, DataTypePath path) throws IOException {
		if (program.getDataTypeManager().getDataType(path) != null ||
				program.getOptions(JOURNAL).getString(path.getDataTypeName(), null) != null) {
			throw new IOException("The destination type or a previous review already exists");
		}
	}

	/** Use Ghidra's managed analysis transaction and undo stack. Run off the event thread. */
	public static Result apply(Program program, Prepared proposal, TaskMonitor monitor) throws Exception {
		if (SwingUtilities.isEventDispatchThread()) {
			throw new IllegalStateException("Run summary layout application off the Swing thread");
		}
		Objects.requireNonNull(monitor, "monitor");
		monitor.checkCancelled();
		if (Thread.currentThread().isInterrupted()) {
			throw new IOException("Interrupted before applying the summary layout");
		}
		if (proposal == null || proposal.program != program || !proposal.consumed.compareAndSet(false, true)) {
			throw new IOException("A fresh summary review of this Program is required");
		}
		Object consumer = retain(program);
		try {
			requireWritable(program);
			checkRevision(program, proposal.review.revision());
			AutoAnalysisManager analysis = AutoAnalysisManager.getAnalysisManager(program);
			if (analysis.isAnalyzing() || program.getCurrentTransactionInfo() != null) {
				throw new IOException("Wait for Ghidra analysis or the active edit to finish");
			}
			return submit(program, proposal, analysis, monitor);
		}
		catch (InterruptedException failure) {
			Thread.currentThread().interrupt();
			throw new IOException("Interrupted while applying. Check the parameter before retrying.", failure);
		}
		finally {
			program.release(consumer);
		}
	}

	private static Result submit(Program program, Prepared proposal, AutoAnalysisManager analysis,
			TaskMonitor monitor) throws Exception {
		AtomicReference<TransactionInfo> written = new AtomicReference<>();
		boolean lateCancellation = false;
		try {
			boolean ran = analysis.scheduleWorker(new AnalysisWorker() {
				@Override
				public String getWorkerName() {
					return TRANSACTION;
				}

				@Override
				public boolean analysisWorkerCallback(Program current, Object ignored,
						TaskMonitor workerMonitor) throws Exception {
					workerMonitor.checkCancelled();
					TransactionInfo scope = current.getCurrentTransactionInfo();
					String parent = scope == null ? "" : scope.getDescription();
					if (current != program || scope == null ||
							(!TRANSACTION.equals(parent) && !"Auto Analysis".equals(parent)) ||
							scope.getStatus() != TransactionInfo.Status.NOT_DONE ||
							!scope.getOpenSubTransactions().equals(List.of(parent))) {
						throw new IOException("Summary application requires its own Ghidra analysis transaction");
					}
					checkRevision(current, proposal.review.revision());
					requireWritable(current);
					Function function = current.getFunctionManager().getFunctionAt(proposal.functionEntry);
					Parameter parameter = eligibleParameter(current, function, proposal.review.parameterIndex());
					checkAvailable(current, proposal.path);
					FunctionState previous = FunctionState.capture(function);
					checkRevision(current, proposal.review.revision());
					int transaction = current.startTransaction(TRANSACTION);
					boolean commit = false;
					try {
						insertAndAssign(current, proposal, parameter, workerMonitor);
						previous.checkPreserved(current, proposal);
						workerMonitor.checkCancelled();
						commit = true;
					}
					finally {
						current.endTransaction(transaction, commit);
					}
					written.set(scope);
					return true;
				}
			}, null, false, monitor);
			if (!ran) {
				throw new CancelledException("Summary layout application did not complete");
			}
		}
		catch (InvocationTargetException failure) {
			if (failure.getCause() instanceof Exception cause) {
				throw cause;
			}
			throw failure;
		}
		catch (CancelledException failure) {
			if (written.get() == null) {
				throw failure;
			}
			lateCancellation = true;
		}
		TransactionInfo scope = written.get();
		if (scope == null) {
			throw new IOException("Ghidra did not apply the reviewed layout");
		}
		// A headed worker wakes its caller before the outer transaction finishes.
		long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
		while (!(program.canUndo() && scope.hasCommittedDBTransaction())) {
			if (scope.getStatus() == TransactionInfo.Status.ABORTED) {
				throw new IOException("Ghidra rolled back the reviewed layout");
			}
			if (System.nanoTime() - deadline >= 0) {
				throw new IOException("Ghidra has not confirmed the edit. Check the parameter before retrying.");
			}
			Thread.sleep(20);
		}
		if (!installed(program, proposal)) {
			throw new IOException("The reviewed layout or parameter is no longer present");
		}
		return new Result(proposal.path.getPath(), lateCancellation || monitor.isCancelled());
	}

	private static void insertAndAssign(Program program, Prepared proposal, Parameter parameter,
			TaskMonitor monitor) throws Exception {
		var types = program.getDataTypeManager();
		StructureDataType structure = new StructureDataType(CATEGORY, proposal.path.getDataTypeName(),
			proposal.review.minimumExtent(), types);
		structure.setDescription("Reviewed BinaryRat summary layout. Extent is a lower bound.");
		for (Field field : proposal.review.fields()) {
			monitor.checkCancelled();
			structure.replaceAtOffset(field.offset(), Undefined.getUndefinedDataType(field.width()),
				field.width(), "field_" + Integer.toHexString(field.offset()),
				field.support() + " BinaryRat observations at " + String.join(", ", field.sites()));
		}
		DataType inserted = types.addDataType(structure, DataTypeConflictHandler.KEEP_HANDLER);
		if (!(inserted instanceof Structure saved) ||
				!saved.getDataTypePath().equals(proposal.path) ||
				saved.getLength() != proposal.review.minimumExtent() ||
				saved.getNumDefinedComponents() != proposal.review.fields().size()) {
			throw new IOException("Ghidra resolved the layout to an unexpected destination");
		}
		for (Field field : proposal.review.fields()) {
			monitor.checkCancelled();
			var actual = saved.getDefinedComponentAtOrAfterOffset(field.offset());
			if (actual == null || actual.getOffset() != field.offset() || actual.getLength() != field.width() ||
					!Undefined.isUndefined(actual.getDataType())) {
				throw new IOException("Ghidra changed a reviewed field's layout");
			}
		}
		monitor.checkCancelled();
		Pointer original = (Pointer) parameter.getFormalDataType();
		parameter.setDataType(original.newPointer(saved), SourceType.USER_DEFINED);
		program.getOptions(JOURNAL).setString(proposal.path.getDataTypeName(), provenance(proposal));
	}

	private static String provenance(Prepared proposal) {
		return "sha256:" + proposal.reportHash + " " + proposal.functionEntry.toString(true) + " parameter " +
			proposal.review.parameterIndex() + " revision " + proposal.review.revision();
	}

	private static boolean installed(Program program, Prepared proposal) {
		Function function = program.getFunctionManager().getFunctionAt(proposal.functionEntry);
		if (function == null) {
			return false;
		}
		Parameter parameter = function.getParameter(proposal.review.parameterIndex());
		if (parameter == null || !(parameter.getFormalDataType() instanceof Pointer pointer) ||
				!(pointer.getDataType() instanceof Structure structure)) {
			return false;
		}
		return structure.getDataTypePath().equals(proposal.path) &&
			function.getSignatureSource() == SourceType.USER_DEFINED &&
			provenance(proposal).equals(program.getOptions(JOURNAL)
				.getString(proposal.path.getDataTypeName(), null));
	}

	private record ParameterState(DataType type, VariableStorage storage, String name, String comment,
			SourceType source, long symbolId) {
		static ParameterState capture(Parameter parameter) {
			var symbol = parameter.getSymbol();
			return new ParameterState(parameter.getFormalDataType(), parameter.getVariableStorage(),
				parameter.getName(), parameter.getComment(), parameter.getSource(), symbol == null ? -1 : symbol.getID());
		}

		boolean matches(Parameter parameter, boolean allowTypeChange, boolean allowSourceChange) {
			ParameterState actual = capture(parameter);
			return (allowTypeChange || type.equals(actual.type())) && storage.equals(actual.storage()) &&
				Objects.equals(name, actual.name()) && Objects.equals(comment, actual.comment()) &&
				(allowSourceChange || source == actual.source()) && symbolId == actual.symbolId();
		}
	}

	private record FunctionState(String convention, boolean noReturn, boolean inline,
			ParameterState result, List<ParameterState> parameters) {
		static FunctionState capture(Function function) {
			List<ParameterState> parameters = new ArrayList<>();
			for (Parameter parameter : function.getParameters()) {
				parameters.add(ParameterState.capture(parameter));
			}
			return new FunctionState(function.getCallingConventionName(), function.hasNoReturn(), function.isInline(),
				ParameterState.capture(function.getReturn()), parameters);
		}

		void checkPreserved(Program program, Prepared proposal) throws IOException {
			Function function = program.getFunctionManager().getFunctionAt(proposal.functionEntry);
			// Ghidra's return parameter reports the entire function's signature source.
			if (function == null || !installed(program, proposal) || !result.matches(function.getReturn(), false, true) ||
					function.getAutoParameterCount() != 0 || function.hasVarArgs() ||
					function.hasCustomVariableStorage() || !Objects.equals(convention, function.getCallingConventionName()) ||
					noReturn != function.hasNoReturn() || inline != function.isInline()) {
				throw new IOException("Ghidra changed the signature outside the selected parameter");
			}
			Parameter[] actual = function.getParameters();
			if (actual.length != parameters.size()) {
				throw new IOException("Ghidra changed the parameter count");
			}
			for (int index = 0; index < actual.length; index++) {
				if (!parameters.get(index).matches(actual[index], index == proposal.review.parameterIndex(), false)) {
					throw new IOException("Ghidra changed other parameter metadata or storage");
				}
			}
		}
	}
}
