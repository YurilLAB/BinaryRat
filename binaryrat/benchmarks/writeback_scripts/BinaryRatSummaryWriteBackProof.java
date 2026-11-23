// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0

import java.io.IOException;
import java.util.HexFormat;
import java.util.List;

import binaryrat.SummaryLayouts;
import binaryrat.writeback.SummaryLayoutWriteBack;
import binaryrat.writeback.SummaryLayoutWriteBack.Recovery;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.database.ProgramDB;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/** Drive live interprocedural recovery and the native Ghidra transaction/undo stack. */
public class BinaryRatSummaryWriteBackProof extends GhidraScript {
	private static final String JOURNAL = "BinaryRat Reviewed Summary Layouts";
	private static final String TYPE_NAME = "BR_1000_p0";
	private static final DataTypePath PATH = new DataTypePath(
		new CategoryPath("/BinaryRat/ReviewedSummaryLayouts"), TYPE_NAME);
	private ProgramDB program;
	private Address root;
	private DomainFile file;

	@Override
	protected void run() throws Exception {
		if (!isRunningHeadless() || currentProgram != null) {
			throw new IllegalStateException("Run as a headless project-only preScript");
		}
		var language = DefaultLanguageService.getLanguageService()
			.getLanguage(new LanguageID("x86:LE:64:default"));
		program = new ProgramDB("BinaryRat disposable summary fixture", language,
			language.getCompilerSpecByID(new CompilerSpecID("gcc")), this);
		try {
			setup();
			protectExistingMetadata();
			refuseStaleAndBusyReview();
			rollBackInsertion();
			commitUndoAndRedo();
			program.save("Save reviewed layout and provenance", monitor);
		}
		finally {
			program.release(this);
		}
		Object reopen = new Object();
		Program loaded = (Program) file.getDomainObject(reopen, false, false, monitor);
		try {
			checkApplied(loaded);
		}
		finally {
			loaded.release(reopen);
		}
		println("BINARYRAT_SUMMARY_WRITEBACK_OK shifted_evidence=true saved_project=true " +
			"protection=true collision=true stale=true busy=true cancellation_rollback=true " +
			"one_use=true neighbors=true native_undo_redo=true");
	}

	private void setup() throws Exception {
		root = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
		Address leaf = root.add(0x40);
		var flat = new FlatProgramAPI(program, monitor);
		int transaction = program.startTransaction("Create disposable forwarding fixture");
		boolean commit = false;
		try {
			program.setExecutableSHA256("a".repeat(64));
			var memory = program.getMemory();
			var code = memory.createInitializedBlock(".text", root, 128, (byte) 0x90, monitor, false);
			code.setExecute(true);
			// Forward the selected pointer with +8; keep the neighbor parameter live.
			// lea rdi, [rdi+8]; call leaf; add eax, esi; ret.
			memory.setBytes(root, HexFormat.of().parseHex("488d7f08e83700000001f0c3"));
			// mov eax, [rdi+4]; ret.
			memory.setBytes(leaf, HexFormat.of().parseHex("8b4704c3"));
			require(flat.disassemble(leaf), "could not disassemble leaf");
			require(flat.disassemble(root), "could not disassemble caller");
			Function source = flat.createFunction(root, "root");
			Function target = flat.createFunction(leaf, "leaf");
			require(source != null && target != null, "could not define fixture functions");
			for (Function function : List.of(source, target)) {
				function.setCallingConvention(program.getCompilerSpec().getDefaultCallingConvention().getName());
				function.setReturnType(IntegerDataType.dataType, SourceType.ANALYSIS);
				function.addParameter(new ParameterImpl("object",
					PointerDataType.getPointer(VoidDataType.dataType, program.getDataTypeManager()),
					program), SourceType.ANALYSIS);
			}
			source.addParameter(new ParameterImpl("neighbor", IntegerDataType.dataType, program),
				SourceType.ANALYSIS).setComment("preserve neighbor");
			commit = true;
		}
		finally {
			program.endTransaction(transaction, commit);
		}
		file = state.getProject().getProjectData().getRootFolder().createFile("summary-fixture", program, monitor);
		require(program.canSave(), "disposable Program cannot save");
	}

	private Function function() {
		return program.getFunctionManager().getFunctionAt(root);
	}

	private Recovery recover() throws Exception {
		return SummaryLayoutWriteBack.recover(program, function(), 0, 30,
			SummaryLayouts.DEFAULT_SUMMARIES, monitor);
	}

	private SummaryLayoutWriteBack.Prepared review() throws Exception {
		Recovery recovery = recover();
		require(recovery.proposal() != null, "expected a write-back proposal: " + recovery.refusal() +
			"\n" + recovery.report());
		var prepared = recovery.proposal();
		var review = prepared.review();
		require(review.fields().size() == 1 && review.minimumExtent() == 16 &&
			review.fields().get(0).offset() == 12 && review.fields().get(0).width() == 4 &&
			review.fields().get(0).sites().equals(List.of("ram:1040")),
			"review did not carry the shifted leaf field and its location: " + review);
		return prepared;
	}

	private void protectExistingMetadata() throws Exception {
		for (SourceType source : List.of(SourceType.USER_DEFINED, SourceType.IMPORTED)) {
			program.withTransaction("Protect signature", () -> function().setSignatureSource(source));
			requireRefused(recover(), "signature is user-defined or imported");
		}
		program.withTransaction("Restore analysis signature", () -> {
			function().setSignatureSource(SourceType.ANALYSIS);
			function().getParameter(0).getSymbol().setSource(SourceType.USER_DEFINED);
		});
		requireRefused(recover(), "parameter is user-defined or imported");
		program.withTransaction("Install a concrete pointer", () -> {
			function().getParameter(0).getSymbol().setSource(SourceType.ANALYSIS);
			function().getParameter(0).setDataType(
				PointerDataType.getPointer(IntegerDataType.dataType, program.getDataTypeManager()),
				SourceType.ANALYSIS);
		});
		requireRefused(recover(), "already has a specific pointer type");
		program.withTransaction("Install a sized opaque pointer", () -> {
			var array = new ArrayDataType(Undefined.getUndefinedDataType(1), 32, 1);
			function().getParameter(0).setDataType(
				PointerDataType.getPointer(array, program.getDataTypeManager()), SourceType.ANALYSIS);
		});
		requireRefused(recover(), "already has a specific pointer type");
		require(((Pointer) function().getParameter(0).getFormalDataType()).getDataType().getLength() == 32,
			"the opaque pointer's existing extent changed");
		program.withTransaction("Restore generic pointer and reserve destination", () -> {
			function().getParameter(0).setDataType(
				PointerDataType.getPointer(VoidDataType.dataType, program.getDataTypeManager()),
				SourceType.ANALYSIS);
			program.getDataTypeManager().addDataType(new StructureDataType(
				PATH.getCategoryPath(), TYPE_NAME, 1), null);
		});
		requireRefused(recover(), "destination type or a previous review already exists");
		require(program.getDataTypeManager().getDataType(PATH).getLength() == 1,
			"protected destination was changed");
		program.withTransaction("Remove disposable collision", () ->
			program.getDataTypeManager().remove(List.of(program.getDataTypeManager().getDataType(PATH)), monitor));
		checkUnapplied(program);
	}

	private void refuseStaleAndBusyReview() throws Exception {
		var busy = review();
		int transaction = program.startTransaction("Hold another edit");
		try {
			expectFailure(busy, "active edit");
		}
		finally {
			program.endTransaction(transaction, false);
		}
		expectFailure(busy, "fresh summary review");
		var stale = review();
		program.withTransaction("Independent analyst note", () ->
			function().getParameter(0).setComment("preserve this note"));
		expectFailure(stale, "prepare a fresh review");
		checkUnapplied(program);
	}

	private void rollBackInsertion() throws Exception {
		var proposal = review();
		program.clearUndo();
		boolean[] reached = { false };
		TaskMonitor cancelling = new TaskMonitorAdapter(true) {
			@Override
			public void checkCancelled() throws CancelledException {
				if (program.getDataTypeManager().getDataType(PATH) != null &&
						VoidDataType.isVoidDataType(((Pointer) function().getParameter(0)
							.getFormalDataType()).getDataType())) {
					reached[0] = true;
					cancel();
				}
				super.checkCancelled();
			}
		};
		try {
			SummaryLayoutWriteBack.apply(program, proposal, cancelling);
			throw new AssertionError("expected cancellation after datatype insertion");
		}
		catch (CancelledException expected) {
			require(reached[0], "cancellation did not occur after insertion");
		}
		checkUnapplied(program);
		require(!program.canUndo() && !program.canRedo(), "rollback polluted native undo history");
		expectFailure(proposal, "fresh summary review");
	}

	private void commitUndoAndRedo() throws Exception {
		var proposal = review();
		String returned = function().getReturn().getVariableStorage().getSerializationString();
		String selected = function().getParameter(0).getVariableStorage().getSerializationString();
		String neighbor = function().getParameter(1).getVariableStorage().getSerializationString();
		long symbolId = function().getParameter(0).getSymbol().getID();
		program.clearUndo();
		var result = SummaryLayoutWriteBack.apply(program, proposal, monitor);
		require(PATH.getPath().equals(result.dataTypePath()) && !result.committedAfterCancellation(),
			"unexpected write-back result");
		checkApplied(program);
		Function reviewed = function();
		require(reviewed.getParameter(0).getSymbol().getID() == symbolId &&
			reviewed.getParameter(0).getSource() == SourceType.ANALYSIS &&
			"preserve this note".equals(reviewed.getParameter(0).getComment()) &&
			selected.equals(reviewed.getParameter(0).getVariableStorage().getSerializationString()),
			"selected parameter identity, comment or storage changed");
		require(neighbor.equals(reviewed.getParameter(1).getVariableStorage().getSerializationString()) &&
			"preserve neighbor".equals(reviewed.getParameter(1).getComment()) &&
			reviewed.getParameter(1).getFormalDataType().isEquivalent(IntegerDataType.dataType) &&
			returned.equals(reviewed.getReturn().getVariableStorage().getSerializationString()) &&
			reviewed.getReturnType().isEquivalent(IntegerDataType.dataType),
			"other parameter/return state changed");
		expectFailure(proposal, "fresh summary review");

		require(program.canUndo(), "summary review did not enter native undo history");
		program.undo();
		checkUnapplied(program);
		require(!program.canUndo() && program.canRedo(), "more than one undo step was required");
		program.redo();
		checkApplied(program);
		require(!program.canRedo(), "more than one redo step was required");
	}

	private void checkApplied(Program current) {
		Function function = current.getFunctionManager().getFunctionAt(root);
		var installed = current.getDataTypeManager().getDataType(PATH);
		require(installed instanceof Structure, "reviewed structure is missing");
		Structure structure = (Structure) installed;
		var field = structure.getDefinedComponentAtOrAfterOffset(12);
		require(structure.getLength() == 16 && structure.getNumDefinedComponents() == 1 &&
			field.getOffset() == 12 && field.getLength() == 4 && Undefined.isUndefined(field.getDataType()) &&
			field.getComment().contains("ram:1040"), "shifted field or durable instruction evidence is missing");
		var pointer = function.getParameter(0).getFormalDataType();
		require(pointer instanceof Pointer type && type.getDataType().getDataTypePath().equals(PATH) &&
			function.getSignatureSource() == SourceType.USER_DEFINED, "reviewed pointer was not assigned");
		String provenance = current.getOptions(JOURNAL).getString(TYPE_NAME, "");
		require(provenance.matches("sha256:[0-9a-f]{64} .* parameter 0 revision [0-9]+"),
			"durable review provenance is missing");
	}

	private void checkUnapplied(Program current) {
		Function function = current.getFunctionManager().getFunctionAt(root);
		var type = function.getParameter(0).getFormalDataType();
		require(type instanceof Pointer pointer && VoidDataType.isVoidDataType(pointer.getDataType()) &&
			function.getSignatureSource() == SourceType.ANALYSIS &&
			current.getDataTypeManager().getDataType(PATH) == null &&
			current.getOptions(JOURNAL).getString(TYPE_NAME, null) == null, "unexpected durable change");
	}

	private void expectFailure(SummaryLayoutWriteBack.Prepared proposal, String text) throws Exception {
		try {
			SummaryLayoutWriteBack.apply(program, proposal, monitor);
			throw new AssertionError("expected refusal: " + text);
		}
		catch (IOException refusal) {
			require(refusal.getMessage().contains(text), "unexpected refusal: " + refusal);
		}
	}

	private static void requireRefused(Recovery recovery, String text) {
		require(recovery.report() != null && recovery.proposal() == null && recovery.refusal() != null &&
			recovery.refusal().contains(text), "unexpected review result: " + recovery.refusal());
	}

	private static void require(boolean condition, String message) {
		if (!condition) {
			throw new AssertionError(message);
		}
	}
}
