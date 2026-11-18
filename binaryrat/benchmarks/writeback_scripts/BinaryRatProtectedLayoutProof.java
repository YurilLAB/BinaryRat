// SPDX-License-Identifier: Apache-2.0
// Verify packaged protected write-back on a disposable, saved headless Program.

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;
import java.util.function.Consumer;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

import binaryrat.writeback.ProtectedLayoutWriteBack;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

public class BinaryRatProtectedLayoutProof extends GhidraScript {
	private static final CategoryPath CATEGORY = new CategoryPath("/BinaryRat/Reviewed");
	private static final String JOURNAL = "BinaryRat Reviewed Layouts";
	private static final String ANALYST = "BinaryRatProofAnalyst";
	private static final String TARGET = "BinaryRatProofCreated";
	private static final String COMMENT = "Previously approved analyst comment";

	private Path report;
	private Function function;
	private Path temporary;

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (!isRunningHeadless() || currentProgram == null || args.length < 1 || args.length > 3) {
			throw new IllegalArgumentException("Run on a disposable writable saved Program with a layout report");
		}
		end(true);
		report = Path.of(args[0]);
		JsonObject artifact = JsonParser.parseString(Files.readString(report)).getAsJsonObject();
		JsonObject target = artifact.getAsJsonObject("function");
		var space = currentProgram.getAddressFactory().getAddressSpace(target.get("address_space").getAsString());
		var entry = space.getAddress(Long.parseUnsignedLong(target.get("address").getAsString(), 16));
		function = currentProgram.getFunctionManager().getFunctionAt(entry);
		expect(function != null && !present(TARGET) && !present(ANALYST), "test project is not fresh");
		String prototype = function.getPrototypeString(false, true);
		edit("Analyst-owned prior type and note", () -> {
			StructureDataType type = new StructureDataType(CATEGORY, ANALYST, 0);
			type.add(IntegerDataType.dataType, 4, "analyst_field", null);
			currentProgram.getDataTypeManager().addDataType(type, DataTypeConflictHandler.KEEP_HANDLER);
			function.setComment(COMMENT);
		});
		String analystUndo = currentProgram.getUndoName();

		temporary = Files.createTempDirectory("binaryrat-layout-proof");
		Path input = temporary.resolve("candidate.json");
		try {
			expectFailure(() -> prepare("unsafe/name"), "ASCII structure identifier");
			expectFailure(() -> prepare(ANALYST), "already exists");
			reject(input, artifact, altered -> altered.getAsJsonArray("layouts").get(0)
				.getAsJsonObject().addProperty("has_overlaps", true), "unambiguous");
			reject(input, artifact, altered -> altered.getAsJsonArray("layouts").get(0)
				.getAsJsonObject().add("union_candidates", JsonParser.parseString("[{}]")), "unambiguous");
			reject(input, artifact, altered -> altered.add("variable_accesses", JsonParser.parseString("[{}]")),
				"Variable-offset accesses");
			reject(input, artifact, altered -> firstField(altered).addProperty("width", 1.5), "integer");
			reject(input, artifact, altered -> firstField(altered).addProperty("offset", 100_000), "Out-of-range");
			reject(input, artifact, altered -> widenFirstField(altered, false), "matching observed access");
			reject(input, artifact, altered -> widenFirstField(altered, true), "Overlapping fields");
			reject(input, artifact, altered -> firstField(altered).getAsJsonArray("evidence_ids")
				.set(0, new JsonPrimitive("missing-evidence-id")), "matching observed access");
			reject(input, artifact, altered -> altered.getAsJsonArray("observations")
				.add(altered.getAsJsonArray("observations").get(0)), "Duplicate layout observation");
			reject(input, artifact, altered -> {
				var observation = altered.getAsJsonArray("observations").get(0).getAsJsonObject();
				String hash = observation.get("instruction_sha256").getAsString();
				observation.addProperty("instruction_sha256",
					(hash.startsWith("0") ? "1" : "0") + hash.substring(1));
			}, "Instruction bytes differ");
			println("PASS protected preview rejected a changed instruction digest");
			reject(input, artifact, altered -> altered.addProperty("program_id", "sha256:" + "0".repeat(64)),
				"different executable");
			Files.writeString(input, "{\"schema_version\":1," + Files.readString(report).substring(1));
			expectFailure(() -> ProtectedLayoutWriteBack.prepare(currentProgram, input, TARGET, monitor),
				"Duplicate layout report property");
			Files.write(input, new byte[(1 << 20) + 1]);
			expectFailure(() -> ProtectedLayoutWriteBack.prepare(currentProgram, input, TARGET, monitor),
				"report exceeds the review byte limit");
			absent(TARGET);
			expect(analystUndo.equals(currentProgram.getUndoName()), "invalid imports changed the undo stack");
			println("PASS bounded imports, exact integers, evidence, ambiguity, collision and identity");
		}
		finally {
			Files.deleteIfExists(input);
			Files.delete(temporary);
		}

		var wrongCode = prepare(TARGET);
		expectFailure(() -> apply(wrongCode, "unknown", monitor), "fresh review");
		expectFailure(() -> apply(wrongCode, code(wrongCode), monitor), "fresh review");
		var stale = prepare(TARGET);
		edit("Analyst changed after preview", () -> function.setComment(COMMENT + " after preview"));
		expectFailure(() -> apply(stale, code(stale), monitor), "changed or closed");
		String staleUndo = currentProgram.getUndoName();
		absent(TARGET);
		expect((COMMENT + " after preview").equals(function.getComment()), "stale rejection changed analyst work");
		println("PASS explicit one-use approval and live revision guard");

		var challenged = prepare(TARGET);
		int[] foreign = { -1 };
		TaskMonitor race = new TaskMonitorAdapter(true) {
			private int checks;
			@Override
			public void checkCancelled() {
				if (++checks == 2) {
					foreign[0] = currentProgram.startTransaction("Unrelated owner during worker submission");
				}
			}
		};
		try {
			expectFailure(() -> apply(challenged, code(challenged), race), "managed Program transaction");
			expect(foreign[0] != -1 && currentProgram.getCurrentTransactionInfo() != null,
				"worker interfered with another owner's transaction");
			absent(TARGET);
		}
		finally {
			if (foreign[0] != -1) {
				currentProgram.endTransaction(foreign[0], true);
			}
		}
		expect(staleUndo.equals(currentProgram.getUndoName()), "interleaved rejection changed undo");
		println("PASS managed worker ownership guard");

		var failure = prepare(TARGET);
		TaskMonitor failAfterType = new TaskMonitorAdapter(true) {
			@Override
			public void checkCancelled() {
				if (present(TARGET) && marker(TARGET) == null) {
					throw new IllegalStateException("forced failure after structure write");
				}
			}
		};
		expectFailure(() -> apply(failure, code(failure), failAfterType), "forced failure after structure");
		absent(TARGET);
		expect(staleUndo.equals(currentProgram.getUndoName()), "failed submission changed undo");

		var cancelled = prepare(TARGET);
		TaskMonitor cancelAfterWrites = cancelWhenPresent(TARGET, false);
		try {
			apply(cancelled, code(cancelled), cancelAfterWrites);
			throw new IllegalStateException("cancelled submission did not throw");
		}
		catch (CancelledException expected) {
			absent(TARGET);
		}
		expect(staleUndo.equals(currentProgram.getUndoName()), "cancelled submission changed undo");
		println("PASS failure and cancellation roll back type and provenance atomically");

		var approved = prepare(TARGET);
		var result = apply(approved, code(approved), monitor);
		expect(!result.committedAfterCancellation() && result.dataTypePath().equals(path(TARGET).getPath()),
			"wrong result for approval");
		verifyCreated(approved, TARGET);
		currentProgram.undo();
		absent(TARGET);
		expect(staleUndo.equals(currentProgram.getUndoName()), "one undo did not expose previous work");
		currentProgram.redo();
		verifyCreated(approved, TARGET);
		expectFailure(() -> prepare(TARGET), "already exists");
		currentProgram.undo();
		absent(TARGET);
		println("PASS native undo/redo and duplicate accept isolation");

		var late = prepare(TARGET);
		var lateResult = apply(late, code(late), cancelWhenPresent(TARGET, true));
		expect(lateResult.committedAfterCancellation(), "post-commit cancellation did not report commit");
		verifyCreated(late, TARGET);
		var analyst = (Structure) currentProgram.getDataTypeManager().getDataType(path(ANALYST));
		expect(analyst != null && "analyst_field".equals(analyst.getDefinedComponents()[0].getFieldName()) &&
			(COMMENT + " after preview").equals(function.getComment()) &&
			prototype.equals(function.getPrototypeString(false, true)), "approved write changed analyst work");
		println("PASS late cancellation reports the committed change and preserves analyst work");
		if (args.length >= 2) {
			verifyForwardedApproval(Path.of(args[1]));
		}
		if (args.length == 3) {
			verifyForwardingPath(Path.of(args[2]));
		}
		println("BINARYRAT_PROTECTED_LAYOUT_PROOF_OK");
	}

	private void verifyForwardedApproval(Path forwarded) throws Exception {
		String name = "BinaryRatProofForwarded";
		var original = ProtectedLayoutWriteBack.prepare(currentProgram, forwarded, name, monitor);
		var root = JsonParser.parseString(Files.readString(forwarded)).getAsJsonObject()
			.getAsJsonObject("function");
		var rootSpace = currentProgram.getAddressFactory().getAddressSpace(root.get("address_space").getAsString());
		var rootEntry = rootSpace.getAddress(Long.parseUnsignedLong(root.get("address").getAsString(), 16));
		var citedEntry = original.review().fields().stream().flatMap(field -> field.evidence().stream())
			.map(evidence -> currentProgram.getAddressFactory().getAddress(evidence.function()))
			.filter(entry -> entry != null && !entry.equals(rootEntry)).findFirst()
			.orElseThrow(() -> new IllegalStateException("The forwarded report has no callee evidence"));
		Function cited = currentProgram.getFunctionManager().getFunctionAt(citedEntry);
		String previous = cited.getName(true);
		edit("Rename cited callee after preparing a review",
			() -> cited.setName("BinaryRatProofRenamedCallee", SourceType.USER_DEFINED));
		try {
			var refreshed = ProtectedLayoutWriteBack.prepare(currentProgram, forwarded, name, monitor);
			expect(!code(original).equals(code(refreshed)), "a cited-only change did not invalidate approval");
			expectFailure(() -> apply(refreshed, code(original), monitor), "fresh review");
			absent(name);
		}
		finally {
			currentProgram.undo();
		}
		var restored = currentProgram.getFunctionManager().getFunctionAt(citedEntry);
		expect(previous.equals(restored.getName(true)), "native undo failed to restore cited function");
		println("PASS edits to a cited callee invalidate a prior approval on a fresh handle");
	}

	private void verifyForwardingPath(Path report) throws Exception {
		String name = "BinaryRatProofTwoHops";
		var artifact = JsonParser.parseString(Files.readString(report)).getAsJsonObject();
		var edges = artifact.getAsJsonArray("forwarded_calls");
		expect(edges.size() == 2, "two-hop fixture must report both forwarding edges");
		var second = edges.get(1).getAsJsonObject();
		var space = currentProgram.getAddressFactory().getAddressSpace(second.get("address_space").getAsString());
		var site = space.getAddress(Long.parseUnsignedLong(second.get("address").getAsString(), 16));
		Function middle = currentProgram.getFunctionManager().getFunctionContaining(site);
		var leaf = space.getAddress(Long.parseUnsignedLong(second.get("callee_address").getAsString(), 16));
		var prepared = ProtectedLayoutWriteBack.prepare(currentProgram, report, name, monitor);
		expect(prepared.review().fields().stream().flatMap(field -> field.evidence().stream())
			.allMatch(row -> leaf.toString(true).equals(row.function())),
			"two-hop fixture must have evidence only in the leaf");
		edit("Rename intermediate forwarder", () -> middle.setName("ProofRenamedMiddle", SourceType.USER_DEFINED));
		try {
			var changed = ProtectedLayoutWriteBack.prepare(currentProgram, report, name, monitor);
			expect(!code(changed).equals(code(prepared)), "a forwarder-only edit left an old approval valid");
			expectFailure(() -> apply(changed, code(prepared), monitor), "fresh review");
		}
		finally {
			currentProgram.undo();
		}

		edit("Redirect forwarded call", () -> {
			var references = currentProgram.getReferenceManager();
			var reference = references.addMemoryReference(site, middle.getEntryPoint(),
				RefType.CALL_OVERRIDE_UNCONDITIONAL, SourceType.USER_DEFINED, 0);
			references.setPrimary(reference, true);
		});
		try {
			var instruction = currentProgram.getListing().getInstructionAt(site);
			expect(leaf.equals(instruction.getDefaultFlows()[0]) &&
				java.util.Arrays.stream(instruction.getPcode(true)).anyMatch(op ->
					op.getOpcode() == PcodeOp.CALL && middle.getEntryPoint().equals(op.getInput(0).getAddress())),
				"test must redirect the effective p-code call while preserving the decoded target");
			expectFailure(() -> ProtectedLayoutWriteBack.prepare(currentProgram, report, name, monitor),
				"Forwarded call no longer matches");
		}
		finally {
			currentProgram.undo();
		}
		var restored = ProtectedLayoutWriteBack.prepare(currentProgram, report, name, monitor);
		expect(code(restored).equals(code(prepared)), "undo did not restore the forwarding path");
		Path editedReport = Files.createTempFile("binaryrat-forwarded", ".json");
		try {
			// Remove the root-to-intermediate edge. The leaf instruction and its caller still exist.
			edges.remove(0);
			Files.writeString(editedReport, artifact.toString());
			expectFailure(() -> ProtectedLayoutWriteBack.prepare(currentProgram, editedReport, name, monitor),
				"Disconnected forwarded call path");
			edges.remove(0);
			Files.writeString(editedReport, artifact.toString());
			expectFailure(() -> ProtectedLayoutWriteBack.prepare(currentProgram, editedReport, name, monitor),
				"verified forwarded function");
		}
		finally {
			Files.deleteIfExists(editedReport);
		}
		absent(name);
		println("PASS two-hop approvals bind intermediate functions and require connected effective calls");
	}

	private TaskMonitor cancelWhenPresent(String name, boolean afterCommit) {
		return new TaskMonitorAdapter(true) {
			@Override
			public void checkCancelled() throws CancelledException {
				if ((currentProgram.getCurrentTransactionInfo() == null) == afterCommit && marker(name) != null) {
					throw new CancelledException();
				}
			}
		};
	}

	private void edit(String name, CheckedAction action) throws Exception {
		int scope = currentProgram.startTransaction(name);
		boolean commit = false;
		try {
			action.run();
			commit = true;
		}
		finally {
			currentProgram.endTransaction(scope, commit);
		}
	}

	private ProtectedLayoutWriteBack.Prepared prepare(String name) throws Exception {
		return ProtectedLayoutWriteBack.prepare(currentProgram, report, name, monitor);
	}

	private static String code(ProtectedLayoutWriteBack.Prepared prepared) {
		return prepared.review().approvalCode();
	}

	private ProtectedLayoutWriteBack.Result apply(ProtectedLayoutWriteBack.Prepared prepared,
			String code, TaskMonitor gate) throws Exception {
		return ProtectedLayoutWriteBack.accept(currentProgram, prepared, code, gate);
	}

	private void reject(Path input, JsonObject artifact, Consumer<JsonObject> change, String diagnostic)
			throws Exception {
		JsonObject altered = artifact.deepCopy();
		change.accept(altered);
		Files.writeString(input, altered.toString());
		expectFailure(() -> ProtectedLayoutWriteBack.prepare(currentProgram, input, TARGET, monitor), diagnostic);
	}

	private static JsonObject firstField(JsonObject artifact) {
		return artifact.getAsJsonArray("layouts").get(0).getAsJsonObject().getAsJsonArray("fields")
			.get(0).getAsJsonObject();
	}

	private static void widenFirstField(JsonObject artifact, boolean widenObservations) {
		JsonObject field = firstField(artifact);
		int width = field.get("width").getAsInt() + 1;
		field.addProperty("width", width);
		if (widenObservations) {
			var ids = field.getAsJsonArray("evidence_ids");
			for (var item : artifact.getAsJsonArray("observations")) {
				var observation = item.getAsJsonObject();
				if (ids.contains(observation.get("evidence_id"))) {
					observation.addProperty("width", width);
				}
			}
		}
	}

	private static DataTypePath path(String type) {
		return new DataTypePath(CATEGORY, type);
	}

	private String marker(String type) {
		return currentProgram.getOptions(JOURNAL).getString(type, null);
	}

	private boolean present(String type) {
		return currentProgram.getDataTypeManager().getDataType(path(type)) != null;
	}

	private void absent(String type) {
		expect(!present(type) && marker(type) == null, "partial write to " + type);
	}

	private void verifyCreated(ProtectedLayoutWriteBack.Prepared prepared, String type) {
		var review = prepared.review();
		expect(Objects.equals(code(prepared) + " " + review.reportSha256(), marker(type)), "missing provenance");
		var created = (Structure) currentProgram.getDataTypeManager().getDataType(path(type));
		expect(created != null && created.getLength() == review.minimumExtent() &&
			created.getNumDefinedComponents() == review.fields().size(), "unexpected committed layout");
		for (var field : review.fields()) {
			var component = created.getDefinedComponentAtOrAfterOffset(field.offset());
			expect(component != null && component.getOffset() == field.offset() &&
				component.getLength() == field.width(), "unexpected committed field");
		}
	}

	@FunctionalInterface
	private interface CheckedAction {
		void run() throws Exception;
	}

	private static void expectFailure(CheckedAction action, String diagnostic) throws Exception {
		try {
			action.run();
		}
		catch (IOException | IllegalArgumentException | IllegalStateException failure) {
			expect(failure.getMessage().contains(diagnostic), "unexpected error: " + failure);
			return;
		}
		throw new IllegalStateException("expected rejection containing " + diagnostic);
	}

	private static void expect(boolean condition, String description) {
		if (!condition) {
			throw new IllegalStateException(description);
		}
	}
}
