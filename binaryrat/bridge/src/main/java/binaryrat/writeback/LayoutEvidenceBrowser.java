// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package binaryrat.writeback;

import static binaryrat.writeback.LayoutReport.*;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Read-only navigation from exact field proposals to their cited listing instructions. */
public final class LayoutEvidenceBrowser {
	private static final int MAXIMUM_BYTES = 8 << 20;
	private static final int MAXIMUM_EXTENT = 1 << 20;
	private static final int MAXIMUM_ACCESSES = 4_096;

	private LayoutEvidenceBrowser() {
	}

	/** The p-code and overlap are recorded evidence. The name and entry come from the open Program. */
	public record Row(Address address, int offset, int width, String operation, long pcodeOrder,
			Address functionEntry, String functionName, boolean overlaps, boolean instructionBytesVerified) {
	}

	/** Revision refers to this open Program during validation, independently of the capture session. */
	public record Review(String functionName, int parameterIndex, long revision, List<Row> rows) {
		public Review {
			rows = List.copyOf(rows);
		}
	}

	public static Review read(Program program, Path report, TaskMonitor monitor)
			throws IOException, CancelledException {
		monitor.checkCancelled();
		long revision = program.getModificationNumber();
		JsonObject artifact = parseReport(readReport(report, MAXIMUM_BYTES), monitor);
		Target target = target(program, artifact, Integer.MAX_VALUE);
		boolean localOnly = !artifact.has("follow_depth") && !artifact.has("forwarded_calls");
		Map<Address, Function> functions = localOnly ?
			Map.of(target.function().getEntryPoint(), target.function()) :
			forwardingPath(program, artifact, target.function(), monitor);
		JsonArray observations = array(artifact.get("observations"), "observations");
		int variableCount = artifact.has("variable_accesses") ?
			array(artifact.get("variable_accesses"), "variable_accesses").size() : 0;
		if (observations.size() + variableCount > MAXIMUM_ACCESSES) {
			throw new IOException("Too many layout observations");
		}
		Map<String, JsonObject> byId = observationsById(artifact, observations, monitor);
		JsonArray layouts = array(artifact.get("layouts"), "layouts");
		if (layouts.size() > 1) {
			throw new IOException("Expected at most one layout for the selected parameter");
		}
		List<Row> rows = new ArrayList<>();
		if (!layouts.isEmpty()) {
			JsonObject layout = object(layouts.get(0), "layout");
			if (!target.objectId().equals(string(layout.get("object_id"), "object_id"))) {
				throw new IOException("Layout object id does not identify its declared target");
			}
			int extent = integer(layout.get("minimum_extent"), 1, MAXIMUM_EXTENT, "minimum_extent");
			JsonArray fields = array(layout.get("fields"), "fields");
			if (fields.size() > observations.size()) {
				throw new IOException("Layout fields exceed the number of observations");
			}
			for (JsonElement element : fields) {
				monitor.checkCancelled();
				JsonObject field = object(element, "field");
				int offset = integer(field.get("offset"), 0, extent - 1, "offset");
				int width = integer(field.get("width"), 1, extent - offset, "width");
				boolean overlaps = flag(field.get("overlaps_other_fields"), "overlaps_other_fields");
				JsonArray ids = array(field.get("evidence_ids"), "evidence_ids");
				if (ids.isEmpty() || ids.size() > byId.size()) {
					throw new IOException("Invalid number of field evidence citations");
				}
				for (JsonElement item : ids) {
					monitor.checkCancelled();
					String id = string(item, "evidence id");
					JsonObject observation = byId.remove(id);
					if (observation == null) {
						throw new IOException("Missing, repeated or rejected field evidence citation");
					}
					rows.add(row(program, target, functions, localOnly, observation, id, offset,
						width, overlaps));
				}
			}
		}
		if (!byId.isEmpty()) {
			throw new IOException("Exact observations lack a field citation or rejection");
		}
		rows.sort(Comparator.comparingInt(Row::offset).thenComparingInt(Row::width)
			.thenComparing(Row::address).thenComparingLong(Row::pcodeOrder));
		var review = new Review(target.function().getName(true), target.parameter(), revision, rows);
		monitor.checkCancelled();
		checkRevision(program, revision);
		return review;
	}

	private static Map<String, JsonObject> observationsById(JsonObject artifact, JsonArray observations,
			TaskMonitor monitor) throws IOException, CancelledException {
		Map<String, JsonObject> byId = new HashMap<>();
		for (JsonElement element : observations) {
			monitor.checkCancelled();
			JsonObject observation = object(element, "observation");
			String id = string(observation.get("evidence_id"), "evidence_id");
			if (byId.putIfAbsent(id, observation) != null) {
				throw new IOException("Duplicate layout observation");
			}
		}
		for (JsonElement element : array(artifact.get("rejected"), "rejected")) {
			monitor.checkCancelled();
			JsonObject rejected = object(element, "rejected observation");
			int index = integer(rejected.get("observation_index"), 0, observations.size() - 1, "observation_index");
			JsonObject observation = observations.get(index).getAsJsonObject();
			if (byId.remove(string(observation.get("evidence_id"), "evidence_id")) == null) {
				throw new IOException("Duplicate rejected observation");
			}
		}
		return byId;
	}

	private static Row row(Program program, Target target, Map<Address, Function> functions,
			boolean localOnly, JsonObject observation, String id, int offset, int width,
			boolean overlaps) throws IOException {
		if (!target.objectId().equals(string(observation.get("object_id"), "object_id")) ||
				!flag(observation.get("object_start_known"), "object_start_known") ||
				integer(observation.get("offset"), 0, MAXIMUM_EXTENT - 1, "observation offset") != offset ||
				integer(observation.get("width"), 1, MAXIMUM_EXTENT, "observation width") != width) {
			throw new IOException("Field evidence must cite a matching observed access");
		}
		String operation = string(observation.get("operation"), "operation");
		if (!operation.equals("LOAD") && !operation.equals("STORE")) {
			throw new IOException("Field evidence must be a LOAD or STORE observation");
		}
		Address root = target.function().getEntryPoint();
		Address entry = root;
		if (!localOnly || observation.has("function_address_space") || observation.has("function_address")) {
			entry = readAddress(program, string(observation.get("function_address_space"), "function_address_space"),
				string(observation.get("function_address"), "function_address"));
		}
		Function function = functions.get(entry);
		String space = string(observation.get("address_space"), "address_space");
		String location = string(observation.get("address"), "address");
		Address site = readAddress(program, space, location);
		var instruction = program.getListing().getInstructionAt(site);
		if (function == null || !function.getBody().contains(site) || instruction == null ||
				!function.equals(program.getFunctionManager().getFunctionContaining(site))) {
			throw new IOException("Field evidence must cite a current instruction in a reachable reported function");
		}
		JsonElement order = observation.get("pcode_order");
		if (order == null || !order.isJsonPrimitive() || !order.getAsJsonPrimitive().isNumber() ||
				!order.getAsString().matches("0|[1-9][0-9]{0,9}")) {
			throw new IOException("Invalid recorded p-code order");
		}
		long orderNumber = Long.parseLong(order.getAsString());
		String prefix = root.equals(entry) ? target.objectId() :
			target.objectId() + "/callee/" + Long.toUnsignedString(entry.getOffset(), 16);
		if (orderNumber > 0xffff_ffffL || !id.equals(prefix + "/" + space + "/" + location + "/" + orderNumber)) {
			throw new IOException("Evidence id disagrees with its cited p-code location");
		}
		boolean verified = verifyInstructionBytes(observation, instruction);
		return new Row(site, offset, width, operation, orderNumber, entry, function.getName(true),
			overlaps, verified);
	}
}
