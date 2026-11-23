// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package binaryrat.writeback;

import static binaryrat.writeback.LayoutReport.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import binaryrat.SummaryLayouts;
import binaryrat.writeback.LayoutEvidenceBrowser.Review;
import binaryrat.writeback.LayoutEvidenceBrowser.Row;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Display the live solver's field evidence at the instructions that produced it. */
public final class SummaryLayoutEvidenceBrowser {
	private static final int MAXIMUM_ROWS = 4_096;
	private static final int MAXIMUM_PATH_LENGTH = 512;

	private SummaryLayoutEvidenceBrowser() {
	}

	public record View(Review evidence, Map<Row, String> callPaths, String status) {
		public View {
			callPaths = Map.copyOf(callPaths);
		}
	}

	private record Summary(Function function, JsonArray accesses) {
	}

	private record State(String summary, long offset, String path) {
	}

	private record Range(int offset, int width) {
	}

	private record Field(Set<String> evidence, boolean overlaps) {
	}

	/** Only used with the current result of the shared in-process recovery service. */
	public static View read(Program program, JsonObject report, TaskMonitor monitor)
			throws IOException, CancelledException {
		monitor.checkCancelled();
		long revision = number(report.get("revision"), "revision");
		checkRevision(program, revision);
		Target target = target(program, report, 255, SummaryLayouts.ANALYSIS_MODE);
		JsonObject solution = object(report.get("solution"), "solution");
		if (!"solved".equals(string(solution.get("status"), "solution status")) ||
				!target.objectId().equals(string(solution.get("summary"), "solution summary"))) {
			throw new IOException("Summary solution does not identify the selected parameter");
		}
		Map<String, Summary> summaries = readSummaries(program, report, monitor);
		List<State> states = readStates(program, report, solution, target.objectId(), summaries, monitor);
		Map<Range, Field> fields = readFields(solution, monitor);
		Map<Row, String> paths = new HashMap<>();
		var observed = bounded(solution.get("derived"), "derived accesses", MAXIMUM_ROWS);
		for (JsonElement element : observed) {
			monitor.checkCancelled();
			JsonObject derived = object(element, "derived access");
			long offset = number(derived.get("offset"), "derived offset");
			if (offset < 0 || offset > Integer.MAX_VALUE) {
				continue; // Out-of-object accesses cannot support a field.
			}
			int width = integer(derived.get("width"), 1, Integer.MAX_VALUE, "derived width");
			Field field = fields.get(new Range((int) offset, width));
			String id = string(derived.get("evidence_id"), "derived evidence");
			if (field == null || !field.evidence().contains(id)) {
				continue;
			}
			State state = states.get(integer(derived.get("state"), 0, states.size() - 1, "state index"));
			Summary summary = summaries.get(state.summary());
			JsonArray accesses = summary.accesses();
			var access = object(accesses.get(integer(derived.get("access"), 0, accesses.size() - 1,
				"access index")), "access");
			if (!id.equals(string(access.get("evidence_id"), "access evidence")) ||
					width != integer(access.get("width"), 1, Integer.MAX_VALUE, "access width") ||
					offset != add(state.offset(), number(access.get("offset"), "access offset"))) {
				throw new IOException("Summary field does not match its observed access");
			}
			Address site = address(program, access);
			Function function = summary.function();
			var instruction = program.getListing().getInstructionAt(site);
			if (instruction == null || !function.equals(program.getFunctionManager().getFunctionContaining(site))) {
				throw new IOException("Summary evidence no longer identifies a current instruction");
			}
			String operation = string(access.get("operation"), "access operation");
			if (!operation.equals("LOAD") && !operation.equals("STORE")) {
				throw new IOException("Summary field evidence must be a load or store");
			}
			var item = new Row(site, (int) offset, width, operation,
				number(access.get("pcode_order"), "p-code order"), function.getEntryPoint(),
				function.getName(true), field.overlaps(), verifyInstructionBytes(access, instruction),
				instruction.toString());
			paths.putIfAbsent(item, state.path());
		}
		List<Row> rows = new ArrayList<>(paths.keySet());
		rows.sort(Comparator.comparingInt(Row::offset).thenComparingInt(Row::width)
			.thenComparing(Row::address).thenComparingLong(Row::pcodeOrder));
		int refused = bounded(report.get("refused_calls"), "refused calls", 1_024).size();
		int variable = bounded(report.get("variable_accesses"), "variable accesses", MAXIMUM_ROWS).size();
		boolean complete = flag(solution.get("complete"), "complete");
		String status = rows.size() + " cited accesses in " + fields.size() + " fields. " +
			(complete ? "" : "Some call paths were withheld. ") +
			(refused == 0 ? "" : refused + " refused calls. ") +
			(variable == 0 ? "" : variable + " variable-offset accesses. ");
		monitor.checkCancelled();
		checkRevision(program, revision);
		return new View(new Review(target.function().getName(true), target.parameter(), revision, rows),
			paths, status);
	}

	private static Map<String, Summary> readSummaries(Program program, JsonObject report, TaskMonitor monitor)
			throws IOException, CancelledException {
		Map<String, Summary> summaries = new HashMap<>();
		for (var element : bounded(report.get("summaries"), "summaries", SummaryLayouts.MAXIMUM_SUMMARIES)) {
			monitor.checkCancelled();
			var item = object(element, "summary");
			var function = findFunction(program, string(item.get("function_address_space"), "function space"),
				string(item.get("function_address"), "function address"));
			var summary = new Summary(function, bounded(item.get("accesses"), "accesses", MAXIMUM_ROWS));
			if (summaries.putIfAbsent(string(item.get("id"), "summary id"), summary) != null) {
				throw new IOException("Repeated function parameter summary");
			}
		}
		return summaries;
	}

	private static List<State> readStates(Program program, JsonObject report, JsonObject solution,
			String root, Map<String, Summary> summaries, TaskMonitor monitor)
			throws IOException, CancelledException {
		JsonArray edges = bounded(report.get("edges"), "call edges", 1_024);
		List<State> states = new ArrayList<>();
		for (var element : bounded(solution.get("states"), "reached states", MAXIMUM_ROWS)) {
			monitor.checkCancelled();
			var item = object(element, "state");
			String id = string(item.get("summary"), "state summary");
			long offset = number(item.get("offset"), "state offset");
			if (!summaries.containsKey(id)) {
				throw new IOException("Reached state refers to an unknown function parameter");
			}
			if (states.isEmpty()) {
				if (!id.equals(root) || offset != 0) {
					throw new IOException("First reached state is not the selected parameter");
				}
				states.add(new State(id, offset, "Direct"));
				continue;
			}
			State parent = states.get(integer(item.get("parent"), 0, states.size() - 1, "parent"));
			var edge = object(edges.get(integer(item.get("edge"), 0, edges.size() - 1, "edge")), "edge");
			long shift = number(edge.get("offset"), "call argument offset");
			if (!parent.summary().equals(string(edge.get("caller"), "caller")) ||
					!id.equals(string(edge.get("callee"), "callee")) || offset != add(parent.offset(), shift)) {
				throw new IOException("Call path does not support the derived offset");
			}
			Address site = address(program, edge);
			var instruction = program.getListing().getInstructionAt(site);
			if (instruction == null || !summaries.get(parent.summary()).function()
					.equals(program.getFunctionManager().getFunctionContaining(site))) {
				throw new IOException("Summary call path no longer identifies a current instruction");
			}
			verifyInstructionBytes(edge, instruction);
			String path = parent.path();
			if (!path.endsWith("…")) {
				String prefix = path.equals("Direct") ? "" : path + " → ";
				String next = prefix + site.toString(true) + " (" + (shift >= 0 ? "+" : "") + shift + ")";
				path = next.length() <= MAXIMUM_PATH_LENGTH ? next : prefix + "…";
			}
			states.add(new State(id, offset, path));
		}
		if (states.isEmpty()) {
			throw new IOException("Summary solution has no reached states");
		}
		return states;
	}

	private static Map<Range, Field> readFields(JsonObject solution, TaskMonitor monitor)
			throws IOException, CancelledException {
		Map<Range, Field> fields = new HashMap<>();
		var element = solution.get("layout");
		if (element == null || element.isJsonNull()) {
			return fields;
		}
		var layout = object(element, "summary layout");
		for (var candidate : bounded(layout.get("fields"), "fields", MAXIMUM_ROWS)) {
			monitor.checkCancelled();
			var field = object(candidate, "field");
			var range = new Range(integer(field.get("offset"), 0, Integer.MAX_VALUE, "field offset"),
				integer(field.get("width"), 1, Integer.MAX_VALUE, "field width"));
			Set<String> ids = new HashSet<>();
			for (var id : bounded(field.get("evidence_ids"), "evidence ids", MAXIMUM_ROWS)) {
				monitor.checkCancelled();
				ids.add(string(id, "evidence id"));
			}
			fields.put(range, new Field(ids, flag(field.get("overlaps_other_fields"), "overlaps")));
		}
		return fields;
	}

	private static Address address(Program program, JsonObject item) throws IOException {
		return readAddress(program, string(item.get("address_space"), "address space"),
			string(item.get("address"), "address"));
	}

	private static JsonArray bounded(JsonElement value, String name, int limit) throws IOException {
		JsonArray result = array(value, name);
		if (result.size() > limit) {
			throw new IOException("Summary evidence exceeds its " + name + " limit");
		}
		return result;
	}

	private static long number(JsonElement value, String name) throws IOException {
		if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isNumber()) {
			throw new IOException("Expected a number for " + name);
		}
		try {
			return Long.parseLong(value.getAsString());
		}
		catch (NumberFormatException failure) {
			throw new IOException("Invalid number for " + name, failure);
		}
	}

	private static long add(long left, long right) throws IOException {
		try {
			return Math.addExact(left, right);
		}
		catch (ArithmeticException failure) {
			throw new IOException("Call path offset overflows", failure);
		}
	}
}
