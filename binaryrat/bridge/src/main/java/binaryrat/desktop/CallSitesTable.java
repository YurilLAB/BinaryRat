// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package binaryrat.desktop;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

import javax.swing.SwingUtilities;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.app.tablechooser.AbstractComparableColumnDisplay;
import ghidra.app.tablechooser.AddressableRowObject;
import ghidra.app.tablechooser.TableChooserDialog;
import ghidra.app.util.query.TableService;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A nonmodal CodeBrowser table of a {@code binaryrat.CallSites} report: one row per call, with
 * the caller's decompiled statement and the arguments the decompiler proved constant.
 */
public final class CallSitesTable {
	public static final String TITLE = "BinaryRat Call Sites";
	private static final Map<String, Integer> COLUMN_WIDTHS = Map.of("Location", 120, "Caller", 160,
		"Statement", 380, "Arguments", 300, "Status", 120);

	private CallSitesTable() {
	}

	/** One call as the table shows it. */
	public record Row(Address address, String caller, String statement, String arguments, String status) {
	}

	/**
	 * Shows a report recovered for the active Program. BinaryRatCallSites.java calls this by name.
	 *
	 * @return a status message when there is nothing to show, or null when the table opened
	 */
	public static String show(PluginTool tool, Program program, JsonObject report, TaskMonitor monitor)
			throws IOException, CancelledException {
		String function = report.getAsJsonObject("root_function").get("name").getAsString();
		long revision = report.get("revision").getAsLong();
		if (program.isClosed() || program.getModificationNumber() != revision) {
			throw new IOException("The Program changed after the call sites were listed. List them again.");
		}
		List<Row> rows = rows(program, report);
		if (rows.isEmpty()) {
			return "No calls to " + function + " were found.";
		}
		if (tool == null || tool.getService(TableService.class) == null ||
				tool.getService(ProgramManager.class) == null || tool.getService(GoToService.class) == null) {
			return "Open the call sites from a CodeBrowser with table and navigation services.";
		}
		var tables = tool.getService(TableService.class);
		var programs = tool.getService(ProgramManager.class);
		AtomicReference<TableChooserDialog> created = new AtomicReference<>();
		DomainObjectListener changed = event -> {
			if (program.getModificationNumber() != revision) {
				Swing.runIfSwingOrRunLater(() -> {
					TableChooserDialog table = created.get();
					if (table != null && table.isVisible()) {
						table.close();
						tool.setStatusInfo("Call sites closed after a program change.");
					}
				});
			}
		};
		boolean shown = false;
		try {
			TableChooserDialog table = Swing.runNow(() -> {
				TableChooserDialog dialog = tables.createTableChooserDialog(null, program,
					TITLE + " — " + function, null, false);
				created.set(dialog);
				addColumn(dialog, "Caller", Row::caller);
				addColumn(dialog, "Statement", Row::statement);
				addColumn(dialog, "Arguments", Row::arguments);
				addColumn(dialog, "Status", Row::status);
				return dialog;
			});
			if (table == null) {
				throw new CancelledException();
			}
			Set<String> callers = new HashSet<>();
			for (Row row : rows) {
				monitor.checkCancelled();
				callers.add(row.caller());
				table.add(new CallRow(row));
			}
			String summary = rows.size() + (rows.size() == 1 ? " call" : " calls") + " from " +
				callers.size() + (callers.size() == 1 ? " caller" : " callers") +
				(report.get("truncated").getAsBoolean() ? " (list truncated)" : "") +
				". Double-click a row to open the call in the Listing.";
			Boolean visible = Swing.runNow(() -> {
				if (monitor.isCancelled() || programs.getCurrentProgram() != program || program.isClosed()) {
					return false;
				}
				table.setClosedListener(() -> program.removeListener(changed));
				program.addListener(changed);
				if (program.getModificationNumber() != revision) {
					return false;
				}
				table.setStatusText(summary);
				readable(table);
				table.show();
				return true;
			});
			monitor.checkCancelled();
			if (visible == null) {
				throw new CancelledException();
			}
			if (!visible) {
				throw new IOException("The active program changed. List the call sites again.");
			}
			shown = true;
			return null;
		}
		finally {
			if (!shown) {
				SwingUtilities.invokeLater(() -> {
					program.removeListener(changed);
					TableChooserDialog table = created.getAndSet(null);
					if (table != null) {
						table.close();
					}
				});
			}
		}
	}

	/** The rows of a report, with each argument written the way a C call shows it. */
	public static List<Row> rows(Program program, JsonObject report) throws IOException {
		List<Row> rows = new ArrayList<>();
		for (JsonElement element : report.getAsJsonArray("sites")) {
			JsonObject site = element.getAsJsonObject();
			AddressSpace space = program.getAddressFactory().getAddressSpace(
				site.get("address_space").getAsString());
			if (space == null) {
				throw new IOException("call site in an unknown address space");
			}
			Address address = space.getAddress(Long.parseUnsignedLong(site.get("address").getAsString(), 16));
			String caller = site.get("caller").isJsonNull() ? "(no function)" :
				site.getAsJsonObject("caller").get("name").getAsString();
			String status = site.get("status").getAsString();
			String statement = text(site, "statement");
			if (statement.isEmpty()) {
				statement = text(site, "reason");
			}
			List<String> arguments = new ArrayList<>();
			for (JsonElement value : site.getAsJsonArray("arguments")) {
				arguments.add(argument(value.getAsJsonObject()));
			}
			if (site.get("arguments_truncated").getAsBoolean()) {
				arguments.add("...");
			}
			rows.add(new Row(address, caller, statement, String.join(", ", arguments),
				status.replace('_', ' ')));
		}
		return rows;
	}

	/** {@code 7}, {@code -1}, {@code 0x401000}, a string, a symbol or the variable's name. */
	static String argument(JsonObject argument) {
		String kind = argument.get("kind").getAsString();
		if (kind.equals("unknown")) {
			String variable = text(argument, "variable");
			return variable.isEmpty() ? "?" : variable;
		}
		if (kind.equals("address")) {
			String string = text(argument, "string");
			String symbol = text(argument, "symbol");
			String value = "0x" + argument.get("value").getAsString();
			return !string.isEmpty() ? string : !symbol.isEmpty() ? "&" + symbol : value;
		}
		JsonElement signed = argument.get("signed");
		if (signed != null && !signed.isJsonNull()) {
			long number = signed.getAsLong();
			if (number > -0x10000 && number < 0x10000) {
				return Long.toString(number);
			}
		}
		return "0x" + argument.get("value").getAsString();
	}

	private static String text(JsonObject object, String key) {
		JsonElement value = object.get(key);
		return value == null || value.isJsonNull() ? "" : value.getAsString();
	}

	private static void readable(TableChooserDialog table) {
		table.setDefaultSize(1100, 420);
		var columns = table.getTable().getColumnModel();
		for (int index = 0; index < columns.getColumnCount(); index++) {
			var column = columns.getColumn(index);
			column.setPreferredWidth(COLUMN_WIDTHS.getOrDefault(String.valueOf(column.getHeaderValue()), 100));
		}
	}

	private record CallRow(Row source) implements AddressableRowObject {
		@Override
		public Address getAddress() {
			return source.address();
		}
	}

	private static void addColumn(TableChooserDialog table, String name, Function<Row, String> value) {
		table.addCustomColumn(new AbstractComparableColumnDisplay<String>() {
			@Override
			public String getColumnName() {
				return name;
			}

			@Override
			public Class<String> getColumnClass() {
				return String.class;
			}

			@Override
			public String getColumnValue(AddressableRowObject object) {
				return value.apply(((CallRow) object).source());
			}
		});
	}
}
