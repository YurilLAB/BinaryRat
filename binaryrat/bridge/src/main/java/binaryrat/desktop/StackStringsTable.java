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

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
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
 * A nonmodal CodeBrowser table of a {@code binaryrat.StackStrings} report: one row per string a
 * function builds on its stack, at the first instruction that writes it.
 */
public final class StackStringsTable {
	public static final String TITLE = "BinaryRat Stack Strings";
	private static final Map<String, Integer> COLUMN_WIDTHS = Map.of("Location", 120, "Function", 170,
		"Text", 380, "Encoding", 80, "Stack offset", 90, "Terminated", 80);
	// Quotes and escapes text as C or JSON would, without Gson's HTML escapes for < > = &.
	private static final Gson QUOTE = new GsonBuilder().disableHtmlEscaping().create();

	private StackStringsTable() {
	}

	/** One string as the table shows it; the text is quoted and escaped. */
	public record Row(Address address, String function, String text, String encoding, String stackOffset,
			String terminated) {
	}

	/**
	 * Shows a report recovered for the active Program. BinaryRatStackStrings.java calls this by name.
	 *
	 * @return a status message when there is nothing to show, or null when the table opened
	 */
	public static String show(PluginTool tool, Program program, JsonObject report, TaskMonitor monitor)
			throws IOException, CancelledException {
		long revision = report.get("revision").getAsLong();
		if (program.isClosed() || program.getModificationNumber() != revision) {
			throw new IOException("The Program changed after the stack strings were listed. List them again.");
		}
		List<Row> rows = rows(program, report);
		if (rows.isEmpty()) {
			return "No stack strings were found in " + report.get("functions_scanned") + " functions.";
		}
		if (tool == null || tool.getService(TableService.class) == null ||
				tool.getService(ProgramManager.class) == null || tool.getService(GoToService.class) == null) {
			return "Open the stack strings from a CodeBrowser with table and navigation services.";
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
						tool.setStatusInfo("Stack strings closed after a program change.");
					}
				});
			}
		};
		boolean shown = false;
		try {
			TableChooserDialog table = Swing.runNow(() -> {
				TableChooserDialog dialog = tables.createTableChooserDialog(null, program, TITLE, null, false);
				created.set(dialog);
				addColumn(dialog, "Function", Row::function);
				addColumn(dialog, "Text", Row::text);
				addColumn(dialog, "Encoding", Row::encoding);
				addColumn(dialog, "Stack offset", Row::stackOffset);
				addColumn(dialog, "Terminated", Row::terminated);
				return dialog;
			});
			if (table == null) {
				throw new CancelledException();
			}
			Set<String> functions = new HashSet<>();
			for (Row row : rows) {
				monitor.checkCancelled();
				functions.add(row.function());
				table.add(new StringRow(row));
			}
			String summary = rows.size() + (rows.size() == 1 ? " string" : " strings") + " in " +
				functions.size() + (functions.size() == 1 ? " function" : " functions") +
				(report.get("truncated").getAsBoolean() ? " (list truncated)" : "") +
				". Double-click a row to open its first store in the Listing.";
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
				throw new IOException("The active program changed. List the stack strings again.");
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

	/** The rows of a report, each at the lowest address of the stores behind its text. */
	public static List<Row> rows(Program program, JsonObject report) throws IOException {
		List<Row> rows = new ArrayList<>();
		for (JsonElement element : report.getAsJsonArray("strings")) {
			JsonObject found = element.getAsJsonObject();
			AddressSpace space = program.getAddressFactory().getAddressSpace(found.get("address_space").getAsString());
			if (space == null) {
				throw new IOException("stack string in an unknown address space");
			}
			Address address = space.getAddress(Long.parseUnsignedLong(found.get("address").getAsString(), 16));
			long offset = found.get("stack_offset").getAsLong();
			String text = QUOTE.toJson(found.get("text").getAsString()) +
				(found.get("text_truncated").getAsBoolean() ? "..." : "");
			rows.add(new Row(address, found.getAsJsonObject("function").get("name").getAsString(), text,
				found.get("encoding").getAsString().equals("utf16le") ? "UTF-16" : "ASCII",
				offset < 0 ? "-0x" + Long.toUnsignedString(-offset, 16) : "0x" + Long.toHexString(offset),
				found.get("terminated").getAsBoolean() ? "yes" : "no"));
		}
		return rows;
	}

	private static void readable(TableChooserDialog table) {
		table.setDefaultSize(1000, 420);
		var columns = table.getTable().getColumnModel();
		for (int index = 0; index < columns.getColumnCount(); index++) {
			var column = columns.getColumn(index);
			column.setPreferredWidth(COLUMN_WIDTHS.getOrDefault(String.valueOf(column.getHeaderValue()), 100));
		}
	}

	private record StringRow(Row source) implements AddressableRowObject {
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
				return value.apply(((StringRow) object).source());
			}
		});
	}
}
