// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package binaryrat.writeback;

import java.io.IOException;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

import javax.swing.SwingUtilities;

import binaryrat.writeback.LayoutEvidenceBrowser.Review;
import binaryrat.writeback.LayoutEvidenceBrowser.Row;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.app.tablechooser.AbstractComparableColumnDisplay;
import ghidra.app.tablechooser.AddressableRowObject;
import ghidra.app.tablechooser.TableChooserDialog;
import ghidra.app.util.query.TableService;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** A nonmodal CodeBrowser table of the instructions cited by a checked layout report. */
public final class LayoutEvidenceTable {
	public static final String TITLE = "BinaryRat Layout Evidence";
	/** Preference key for the folder of the latest report, shared by the recover and browse actions. */
	public static final String DIRECTORY_PREFERENCE = "BinaryRat.LayoutReportDirectory";
	private static final Map<String, Integer> COLUMN_WIDTHS = Map.of("Location", 130, "Offset", 64,
		"Width", 52, "Access", 64, "Instruction", 320, "Function", 170, "P-code order", 90,
		"Overlaps", 70, "Instruction bytes", 110);

	private LayoutEvidenceTable() {
	}

	/** A field offset that sorts numerically and reads as in a C struct listing: {@code +0x10}. */
	public record Offset(int value) implements Comparable<Offset> {
		@Override
		public int compareTo(Offset other) {
			return Integer.compare(value, other.value);
		}

		@Override
		public String toString() {
			return "+0x" + Integer.toHexString(value);
		}
	}

	/**
	 * Opens a report that was just published for the active Program and remembers its folder for
	 * Browse Layout Evidence. Recover Layout at Cursor calls this by name: a checkout
	 * {@code -scriptPath} compiles that script without BinaryRat.jar.
	 *
	 * @return a status message when there is nothing to show, or null when the table opened
	 */
	public static String openReport(PluginTool tool, Program program, Path report, TaskMonitor monitor)
			throws IOException, CancelledException {
		Path folder = report.toAbsolutePath().getParent();
		if (folder != null) {
			Preferences.setProperty(DIRECTORY_PREFERENCE, folder.toString());
			Preferences.store();
		}
		if (!supported(tool)) {
			return "The layout report is at " + report + ". Open it with Browse Layout Evidence.";
		}
		Review review = LayoutEvidenceBrowser.read(program, report, monitor);
		if (review.rows().isEmpty()) {
			return "BinaryRat found no exact field accesses. The report is at " + report;
		}
		show(tool, program, review, monitor);
		return null;
	}

	/** Whether a tool has the services the table needs to show rows and navigate. */
	public static boolean supported(PluginTool tool) {
		return tool != null && tool.getService(TableService.class) != null &&
			tool.getService(ProgramManager.class) != null && tool.getService(GoToService.class) != null;
	}

	/**
	 * Shows the review's rows for the active Program. The table closes itself when the Program
	 * changes, because its rows were checked against one revision.
	 *
	 * @throws IOException if the active Program changed before the table could be shown
	 */
	public static void show(PluginTool tool, Program program, Review review, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (!supported(tool)) {
			throw new IOException("Open the layout evidence from a CodeBrowser with table and navigation services.");
		}
		var tables = tool.getService(TableService.class);
		var programs = tool.getService(ProgramManager.class);
		long revision = review.revision();
		String title = TITLE + " — " + review.functionName() + " (parameter " + review.parameterIndex() + ")";
		AtomicReference<TableChooserDialog> created = new AtomicReference<>();
		DomainObjectListener changed = event -> {
			if (program.getModificationNumber() != revision) {
				Swing.runIfSwingOrRunLater(() -> {
					TableChooserDialog table = created.get();
					if (table != null && table.isVisible()) {
						table.close();
						tool.setStatusInfo("Layout evidence closed after a program change.");
					}
				});
			}
		};
		boolean shown = false;
		try {
			TableChooserDialog table = Swing.runNow(() -> {
				TableChooserDialog dialog = tables.createTableChooserDialog(null, program, title, null, false);
				created.set(dialog);
				addColumn(dialog, "Offset", Offset.class, row -> new Offset(row.offset()));
				addColumn(dialog, "Width", Integer.class, Row::width);
				addColumn(dialog, "Access", String.class, Row::operation);
				addColumn(dialog, "Instruction", String.class, Row::instruction);
				addColumn(dialog, "Function", String.class, Row::functionName);
				addColumn(dialog, "P-code order", Long.class, Row::pcodeOrder);
				addColumn(dialog, "Overlaps", Boolean.class, Row::overlaps);
				addColumn(dialog, "Instruction bytes", String.class,
					row -> row.instructionBytesVerified() ? "Verified" : "Unrecorded");
				return dialog;
			});
			if (table == null) {
				throw new CancelledException();
			}

			// TableChooserDialog accepts rows from a worker thread and filters/sorts asynchronously.
			Set<Integer> offsets = new HashSet<>();
			for (Row row : review.rows()) {
				monitor.checkCancelled();
				offsets.add(row.offset());
				table.add(new EvidenceRow(row));
			}
			String summary = review.rows().size() + (review.rows().size() == 1 ? " access" : " accesses") +
				" at " + offsets.size() + (offsets.size() == 1 ? " offset" : " offsets") +
				". Double-click a row to open its instruction in the Listing.";

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
				throw new IOException("The active program changed. Reopen the report to check its evidence.");
			}
			shown = true;
		}
		finally {
			if (!shown) {
				// Run after any late creation or publication callback, even if this worker
				// has already been interrupted. The EDT owns both listener and dialog cleanup.
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

	/**
	 * Opens wide enough to read the disassembly next to its offset and access. Ghidra's column
	 * state keeps any explicit preferred width but gives unset columns a large default, so every
	 * column gets one.
	 */
	private static void readable(TableChooserDialog table) {
		table.setDefaultSize(1000, 420);
		var columns = table.getTable().getColumnModel();
		for (int index = 0; index < columns.getColumnCount(); index++) {
			var column = columns.getColumn(index);
			column.setPreferredWidth(COLUMN_WIDTHS.getOrDefault(String.valueOf(column.getHeaderValue()), 100));
		}
	}

	private record EvidenceRow(Row source) implements AddressableRowObject {
		@Override
		public Address getAddress() {
			return source.address();
		}
	}

	private static <T extends Comparable<T>> void addColumn(TableChooserDialog table, String name,
			Class<T> type, Function<Row, T> value) {
		table.addCustomColumn(new AbstractComparableColumnDisplay<T>() {
			@Override
			public String getColumnName() {
				return name;
			}

			@Override
			public Class<T> getColumnClass() {
				return type;
			}

			@Override
			public T getColumnValue(AddressableRowObject object) {
				return value.apply(((EvidenceRow) object).source());
			}
		});
	}
}
