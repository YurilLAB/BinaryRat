// List strings that functions build on the stack with constant stores.
// @category BinaryRat
// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.stream.Stream;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import binaryrat.EntryAddress;
import binaryrat.StackStrings;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Stack strings ({@link StackStrings}). In CodeBrowser it scans every function and opens a
 * table; headless it publishes the JSON report with a hard link, never replacing a file.
 */
public class BinaryRatStackStrings extends GhidraScript {
	private static final int MAXIMUM_SYMBOL_MATCHES = 4_096;
	private static final String TABLE = "binaryrat.desktop.StackStringsTable";
	private long revision;

	@Override
	protected void run() throws Exception {
		if (currentProgram == null) {
			throw new IllegalStateException("Open an analyzed Program before listing stack strings");
		}
		// GhidraScript opens an implicit transaction; a read-only scan must not hold one open,
		// or undo and other tools wait for as long as the scan takes.
		end(true);
		revision = currentProgram.getModificationNumber();
		if (AutoAnalysisManager.getAnalysisManager(currentProgram).isAnalyzing()) {
			throw new IllegalStateException("auto-analysis must finish before listing stack strings");
		}
		if (isRunningHeadless()) {
			headless();
			return;
		}
		JsonObject report = StackStrings.recover(currentProgram, null, StackStrings.DEFAULT_MINIMUM_LENGTH,
			StackStrings.DEFAULT_FUNCTIONS, monitor);
		checkCurrent();
		printSummary(report);
		String status = showTable(state.getTool(), currentProgram, report);
		if (status != null) {
			println(status);
		}
	}

	private void headless() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 1 || args.length > 4) {
			throw new IllegalArgumentException("Use as a headless postScript: BinaryRatStackStrings.java " +
				"OUTPUT_JSON [all|ENTRY_HEX|SPACE:HEX|name:FUNCTION [MINIMUM_LENGTH [MAX_FUNCTIONS]]]");
		}
		Function function = args.length >= 2 && !args[1].equals("all") ? selectFunction(args[1]) : null;
		int minimum = args.length >= 3 ? Integer.parseInt(args[2]) : StackStrings.DEFAULT_MINIMUM_LENGTH;
		int functions = args.length == 4 ? Integer.parseInt(args[3]) : StackStrings.DEFAULT_FUNCTIONS;
		Path output = Path.of(args[0]).toAbsolutePath().normalize();
		if (Files.exists(output, LinkOption.NOFOLLOW_LINKS)) {
			throw new IOException("stack-string report destination already exists: " + output);
		}
		checkCurrent();
		JsonObject report = StackStrings.recover(currentProgram, function, minimum, functions, monitor);
		checkCurrent();
		Path workspace = Files.createTempDirectory(output.getParent(), ".binaryrat-stackstrings-");
		try {
			Path staged = workspace.resolve("report.json");
			String content = new GsonBuilder().serializeNulls().setPrettyPrinting().create().toJson(report);
			Files.writeString(staged, content + "\n", StandardCharsets.UTF_8);
			checkCurrent();
			// A hard link publishes the complete report and refuses an existing destination.
			try {
				Files.createLink(output, staged);
			}
			catch (UnsupportedOperationException failure) {
				throw new IOException("report publication requires hard-link support in the output directory",
					failure);
			}
			printSummary(report);
			println("BinaryRat stack strings written: " + output);
		}
		finally {
			try (Stream<Path> files = Files.walk(workspace)) {
				for (Path file : (Iterable<Path>) files.sorted(Comparator.reverseOrder())::iterator) {
					Files.deleteIfExists(file);
				}
			}
			catch (IOException cleanup) {
				printerr("Unable to clean up temporary stack-string workspace: " + cleanup.getMessage());
			}
		}
	}

	/**
	 * Opens the extension's table by name: a checkout {@code -scriptPath} compiles this script
	 * without BinaryRat.jar, and then the console summary is the whole result.
	 */
	private String showTable(PluginTool tool, Program program, JsonObject report) throws Exception {
		try {
			Class<?> table = Class.forName(TABLE, true, ClassLoader.getSystemClassLoader());
			Object status = table.getMethod("show", PluginTool.class, Program.class, JsonObject.class,
				TaskMonitor.class).invoke(null, tool, program, report, monitor);
			return status == null ? null : status.toString();
		}
		catch (InvocationTargetException failure) {
			if (failure.getCause() instanceof CancelledException cancelled) {
				throw cancelled;
			}
			return "Could not open the stack-string table: " + failure.getCause();
		}
		catch (ReflectiveOperationException | LinkageError missing) {
			return "Install the BinaryRat extension to see stack strings in a table.";
		}
	}

	private void printSummary(JsonObject report) {
		println("Stack strings: " + report.getAsJsonArray("strings").size() + " in " +
			report.get("functions_scanned") + " functions" +
			(report.get("truncated").getAsBoolean() ? " (truncated)" : ""));
		for (JsonElement element : report.getAsJsonArray("strings")) {
			JsonObject found = element.getAsJsonObject();
			println("  " + found.get("address").getAsString() + "  " +
				found.getAsJsonObject("function").get("name").getAsString() + "  " +
				new GsonBuilder().disableHtmlEscaping().create().toJson(found.get("text")) +
				(found.get("encoding").getAsString().equals("utf16le") ? " (UTF-16)" : ""));
		}
	}

	private Function selectFunction(String selector) throws Exception {
		if (selector.startsWith("name:")) {
			String name = selector.substring("name:".length());
			if (name.isBlank() || name.length() > 1024) {
				throw new IllegalArgumentException("invalid function name selector");
			}
			Function match = null;
			int visited = 0;
			SymbolIterator symbols = currentProgram.getSymbolTable().getSymbols(name);
			while (symbols.hasNext()) {
				checkCurrent();
				if (++visited > MAXIMUM_SYMBOL_MATCHES) {
					throw new IOException("too many symbols with that name; select a function entry");
				}
				Symbol symbol = symbols.next();
				if (symbol.getSymbolType() != SymbolType.FUNCTION && symbol.getSymbolType() != SymbolType.LABEL) {
					continue;
				}
				Function candidate = currentProgram.getFunctionManager().getFunctionAt(symbol.getAddress());
				if (candidate != null && !candidate.isExternal()) {
					if (match != null && !match.getEntryPoint().equals(candidate.getEntryPoint())) {
						throw new IOException("ambiguous function name; select a function entry (SPACE:HEX in an overlay)");
					}
					match = candidate;
				}
			}
			if (match != null) {
				return match;
			}
		}
		else {
			if (!EntryAddress.matches(selector)) {
				throw new IllegalArgumentException("function entry must be HEX, SPACE:HEX, name:FUNCTION or all");
			}
			Function match = currentProgram.getFunctionManager().getFunctionAt(
				EntryAddress.parse(currentProgram, selector));
			if (match != null) {
				return match;
			}
		}
		throw new IOException("no function matches " + selector);
	}

	private void checkCurrent() throws Exception {
		monitor.checkCancelled();
		if (currentProgram.isClosed() || revision != currentProgram.getModificationNumber()) {
			throw new IllegalStateException("Program changed while listing stack strings");
		}
	}
}
