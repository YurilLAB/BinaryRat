// List every call to the function at the cursor with its decompiled statement and constant arguments.
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

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import binaryrat.CallSites;
import binaryrat.EntryAddress;
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
 * Call sites of one function ({@link CallSites}). In CodeBrowser it uses the function at the
 * cursor and opens a table; headless it publishes the JSON report with a hard link, never
 * replacing a file.
 */
public class BinaryRatCallSites extends GhidraScript {
	private static final int MAXIMUM_SYMBOL_MATCHES = 4_096;
	private static final String TABLE = "binaryrat.desktop.CallSitesTable";
	private long revision;

	@Override
	protected void run() throws Exception {
		if (currentProgram == null) {
			throw new IllegalStateException("Open an analyzed Program before listing call sites");
		}
		// GhidraScript opens an implicit transaction; a read-only listing must not hold one
		// open, or undo and other tools wait for as long as the decompiles take.
		end(true);
		revision = currentProgram.getModificationNumber();
		if (AutoAnalysisManager.getAnalysisManager(currentProgram).isAnalyzing()) {
			throw new IllegalStateException("auto-analysis must finish before listing call sites");
		}
		if (isRunningHeadless()) {
			headless();
			return;
		}
		Function function = currentAddress == null ? null :
			currentProgram.getFunctionManager().getFunctionContaining(currentAddress);
		if (function == null) {
			popup("Place the cursor in a function to list the calls to it.");
			return;
		}
		JsonObject report = CallSites.recover(currentProgram, function, 30, CallSites.DEFAULT_SITES,
			CallSites.DEFAULT_CALLERS, monitor);
		checkCurrent();
		printSummary(report);
		String status = showTable(state.getTool(), currentProgram, report);
		if (status != null) {
			println(status);
		}
	}

	private void headless() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 2 || args.length > 5) {
			throw new IllegalArgumentException("Use as a headless postScript: BinaryRatCallSites.java " +
				"OUTPUT_JSON ENTRY_HEX|SPACE:HEX|name:FUNCTION [TIMEOUT_SECONDS [MAX_SITES [MAX_CALLERS]]]");
		}
		int timeout = args.length >= 3 ? Integer.parseInt(args[2]) : 30;
		int sites = args.length >= 4 ? Integer.parseInt(args[3]) : CallSites.DEFAULT_SITES;
		int callers = args.length == 5 ? Integer.parseInt(args[4]) : CallSites.DEFAULT_CALLERS;
		Function function = selectFunction(args[1]);
		Path output = Path.of(args[0]).toAbsolutePath().normalize();
		if (Files.exists(output, LinkOption.NOFOLLOW_LINKS)) {
			throw new IOException("call-site report destination already exists: " + output);
		}
		checkCurrent();
		JsonObject report = CallSites.recover(currentProgram, function, timeout, sites, callers, monitor);
		checkCurrent();
		Path workspace = Files.createTempDirectory(output.getParent(), ".binaryrat-callsites-");
		try {
			Path staged = workspace.resolve("report.json");
			String content = CallSites.encodeReport(report);
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
			println("BinaryRat call sites written: " + output);
		}
		finally {
			try (Stream<Path> files = Files.walk(workspace)) {
				for (Path file : (Iterable<Path>) files.sorted(Comparator.reverseOrder())::iterator) {
					Files.deleteIfExists(file);
				}
			}
			catch (IOException cleanup) {
				printerr("Unable to clean up temporary call-site workspace: " + cleanup.getMessage());
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
			return "Could not open the call-site table: " + failure.getCause();
		}
		catch (ReflectiveOperationException | LinkageError missing) {
			return "Install the BinaryRat extension to see call sites in a table.";
		}
	}

	private void printSummary(JsonObject report) {
		JsonObject root = report.getAsJsonObject("root_function");
		println("Calls to " + root.get("name").getAsString() + ": " + report.get("call_references") +
			" call sites, " + report.get("decompiled_callers") + " callers decompiled" +
			(report.get("truncated").getAsBoolean() ? " (truncated)" : ""));
		for (JsonElement element : report.getAsJsonArray("sites")) {
			JsonObject site = element.getAsJsonObject();
			String text = site.get("statement").isJsonNull() ? "[" + site.get("status").getAsString() + "] " +
				string(site, "reason") : site.get("statement").getAsString();
			println("  " + site.get("address").getAsString() + "  " + text);
		}
	}

	private static String string(JsonObject object, String key) {
		JsonElement value = object.get(key);
		return value == null || value.isJsonNull() ? "" : value.getAsString();
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
				if (symbol.getSymbolType() != SymbolType.FUNCTION &&
						symbol.getSymbolType() != SymbolType.LABEL) {
					continue;
				}
				Function candidate = currentProgram.getFunctionManager().getFunctionAt(symbol.getAddress());
				if (candidate == null) {
					continue;
				}
				// A thunk and the function it reaches have the same call sites.
				if (match != null && !root(match).getEntryPoint().equals(root(candidate).getEntryPoint())) {
					throw new IOException("ambiguous function name; select a function entry (SPACE:HEX in an overlay)");
				}
				match = match == null || match.isThunk() ? candidate : match;
			}
			if (match != null) {
				return match;
			}
		}
		else {
			if (!EntryAddress.matches(selector)) {
				throw new IllegalArgumentException("function entry must be HEX, SPACE:HEX or name:FUNCTION");
			}
			Function match = currentProgram.getFunctionManager().getFunctionAt(
				EntryAddress.parse(currentProgram, selector));
			if (match != null) {
				return match;
			}
		}
		throw new IOException("no function matches " + selector);
	}

	private static Function root(Function function) {
		Function thunked = function.isThunk() ? function.getThunkedFunction(true) : null;
		return thunked == null ? function : thunked;
	}

	private void checkCurrent() throws Exception {
		monitor.checkCancelled();
		if (currentProgram.isClosed() || revision != currentProgram.getModificationNumber()) {
			throw new IllegalStateException("Program changed while listing call sites");
		}
	}
}
