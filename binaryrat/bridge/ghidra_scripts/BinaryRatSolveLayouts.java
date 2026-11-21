// Propagate read-only layout evidence over direct calls with the engine's summary solver.
// @category BinaryRat
// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.stream.Stream;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;

import binaryrat.EntryAddress;
import binaryrat.SummaryLayouts;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolType;

/**
 * Headless entrypoint for summary-based layout evidence ({@link SummaryLayouts}). The report
 * is staged beside the destination and published with a hard link, never replacing a file.
 */
public class BinaryRatSolveLayouts extends GhidraScript {
	private static final int MAXIMUM_SYMBOL_MATCHES = 4_096;
	private long revision;

	@Override
	protected void run() throws Exception {
		if (currentProgram == null) {
			throw new IllegalStateException("Open an analyzed Program before solving layout evidence");
		}
		end(true);
		revision = currentProgram.getModificationNumber();
		if (!isRunningHeadless()) {
			throw new IllegalStateException("BinaryRatSolveLayouts.java runs as a headless postScript");
		}
		if (AutoAnalysisManager.getAnalysisManager(currentProgram).isAnalyzing()) {
			throw new IllegalStateException("auto-analysis must finish before layout extraction");
		}
		String[] args = getScriptArgs();
		if (args.length < 3 || args.length > 5) {
			throw new IllegalArgumentException("Use as a headless postScript: BinaryRatSolveLayouts.java " +
				"OUTPUT_JSON ENTRY_HEX|SPACE:HEX|name:FUNCTION PARAM_INDEX [TIMEOUT_SECONDS [MAX_SUMMARIES]]");
		}
		int parameter = Integer.parseInt(args[2]);
		int timeout = args.length >= 4 ? Integer.parseInt(args[3]) : 30;
		int maximumSummaries = args.length == 5 ? Integer.parseInt(args[4]) : SummaryLayouts.DEFAULT_SUMMARIES;
		if (maximumSummaries < 1 || maximumSummaries > SummaryLayouts.MAXIMUM_SUMMARIES) {
			throw new IllegalArgumentException("summary limit must be between 1 and " +
				SummaryLayouts.MAXIMUM_SUMMARIES);
		}
		Function function = selectFunction(args[1]);
		Path output = Path.of(args[0]).toAbsolutePath().normalize();
		if (Files.exists(output, LinkOption.NOFOLLOW_LINKS)) {
			throw new IOException("layout evidence destination already exists: " + output);
		}
		checkCurrent();

		JsonObject report = SummaryLayouts.recover(currentProgram, function, parameter, timeout,
			maximumSummaries, monitor);
		checkCurrent();
		Path workspace = Files.createTempDirectory(output.getParent(), ".binaryrat-summary-");
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
				throw new IOException("layout publication requires hard-link support in the output directory",
					failure);
			}
			println("BinaryRat summary layout evidence written: " + output);
		}
		finally {
			try (Stream<Path> files = Files.walk(workspace)) {
				for (Path file : (Iterable<Path>) files.sorted(Comparator.reverseOrder())::iterator) {
					Files.deleteIfExists(file);
				}
			}
			catch (IOException cleanup) {
				printerr("Unable to clean up temporary layout workspace: " + cleanup.getMessage());
			}
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
				if (symbol.getSymbolType() != SymbolType.FUNCTION &&
						symbol.getSymbolType() != SymbolType.LABEL) {
					continue;
				}
				Function candidate = currentProgram.getFunctionManager().getFunctionAt(symbol.getAddress());
				if (candidate != null) {
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

	private void checkCurrent() throws Exception {
		monitor.checkCancelled();
		if (currentProgram.isClosed() || revision != currentProgram.getModificationNumber()) {
			throw new IllegalStateException("Program changed during layout evidence extraction");
		}
	}
}
