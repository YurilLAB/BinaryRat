// Survey read-only layout evidence for every function's register parameters.
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

import binaryrat.LayoutSurvey;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;

/**
 * Headless entrypoint for the program-wide layout survey ({@link LayoutSurvey}). The report is
 * staged beside the destination and published with a hard link, never replacing a file.
 */
public class BinaryRatSurveyLayouts extends GhidraScript {
	private long revision;

	@Override
	protected void run() throws Exception {
		if (currentProgram == null) {
			throw new IllegalStateException("Open an analyzed Program before surveying layout evidence");
		}
		end(true);
		revision = currentProgram.getModificationNumber();
		if (!isRunningHeadless()) {
			throw new IllegalStateException("BinaryRatSurveyLayouts.java runs as a headless postScript");
		}
		if (AutoAnalysisManager.getAnalysisManager(currentProgram).isAnalyzing()) {
			throw new IllegalStateException("auto-analysis must finish before layout extraction");
		}
		String[] args = getScriptArgs();
		if (args.length < 1 || args.length > 4) {
			throw new IllegalArgumentException("Use as a headless postScript: BinaryRatSurveyLayouts.java " +
				"OUTPUT_JSON [TIMEOUT_SECONDS [DEADLINE_SECONDS [MAX_FUNCTIONS]]]");
		}
		int timeout = args.length >= 2 ? Integer.parseInt(args[1]) : 30;
		int deadline = args.length >= 3 ? Integer.parseInt(args[2]) : 1_800;
		int maximumFunctions = args.length == 4 ? Integer.parseInt(args[3]) : LayoutSurvey.MAXIMUM_FUNCTIONS;
		Path output = Path.of(args[0]).toAbsolutePath().normalize();
		if (Files.exists(output, LinkOption.NOFOLLOW_LINKS)) {
			throw new IOException("layout survey destination already exists: " + output);
		}
		checkCurrent();

		JsonObject report = LayoutSurvey.survey(currentProgram, timeout, deadline, maximumFunctions, monitor);
		checkCurrent();
		Path workspace = Files.createTempDirectory(output.getParent(), ".binaryrat-survey-");
		try {
			Path staged = workspace.resolve("report.json");
			String content = new GsonBuilder().serializeNulls().create().toJson(report);
			Files.writeString(staged, content + "\n", StandardCharsets.UTF_8);
			checkCurrent();
			// A hard link publishes the complete report and refuses an existing destination.
			try {
				Files.createLink(output, staged);
			}
			catch (UnsupportedOperationException failure) {
				throw new IOException("survey publication requires hard-link support in the output directory",
					failure);
			}
			println("BinaryRat layout survey written: " + output);
		}
		finally {
			try (Stream<Path> files = Files.walk(workspace)) {
				for (Path file : (Iterable<Path>) files.sorted(Comparator.reverseOrder())::iterator) {
					Files.deleteIfExists(file);
				}
			}
			catch (IOException cleanup) {
				printerr("Unable to clean up temporary survey workspace: " + cleanup.getMessage());
			}
		}
	}

	private void checkCurrent() throws Exception {
		monitor.checkCancelled();
		if (currentProgram.isClosed() || revision != currentProgram.getModificationNumber()) {
			throw new IllegalStateException("Program changed during the layout survey");
		}
	}
}
