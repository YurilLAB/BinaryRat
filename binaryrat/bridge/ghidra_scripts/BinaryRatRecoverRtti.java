// Collect read-only C++ ABI class, inheritance, and vtable evidence.
//@category BinaryRat

// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.Locale;

import com.google.gson.GsonBuilder;

import binaryrat.RttiEvidence;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;

public class BinaryRatRecoverRtti extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (!isRunningHeadless() || currentProgram == null || args.length != 1) {
			throw new IllegalArgumentException("Use as a headless postScript: BinaryRatRecoverRtti.java OUTPUT_JSON");
		}
		end(true);
		if (AutoAnalysisManager.getAnalysisManager(currentProgram).isAnalyzing()) {
			throw new IllegalStateException("auto-analysis must finish before RTTI extraction");
		}
		Path output = Path.of(args[0]).toAbsolutePath().normalize();
		if (Files.exists(output, LinkOption.NOFOLLOW_LINKS)) {
			throw new IOException("RTTI evidence destination already exists: " + output);
		}
		long revision = currentProgram.getModificationNumber();
		String digest = currentProgram.getExecutableSHA256();
		if (digest == null || !digest.matches("[0-9a-fA-F]{64}")) {
			throw new IOException("RTTI evidence requires a valid executable SHA-256");
		}
		var report = RttiEvidence.collect(currentProgram, monitor, revision,
			"sha256:" + digest.toLowerCase(Locale.ROOT));
		Path staged = Files.createTempFile(output.getParent(), ".binaryrat-rtti-", ".json");
		try {
			try (var writer = Files.newBufferedWriter(staged, StandardCharsets.UTF_8)) {
				new GsonBuilder().serializeNulls().setPrettyPrinting().create().toJson(report, writer);
				writer.write('\n');
			}
			monitor.checkCancelled();
			if (currentProgram.getModificationNumber() != revision) {
				throw new IOException("Program changed before publication of RTTI evidence");
			}
			Files.createLink(output, staged);
			println("BINARYRAT_RTTI_REPORT_PUBLISHED");
		}
		finally {
			Files.deleteIfExists(staged);
		}
	}
}
