// Preview or explicitly accept creation of a new structure from imported BinaryRat evidence.
// @category BinaryRat
// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0

import java.nio.file.Path;

import com.google.gson.GsonBuilder;

import binaryrat.writeback.ProtectedLayoutWriteBack;
import ghidra.app.script.GhidraScript;

public class BinaryRatReviewLayout extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		boolean preview = args.length == 3 && "preview".equals(args[0]);
		boolean accept = args.length == 4 && "accept".equals(args[0]);
		if (!isRunningHeadless() || currentProgram == null || (!preview && !accept)) {
			throw new IllegalArgumentException("Use as a headless postScript: " +
				"BinaryRatReviewLayout.java preview REPORT STRUCTURE_NAME or " +
				"BinaryRatReviewLayout.java accept REPORT STRUCTURE_NAME APPROVAL_CODE");
		}
		// Release the empty script transaction before the coordinated worker. Otherwise
		// rollback and undo can join the script's transaction rather than our own.
		end(true);
		var prepared = ProtectedLayoutWriteBack.prepare(currentProgram, Path.of(args[1]),
			args[2], monitor);
		if (preview) {
			println("Imported layout evidence for analyst review");
			println(new GsonBuilder().setPrettyPrinting().create().toJson(prepared.review()));
			return;
		}
		var result = ProtectedLayoutWriteBack.accept(currentProgram, prepared, args[3], monitor);
		println("BINARYRAT_REVIEWED_LAYOUT_CREATED " + result.dataTypePath());
		if (result.committedAfterCancellation()) {
			println("The approved change committed before cancellation was reported");
		}
	}
}
