// Check production RTTI collection against cancellation and stale revisions.
//@category BinaryRat.Tests

// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
import java.io.IOException;

import binaryrat.RttiEvidence;
import ghidra.app.script.GhidraScript;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitorAdapter;

public class BinaryRatRttiInvariants extends GhidraScript {
	@Override
	protected void run() throws Exception {
		end(true);
		long revision = currentProgram.getModificationNumber();
		String programId = "sha256:" + currentProgram.getExecutableSHA256();
		var cancelled = new TaskMonitorAdapter(true);
		cancelled.cancel();
		try {
			RttiEvidence.collect(currentProgram, cancelled, revision, programId);
			throw new IllegalStateException("RTTI recovery accepted a cancelled monitor");
		}
		catch (CancelledException expected) {
			// A cancelled request must not return a report.
		}
		try {
			RttiEvidence.collect(currentProgram, monitor, revision - 1, programId);
			throw new IllegalStateException("RTTI recovery accepted a stale revision");
		}
		catch (IOException error) {
			if (!error.getMessage().equals("Program changed while collecting RTTI evidence")) {
				throw error;
			}
		}
		if (currentProgram.getModificationNumber() != revision) {
			throw new IllegalStateException("RTTI evidence changed the Program revision");
		}
		println("BINARYRAT_RTTI_INVARIANTS_VERIFIED");
	}
}
