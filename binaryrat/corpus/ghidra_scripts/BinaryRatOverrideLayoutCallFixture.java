// Redirect a direct call in a disposable layout recovery fixture.
// @category BinaryRat.Tests
// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0

import ghidra.app.plugin.core.analysis.AnalysisWorker;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class BinaryRatOverrideLayoutCallFixture extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String[] names = getScriptArgs();
		if (!isRunningHeadless() || currentProgram == null || names.length != 3) {
			throw new IllegalArgumentException("Use on a disposable headless fixture: " +
				"BinaryRatOverrideLayoutCallFixture.java CALLER ORIGINAL_TARGET ALTERNATE_TARGET");
		}
		end(true);
		var analysis = AutoAnalysisManager.getAnalysisManager(currentProgram);
		if (analysis.isAnalyzing()) {
			throw new IllegalStateException("auto-analysis must finish before the fixture override");
		}
		boolean changed = analysis.scheduleWorker(new AnalysisWorker() {
			@Override
			public String getWorkerName() {
				return "Set BinaryRat layout fixture call override";
			}

			@Override
			public boolean analysisWorkerCallback(Program program, Object context, TaskMonitor task)
					throws Exception {
				Function caller = findFunction(program, names[0], task);
				Address original = findFunction(program, names[1], task).getEntryPoint();
				Address alternate = findFunction(program, names[2], task).getEntryPoint();
				if (original.equals(alternate)) {
					throw new IllegalArgumentException("fixture call targets must differ");
				}
				Instruction call = findCall(program, caller, original, task);
				if (!pcodeCalls(call, original)) {
					throw new IllegalStateException("fixture call was already redirected");
				}
				int transaction = program.startTransaction(getWorkerName());
				boolean commit = false;
				try {
					var references = program.getReferenceManager();
					var override = references.addMemoryReference(call.getAddress(), alternate,
						RefType.CALL_OVERRIDE_UNCONDITIONAL, SourceType.USER_DEFINED, 0);
					references.setPrimary(override, true);
					if (!decodedCallTo(call, original) || !pcodeCalls(call, alternate)) {
						throw new IllegalStateException("override did not change only the p-code target");
					}
					task.checkCancelled();
					commit = true;
					return true;
				}
				finally {
					program.endTransaction(transaction, commit);
				}
			}
		}, null, false, monitor);
		if (!changed) {
			throw new IllegalStateException("fixture call override was not committed");
		}
		println("BINARYRAT_LAYOUT_CALL_OVERRIDE_SET");
	}

	private static Function findFunction(Program program, String name, TaskMonitor task)
			throws CancelledException {
		Function match = null;
		var symbols = program.getSymbolTable().getSymbols(name);
		while (symbols.hasNext()) {
			task.checkCancelled();
			var candidate = program.getFunctionManager().getFunctionAt(symbols.next().getAddress());
			if (candidate == null) {
				continue;
			}
			if (match != null && !match.getEntryPoint().equals(candidate.getEntryPoint())) {
				throw new IllegalStateException("ambiguous fixture function " + name);
			}
			match = candidate;
		}
		if (match == null) {
			throw new IllegalStateException("missing fixture function " + name);
		}
		return match;
	}

	private static Instruction findCall(Program program, Function caller, Address target,
			TaskMonitor task) throws CancelledException {
		Instruction match = null;
		for (Instruction instruction : program.getListing().getInstructions(caller.getBody(), true)) {
			task.checkCancelled();
			if (decodedCallTo(instruction, target)) {
				if (match != null) {
					throw new IllegalStateException("multiple decoded calls to the fixture target");
				}
				match = instruction;
			}
		}
		if (match == null) {
			throw new IllegalStateException("decoded direct call to fixture target is missing");
		}
		return match;
	}

	private static boolean decodedCallTo(Instruction instruction, Address target) {
		var flow = instruction.getFlowType();
		Address[] destinations = instruction.getDefaultFlows();
		return instruction.getFlowOverride() == FlowOverride.NONE && flow.isCall() &&
			!flow.isComputed() && destinations != null && destinations.length == 1 &&
			target.equals(destinations[0]);
	}

	private static boolean pcodeCalls(Instruction instruction, Address target) {
		for (PcodeOp operation : instruction.getPcode(true)) {
			if (operation.getOpcode() == PcodeOp.CALL &&
				target.equals(operation.getInput(0).getAddress())) {
				return true;
			}
		}
		return false;
	}
}
