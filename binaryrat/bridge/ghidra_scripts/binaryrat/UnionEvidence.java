// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package binaryrat;

import java.util.ArrayDeque;
import java.util.Collections;
import java.util.Comparator;
import java.util.IdentityHashMap;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Identifies a typed consumer of a rooted, exact-width load. */
public final class UnionEvidence {
	private static final int MAXIMUM_VALUES = 16;
	private static final int MAXIMUM_USES = 64;
	private static final Comparator<Use> ORDER =
		Comparator.comparing(Use::address).thenComparingLong(Use::pcodeOrder);

	public record Use(String kind, Address address, long pcodeOrder, String operation) {
	}

	private UnionEvidence() {
	}

	public static Use classify(PcodeOp load, Function function, TaskMonitor monitor)
			throws CancelledException {
		Varnode loaded = load.getOutput();
		if (loaded == null || !supportedIntegerWidth(loaded.getSize())) {
			return null;
		}
		var pending = new ArrayDeque<Varnode>();
		Set<Varnode> seen = Collections.newSetFromMap(new IdentityHashMap<>());
		pending.add(loaded);
		seen.add(loaded);
		Use first = null;
		int uses = 0;
		while (!pending.isEmpty()) {
			var value = pending.removeFirst();
			var consumers = value.getDescendants();
			while (consumers.hasNext()) {
				monitor.checkCancelled();
				if (++uses > MAXIMUM_USES) {
					return null;
				}
				var operation = consumers.next();
				var site = operation.getSeqnum().getTarget();
				if (operation.getParent() == null || !function.getBody().contains(site)) {
					continue;
				}
				int opcode = operation.getOpcode();
				Varnode result = operation.getOutput();
				if (opcode == PcodeOp.COPY || opcode == PcodeOp.CAST) {
					if (result != null && result.getSize() == loaded.getSize() && seen.add(result)) {
						if (seen.size() > MAXIMUM_VALUES) {
							return null;
						}
						pending.addLast(result);
					}
					continue;
				}
				String kind = operationKind(opcode, loaded.getSize());
				if (kind == null) {
					continue;
				}
				if (first != null && !first.kind().equals(kind)) {
					// A single load used both ways cannot supply independent views.
					return null;
				}
				var use = new Use(kind, site, Integer.toUnsignedLong(operation.getSeqnum().getTime()),
					operation.getMnemonic());
				if (first == null || ORDER.compare(use, first) < 0) {
					first = use;
				}
			}
		}
		return first;
	}

	private static boolean supportedIntegerWidth(int width) {
		return width == 1 || width == 2 || width == 4 || width == 8;
	}

	/** Check a recorded consumer against the same high-p-code operations used during capture. */
	public static boolean matches(String kind, int width, String mnemonic) {
		try {
			return supportedIntegerWidth(width) && kind.equals(operationKind(PcodeOp.getOpcode(mnemonic), width));
		}
		catch (UnknownInstructionException unsupported) {
			return false;
		}
	}

	private static String operationKind(int opcode, int width) {
		return switch (opcode) {
			case PcodeOp.INT_AND, PcodeOp.INT_OR, PcodeOp.INT_XOR, PcodeOp.INT_LEFT,
					PcodeOp.INT_RIGHT, PcodeOp.INT_SRIGHT, PcodeOp.INT_MULT, PcodeOp.INT_DIV,
					PcodeOp.INT_SDIV, PcodeOp.INT_REM, PcodeOp.INT_SREM -> "integer";
			case PcodeOp.FLOAT_EQUAL, PcodeOp.FLOAT_NOTEQUAL, PcodeOp.FLOAT_LESS,
					PcodeOp.FLOAT_LESSEQUAL, PcodeOp.FLOAT_NAN, PcodeOp.FLOAT_ADD,
					PcodeOp.FLOAT_DIV, PcodeOp.FLOAT_MULT, PcodeOp.FLOAT_SUB, PcodeOp.FLOAT_NEG,
					PcodeOp.FLOAT_ABS, PcodeOp.FLOAT_SQRT, PcodeOp.FLOAT_FLOAT2FLOAT,
					PcodeOp.FLOAT_TRUNC -> width == 4 || width == 8 ? "floating_point" : null;
			default -> null;
		};
	}
}
