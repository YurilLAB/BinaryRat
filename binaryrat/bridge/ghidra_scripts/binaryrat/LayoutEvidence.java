// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package binaryrat;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighParam;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Collects memory access evidence relative to one analyst-selected entry parameter. */
public final class LayoutEvidence {
	public static final long MAXIMUM_EXTENT = 1L << 20;
	public static final int MAXIMUM_ACCESSES = 4_096;
	private static final int MAXIMUM_OPS = 32_768;
	private static final int MAXIMUM_FORWARDING_CALLS = 32;
	private static final int MAXIMUM_DEFINITION_DEPTH = 32;

	public record Access(Address address, long pcodeOrder, String operation, long offset,
			long maximumOffset, long width, long stride) {
	}

	public record ForwardedCall(Address address, long pcodeOrder, Address callee,
			Address argumentStorage) {
	}

	public record Capture(List<Access> accesses, List<ForwardedCall> calls, int unresolvedAccesses,
			int pcodeOps) {
	}

	// Zero stride means the offset is constant. A nonzero stride describes a bounded
	// affine expression and records spacing, without asserting an array or its length.
	private record Relative(long minimum, long maximum, long stride) {
		Relative shift(long offset) {
			return new Relative(Math.addExact(minimum, offset), Math.addExact(maximum, offset), stride);
		}
	}

	private record IndexBounds(long minimum, long maximum) {
	}

	private LayoutEvidence() {
	}

	public static Capture collect(Program program, HighFunction high, int parameterIndex,
			boolean includeCalls, TaskMonitor monitor) throws IOException, CancelledException {
		LocalSymbolMap symbols = high.getLocalSymbolMap();
		if (parameterIndex < 0 || parameterIndex >= symbols.getNumParams()) {
			throw new IOException("decompiler has no parameter at index " + parameterIndex);
		}
		Varnode root = entryInput(program, symbols, parameterIndex);
		if (root == null) {
			throw new IOException("selected parameter is not a pointer-sized entry input");
		}
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		if (!space.isMemorySpace() || space.getAddressableUnitSize() != 1) {
			throw new IOException("layout evidence requires a byte-addressed default memory space");
		}
		Function function = high.getFunction();
		List<Access> accesses = new ArrayList<>();
		List<ForwardedCall> calls = new ArrayList<>();
		boolean collectCalls = includeCalls && hasDefaultPrototype(program, high);
		int operations = 0;
		int unresolved = 0;
		// Use block membership. Ghidra 12.2's HighFunction decoder installs ops in
		// blocks without clearing the PcodeOpAST dead flag.
		for (PcodeBlockBasic block : high.getBasicBlocks()) {
			monitor.checkCancelled();
			if (block == null) {
				continue;
			}
			Iterator<PcodeOp> iterator = block.getIterator();
			while (iterator.hasNext()) {
				monitor.checkCancelled();
				if (++operations > MAXIMUM_OPS) {
					throw new IOException("function exceeds the p-code operation limit");
				}
				PcodeOp operation = iterator.next();
				int opcode = operation.getOpcode();
				if (collectCalls && opcode == PcodeOp.CALL) {
					ForwardedCall call = observeCall(operation, function, space, root);
					if (call != null) {
						if (calls.size() >= MAXIMUM_FORWARDING_CALLS) {
							throw new IOException("function exceeds the direct forwarding call limit");
						}
						calls.add(call);
					}
				}
				if (opcode != PcodeOp.LOAD && opcode != PcodeOp.STORE) {
					continue;
				}
				Access access = observe(operation, function, space, root);
				if (access == null) {
					unresolved++;
					continue;
				}
				if (accesses.size() >= MAXIMUM_ACCESSES) {
					throw new IOException("function exceeds the layout evidence limit");
				}
				accesses.add(access);
			}
		}
		accesses.sort(Comparator.comparing(Access::address).thenComparingLong(Access::pcodeOrder));
		calls.sort(Comparator.comparing(ForwardedCall::address)
			.thenComparingLong(ForwardedCall::pcodeOrder));
		return new Capture(List.copyOf(accesses), List.copyOf(calls), unresolved, operations);
	}

	/** Checks first-slot storage and prototype before transferring an object-start assumption. */
	public static boolean acceptsForwardedInput(Program program, HighFunction high,
			Address argumentStorage) {
		LocalSymbolMap symbols = high.getLocalSymbolMap();
		if (symbols.getNumParams() != 1 || !hasDefaultPrototype(program, high)) {
			return false;
		}
		Varnode input = entryInput(program, symbols, 0);
		return input != null && input.getAddress().equals(argumentStorage);
	}

	private static Varnode entryInput(Program program, LocalSymbolMap symbols, int parameterIndex) {
		var symbol = symbols.getParamSymbol(parameterIndex);
		if (symbol == null || !(symbol.getHighVariable() instanceof HighParam parameter) ||
				parameter.getSlot() != parameterIndex) {
			return null;
		}
		Varnode input = parameter.getRepresentative();
		int pointerSize = program.getDefaultPointerSize();
		return input != null && input.isInput() && input.getSize() == pointerSize &&
			pointerSize >= 1 && pointerSize <= Long.BYTES ? input : null;
	}

	private static boolean hasDefaultPrototype(Program program, HighFunction high) {
		Function function = high.getFunction();
		var expected = program.getCompilerSpec().getDefaultCallingConvention();
		var declared = function.getCallingConvention();
		var proto = high.getFunctionPrototype();
		return expected != null && proto != null && expected.getName().equals(proto.getModelName()) &&
			(declared == null || expected.getName().equals(declared.getName())) &&
			!proto.isVarArg() && !function.hasVarArgs() && !function.hasCustomVariableStorage() &&
			function.getAutoParameterCount() == 0 && function.getCallFixup() == null;
	}

	private static ForwardedCall observeCall(PcodeOp op, Function function, AddressSpace space,
			Varnode root) {
		if (op.getNumInputs() != 2) {
			return null;
		}
		Varnode target = op.getInput(0);
		Varnode argument = op.getInput(1);
		Address site = op.getSeqnum().getTarget();
		if (target == null || !target.isAddress() ||
				!target.getAddress().getAddressSpace().equals(space) || argument == null ||
				!argument.getAddress().isRegisterAddress() || !function.getBody().contains(site)) {
			return null;
		}
		try {
			Relative relative = offset(argument, root, 0);
			if (relative != null && relative.minimum() == 0 && relative.maximum() == 0) {
				return new ForwardedCall(site, Integer.toUnsignedLong(op.getSeqnum().getTime()),
					target.getAddress(), argument.getAddress());
			}
		}
		catch (ArithmeticException overflow) {
			// Overflow cannot establish object identity across the call.
		}
		return null;
	}

	private static Access observe(PcodeOp op, Function function, AddressSpace space, Varnode root) {
		boolean load = op.getOpcode() == PcodeOp.LOAD;
		int inputCount = load ? 2 : 3;
		if (op.getNumInputs() != inputCount || !constant(op.getInput(0)) ||
				op.getInput(0).getOffset() != Integer.toUnsignedLong(space.getSpaceID())) {
			return null;
		}
		Address address = op.getSeqnum().getTarget();
		Varnode value = load ? op.getOutput() : op.getInput(2);
		if (value == null || value.getSize() < 1 || !function.getBody().contains(address)) {
			return null;
		}
		try {
			Relative relative = offset(op.getInput(1), root, 0);
			if (relative == null || (relative.stride() != 0 &&
					(relative.minimum() < 0 || relative.maximum() > MAXIMUM_EXTENT - value.getSize()))) {
				return null;
			}
			return new Access(address, Integer.toUnsignedLong(op.getSeqnum().getTime()),
				op.getMnemonic(), relative.minimum(), relative.maximum(), value.getSize(),
				relative.stride());
		}
		catch (ArithmeticException overflow) {
			return null;
		}
	}

	private static Relative offset(Varnode expression, Varnode root, int depth) {
		if (expression == null || expression.getSize() != root.getSize() ||
				depth >= MAXIMUM_DEFINITION_DEPTH) {
			return null;
		}
		if (expression == root) {
			return new Relative(0, 0, 0);
		}
		PcodeOp definition = expression.getDef();
		if (definition == null || definition.getParent() == null) {
			return null;
		}
		Varnode[] inputs = definition.getInputs();
		int next = depth + 1;
		Relative relative = switch (definition.getOpcode()) {
			case PcodeOp.COPY, PcodeOp.CAST ->
				inputs.length == 1 ? offset(inputs[0], root, next) : null;
			case PcodeOp.INT_ADD, PcodeOp.INT_SUB, PcodeOp.PTRSUB ->
				addConstant(definition.getOpcode(), inputs, root, next);
			case PcodeOp.PTRADD -> addIndex(inputs, root, next);
			default -> null;
		};
		long maxSigned = signedMaximum(root.getSize());
		return relative != null && relative.minimum() >= -maxSigned - 1 &&
			relative.maximum() <= maxSigned ? relative : null;
	}

	private static Relative addConstant(int opcode, Varnode[] inputs, Varnode root, int depth) {
		if (inputs.length != 2) {
			return null;
		}
		int constantIndex = opcode == PcodeOp.INT_ADD && constant(inputs[0]) ? 0 : 1;
		Varnode immediate = inputs[constantIndex];
		if (!constant(immediate) || immediate.getSize() != root.getSize()) {
			return null;
		}
		Relative base = offset(inputs[1 - constantIndex], root, depth);
		if (base == null) {
			return null;
		}
		long delta = signedConstant(immediate);
		// PTRSUB is a subcomponent address calculation. The offset is added.
		return base.shift(opcode == PcodeOp.INT_SUB ? Math.negateExact(delta) : delta);
	}

	private static Relative addIndex(Varnode[] inputs, Varnode root, int depth) {
		if (inputs.length != 3 || inputs[1] == null || !constant(inputs[2]) ||
				inputs[1].getSize() != root.getSize() || inputs[2].getSize() != root.getSize()) {
			return null;
		}
		long scale = signedConstant(inputs[2]);
		if (scale < 1 || scale > MAXIMUM_EXTENT) {
			return null;
		}
		Relative base = offset(inputs[0], root, depth);
		if (base == null) {
			return null;
		}
		if (constant(inputs[1])) {
			return base.shift(Math.multiplyExact(signedConstant(inputs[1]), scale));
		}
		if (base.stride() != 0) {
			return null;
		}
		IndexBounds index = indexBounds(inputs[1], depth);
		if (index == null) {
			return null;
		}
		long minimum = Math.addExact(base.minimum(), Math.multiplyExact(index.minimum(), scale));
		long maximum = Math.addExact(base.maximum(), Math.multiplyExact(index.maximum(), scale));
		return new Relative(minimum, maximum, minimum == maximum ? 0 : scale);
	}

	/** Recognizes bounded nonnegative indices from masks, constant adds and value-preserving extensions. */
	private static IndexBounds indexBounds(Varnode expression, int depth) {
		if (expression == null || expression.getSize() < 1 ||
				expression.getSize() > Long.BYTES || depth >= MAXIMUM_DEFINITION_DEPTH) {
			return null;
		}
		PcodeOp definition = expression.getDef();
		if (definition == null || definition.getParent() == null) {
			return null;
		}
		Varnode[] inputs = definition.getInputs();
		int opcode = definition.getOpcode();
		int size = expression.getSize();
		if ((opcode == PcodeOp.INT_AND || opcode == PcodeOp.INT_ADD) && inputs.length == 2) {
			int constantIndex = constant(inputs[0]) ? 0 : 1;
			Varnode immediate = inputs[constantIndex];
			Varnode value = inputs[1 - constantIndex];
			if (!constant(immediate) || value == null || immediate.getSize() != size ||
					value.getSize() != size) {
				return null;
			}
			long amount = signedConstant(immediate);
			if (opcode == PcodeOp.INT_AND) {
				return amount < 0 ? null : new IndexBounds(0, amount);
			}
			IndexBounds base = indexBounds(value, depth + 1);
			if (base == null) {
				return null;
			}
			long minimum = Math.addExact(base.minimum(), amount);
			long maximum = Math.addExact(base.maximum(), amount);
			long maxSigned = signedMaximum(size);
			return minimum < 0 || maximum > maxSigned ? null : new IndexBounds(minimum, maximum);
		}
		if (inputs.length != 1 || inputs[0] == null) {
			return null;
		}
		int inputSize = inputs[0].getSize();
		boolean sameWidth = (opcode == PcodeOp.COPY || opcode == PcodeOp.CAST) && inputSize == size;
		boolean extendsWidth = (opcode == PcodeOp.INT_ZEXT || opcode == PcodeOp.INT_SEXT) &&
			inputSize < size;
		return sameWidth || extendsWidth ? indexBounds(inputs[0], depth + 1) : null;
	}

	private static boolean constant(Varnode varnode) {
		return varnode != null && varnode.isConstant() &&
			varnode.getSize() >= 1 && varnode.getSize() <= Long.BYTES;
	}

	private static long signedConstant(Varnode varnode) {
		int shift = (Long.BYTES - varnode.getSize()) * Byte.SIZE;
		return varnode.getOffset() << shift >> shift;
	}

	private static long signedMaximum(int size) {
		return Long.MAX_VALUE >>> ((Long.BYTES - size) * Byte.SIZE);
	}
}
