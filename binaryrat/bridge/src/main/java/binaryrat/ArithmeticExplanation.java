/* Copyright 2026 YurilLAB
 * SPDX-License-Identifier: Apache-2.0
 */
package binaryrat;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Explains a general register after a bounded, straight-line range of Listing instructions. */
public final class ArithmeticExplanation {
	private static final int MAX_INSTRUCTIONS = 32;
	private static final int MAX_OPERATIONS = 256;
	private static final int MAX_NODES = 256;
	private static final Set<String> X86_REGISTERS = Set.of("RAX", "RBX", "RCX", "RDX",
		"RSI", "RDI", "RSP", "RBP", "R8", "R9", "R10", "R11", "R12", "R13",
		"R14", "R15");
	private static final Set<String> ARM_REGISTERS = Set.of("SP", "X0", "X1", "X2", "X3",
		"X4", "X5", "X6", "X7", "X8", "X9", "X10", "X11", "X12", "X13", "X14",
		"X15", "X16", "X17", "X18", "X19", "X20", "X21", "X22", "X23", "X24",
		"X25", "X26", "X27", "X28", "X29", "X30");
	private static final Set<String> BINARY = Set.of("INT_ADD", "INT_SUB", "INT_AND",
		"INT_OR", "INT_XOR");
	private static final Set<String> UNARY = Set.of("COPY", "INT_NEGATE", "INT_2COMP");
	private static final Set<String> EXTEND = Set.of("INT_ZEXT", "INT_SEXT");
	// Flag and intermediate calculations are allowed off the slice. All effects in
	// the selected range must be known, even those after the last target write.
	private static final Set<String> OTHER_PURE = Set.of("INT_EQUAL", "INT_NOTEQUAL",
		"INT_SLESS", "INT_SLESSEQUAL", "INT_LESS", "INT_LESSEQUAL", "INT_CARRY", "INT_SCARRY",
		"INT_SBORROW", "INT_LEFT", "INT_RIGHT", "INT_SRIGHT", "INT_MULT", "BOOL_NEGATE",
		"BOOL_XOR", "BOOL_AND", "BOOL_OR", "PIECE", "SUBPIECE", "POPCOUNT", "LZCOUNT");

	private ArithmeticExplanation() {}

	/** Node indices in arguments refer to earlier rows. Leaves have no evidence site. */
	public record Node(String operation, int size, List<Integer> arguments, String value,
			Address storage, Address site, int sequence) {
		public Node {
			arguments = List.copyOf(arguments);
		}
	}

	public record Result(long revision, String targetRegister, int root, List<Node> nodes) {
		public Result {
			nodes = List.copyOf(nodes);
		}
	}

	public static final class Unsupported extends IllegalArgumentException {
		private Unsupported(String message) {
			super(message);
		}
	}

	private static Set<String> baseRegisters(Program program) {
		return switch (program.getLanguageID().getIdAsString()) {
			case "x86:LE:64:default" -> X86_REGISTERS;
			case "AARCH64:LE:64:v8A" -> ARM_REGISTERS;
			default -> Set.of();
		};
	}

	public static boolean supportsRegister(Program program, Register register) {
		return supportsRegister(baseRegisters(program), register);
	}

	/** Names for the desktop selection dialog, taken from the loaded language definition. */
	public static List<String> registerNames(Program program) {
		Set<String> bases = baseRegisters(program);
		if (bases.isEmpty()) {
			return List.of();
		}
		return program.getLanguage().getRegisters().stream()
				.filter(reg -> supportsRegister(bases, reg))
				.map(Register::getName).distinct().sorted().toList();
	}

	private static boolean supportsRegister(Set<String> bases, Register register) {
		if (register == null || !register.getAddress().isRegisterAddress() || register.isZero() ||
			register.getLeastSignificantBit() != 0 || register.getNumBytes() * 8 != register.getBitLength()) {
			return false;
		}
		String base = register.getBaseRegister().getName().toUpperCase(Locale.ROOT);
		return bases.contains(base);
	}

	public static Result explain(Program program, Address first, Address last, String register,
			TaskMonitor monitor) throws CancelledException {
		return explain(program, first, last, register, program.getModificationNumber(), monitor);
	}

	/** Both endpoints are instruction starts. The result is detached from the live Listing. */
	public static Result explain(Program program, Address first, Address last, String register,
			long expectedRevision, TaskMonitor monitor) throws CancelledException {
		checkProgram(program, expectedRevision, monitor);
		try {
			if (baseRegisters(program).isEmpty()) {
				throw new Unsupported("Unsupported arithmetic language: " + program.getLanguageID());
			}
			if (first == null || last == null || !first.isMemoryAddress() || !first.getAddressSpace().equals(last.getAddressSpace()) ||
				first.compareTo(last) > 0) {
				throw new IllegalArgumentException("Select an ordered range in a single memory space.");
			}
			if (first.getAddressSpace().getAddressableUnitSize() != 1) {
				throw new Unsupported("Arithmetic ranges require byte-addressed memory.");
			}
			if (register == null || register.isBlank() || register.length() > 100) {
				throw new IllegalArgumentException("Expected a register name of 1 to 100 characters.");
			}
			Register target = program.getRegister(register);
			if (target == null) {
				throw new IllegalArgumentException("Unknown register: " + register);
			}
			if (!supportsRegister(program, target)) {
				throw new Unsupported("Select a general-purpose register in x86-64 or AArch64.");
			}
			List<PcodeOp> ops = collect(program.getListing(), first, last, monitor);
			int writer = source(ops, ops.size(), target.getAddress(), target.getNumBytes(), last);
			if (writer < 0) {
				throw new Unsupported("The selected register has no writer in this range.");
			}
			List<Node> nodes = slice(program, ops, writer, monitor);
			return new Result(expectedRevision, target.getName(), nodes.size() - 1, nodes);
		}
		finally {
			// An edit during a lift can also produce an apparent unsupported instruction.
			checkProgram(program, expectedRevision, monitor);
		}
	}

	private static void checkProgram(Program program, long revision, TaskMonitor monitor)
			throws CancelledException {
		monitor.checkCancelled();
		if (program.isClosed() || program.getModificationNumber() != revision ||
			program.getCurrentTransactionInfo() != null) {
			throw new IllegalStateException("The Program is changing or has been closed. Select the instructions again.");
		}
	}

	private static List<PcodeOp> collect(Listing listing, Address first, Address last,
			TaskMonitor monitor) throws CancelledException {
		List<PcodeOp> ops = new ArrayList<>();
		if (listing.getInstructionAt(last) == null) {
			throw new IllegalArgumentException("Expected a defined instruction at " + last);
		}
		Address cursor = first;
		for (int count = 0; count < MAX_INSTRUCTIONS; count++) {
			monitor.checkCancelled();
			Instruction instruction = listing.getInstructionAt(cursor);
			if (instruction == null) {
				throw new IllegalArgumentException("Expected a defined instruction at " + cursor);
			}
			if (!instruction.getFlowType().isFallthrough() || instruction.isFallThroughOverridden() ||
				instruction.getFlowOverride() != FlowOverride.NONE || instruction.isInDelaySlot() ||
				instruction.getDelaySlotDepth() != 0 || instruction.getLength() != instruction.getParsedLength()) {
				throw new Unsupported("Expected ordinary straight-line flow at " + cursor);
			}
			PcodeOp[] lifted = instruction.getPcode(true);
			if (lifted.length > 128 || lifted.length + ops.size() > MAX_OPERATIONS) {
				throw new Unsupported("Selection exceeds the p-code operation budget.");
			}
			Set<Integer> orders = new HashSet<>();
			for (PcodeOp op : lifted) {
				monitor.checkCancelled();
				String name = op.getMnemonic();
				if (!BINARY.contains(name) && !UNARY.contains(name) && !EXTEND.contains(name) &&
					!OTHER_PURE.contains(name)) {
					throw new Unsupported("Unsupported instruction effect " + name + " at " + cursor);
				}
				if (!cursor.equals(op.getSeqnum().getTarget()) || !orders.add(op.getSeqnum().getTime()) ||
					op.getNumInputs() > 8) {
					throw new Unsupported("Ambiguous p-code operation at " + cursor);
				}
				checkStorage(op.getOutput(), false);
				for (Varnode operand : op.getInputs()) {
					checkStorage(operand, true);
				}
				ops.add(op);
			}
			if (cursor.equals(last)) {
				return ops;
			}
			cursor = instruction.getMaxAddress().next();
			if (cursor == null || cursor.compareTo(last) > 0 || !cursor.equals(instruction.getFallThrough())) {
				throw new Unsupported("Select contiguous, complete instructions.");
			}
		}
		throw new Unsupported("Select at most " + MAX_INSTRUCTIONS + " instructions.");
	}

	private static void checkStorage(Varnode node, boolean input) {
		if (node == null || node.getSize() < 1 || node.getSize() > 8 ||
			!(node.isRegister() || node.isUnique() || (input && node.isConstant())) ||
			(!node.isConstant() && Long.compareUnsigned(node.getOffset() + node.getSize() - 1,
				node.getOffset()) < 0)) {
			throw new Unsupported("Unsupported p-code storage or width.");
		}
	}

	private static boolean overlaps(Address a, int aSize, Address b, int bSize) {
		if (!a.getAddressSpace().equals(b.getAddressSpace())) {
			return false;
		}
		// Widths are checked before this call; comparing inclusive ends avoids overflow at 2^64.
		return Long.compareUnsigned(a.getOffset(), b.getOffset() + bSize - 1) <= 0 &&
			Long.compareUnsigned(b.getOffset(), a.getOffset() + aSize - 1) <= 0;
	}

	/** Index of the most recent exact writer, or -1 for an entry register/constant. */
	private static int source(List<PcodeOp> ops, int before, Address address, int size, Address site) {
		if (address.isConstantAddress()) {
			return -1;
		}
		for (int i = before - 1; i >= 0; i--) {
			PcodeOp op = ops.get(i);
			if (address.isUniqueAddress() && !site.equals(op.getSeqnum().getTarget())) {
				break;
			}
			Varnode out = op.getOutput();
			if (out.getSize() == size && address.equals(out.getAddress())) {
				return i;
			}
			if (overlaps(address, size, out.getAddress(), out.getSize())) {
				throw new Unsupported("Partial or overlapping write at " + op.getSeqnum().getTarget());
			}
		}
		if (address.isUniqueAddress()) {
			throw new Unsupported("Missing instruction-local temporary at " + site);
		}
		return -1;
	}

	private static void checkShape(PcodeOp op) {
		int size = op.getOutput().getSize();
		String name = op.getMnemonic();
		boolean valid;
		if (EXTEND.contains(name)) {
			valid = op.getNumInputs() == 1 && op.getInput(0).getSize() < size;
		}
		else {
			int arity = BINARY.contains(name) ? 2 : 1;
			valid = (BINARY.contains(name) || UNARY.contains(name)) && op.getNumInputs() == arity;
			for (Varnode operand : op.getInputs()) {
				valid &= operand.getSize() == size;
			}
		}
		if (!valid) {
			throw new Unsupported("Unsupported arithmetic producer or widths for " + name +
				" at " + op.getSeqnum().getTarget());
		}
	}

	private static List<Node> slice(Program program, List<PcodeOp> ops, int root, TaskMonitor monitor)
			throws CancelledException {
		boolean[] needed = new boolean[root + 1];
		needed[root] = true;
		int[][] sources = new int[root + 1][];
		for (int i = root; i >= 0; i--) {
			monitor.checkCancelled();
			if (!needed[i]) {
				continue;
			}
			PcodeOp op = ops.get(i);
			checkShape(op);
			sources[i] = new int[op.getNumInputs()];
			for (int j = 0; j < op.getNumInputs(); j++) {
				Varnode input = op.getInput(j);
				int producer = source(ops, i, input.getAddress(), input.getSize(), op.getSeqnum().getTarget());
				sources[i][j] = producer;
				if (producer >= 0) {
					needed[producer] = true;
				}
			}
		}
		List<Node> nodes = new ArrayList<>();
		Map<Node, Integer> leaves = new HashMap<>();
		int[] indices = new int[root + 1];
		for (int i = 0; i <= root; i++) {
			if (!needed[i]) {
				continue;
			}
			monitor.checkCancelled();
			PcodeOp op = ops.get(i);
			List<Integer> args = new ArrayList<>(op.getNumInputs());
			for (int j = 0; j < op.getNumInputs(); j++) {
				int producer = sources[i][j];
				args.add(producer >= 0 ? indices[producer] : leaf(program, op.getInput(j), nodes, leaves));
			}
			indices[i] = append(nodes, new Node(op.getMnemonic(), op.getOutput().getSize(), args, "",
				null, op.getSeqnum().getTarget(), op.getSeqnum().getTime()));
		}
		return nodes;
	}

	private static int leaf(Program program, Varnode operand, List<Node> nodes, Map<Node, Integer> leaves) {
		int size = operand.getSize();
		Node leaf;
		if (operand.isConstant()) {
			long mask = size == Long.BYTES ? -1L : (1L << (8 * size)) - 1;
			leaf = new Node("CONSTANT", size, List.of(), "0x" + Long.toHexString(operand.getOffset() & mask),
				null, null, -1);
		}
		else {
			Address address = operand.getAddress();
			Register reg = program.getRegister(address, size);
			if (!supportsRegister(program, reg) || reg.getNumBytes() != size || !reg.getAddress().equals(address)) {
				throw new Unsupported("Input at " + address + " is outside the named general registers.");
			}
			leaf = new Node("INPUT", size, List.of(), reg.getName(), address, null, -1);
		}
		Integer existing = leaves.get(leaf);
		if (existing != null) {
			return existing;
		}
		if (leaf.storage() != null) {
			for (Node other : leaves.keySet()) {
				if (other.storage() != null && overlaps(leaf.storage(), size, other.storage(), other.size())) {
					throw new Unsupported("Overlapping input registers require alias modeling.");
				}
			}
		}
		int index = append(nodes, leaf);
		leaves.put(leaf, index);
		return index;
	}

	private static int append(List<Node> nodes, Node node) {
		if (nodes.size() == MAX_NODES) {
			throw new Unsupported("Expression exceeds " + MAX_NODES + " nodes.");
		}
		nodes.add(node);
		return nodes.size() - 1;
	}
}
