// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package binaryrat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Pattern;

import ghidra.app.cmd.data.rtti.Rtti4Model;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.app.util.opinion.PeLoader;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.Relocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Read-only C++ runtime type metadata from supported linked and relocated images. */
public final class RttiEvidence {
	private static final int POINTER = 8;
	private static final int MAX_RELOCATIONS = 200_000;
	private static final int MAX_CLASSES = 1_024;
	private static final int MAX_BASES = 128;
	private static final int MAX_TOTAL_BASE_RECORDS = 16_384;
	private static final int MAX_GRAPH_DEPTH = 32;
	private static final int MAX_TABLES = 4_096;
	private static final int MAX_NAME = 512;
	private static final int MAX_DISPLACEMENT = 1 << 20;
	private static final int PE_DIR64 = 10;
	private static final long BCD_HAS_HIERARCHY = 0x40;
	private static final Pattern ITANIUM_NAME = Pattern.compile("\\*?(?:[1-9]|N)[A-Za-z0-9_]+");
	private static final Pattern MSVC_NAME = Pattern.compile("\\.\\?A[UV][A-Za-z0-9_?$@]+@@");
	private static final Map<String, String> ITANIUM_ANCHORS = Map.of(
		"_ZTVN10__cxxabiv117__class_type_infoE", "class",
		"_ZTVN10__cxxabiv120__si_class_type_infoE", "single",
		"_ZTVN10__cxxabiv121__vmi_class_type_infoE", "multiple_or_virtual");

	public record Report(int schema_version, String program_id, String abi, String image_base,
			int relocations_examined, int rejected_metadata, List<ClassEvidence> classes) {}

	public record ClassEvidence(String encoded_name, String descriptor_address,
			String hierarchy_address, String metadata_kind, String descriptor_provenance,
			List<BaseEvidence> direct_bases, List<TableEvidence> vtables) {}

	public record BaseEvidence(String encoded_name, String descriptor_address,
			String evidence_address, boolean virtual_base, Boolean public_base, Long object_offset,
			Long virtual_table_offset, Integer msvc_pmd_mdisp, Integer msvc_pmd_pdisp,
			Integer msvc_pmd_vdisp, long flags) {}

	public record TableEvidence(String address_point, String metadata_slot, String locator_address,
			String first_function_address, long subobject_offset, Integer constructor_displacement) {}

	private record Base(Address descriptor, Address location, boolean virtualBase, Boolean publicBase,
			Long offset, Long virtualTableOffset, Integer mdisp, Integer pdisp, Integer vdisp, long flags) {
		BaseEvidence evidence(String name) {
			return new BaseEvidence(name, hex(descriptor), hex(location), virtualBase, publicBase,
				offset, virtualTableOffset, mdisp, pdisp, vdisp, flags);
		}
	}

	private record ItaniumType(String name, String kind, String relocationSymbol, List<Base> bases) {}

	private record MsHierarchy(Address type, Address address) {}

	private record MsChild(String name, Base base, MsHierarchy hierarchy) {}

	private record MsType(String name, List<MsChild> children) {}

	private record MsBase(MsChild child, int span) {}

	private static final class InvalidRtti extends Exception {
		private static final long serialVersionUID = 1L;
	}

	private final Program program;
	private final Memory memory;
	private final AddressSpace space;
	private final TaskMonitor monitor;
	private final long revision;
	private int relocations;
	private int rejected;
	private int tableCount;
	private int baseRecords;

	private RttiEvidence(Program program, TaskMonitor monitor, long revision) {
		this.program = program;
		this.memory = program.getMemory();
		this.space = program.getAddressFactory().getDefaultAddressSpace();
		this.monitor = monitor;
		this.revision = revision;
	}

	public static Report collect(Program program, TaskMonitor monitor, long revision, String programId)
			throws IOException, CancelledException {
		return new RttiEvidence(program, monitor, revision).collect(programId);
	}

	private Report collect(String programId) throws IOException, CancelledException {
		checkCurrent();
		String processor = program.getLanguage().getProcessor().toString();
		if (program.getDefaultPointerSize() != POINTER || program.getLanguage().isBigEndian() ||
				!space.isMemorySpace() || space.getAddressableUnitSize() != 1 ||
				!(processor.equals("x86") || processor.equals("AARCH64"))) {
			throw new IOException("RTTI recovery supports little-endian x86-64 and AArch64 programs");
		}
		String abi;
		List<ClassEvidence> records;
		switch (program.getExecutableFormat()) {
			case ElfLoader.ELF_NAME -> {
				abi = "itanium";
				records = itanium();
			}
			case PeLoader.PE_NAME -> {
				abi = "msvc";
				records = microsoft();
			}
			default -> throw new IOException("RTTI recovery requires an ELF or PE executable");
		}
		checkCurrent();
		return new Report(1, programId, abi, hex(program.getImageBase()), relocations,
			rejected, records);
	}

	private List<ClassEvidence> itanium() throws IOException, CancelledException {
		Map<Address, ItaniumType> types = new TreeMap<>();
		// R_X86_64_64 and R_AARCH64_ABS64 supply absolute 64-bit pointers.
		int absolute = program.getLanguage().getProcessor().toString().equals("x86") ? 1 : 257;
		var scan = program.getRelocationTable().getRelocations();
		while (scan.hasNext()) {
			Relocation relocation = scan.next();
			scanStep();
			String name = relocation.getSymbolName();
			String kind = name == null ? null : ITANIUM_ANCHORS.get(name);
			if (kind == null || relocation.getType() != absolute ||
					relocation.getStatus() != Relocation.Status.APPLIED) {
				continue;
			}
			Address site = relocation.getAddress();
			try {
				ItaniumType candidate = itaniumType(site, kind, name);
				require(!types.containsKey(site));
				checkLimit(types.size(), MAX_CLASSES, "Itanium class");
				types.put(site, candidate);
			}
			catch (InvalidRtti | MemoryAccessException | AddressOverflowException |
					AddressOutOfBoundsException e) {
				rejected++;
			}
		}

		Map<Address, List<Address>> parents = new HashMap<>();
		for (var entry : types.entrySet()) {
			parents.put(entry.getKey(), entry.getValue().bases().stream().map(Base::descriptor).toList());
		}
		Set<Address> valid = validGraph(parents, true);
		rejected += types.size() - valid.size();
		Map<Address, List<TableEvidence>> tables = new HashMap<>();
		if (!valid.isEmpty()) {
			scan = program.getRelocationTable().getRelocations();
			while (scan.hasNext()) {
				Relocation relocation = scan.next();
				scanStep();
				Address slot = relocation.getAddress();
				if (relocation.getStatus() != Relocation.Status.APPLIED ||
						!span(slot, POINTER * 2, POINTER, true)) {
					continue;
				}
				try {
					Address descriptor = pointer(slot);
					if (!valid.contains(descriptor)) {
						continue;
					}
					Address header = slot.subtractNoWrap(POINTER);
					Address point = slot.addNoWrap(POINTER);
					if (!span(header, POINTER * 3, POINTER, true)) {
						continue;
					}
					long offsetToTop = memory.getLong(header);
					Address function = pointer(point);
					if (offsetToTop <= 0 && offsetToTop >= -MAX_DISPLACEMENT && executable(function)) {
						addTable(tables, descriptor, new TableEvidence(hex(point), hex(slot), null,
							hex(function), -offsetToTop, null));
					}
				}
				catch (MemoryAccessException | AddressOverflowException | AddressOutOfBoundsException e) {
					rejected++;
				}
			}
		}

		List<ClassEvidence> records = new ArrayList<>();
		for (var entry : types.entrySet()) {
			Address address = entry.getKey();
			if (!valid.contains(address)) {
				continue;
			}
			ItaniumType type = entry.getValue();
			List<BaseEvidence> bases = new ArrayList<>();
			for (Base base : type.bases()) {
				bases.add(base.evidence(types.get(base.descriptor()).name()));
			}
			records.add(new ClassEvidence(type.name(), hex(address), null, type.kind(),
				type.relocationSymbol(), bases, tables.getOrDefault(address, List.of())));
		}
		return records;
	}

	private ItaniumType itaniumType(Address site, String kind, String symbol) throws InvalidRtti,
			MemoryAccessException, AddressOverflowException, CancelledException, IOException {
		require(span(site, POINTER * 2, POINTER, true));
		Address vtable = pointer(site);
		require(matchesRuntimeVtable(vtable, symbol));
		String name = encodedName(pointer(site.addNoWrap(POINTER)), ITANIUM_NAME, true);
		List<Base> bases = new ArrayList<>();
		if (kind.equals("single")) {
			require(span(site, POINTER * 3, POINTER, true));
			baseStep();
			Address field = site.addNoWrap(POINTER * 2);
			bases.add(new Base(pointer(field), field, false, true, 0L, null, null, null, null, 2));
		}
		if (kind.equals("multiple_or_virtual")) {
			require(span(site, POINTER * 3, POINTER, true));
			long flags = u32(site.addNoWrap(POINTER * 2));
			long count = u32(site.addNoWrap(POINTER * 2 + 4));
			require(flags <= 3 && count > 0 && count <= MAX_BASES);
			require(span(site, (int) (POINTER * 3 + POINTER * 2 * count), POINTER, true));
			for (int index = 0; index < count; index++) {
				baseStep();
				Address field = site.addNoWrap(POINTER * 3 + POINTER * 2 * index);
				Address descriptor = pointer(field);
				long offsetFlags = memory.getLong(field.addNoWrap(POINTER));
				long offset = offsetFlags >> 8;
				boolean virtual = (offsetFlags & 1) != 0;
				require((offsetFlags & 0xfc) == 0 && offset >= -MAX_DISPLACEMENT &&
					offset <= MAX_DISPLACEMENT &&
					(virtual ? offset < 0 && offset % POINTER == 0 : offset >= 0));
				bases.add(new Base(descriptor, field, virtual, (offsetFlags & 2) != 0,
					virtual ? null : offset, virtual ? offset : null, null, null, null,
					offsetFlags & 0xff));
			}
		}
		return new ItaniumType(name, kind, symbol, bases);
	}

	private boolean matchesRuntimeVtable(Address vtable, String symbol)
			throws AddressOverflowException {
		if (vtable == null) {
			return false;
		}
		Address header = vtable.subtractNoWrap(POINTER * 2);
		var symbols = program.getSymbolTable().getSymbols(symbol);
		for (int checked = 0; checked < 16 && symbols.hasNext(); checked++) {
			if (header.equals(symbols.next().getAddress())) {
				return true;
			}
		}
		return false;
	}

	private List<ClassEvidence> microsoft() throws IOException, CancelledException {
		Map<Address, List<TableEvidence>> tables = new HashMap<>();
		Map<Address, MsHierarchy> roots = new TreeMap<>();
		Map<MsHierarchy, MsType> types = new HashMap<>();
		var scan = program.getRelocationTable().getRelocations();
		while (scan.hasNext()) {
			Relocation relocation = scan.next();
			scanStep();
			Address slot = relocation.getAddress();
			if (relocation.getType() != PE_DIR64 ||
					(relocation.getStatus() != Relocation.Status.APPLIED &&
					relocation.getStatus() != Relocation.Status.SKIPPED) ||
					!span(slot, POINTER * 2, POINTER, true)) {
				continue;
			}
			try {
				Address point = slot.addNoWrap(POINTER);
				Address function = pointer(point);
				Address locator = pointer(slot);
				if (!executable(function) || !span(locator, 24, 4, true)) {
					continue;
				}
				long signature = u32(locator);
				if (signature != 1 || !locator.equals(rva(locator.addNoWrap(20)))) {
					continue;
				}
				long offset = u32(locator.addNoWrap(Rtti4Model.getVBTableComponentOffset()));
				long displacement = u32(locator.addNoWrap(Rtti4Model.getConstructorDisplacementComponentOffset()));
				require(offset <= MAX_DISPLACEMENT && displacement <= MAX_DISPLACEMENT);
				Address descriptor = rva(locator.addNoWrap(Rtti4Model.getRtti0PointerComponentOffset()));
				Address hierarchy = rva(locator.addNoWrap(Rtti4Model.getRtti3PointerComponentOffset()));
				MsHierarchy root = new MsHierarchy(descriptor, hierarchy);
				MsType parsed = types.get(root);
				if (parsed == null) {
					checkLimit(types.size(), MAX_CLASSES, "MSVC class");
					parsed = microsoftType(root);
					types.put(root, parsed);
				}
				MsHierarchy existing = roots.putIfAbsent(descriptor, root);
				require(existing == null || existing.equals(root));
				addTable(tables, descriptor, new TableEvidence(hex(point), hex(slot), hex(locator),
					hex(function), offset, (int) displacement));
			}
			catch (InvalidRtti | MemoryAccessException | AddressOverflowException |
					AddressOutOfBoundsException e) {
				rejected++;
			}
		}

		// A base descriptor can include its own hierarchy. It is accounted for only
		// if that hierarchy independently validates with the same type at its root.
		ArrayDeque<MsHierarchy> queue = new ArrayDeque<>(roots.values());
		while (!queue.isEmpty()) {
			checkCurrent();
			MsHierarchy root = queue.remove();
			for (MsChild child : types.get(root).children()) {
				MsHierarchy base = child.hierarchy();
				if (base == null || roots.containsKey(base.type())) {
					continue;
				}
				try {
					checkLimit(types.size(), MAX_CLASSES, "MSVC class");
					MsType parsed = microsoftType(base);
					types.put(base, parsed);
					roots.put(base.type(), base);
					queue.add(base);
				}
				catch (InvalidRtti | MemoryAccessException | AddressOverflowException |
						AddressOutOfBoundsException e) {
					rejected++;
				}
			}
		}
		Map<Address, List<Address>> parents = new HashMap<>();
		for (var entry : roots.entrySet()) {
			List<Address> parentAddresses = new ArrayList<>();
			for (MsChild child : types.get(entry.getValue()).children()) {
				parentAddresses.add(child.base().descriptor());
			}
			parents.put(entry.getKey(), parentAddresses);
		}
		Set<Address> valid = validGraph(parents, false);
		rejected += roots.size() - valid.size();

		List<ClassEvidence> records = new ArrayList<>();
		for (var entry : roots.entrySet()) {
			if (!valid.contains(entry.getKey())) {
				continue;
			}
			MsHierarchy root = entry.getValue();
			MsType type = types.get(root);
			List<BaseEvidence> bases = new ArrayList<>();
			for (MsChild child : type.children()) {
				bases.add(child.base().evidence(child.name()));
			}
			List<TableEvidence> vtables = tables.getOrDefault(entry.getKey(), List.of());
			String provenance = vtables.isEmpty() ? "pe_base_descriptor_hierarchy_link" :
				"pe_dir64_complete_object_locator_chain";
			records.add(new ClassEvidence(type.name(), hex(entry.getKey()), hex(root.address()),
				"class_hierarchy_descriptor", provenance, bases, vtables));
		}
		return records;
	}

	/** Drops cycles, overdeep paths, and references to absent required descriptors. */
	private Set<Address> validGraph(Map<Address, List<Address>> parents, boolean requireParents)
			throws IOException, CancelledException {
		Map<Address, List<Address>> descendants = new HashMap<>();
		Map<Address, Integer> remaining = new HashMap<>();
		ArrayDeque<Address> ready = new ArrayDeque<>();
		for (var entry : parents.entrySet()) {
			Address type = entry.getKey();
			int count = 0;
			for (Address base : entry.getValue()) {
				if (requireParents || parents.containsKey(base)) {
					count++;
					descendants.computeIfAbsent(base, k -> new ArrayList<>()).add(type);
				}
			}
			remaining.put(type, count);
			if (count == 0) {
				ready.add(type);
			}
		}
		Set<Address> valid = new HashSet<>();
		Map<Address, Integer> depths = new HashMap<>();
		while (!ready.isEmpty()) {
			checkCurrent();
			Address type = ready.remove();
			int depth = depths.getOrDefault(type, 0);
			if (depth > MAX_GRAPH_DEPTH) {
				continue;
			}
			valid.add(type);
			for (Address child : descendants.getOrDefault(type, List.of())) {
				depths.merge(child, depth + 1, Math::max);
				if (remaining.merge(child, -1, Integer::sum) == 0) {
					ready.add(child);
				}
			}
		}
		return valid;
	}

	private MsType microsoftType(MsHierarchy root) throws InvalidRtti, AddressOverflowException,
			MemoryAccessException, CancelledException, IOException {
		String name = microsoftName(root.type());
		Address hierarchy = root.address();
		// Rtti3Model: signature/attributes/count/array; Rtti1Model: type/count/PMD/attributes/hierarchy.
		require(span(hierarchy, 16, 4, true) && u32(hierarchy) == 0 &&
			u32(hierarchy.addNoWrap(4)) <= 7);
		long count = u32(hierarchy.addNoWrap(8));
		require(count > 0 && count <= MAX_BASES);
		Address array = rva(hierarchy.addNoWrap(12));
		require(span(array, (int) count * 4, 4, true));

		int[] boundaries = new int[MAX_GRAPH_DEPTH];
		int depth = 0;
		List<MsChild> children = new ArrayList<>();
		for (int index = 0; index < count; index++) {
			baseStep();
			while (depth > 0 && boundaries[depth - 1] == index) {
				depth--;
			}
			MsBase row = microsoftBase(rva(array.addNoWrap((long) index * 4)));
			Base base = row.child().base();
			long end = (long) index + row.span() + 1;
			if (index == 0) {
				require(end == count && base.descriptor().equals(root.type()) &&
					base.pdisp() == -1 && base.mdisp() == 0 &&
					(row.child().hierarchy() == null || row.child().hierarchy().equals(root)));
			}
			else {
				require(depth > 0 && end <= boundaries[depth - 1] &&
					!base.descriptor().equals(root.type()));
				if (depth == 1) {
					children.add(row.child());
				}
			}
			if (row.span() > 0) {
				require(depth < boundaries.length);
				boundaries[depth++] = (int) end;
			}
		}
		return new MsType(name, children);
	}

	private MsBase microsoftBase(Address field) throws InvalidRtti, AddressOverflowException,
			MemoryAccessException {
		require(span(field, 24, 4, true));
		Address type = rva(field);
		String name = microsoftName(type);
		long count = u32(field.addNoWrap(4));
		int mdisp = memory.getInt(field.addNoWrap(8));
		int pdisp = memory.getInt(field.addNoWrap(12));
		int vdisp = memory.getInt(field.addNoWrap(16));
		long flags = u32(field.addNoWrap(20));
		require(count < MAX_BASES && mdisp >= 0 && mdisp <= MAX_DISPLACEMENT &&
			pdisp >= -1 && pdisp <= MAX_DISPLACEMENT && vdisp >= 0 && vdisp <= MAX_DISPLACEMENT &&
			vdisp % 4 == 0 && (pdisp >= 0 || vdisp == 0) && flags <= 0xff);
		Base base = new Base(type, field, pdisp >= 0, null, pdisp >= 0 ? null : (long) mdisp,
			null, mdisp, pdisp, vdisp, flags);
		MsHierarchy hierarchy = null;
		if ((flags & BCD_HAS_HIERARCHY) != 0) {
			require(span(field, 28, 4, true));
			Address ownHierarchy = rva(field.addNoWrap(24));
			require(span(ownHierarchy, 16, 4, true));
			hierarchy = new MsHierarchy(type, ownHierarchy);
		}
		return new MsBase(new MsChild(name, base, hierarchy), (int) count);
	}

	private String microsoftName(Address descriptor)
			throws InvalidRtti, AddressOverflowException, MemoryAccessException {
		require(span(descriptor, 2 * POINTER + 1, POINTER, false) &&
			span(pointer(descriptor), POINTER, POINTER, true));
		return encodedName(descriptor.addNoWrap(2 * POINTER), MSVC_NAME, false);
	}

	private String encodedName(Address address, Pattern grammar, boolean readOnly)
			throws InvalidRtti, MemoryAccessException {
		require(span(address, 1, 1, readOnly));
		long remaining = memory.getBlock(address).getEnd().subtract(address) + 1;
		byte[] bytes = new byte[(int) Math.min(MAX_NAME + 1, remaining)];
		int size = memory.getBytes(address, bytes);
		for (int i = 0; i < size; i++) {
			if (bytes[i] == 0) {
				String name = new String(bytes, 0, i, StandardCharsets.US_ASCII);
				require(grammar.matcher(name).matches());
				return name;
			}
			require(bytes[i] >= 0x21 && bytes[i] <= 0x7e);
		}
		throw new InvalidRtti();
	}

	private boolean span(Address address, int size, int alignment, boolean readOnly) {
		if (address == null || !address.getAddressSpace().equals(space) ||
				Long.remainderUnsigned(address.getOffset(), alignment) != 0) {
			return false;
		}
		MemoryBlock block = memory.getBlock(address);
		return block != null && block.isLoaded() && block.isInitialized() && block.isRead() &&
			!block.isExecute() && !block.isVolatile() && !block.isOverlay() &&
			(!readOnly || !block.isWrite()) &&
			Long.compareUnsigned(block.getEnd().subtract(address), size - 1L) >= 0;
	}

	private boolean executable(Address address) {
		MemoryBlock block = address == null ? null : memory.getBlock(address);
		return block != null && block.isExecute() && block.isLoaded() &&
			block.isInitialized() && !block.isVolatile() && !block.isOverlay();
	}

	private Address pointer(Address address) throws MemoryAccessException {
		long value = memory.getLong(address);
		return value == 0 ? null : space.getAddress(value);
	}

	private Address rva(Address field) throws MemoryAccessException, AddressOverflowException {
		long offset = u32(field);
		return offset == 0 ? null : program.getImageBase().addNoWrap(offset);
	}

	private long u32(Address address) throws MemoryAccessException {
		return Integer.toUnsignedLong(memory.getInt(address));
	}

	private void addTable(Map<Address, List<TableEvidence>> tables, Address descriptor,
			TableEvidence table) throws IOException {
		checkLimit(tableCount, MAX_TABLES, "vtable");
		List<TableEvidence> entries = tables.computeIfAbsent(descriptor, k -> new ArrayList<>());
		if (!entries.contains(table)) {
			entries.add(table);
			tableCount++;
		}
	}

	private void scanStep() throws IOException, CancelledException {
		checkLimit(relocations, MAX_RELOCATIONS, "relocation");
		if (++relocations % 256 == 0) {
			checkCurrent();
		}
	}

	private void baseStep() throws IOException, CancelledException {
		monitor.checkCancelled();
		checkLimit(baseRecords, MAX_TOTAL_BASE_RECORDS, "base record");
		baseRecords++;
	}

	private void checkCurrent() throws IOException, CancelledException {
		monitor.checkCancelled();
		if (program.getModificationNumber() != revision) {
			throw new IOException("Program changed while collecting RTTI evidence");
		}
	}

	private static void checkLimit(int count, int maximum, String kind) throws IOException {
		if (count >= maximum) {
			throw new IOException("RTTI " + kind + " work limit exceeded");
		}
	}

	private static void require(boolean condition) throws InvalidRtti {
		if (!condition) {
			throw new InvalidRtti();
		}
	}

	private static String hex(Address address) {
		return "0x" + Long.toUnsignedString(address.getOffset(), 16);
	}
}
