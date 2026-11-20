// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package binaryrat;

import java.util.*;

import ghidra.program.database.mem.ByteMappingScheme;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;

/**
 * Addresses whose bytes change when other addresses are written. Ghidra reports a byte
 * write only at the addresses written ({@code MemoryMapDB.fireBytesChanged}), yet a
 * byte-mapped or bit-mapped block shows the bytes of its source range, and blocks made from
 * the same file bytes share one modifiable copy of them ({@code FileBytesSubMemoryBlock}).
 * A write to a source therefore changes what a read of its aliases returns without any
 * event at the alias. (A write through a mapped block is reported at both ends by Ghidra.)
 *
 * <p>An index describes the memory map it was built from: build a new one after any change
 * to the blocks.
 */
final class MemoryAliases {
	/** Ranges examined for one write, aliases of aliases included. */
	static final int MAX_STEPS = 4_096;

	/**
	 * A mapped block's view of its source range. Of every {@code sourceBytes} source bytes,
	 * the first {@code mappedBytes} appear in order; a bit-mapped view shows each source
	 * byte as eight bytes.
	 */
	private record Mapped(Address sourceMin, Address sourceMax, Address min, long length, boolean bits,
			int mappedBytes, int sourceBytes) {
	}

	/** A part of a block whose bytes are file bytes [fileOffset, fileOffset + length). */
	private record FileView(Address min, long fileOffset, long length) {
	}

	private final List<Mapped> mapped;
	private final List<List<FileView>> shared;

	private MemoryAliases(List<Mapped> mapped, List<List<FileView>> shared) {
		this.mapped = mapped;
		this.shared = shared;
	}

	static MemoryAliases of(Memory memory) {
		List<Mapped> mapped = new ArrayList<>();
		Map<FileBytes, List<FileView>> files = new HashMap<>();
		for (MemoryBlock block : memory.getBlocks()) {
			boolean bits = block.getType() == MemoryBlockType.BIT_MAPPED;
			for (MemoryBlockSourceInfo info : block.getSourceInfos()) {
				Optional<AddressRange> source = info.getMappedRange();
				if (source.isPresent()) {
					int mappedBytes = 1;
					int sourceBytes = 1;
					Optional<ByteMappingScheme> scheme = info.getByteMappingScheme();
					if (!bits && scheme.isPresent()) {
						mappedBytes = scheme.get().getMappedByteCount();
						sourceBytes = scheme.get().getMappedSourceByteCount();
					}
					if (mappedBytes < 1 || sourceBytes < mappedBytes) {
						throw new IllegalStateException("unsupported byte mapping in " + block.getName());
					}
					mapped.add(new Mapped(source.get().getMinAddress(), source.get().getMaxAddress(),
						info.getMinAddress(), info.getLength(), bits, mappedBytes, sourceBytes));
				}
				Optional<FileBytes> file = info.getFileBytes();
				if (file.isPresent() && info.getFileBytesOffset() >= 0) {
					files.computeIfAbsent(file.get(), ignored -> new ArrayList<>())
						.add(new FileView(info.getMinAddress(), info.getFileBytesOffset(), info.getLength()));
				}
			}
		}
		List<List<FileView>> shared = new ArrayList<>();
		for (List<FileView> views : files.values()) {
			if (views.size() > 1) {
				shared.add(List.copyOf(views));
			}
		}
		return new MemoryAliases(List.copyOf(mapped), List.copyOf(shared));
	}

	/** True when no write can change the bytes of another address. */
	boolean isEmpty() {
		return mapped.isEmpty() && shared.isEmpty();
	}

	/**
	 * Adds the line keys of every other address whose bytes a write to [start, end] changes,
	 * aliases of aliases included. Returns false when they cannot all be named within the
	 * limits; the change must then be treated as having unknown reach.
	 */
	boolean addAliasLines(Collection<String> keys, Address start, Address end) {
		if (isEmpty() || start == null || !start.isMemoryAddress()) {
			return true;
		}
		Address last = end == null ? start : end;
		if (!last.getAddressSpace().equals(start.getAddressSpace()) || last.compareTo(start) < 0) {
			return false;
		}
		AddressSet seen = new AddressSet(start, last);
		ArrayDeque<AddressRange> work = new ArrayDeque<>();
		work.add(new AddressRangeImpl(start, last));
		try {
			for (int steps = 0; !work.isEmpty(); steps++) {
				if (steps == MAX_STEPS) {
					return false;
				}
				AddressRange range = work.poll();
				for (Mapped view : mapped) {
					AddressRange part = intersect(range, view.sourceMin(), view.sourceMax());
					if (part == null) {
						continue;
					}
					long firstOffset = part.getMinAddress().subtract(view.sourceMin());
					long lastOffset = part.getMaxAddress().subtract(view.sourceMin());
					long low;
					long high;
					if (view.bits()) {
						low = Math.multiplyExact(firstOffset, 8L);
						high = Math.addExact(Math.multiplyExact(lastOffset, 8L), 7L);
					}
					else {
						// Name every mapped byte of each source group the write touches.
						low = Math.multiplyExact(firstOffset / view.sourceBytes(), (long) view.mappedBytes());
						high = Math.addExact(Math.multiplyExact(lastOffset / view.sourceBytes(),
							(long) view.mappedBytes()), view.mappedBytes() - 1L);
					}
					if (!add(keys, seen, work, view.min(), view.length(), low, high)) {
						return false;
					}
				}
				for (List<FileView> views : shared) {
					for (int from = 0; from < views.size(); from++) {
						FileView source = views.get(from);
						AddressRange part = intersect(range, source.min(),
							source.min().addNoWrap(source.length() - 1));
						if (part == null) {
							continue;
						}
						long fileFirst = Math.addExact(source.fileOffset(),
							part.getMinAddress().subtract(source.min()));
						long fileLast = Math.addExact(source.fileOffset(),
							part.getMaxAddress().subtract(source.min()));
						for (int to = 0; to < views.size(); to++) {
							FileView target = views.get(to);
							long targetEnd = Math.addExact(target.fileOffset(), target.length() - 1);
							if (to == from || fileLast < target.fileOffset() || fileFirst > targetEnd) {
								continue;
							}
							if (!add(keys, seen, work, target.min(), target.length(),
								Math.max(fileFirst, target.fileOffset()) - target.fileOffset(),
								Math.min(fileLast, targetEnd) - target.fileOffset())) {
								return false;
							}
						}
					}
				}
			}
			return true;
		}
		catch (ArithmeticException | AddressOverflowException | IllegalArgumentException unrepresentable) {
			return false;
		}
	}

	private static AddressRange intersect(AddressRange range, Address min, Address max) {
		if (!range.getAddressSpace().equals(min.getAddressSpace()) ||
			range.getMaxAddress().compareTo(min) < 0 || range.getMinAddress().compareTo(max) > 0) {
			return null;
		}
		return new AddressRangeImpl(range.getMinAddress().compareTo(min) > 0 ? range.getMinAddress() : min,
			range.getMaxAddress().compareTo(max) < 0 ? range.getMaxAddress() : max);
	}

	/** Names [min + low, min + high], clipped to a view of the given length, and queues it. */
	private static boolean add(Collection<String> keys, AddressSet seen, ArrayDeque<AddressRange> work,
			Address min, long length, long low, long high) throws AddressOverflowException {
		if (length <= 0 || low < 0 || low > length - 1) {
			return true;
		}
		long clipped = Math.min(high, length - 1);
		Address first = min.addNoWrap(low);
		Address last = min.addNoWrap(clipped);
		if (seen.contains(first, last)) {
			return true;
		}
		seen.add(first, last);
		work.add(new AddressRangeImpl(first, last));
		return Trace.addLines(keys, first, clipped - low + 1);
	}
}
