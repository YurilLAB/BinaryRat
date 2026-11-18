// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package binaryrat;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;

/**
 * Everything one decompilation read: each query with a digest of its answer, the
 * program facts those answers depended on, and a digest over the whole sequence.
 * The decompiler is deterministic, so a later program that gives the same answers
 * to the same queries yields the same output.
 */
public final class Trace implements RecordingCallback.Sink {
	/** Dependencies on memory are kept per line of 2^LINE_SHIFT addressable units. */
	public static final int LINE_SHIFT = 8;
	/** A read or a change wider than this many lines is not tracked precisely. */
	public static final long MAX_LINES = 1L << 14;

	// A skipped trace only costs a future decompilation. Keep Java heap bounded
	// independently of the number and size of queries the native worker makes.
	static final int MAX_KEY_CHARS = 256;
	static final int MAX_READS = 65_536;
	static final int MAX_READ_CHARS = 2 * 1024 * 1024;
	private int readChars;
	private boolean abandoned;
	private final List<String> reads = new ArrayList<>();
	private final MessageDigest combined = sha256();
	private final TreeSet<String> dependencies = new TreeSet<>();
	private final List<String> unpredictable = new ArrayList<>();

	static MessageDigest sha256() {
		try {
			return MessageDigest.getInstance("SHA-256");
		}
		catch (Exception exception) {
			throw new IllegalStateException(exception);
		}
	}

	static String hex(byte[] bytes, int length) {
		return HexFormat.of().formatHex(bytes, 0, Math.min(length, bytes.length));
	}

	/** Folds one query and its answer digest into a running sequence digest. */
	static void fold(MessageDigest digest, String request, byte[] answer) {
		digest.update(request.getBytes(StandardCharsets.UTF_8));
		digest.update((byte) 0);
		digest.update(answer);
	}

	/** The record of one query: request, then the first 8 bytes of its answer digest. */
	static String record(String request, byte[] answer) {
		return request + "|" + hex(answer, 8);
	}

	@Override
	public void answer(String request, byte[] digest) {
		if (abandoned) return;
		// The recorded answer suffix occupies one separator and 16 hex characters.
		if (reads.size() >= MAX_READS || request.length() > MAX_READ_CHARS - readChars - 17) {
			abandoned = true;
			reads.clear();
			dependencies.clear();
			unpredictable.clear();
			return;
		}
		readChars += request.length() + 17;
		reads.add(record(request, digest));
		fold(combined, request, digest);
	}

	@Override
	public void depends(Address start, long length) {
		if (!abandoned && !addLines(dependencies, start, length)) {
			unpredictable("address dependencies exceed the tracking budget");
		}
	}

	@Override
	public void dependsOnName(String name) {
		if (abandoned || name == null) return;
		if (dependencies.size() >= MAX_LINES || name.length() > MAX_KEY_CHARS) {
			unpredictable("symbol dependencies exceed the tracking budget");
			return;
		}
		dependencies.add(nameKey(name));
	}

	@Override
	public void unpredictable(String why) {
		if (!abandoned && unpredictable.isEmpty()) {
			unpredictable.add(why.length() <= 256 ? why : why.substring(0, 256));
		}
	}

	static String nameKey(String name) {
		return "n:" + RecordingCallback.text(name);
	}

	static String lineKey(AddressSpace space, long line) {
		return "l:" + RecordingCallback.text(space.getName()) + ":" + Long.toHexString(line);
	}

	/**
	 * Adds the line keys covering [start, start + length). Addresses outside memory
	 * spaces add nothing: changes there are always reported as changes of unknown
	 * reach. Returns false when the range or the combined dependency set exceeds MAX_LINES.
	 */
	static boolean addLines(Collection<String> keys, Address start, long length) {
		if (start == null || start == Address.NO_ADDRESS || !start.isMemoryAddress()) {
			return true;
		}
		AddressSpace space = start.getAddressSpace();
		if (space.getName().length() > MAX_KEY_CHARS) return false;
		long first = start.getOffset() >>> LINE_SHIFT;
		long lastOffset = start.getOffset() + Math.max(length, 1) - 1;
		long maximum = space.getMaxAddress().getOffset();
		if (Long.compareUnsigned(lastOffset, start.getOffset()) < 0 ||
			Long.compareUnsigned(lastOffset, maximum) > 0) {
			lastOffset = maximum;
		}
		long last = lastOffset >>> LINE_SHIFT;
		if (Long.compareUnsigned(last - first, MAX_LINES) >= 0) {
			return false;
		}
		for (long line = first;; line++) {
			String key = lineKey(space, line);
			if (keys.size() >= MAX_LINES && !keys.contains(key)) return false;
			keys.add(key);
			if (line == last) {
				break;
			}
		}
		return true;
	}

	public List<String> reads() {
		return Collections.unmodifiableList(reads);
	}

	public SortedSet<String> dependencies() {
		return Collections.unmodifiableSortedSet(dependencies);
	}

	public List<String> unpredictable() {
		return Collections.unmodifiableList(unpredictable);
	}

	/** Digest over every query and full answer digest, in order. */
	public String digest() {
		try {
			return hex(((MessageDigest) combined.clone()).digest(), 32);
		}
		catch (CloneNotSupportedException exception) {
			throw new IllegalStateException(exception);
		}
	}

	/** True when every read can be replayed against a program later. */
	public boolean replayable() {
		if (abandoned) return false;
		for (String read : reads) {
			if (read.startsWith("I|") && read.contains("|!|")) {
				return false;
			}
		}
		return true;
	}
}
