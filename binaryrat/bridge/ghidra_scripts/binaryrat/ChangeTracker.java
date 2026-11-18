// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package binaryrat;

import java.io.IOException;
import java.util.*;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.framework.model.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.ProgramChangeRecord;
import ghidra.program.util.ProgramEvent;

/**
 * Reports every program change to the engine's live cache as the dependency keys it
 * touched, so the engine removes exactly the cached results that read them. A change
 * this class cannot map precisely is reported as a change of unknown reach, which
 * makes every cached result unverified rather than wrong.
 *
 * <p>Ghidra increments the program's modification number once per change record it
 * fires, so {@link #sync()} can prove that every change made so far has been reported
 * before a cached result is trusted without verification.
 */
public final class ChangeTracker implements DomainObjectListener, AutoCloseable {
	private static final EnumSet<ProgramEvent> IGNORED = EnumSet.of(
		// Never read by the decompiler callback.
		ProgramEvent.BOOKMARK_TYPE_ADDED, ProgramEvent.BOOKMARK_TYPE_REMOVED,
		ProgramEvent.BOOKMARK_ADDED, ProgramEvent.BOOKMARK_REMOVED, ProgramEvent.BOOKMARK_CHANGED,
		ProgramEvent.PROGRAM_TREE_CREATED, ProgramEvent.PROGRAM_TREE_REMOVED,
		ProgramEvent.PROGRAM_TREE_RENAMED, ProgramEvent.GROUP_ADDED, ProgramEvent.GROUP_REMOVED,
		ProgramEvent.GROUP_RENAMED, ProgramEvent.GROUP_COMMENT_CHANGED,
		ProgramEvent.GROUP_ALIAS_CHANGED, ProgramEvent.GROUP_REPARENTED,
		ProgramEvent.MODULE_REORDERED, ProgramEvent.FRAGMENT_MOVED, ProgramEvent.FRAGMENT_CHANGED,
		ProgramEvent.FUNCTION_TAG_CREATED, ProgramEvent.FUNCTION_TAG_CHANGED,
		ProgramEvent.FUNCTION_TAG_DELETED, ProgramEvent.FUNCTION_TAG_APPLIED,
		ProgramEvent.FUNCTION_TAG_UNAPPLIED, ProgramEvent.SOURCE_FILE_ADDED,
		ProgramEvent.SOURCE_FILE_REMOVED, ProgramEvent.RELOCATION_ADDED);

	/** Changes whose start..end range names every address they can affect. */
	private static final EnumSet<ProgramEvent> RANGED = EnumSet.of(
		ProgramEvent.MEMORY_BYTES_CHANGED, ProgramEvent.CODE_ADDED, ProgramEvent.CODE_REMOVED,
		ProgramEvent.CODE_REPLACED, ProgramEvent.CODE_UNIT_PROPERTY_CHANGED,
		ProgramEvent.CODE_UNIT_PROPERTY_RANGE_REMOVED, ProgramEvent.CODE_UNIT_USER_DATA_CHANGED,
		ProgramEvent.COMMENT_CHANGED, ProgramEvent.REFERENCE_ADDED, ProgramEvent.REFERENCE_REMOVED,
		ProgramEvent.REFERENCE_TYPE_CHANGED, ProgramEvent.REFERNCE_PRIMARY_SET,
		ProgramEvent.REFERENCE_PRIMARY_REMOVED, ProgramEvent.SYMBOL_ASSOCIATION_ADDED,
		ProgramEvent.SYMBOL_ASSOCIATION_REMOVED, ProgramEvent.EQUATE_REFERENCE_ADDED,
		ProgramEvent.EQUATE_REFERENCE_REMOVED, ProgramEvent.VARIABLE_REFERENCE_ADDED,
		ProgramEvent.VARIABLE_REFERENCE_REMOVED, ProgramEvent.FALLTHROUGH_CHANGED,
		ProgramEvent.FLOW_OVERRIDE_CHANGED, ProgramEvent.LENGTH_OVERRIDE_CHANGED,
		ProgramEvent.REGISTER_VALUES_CHANGED, ProgramEvent.DATA_TYPE_SETTING_CHANGED,
		ProgramEvent.USER_DATA_CHANGED, ProgramEvent.ADDRESS_PROPERTY_MAP_CHANGED,
		ProgramEvent.INT_PROPERTY_MAP_CHANGED, ProgramEvent.FUNCTION_CHANGED);

	private static final EnumSet<ProgramEvent> SYMBOLS = EnumSet.of(ProgramEvent.SYMBOL_ADDED,
		ProgramEvent.SYMBOL_REMOVED, ProgramEvent.SYMBOL_SOURCE_CHANGED,
		ProgramEvent.SYMBOL_ANCHOR_FLAG_CHANGED, ProgramEvent.SYMBOL_PRIMARY_STATE_CHANGED,
		ProgramEvent.SYMBOL_RENAMED, ProgramEvent.SYMBOL_SCOPE_CHANGED,
		ProgramEvent.SYMBOL_DATA_CHANGED, ProgramEvent.SYMBOL_ADDRESS_CHANGED);

	/** Counts of what was reported, for the proof report. */
	public static final class Counts {
		public long records;
		public long ignored;
		public long precise;
		public long unknownReach;
		public long resyncs;
		public long removed;
		public final Map<String, Long> unknownByEvent = new TreeMap<>();
	}

	private final Program program;
	private final EngineClient engine;
	private final Counts counts = new Counts();
	private long baseline;
	private long delivered;
	private long seq;
	private boolean blind;

	public ChangeTracker(Program program, EngineClient engine) {
		this.program = program;
		this.engine = engine;
		synchronized (this) {
			baseline = program.getModificationNumber();
		}
		program.addListener(this);
	}

	@Override
	public void close() {
		program.removeListener(this);
	}

	/**
	 * Drops changes instead of reporting them, and keeps the bookkeeping that would
	 * otherwise notice. Only for the negative control that proves stale results are
	 * caught by the proof harness.
	 */
	public synchronized void setBlind(boolean blind) {
		this.blind = blind;
		if (!blind) {
			baseline = program.getModificationNumber() - delivered;
		}
	}

	public synchronized Counts counts() {
		return counts;
	}

	@Override
	public synchronized void domainObjectChanged(DomainObjectChangedEvent event) {
		Set<String> keys = new TreeSet<>();
		boolean unknown = false;
		for (int index = 0; index < event.numRecords(); index++) {
			DomainObjectChangeRecord record = event.getChangeRecord(index);
			delivered++;
			counts.records++;
			Outcome outcome = map(record, keys);
			if (outcome == Outcome.IGNORED) {
				counts.ignored++;
			}
			else if (outcome == Outcome.UNKNOWN) {
				counts.unknownReach++;
				counts.unknownByEvent.merge(String.valueOf(record.getEventType()), 1L, Long::sum);
				unknown = true;
			}
			else {
				counts.precise++;
			}
		}
		if (blind) {
			return;
		}
		try {
			report(keys, unknown);
		}
		catch (IOException exception) {
			// Without the report the cache cannot be trusted; poison the accounting so
			// the next sync() reports a change of unknown reach.
			baseline = Long.MIN_VALUE / 2;
		}
	}

	private void report(Set<String> keys, boolean unknown) throws IOException {
		JsonObject request = new JsonObject();
		if (unknown) {
			request.addProperty("all", true);
		}
		else {
			if (keys.isEmpty()) {
				return;
			}
			JsonArray dependencies = new JsonArray();
			keys.forEach(dependencies::add);
			request.add("dependencies", dependencies);
		}
		JsonObject result = engine.call("cache.changed", request);
		seq = result.get("seq").getAsLong();
		counts.removed += result.get("removed").getAsLong();
	}

	/**
	 * Makes sure every change made so far has reached the engine. Returns once the
	 * program's modification number is fully accounted for; if some change cannot be
	 * accounted for (events disabled, or still in flight), reports a change of unknown
	 * reach instead. Call before relying on an unverified-free cache hit.
	 */
	public void sync() throws IOException {
		program.flushEvents();
		long deadline = System.nanoTime() + 200_000_000L;
		while (true) {
			synchronized (this) {
				long current = program.getModificationNumber();
				if (baseline + delivered == current) {
					return;
				}
				if (System.nanoTime() > deadline) {
					counts.resyncs++;
					baseline = current - delivered;
					if (!blind) {
						report(Set.of(), true);
					}
					return;
				}
			}
			try {
				Thread.sleep(1);
			}
			catch (InterruptedException exception) {
				Thread.currentThread().interrupt();
				throw new IOException("interrupted while syncing changes", exception);
			}
		}
	}

	private enum Outcome {
		IGNORED, PRECISE, UNKNOWN
	}

	private static boolean lines(Set<String> keys, Address start, Address end) {
		if (start == null || !start.isMemoryAddress()) {
			return false;
		}
		long length = 1;
		if (end != null) {
			if (!end.getAddressSpace().equals(start.getAddressSpace()) ||
				end.compareTo(start) < 0) {
				return false;
			}
			length = end.subtract(start) + 1;
			if (length <= 0) {
				return false;
			}
		}
		return Trace.addLines(keys, start, length);
	}

	private static boolean body(Set<String> keys, AddressSetView body) {
		if (body == null) {
			return false;
		}
		for (AddressRange range : body) {
			if (!lines(keys, range.getMinAddress(), range.getMaxAddress())) {
				return false;
			}
		}
		return true;
	}

	private static Outcome map(DomainObjectChangeRecord record, Set<String> keys) {
		EventType type = record.getEventType();
		if (!(type instanceof ProgramEvent event)) {
			return type == DomainObjectEvent.SAVED || type == DomainObjectEvent.CLOSED ?
				Outcome.IGNORED : Outcome.UNKNOWN;
		}
		if (IGNORED.contains(event)) {
			return Outcome.IGNORED;
		}
		if (!(record instanceof ProgramChangeRecord change)) {
			return Outcome.UNKNOWN;
		}
		if (RANGED.contains(event)) {
			return lines(keys, change.getStart(), change.getEnd()) ? Outcome.PRECISE : Outcome.UNKNOWN;
		}
		if (event == ProgramEvent.FUNCTION_ADDED) {
			// Queries anywhere in the new body now find this function.
			return change.getObject() instanceof Function function &&
				lines(keys, change.getStart(), null) && body(keys, function.getBody()) ?
					Outcome.PRECISE : Outcome.UNKNOWN;
		}
		if (event == ProgramEvent.FUNCTION_REMOVED) {
			return change.getOldValue() instanceof AddressSetView oldBody &&
				lines(keys, change.getStart(), null) && body(keys, oldBody) ?
					Outcome.PRECISE : Outcome.UNKNOWN;
		}
		if (SYMBOLS.contains(event)) {
			return symbol(change, keys);
		}
		// Data types, memory blocks, externals, equate definitions, language, overlays,
		// image base, property maps added or removed, source archives, and any event
		// added later: reach unknown.
		return Outcome.UNKNOWN;
	}

	private static Outcome symbol(ProgramChangeRecord change, Set<String> keys) {
		Object affected = change.getObject();
		Symbol symbol = affected instanceof Symbol s ? s : null;
		if (symbol == null && change.getNewValue() instanceof Symbol s) {
			symbol = s;
		}
		for (Object value : new Object[] { change.getOldValue(), change.getNewValue() }) {
			if (value instanceof String name) {
				keys.add(Trace.nameKey(name));
			}
		}
		Address start = change.getStart();
		try {
			if (symbol != null) {
				keys.add(Trace.nameKey(symbol.getName()));
			}
			if (start != null && start.isMemoryAddress()) {
				lines(keys, start, null);
				if (change.getEventType() == ProgramEvent.SYMBOL_ADDRESS_CHANGED &&
					change.getNewValue() instanceof Address moved && !lines(keys, moved, null)) {
					return Outcome.UNKNOWN;
				}
				return Outcome.PRECISE;
			}
			// Parameters and locals live at variable addresses; what they change is the
			// owning function's own decompilation.
			if (symbol != null && !symbol.isDeleted()) {
				Namespace parent = symbol.getParentNamespace();
				if (parent instanceof Function function && lines(keys, function.getEntryPoint(), null)) {
					return Outcome.PRECISE;
				}
			}
		}
		catch (RuntimeException deleted) {
			// A symbol deleted in the same transaction cannot be inspected.
		}
		return Outcome.UNKNOWN;
	}
}
