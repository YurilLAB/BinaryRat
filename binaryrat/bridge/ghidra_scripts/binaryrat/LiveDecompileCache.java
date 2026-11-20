// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package binaryrat;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ArrayBlockingQueue;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.app.decompiler.DecompileOptions;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

/**
 * Decompiler output cached in the engine and kept correct while the program changes.
 *
 * <p>Each entry holds the output and the trace of what the decompilation read. The
 * {@link ChangeTracker} reports changes, and the engine removes the entries that read
 * what changed. An entry the engine cannot vouch for (a change of unknown reach, an
 * earlier session) is replayed against the current program before it is used, and is
 * removed if any answer differs.
 *
 * <p>The cache is optional: when the engine refuses a cache request (its disk is full, a
 * scanner holds a record file) the decompilation is computed or kept uncached, and the
 * refusal is reported, never thrown. Only a failed connection to the engine is thrown. If a
 * refusal leaves an entry the engine vouched for that is known to be wrong, every entry is
 * made unverified; if the engine refuses that too, this cache stops serving for the session.
 */
public final class LiveDecompileCache {
	public enum Kind {
		/** No change since it was stored or checked can have affected it. */
		HIT,
		/** Unverified, replayed against the program, and still exact. */
		REPLAYED,
		/** Nothing usable cached. */
		MISS
	}

	public record Lookup(Kind kind, DecompOutput output, long seq, String rejected) {
		public boolean usable() {
			return kind != Kind.MISS && output != null && output.cacheable() && rejected == null;
		}
	}

	private final EngineClient engine;
	private final Program program;
	private final ChangeTracker tracker;
	private final String programId;
	// Desktop and Python workers can outlive several Programs. Keep each replay
	// verifier with its cache owner rather than in the borrowing thread's state.
	private final ArrayBlockingQueue<TraceVerifier> verifiers = new ArrayBlockingQueue<>(64);
	private final DecompileOptions options;
	private volatile String registration;
	// Why this cache no longer serves or stores anything, or null while it does.
	private volatile String disabled;

	public LiveDecompileCache(EngineClient engine, Program program, ChangeTracker tracker,
			DecompileOptions options, String programId, String registration) {
		this.engine = engine;
		this.program = program;
		this.tracker = tracker;
		this.programId = programId;
		this.registration = registration;
		this.options = options;
	}

	/** Re-keys the cache after something the decompiler registered with changed. */
	public void setRegistration(String registration) {
		this.registration = registration;
	}

	JsonObject key(Function function) {
		return key(function, registration);
	}

	private JsonObject key(Function function, String registered) {
		Address entry = function.getEntryPoint();
		JsonObject key = new JsonObject();
		key.addProperty("schema_version", 2);
		key.addProperty("ghidra_version", Application.getApplicationVersion());
		key.addProperty("kind", "decompile");
		key.addProperty("program_id", programId);
		key.addProperty("address_space", entry.getAddressSpace().getName());
		key.addProperty("address", Long.toUnsignedString(entry.getOffset(), 16));
		key.addProperty("options_digest", registered);
		return key;
	}

	private boolean unchanged(long modification, String registered) {
		return program.getModificationNumber() == modification &&
			Objects.equals(registration, registered);
	}

	/**
	 * Looks a function up. With audit set, even an entry the engine vouches for is
	 * replayed, and a failed replay of such an entry is reported in {@code rejected}
	 * with kind HIT: that would be a missed change, i.e. a stale result served.
	 */
	public Lookup lookup(Function function, boolean audit) throws IOException {
		String off = disabled;
		if (off != null) {
			return new Lookup(Kind.MISS, null, 0, off);
		}
		long modification = program.getModificationNumber();
		String registered = registration;
		JsonObject lookupKey = key(function, registered);
		JsonObject found;
		try {
			tracker.sync();
			JsonObject request = new JsonObject();
			request.add("key", lookupKey);
			found = engine.call("cache.get", request);
		}
		catch (EngineClient.Refused refused) {
			// Sequence 0 makes a later store of this function's fresh output pessimistic:
			// any journaled change to what it read leaves that entry unverified.
			return new Lookup(Kind.MISS, null, 0, refusal("cache.get", refused));
		}
		long seq = found.get("seq").getAsLong();
		if (!unchanged(modification, registered)) {
			return new Lookup(Kind.MISS, null, seq, "program or registration changed during lookup");
		}
		if (!found.get("hit").getAsBoolean()) {
			return new Lookup(Kind.MISS, null, seq, null);
		}
		JsonObject value = found.getAsJsonObject("value");
		DecompOutput output = DecompOutput.fromJson(value.getAsJsonObject("output"));
		boolean vouched = found.get("verified").getAsBoolean() &&
			!value.get("always_verify").getAsBoolean();
		if (vouched && !audit) {
			return unchanged(modification, registered) ? new Lookup(Kind.HIT, output, seq, null) :
				new Lookup(Kind.MISS, null, seq, "program or registration changed before cache hit");
		}
		List<String> reads = new ArrayList<>();
		for (JsonElement read : value.getAsJsonArray("reads")) {
			reads.add(read.getAsString());
		}
		TraceVerifier verifier = verifiers.poll();
		if (verifier == null) {
			verifier = new TraceVerifier(program, options);
		}
		String why;
		try {
			why = verifier.verify(function, reads, value.get("reads_sha256").getAsString());
		}
		finally {
			verifiers.offer(verifier);
		}
		if (!unchanged(modification, registered)) {
			return new Lookup(Kind.MISS, null, seq, "program or registration changed during replay");
		}
		if (why == null) {
			JsonObject confirm = new JsonObject();
			confirm.add("key", lookupKey);
			confirm.addProperty("seq", seq);
			confirm.addProperty("generation", found.get("generation").getAsLong());
			JsonObject confirmed;
			try {
				confirmed = engine.call("cache.confirm", confirm);
			}
			catch (EngineClient.Refused refused) {
				return new Lookup(Kind.MISS, null, seq, refusal("cache.confirm", refused));
			}
			if (!confirmed.get("confirmed").getAsBoolean()) {
				return new Lookup(Kind.MISS, null, seq, "cache generation changed during replay");
			}
			if (!unchanged(modification, registered)) {
				return new Lookup(Kind.MISS, null, seq, "program or registration changed during confirmation");
			}
			return new Lookup(vouched ? Kind.HIT : Kind.REPLAYED, output, seq, null);
		}
		JsonObject evict = new JsonObject();
		evict.add("key", lookupKey);
		try {
			engine.call("cache.evict", evict);
		}
		catch (EngineClient.Refused refused) {
			// The entry stays in the engine. Unverified, it is replayed again before any use
			// and fails again. One the engine still vouches for would be served as it is by
			// the next lookup without an audit, so the engine must stop vouching for anything.
			why = why + "; " + refusal("cache.evict", refused);
			if (vouched) {
				distrustAll(why);
			}
		}
		if (!unchanged(modification, registered)) {
			return new Lookup(Kind.MISS, null, seq, "program or registration changed before replay rejection");
		}
		// Only an explicit audit can reach this vouched-but-invalid diagnostic. Normal
		// lookups never knowingly serve a failed replay; the negative control needs
		// the old output to prove that the omitted change would have served stale C.
		return new Lookup(vouched ? Kind.HIT : Kind.MISS, vouched ? output : null, seq, why);
	}

	/** Makes every entry unverified; if the engine refuses, stops using this cache. */
	private void distrustAll(String why) throws IOException {
		JsonObject all = new JsonObject();
		all.addProperty("all", true);
		try {
			engine.call("cache.changed", all);
		}
		catch (EngineClient.Refused refused) {
			disabled = "cache disabled for this session: " + why + "; " + refusal("cache.changed", refused);
		}
	}

	private static String refusal(String operation, EngineClient.Refused refused) {
		String detail = refused.detail();
		return "engine refused " + operation + " (" + refused.code() + "): " +
			(detail.length() <= 200 ? detail : detail.substring(0, 200) + "...");
	}

	/** Why this cache stopped serving for the session, or null while it serves. */
	public String disabledReason() {
		return disabled;
	}

	/**
	 * Stores a finished decompilation. asOf is the seq from the lookup made before
	 * decompiling; modification is the program's modification number at that time.
	 * Returns whether the entry was stored; {@link #put} also says why not.
	 */
	public boolean store(Function function, DecompOutput output, Trace trace, long asOf,
			long modification) throws IOException {
		return put(function, output, trace, asOf, modification) == null;
	}

	/**
	 * Stores a finished decompilation like {@link #store}. Returns null when it was stored,
	 * otherwise why it was not; the output itself stays valid for the caller either way.
	 */
	public String put(Function function, DecompOutput output, Trace trace, long asOf,
			long modification) throws IOException {
		String off = disabled;
		if (off != null) {
			return off;
		}
		if (!output.cacheable()) {
			return "output is not cacheable";
		}
		if (!trace.replayable()) {
			return "trace is not replayable";
		}
		if (program.getModificationNumber() != modification) {
			return "program changed during decompilation";
		}
		JsonObject value = new JsonObject();
		value.add("output", output.toJson());
		JsonArray reads = new JsonArray();
		trace.reads().forEach(reads::add);
		value.add("reads", reads);
		value.addProperty("reads_sha256", trace.digest());
		value.addProperty("always_verify", !trace.unpredictable().isEmpty());
		JsonArray dependencies = new JsonArray();
		trace.dependencies().forEach(dependencies::add);
		JsonObject request = new JsonObject();
		request.add("key", key(function));
		request.add("value", value);
		request.add("dependencies", dependencies);
		request.addProperty("as_of", asOf);
		try {
			engine.call("cache.put", request);
			return null;
		}
		catch (EngineClient.FrameTooLarge oversized) {
			// The completed decompilation is still usable by the caller.
			return "entry exceeds the engine request size limit";
		}
		catch (EngineClient.Refused refused) {
			// A failed write adds nothing the engine would serve: the old record and its
			// dependencies stay as they were, or a replaced but unindexed record is dropped
			// on its next read (live_cache.cpp put and get).
			return refusal("cache.put", refused);
		}
	}

	public JsonObject stats() throws IOException {
		return engine.call("cache.stats", new JsonObject());
	}
}
