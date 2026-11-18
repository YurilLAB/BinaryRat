// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package binaryrat;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

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
	}

	private final EngineClient engine;
	private final Program program;
	private final ChangeTracker tracker;
	private final String programId;
	private final ThreadLocal<TraceVerifier> verifiers;
	private volatile String registration;

	public LiveDecompileCache(EngineClient engine, Program program, ChangeTracker tracker,
			DecompileOptions options, String programId, String registration) {
		this.engine = engine;
		this.program = program;
		this.tracker = tracker;
		this.programId = programId;
		this.registration = registration;
		this.verifiers = ThreadLocal.withInitial(() -> new TraceVerifier(program, options));
	}

	/** Re-keys the cache after something the decompiler registered with changed. */
	public void setRegistration(String registration) {
		this.registration = registration;
	}

	JsonObject key(Function function) {
		Address entry = function.getEntryPoint();
		JsonObject key = new JsonObject();
		key.addProperty("schema_version", 2);
		key.addProperty("ghidra_version", Application.getApplicationVersion());
		key.addProperty("kind", "decompile");
		key.addProperty("program_id", programId);
		key.addProperty("address_space", entry.getAddressSpace().getName());
		key.addProperty("address", Long.toUnsignedString(entry.getOffset(), 16));
		key.addProperty("options_digest", registration);
		return key;
	}

	/**
	 * Looks a function up. With audit set, even an entry the engine vouches for is
	 * replayed, and a failed replay of such an entry is reported in {@code rejected}
	 * with kind HIT: that would be a missed change, i.e. a stale result served.
	 */
	public Lookup lookup(Function function, boolean audit) throws IOException {
		tracker.sync();
		JsonObject request = new JsonObject();
		request.add("key", key(function));
		JsonObject found = engine.call("cache.get", request);
		long seq = found.get("seq").getAsLong();
		if (!found.get("hit").getAsBoolean()) {
			return new Lookup(Kind.MISS, null, seq, null);
		}
		JsonObject value = found.getAsJsonObject("value");
		DecompOutput output = DecompOutput.fromJson(value.getAsJsonObject("output"));
		boolean vouched = found.get("verified").getAsBoolean() &&
			!value.get("always_verify").getAsBoolean();
		if (vouched && !audit) {
			return new Lookup(Kind.HIT, output, seq, null);
		}
		List<String> reads = new ArrayList<>();
		for (JsonElement read : value.getAsJsonArray("reads")) {
			reads.add(read.getAsString());
		}
		String why = verifiers.get().verify(function, reads, value.get("reads_sha256").getAsString());
		if (why == null) {
			JsonObject confirm = new JsonObject();
			confirm.add("key", key(function));
			confirm.addProperty("seq", seq);
			confirm.addProperty("generation", found.get("generation").getAsLong());
			engine.call("cache.confirm", confirm);
			return new Lookup(vouched ? Kind.HIT : Kind.REPLAYED, output, seq, null);
		}
		JsonObject evict = new JsonObject();
		evict.add("key", key(function));
		engine.call("cache.evict", evict);
		return new Lookup(vouched ? Kind.HIT : Kind.MISS, vouched ? output : null, seq, why);
	}

	/**
	 * Stores a finished decompilation. asOf is the seq from the lookup made before
	 * decompiling; modification is the program's modification number at that time.
	 */
	public boolean store(Function function, DecompOutput output, Trace trace, long asOf,
			long modification) throws IOException {
		if (!output.cacheable() || !trace.replayable() ||
			program.getModificationNumber() != modification) {
			return false;
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
		engine.call("cache.put", request);
		return true;
	}

	public JsonObject stats() throws IOException {
		return engine.call("cache.stats", new JsonObject());
	}
}
