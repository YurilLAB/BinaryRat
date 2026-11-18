// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package binaryrat;

import com.google.gson.JsonObject;

import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;

/** The part of an export record that comes from the decompiler, and the part that is cached. */
public record DecompOutput(boolean completed, boolean timedOut, boolean cancelled,
		boolean failedToStart, String error, String prototype, String c) {

	public static DecompOutput of(DecompileResults results) {
		DecompiledFunction decompiled = results.getDecompiledFunction();
		return new DecompOutput(results.decompileCompleted(), results.isTimedOut(),
			results.isCancelled(), results.failedToStart(), orEmpty(results.getErrorMessage()),
			decompiled == null ? "" : orEmpty(decompiled.getSignature()),
			decompiled == null ? "" : orEmpty(decompiled.getC()));
	}

	/** A decompilation the engine stopped before it finished. */
	public static DecompOutput stopped(DecompileResults results, String status, String reason) {
		DecompOutput output = of(results);
		if ("completed".equals(status)) {
			// The lease ended normally; preserve a native timeout/startup failure
			// instead of relabelling every incomplete native result as cancelled.
			return output;
		}
		boolean timedOut = "timed_out".equals(status) || "timeout".equals(reason);
		String error = "memory_exceeded".equals(status) ?
			"BinaryRat: the decompiler process exceeded its memory reservation" :
			"cancelled".equals(status) ? "BinaryRat: decompilation was cancelled" :
			timedOut ? "BinaryRat: decompilation exceeded its lease deadline" : output.error();
		// An engine stop is authoritative even if native output completed in the
		// cancellation race. Never publish or cache output from a stopped lease.
		return new DecompOutput(false, timedOut, !timedOut, output.failedToStart(), error,
			"", "");
	}

	/** Only finished decompilations are worth caching; the rest depend on timing. */
	public boolean cacheable() {
		return completed && !timedOut && !cancelled && !failedToStart;
	}

	private static String orEmpty(String value) {
		return value == null ? "" : value;
	}

	public JsonObject toJson() {
		JsonObject json = new JsonObject();
		json.addProperty("completed", completed);
		json.addProperty("timed_out", timedOut);
		json.addProperty("cancelled", cancelled);
		json.addProperty("failed_to_start", failedToStart);
		json.addProperty("error", error);
		json.addProperty("prototype", prototype);
		json.addProperty("c", c);
		return json;
	}

	public static DecompOutput fromJson(JsonObject json) {
		return new DecompOutput(json.get("completed").getAsBoolean(),
			json.get("timed_out").getAsBoolean(), json.get("cancelled").getAsBoolean(),
			json.get("failed_to_start").getAsBoolean(), json.get("error").getAsString(),
			json.get("prototype").getAsString(), json.get("c").getAsString());
	}
}
