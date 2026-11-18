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
		if (output.completed()) {
			return output;
		}
		boolean timedOut = "timed_out".equals(status) || "timeout".equals(reason);
		String error = "memory_exceeded".equals(status) ?
			"BinaryRat: the decompiler process exceeded its memory reservation" :
			output.error();
		return new DecompOutput(false, timedOut, !timedOut, output.failedToStart(), error,
			output.prototype(), output.c());
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
