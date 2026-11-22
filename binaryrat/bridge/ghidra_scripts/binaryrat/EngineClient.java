// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package binaryrat;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonWriter;

import ghidra.framework.Application;
import ghidra.framework.OSFileNotFoundException;
import ghidra.framework.Platform;

/**
 * Talks to one {@code binaryrat-engine serve} process over its JSON-lines protocol.
 * Requests may be outstanding concurrently: responses are matched by id, and lease
 * events are handed to the listener registered for that lease. Thread safe.
 */
public final class EngineClient implements AutoCloseable {
	// Native serve() accepts 16 MiB per UTF-8 frame (excluding its newline).
	private static final int MAX_FRAME_BYTES = 16 * 1024 * 1024;
	// Match maximum_json_depth in native/src/json_depth.hpp, including the request object.
	private static final int MAX_JSON_DEPTH = 64;
	// Disk records add a SHA-256 checksum and a small envelope around the same fields.
	private static final int CACHE_ENVELOPE_BYTES = 256;
	private static final TypeAdapter<JsonElement> JSON = new Gson().getAdapter(JsonElement.class);

	private final Process process;
	private final OutputStream input;
	private final Map<String, CompletableFuture<JsonObject>> pending = new ConcurrentHashMap<>();
	private final Map<String, Consumer<JsonObject>> leaseListeners = new ConcurrentHashMap<>();
	private final AtomicLong ids = new AtomicLong();
	private final Thread reader;
	private volatile IOException failure;

	private EngineClient(Process process) {
		this.process = process;
		this.input = process.getOutputStream();
		this.reader = new Thread(this::readResponses, "binaryrat-engine-reader");
		this.reader.setDaemon(true);
		this.reader.start();
	}

	/** Uses the configured engine, or the executable shipped with this extension. */
	public static Path findExecutable() {
		String value = System.getenv("BINARYRAT_ENGINE");
		Path engine;
		if (value == null || value.isBlank()) {
			String name = "binaryrat-engine" + Platform.CURRENT_PLATFORM.getExecutableExtension();
			try {
				engine = Application.getOSFile("BinaryRat", name).toPath();
			}
			catch (OSFileNotFoundException missing) {
				throw new IllegalArgumentException("Install the BinaryRat extension for this platform " +
					"or set BINARYRAT_ENGINE to the binaryrat-engine executable", missing);
			}
		}
		else {
			engine = Path.of(value).toAbsolutePath().normalize();
		}
		if (!Files.isRegularFile(engine) || !Files.isExecutable(engine)) {
			throw new IllegalArgumentException("BinaryRat engine is not an executable file: " + engine);
		}
		return engine;
	}

	/** Starts the engine with its own cache directory. */
	public static EngineClient start(Path engine, Path cacheDirectory) throws IOException {
		ProcessBuilder builder = new ProcessBuilder(engine.toString(), "serve", "--cache",
			cacheDirectory.toString());
		builder.redirectError(ProcessBuilder.Redirect.INHERIT);
		EngineClient client = new EngineClient(builder.start());
		try {
			JsonObject ping = client.call("ping", new JsonObject());
			if (!ping.has("capabilities") ||
				!ping.get("capabilities").toString().contains("\"lease-scheduler\"")) {
				throw new IOException("engine does not offer the lease scheduler: " + ping);
			}
			return client;
		}
		catch (IOException | RuntimeException failure) {
			try {
				client.close();
			}
			catch (IOException cleanup) {
				failure.addSuppressed(cleanup);
			}
			throw failure;
		}
	}

	private void readResponses() {
		IOException ended = new IOException("engine closed its output");
		try (BufferedReader output = new BufferedReader(
			new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
			String line;
			while ((line = output.readLine()) != null) {
				JsonObject message = JsonParser.parseString(line).getAsJsonObject();
				if (message.has("event")) {
					Consumer<JsonObject> listener =
						leaseListeners.get(message.get("lease").getAsString());
					if (listener != null) {
						listener.accept(message);
					}
					continue;
				}
				JsonElement id = message.get("id");
				if (id == null || id.isJsonNull()) {
					throw new IOException("engine response has no request id");
				}
				String responseId = id.getAsString();
				// Keep this owner visible to connection cleanup until the entire reply is parsed.
				CompletableFuture<JsonObject> waiting = pending.get(responseId);
				if (waiting == null) {
					continue;
				}
				if (message.get("ok").getAsBoolean()) {
					JsonObject result = message.getAsJsonObject("result");
					if (result == null) throw new IOException("engine response has no result");
					waiting.complete(result);
				}
				else {
					waiting.completeExceptionally(Refused.of(message.get("error")));
				}
				pending.remove(responseId);
			}
		}
		catch (IOException | RuntimeException exception) {
			ended = new IOException("engine connection failed", exception);
		}
		failure = ended;
		for (CompletableFuture<JsonObject> waiting : pending.values()) {
			waiting.completeExceptionally(ended);
		}
		pending.clear();
	}

	/**
	 * The engine answered with an error: this request failed, but the connection is intact and
	 * later requests are answered. Any other IOException from a call means the connection
	 * itself failed or timed out.
	 */
	public static final class Refused extends IOException {
		private final String code;
		private final String detail;

		private Refused(String code, String detail, String error) {
			super("engine refused request: " + error);
			this.code = code;
			this.detail = detail;
		}

		static Refused of(JsonElement error) {
			String code = "unknown";
			String detail = String.valueOf(error);
			if (error != null && error.isJsonObject()) {
				JsonObject object = error.getAsJsonObject();
				if (object.has("code") && object.get("code").isJsonPrimitive()) {
					code = object.get("code").getAsString();
				}
				if (object.has("message") && object.get("message").isJsonPrimitive()) {
					detail = object.get("message").getAsString();
				}
			}
			return new Refused(code, detail, String.valueOf(error));
		}

		/** The protocol error code, such as {@code invalid_request} or {@code operation_failed}. */
		public String code() {
			return code;
		}

		/** The engine's own description of the failure. */
		public String detail() {
			return detail;
		}
	}

	static final class FrameTooLarge extends IOException {
		FrameTooLarge(int limit) {
			super("engine request exceeds " + limit + " UTF-8 bytes");
		}
	}

	/** Fully encode and check a frame before sending any of it. */
	static ByteArrayOutputStream encodeRequest(JsonObject request, int limit) throws IOException {
		ByteArrayOutputStream bytes = new ByteArrayOutputStream();
		OutputStream bounded = new OutputStream() {
			@Override
			public void write(int value) throws IOException {
				if (bytes.size() == limit) throw new FrameTooLarge(limit);
				bytes.write(value);
			}

			@Override
			public void write(byte[] data, int start, int length) throws IOException {
				if (length > limit - bytes.size()) throw new FrameTooLarge(limit);
				bytes.write(data, start, length);
			}
		};
		// OutputStreamWriter.write(String, ...) copies the entire slice into a char[].
		// Feed it bounded char buffers even for a single very large C string.
		try (JsonWriter json = new JsonWriter(new BufferedWriter(
			new OutputStreamWriter(bounded, StandardCharsets.UTF_8), 1024)) {
			private int depth;

			private void beginContainer() throws IOException {
				if (++depth > MAX_JSON_DEPTH) {
					throw new IOException("engine request nests deeper than " + MAX_JSON_DEPTH + " levels");
				}
			}

			@Override
			public JsonWriter beginArray() throws IOException {
				beginContainer();
				return super.beginArray();
			}

			@Override
			public JsonWriter endArray() throws IOException {
				depth--;
				return super.endArray();
			}

			@Override
			public JsonWriter beginObject() throws IOException {
				beginContainer();
				return super.beginObject();
			}

			@Override
			public JsonWriter endObject() throws IOException {
				depth--;
				return super.endObject();
			}
		}) {
			JSON.write(json, request);
		}
		return bytes;
	}

	/** Sends a request; the future completes with its result. */
	public CompletableFuture<JsonObject> send(String op, JsonObject fields) {
		String id = Long.toString(ids.incrementAndGet());
		JsonObject request = new JsonObject();
		fields.entrySet().forEach(entry -> request.add(entry.getKey(), entry.getValue()));
		request.addProperty("id", id);
		request.addProperty("op", op);
		CompletableFuture<JsonObject> result = new CompletableFuture<>();
		IOException failed = failure;
		if (failed != null) {
			result.completeExceptionally(failed);
			return result;
		}
		try {
			int limit = "cache.put".equals(op) ?
				MAX_FRAME_BYTES - CACHE_ENVELOPE_BYTES : MAX_FRAME_BYTES;
			synchronized (input) {
				var bytes = encodeRequest(request, limit);
				pending.put(id, result);
				// The reader can fail while the request is being encoded.
				failed = failure;
				if (failed != null) throw failed;
				bytes.writeTo(input);
				input.write('\n');
				input.flush();
			}
		}
		catch (IOException | RuntimeException exception) {
			pending.remove(id);
			result.completeExceptionally(exception);
		}
		return result;
	}

	/** Sends a request and waits for its result. */
	public JsonObject call(String op, JsonObject fields) throws IOException {
		return await(send(op, fields), 60);
	}

	/** Waits for a result, turning failures into IOExceptions. */
	public static JsonObject await(CompletableFuture<JsonObject> result, long seconds)
			throws IOException {
		try {
			return seconds > 0 ? result.get(seconds, TimeUnit.SECONDS) : result.get();
		}
		catch (InterruptedException exception) {
			Thread.currentThread().interrupt();
			throw new IOException("interrupted while waiting for the engine", exception);
		}
		catch (ExecutionException exception) {
			Throwable cause = exception.getCause();
			throw cause instanceof IOException io ? io : new IOException(cause);
		}
		catch (TimeoutException exception) {
			throw new IOException("engine did not answer in " + seconds + " seconds", exception);
		}
	}

	public void onLease(String lease, Consumer<JsonObject> listener) {
		leaseListeners.put(lease, listener);
	}

	public void forgetLease(String lease) {
		leaseListeners.remove(lease);
	}

	@Override
	public void close() throws IOException {
		try {
			synchronized (input) {
				input.close();
			}
		}
		finally {
			try {
				if (!process.waitFor(30, TimeUnit.SECONDS)) {
					process.destroyForcibly();
				}
			}
			catch (InterruptedException exception) {
				process.destroyForcibly();
				Thread.currentThread().interrupt();
			}
		}
	}
}
