// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package binaryrat;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * Talks to one {@code binaryrat-engine serve} process over its JSON-lines protocol.
 * Requests may be outstanding concurrently: responses are matched by id, and lease
 * events are handed to the listener registered for that lease. Thread safe.
 */
public final class EngineClient implements AutoCloseable {
	private final Process process;
	private final BufferedWriter input;
	private final Map<String, CompletableFuture<JsonObject>> pending = new ConcurrentHashMap<>();
	private final Map<String, Consumer<JsonObject>> leaseListeners = new ConcurrentHashMap<>();
	private final AtomicLong ids = new AtomicLong();
	private final Thread reader;
	private volatile IOException failure;

	private EngineClient(Process process) {
		this.process = process;
		this.input = new BufferedWriter(
			new OutputStreamWriter(process.getOutputStream(), StandardCharsets.UTF_8));
		this.reader = new Thread(this::readResponses, "binaryrat-engine-reader");
		this.reader.setDaemon(true);
		this.reader.start();
	}

	/** Starts the engine with its own cache directory. */
	public static EngineClient start(Path engine, Path cacheDirectory) throws IOException {
		ProcessBuilder builder = new ProcessBuilder(engine.toString(), "serve", "--cache",
			cacheDirectory.toString());
		builder.redirectError(ProcessBuilder.Redirect.INHERIT);
		EngineClient client = new EngineClient(builder.start());
		JsonObject ping = client.call("ping", new JsonObject());
		if (!ping.has("capabilities") ||
			!ping.get("capabilities").toString().contains("\"lease-scheduler\"")) {
			client.close();
			throw new IOException("engine does not offer the lease scheduler: " + ping);
		}
		return client;
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
				CompletableFuture<JsonObject> waiting =
					id == null || id.isJsonNull() ? null : pending.remove(id.getAsString());
				if (waiting == null) {
					continue;
				}
				if (message.get("ok").getAsBoolean()) {
					waiting.complete(message.getAsJsonObject("result"));
				}
				else {
					waiting.completeExceptionally(
						new IOException("engine refused request: " + message.get("error")));
				}
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

	/** Sends a request; the future completes with its result. */
	public CompletableFuture<JsonObject> send(String op, JsonObject fields) {
		String id = Long.toString(ids.incrementAndGet());
		JsonObject request = fields.deepCopy();
		request.addProperty("id", id);
		request.addProperty("op", op);
		CompletableFuture<JsonObject> result = new CompletableFuture<>();
		pending.put(id, result);
		IOException failed = failure;
		if (failed != null) {
			pending.remove(id);
			result.completeExceptionally(failed);
			return result;
		}
		try {
			synchronized (input) {
				input.write(request.toString());
				input.write('\n');
				input.flush();
			}
		}
		catch (IOException exception) {
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
