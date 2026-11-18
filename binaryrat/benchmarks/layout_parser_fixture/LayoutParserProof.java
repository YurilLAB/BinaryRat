// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package binaryrat.writeback;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Random;

import com.google.gson.JsonObject;
import ghidra.program.model.listing.InstructionStub;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/** Exercises the packaged decoder and byte witnesses without starting a Ghidra project. */
public class LayoutParserProof {
	private static final int SEED = 7823;

	private static JsonObject parse(byte[] input) throws IOException, CancelledException {
		return LayoutReport.parseReport(input, TaskMonitor.DUMMY);
	}

	private static byte[] utf8(String text) {
		return text.getBytes(StandardCharsets.UTF_8);
	}

	private static void require(boolean result, String message) {
		if (!result) {
			throw new AssertionError(message);
		}
	}

	private interface Check {
		void run() throws Exception;
	}

	private static void reject(Check check) throws Exception {
		try {
			check.run();
		}
		catch (IOException expected) {
			return;
		}
		throw new AssertionError("Accepted invalid input");
	}

	private static JsonObject mutations() throws Exception {
		var random = new Random(SEED);
		int accepted = 0;
		int rejected = 0;
		for (int i = 0; i < 500; i++) {
			int offset = random.nextInt(1 << 20);
			String operation = random.nextBoolean() ? "LOAD" : "STORE";
			String object = "{\"schema_version\":1,\"observations\":[{\"operation\":\"" + operation +
				"\",\"offset\":" + offset + "}]}";
			var parsed = parse(utf8(object));
			var row = parsed.getAsJsonArray("observations").get(0).getAsJsonObject();
			require(row.get("offset").getAsInt() == offset &&
				row.get("operation").getAsString().equals(operation), "Changed a valid observation");
			String invalid = switch (i % 4) {
				case 0 -> object + "{}";
				case 1 -> object.substring(0, object.length() - 1);
				case 2 -> object.replace("\"offset\":", "\"offset\":0,\"offset\":");
				default -> object.replace("\"operation\":", "operation:");
			};
			reject(() -> parse(utf8(invalid)));
			for (int j = 0; j < 4; j++) {
				byte[] mutated = utf8(object);
				mutated[random.nextInt(mutated.length)] ^= (byte) (1 + random.nextInt(255));
				JsonObject result;
				try {
					result = parse(mutated);
				}
				catch (IOException expected) {
					rejected++;
					continue;
				}
				require(result.equals(parse(utf8(result.toString()))), "Accepted JSON did not round-trip");
				accepted++;
			}
		}
		require(accepted > 0 && rejected > 0, "Mutations missed one decoder outcome");
		var stats = new JsonObject();
		stats.addProperty("seed", SEED);
		stats.addProperty("valid_controls", 500);
		stats.addProperty("invalid_controls", 500);
		stats.addProperty("mutations_accepted", accepted);
		stats.addProperty("mutations_rejected", rejected);
		return stats;
	}

	private static void limits() throws Exception {
		var file = Files.createTempFile("layout-parser", ".json");
		try {
			Files.write(file, utf8("{}"));
			require(LayoutReport.readReport(file, 2).length == 2, "Rejected a file at its byte limit");
			reject(() -> LayoutReport.readReport(file, 1));
		}
		finally {
			Files.deleteIfExists(file);
		}
		reject(() -> parse(new byte[] { (byte) 0xff }));
		reject(() -> parse(utf8("{\"x\":" + "[".repeat(64) + "0" + "]".repeat(64) + "}")));
		reject(() -> parse(utf8("{\"x\":[" + "0,".repeat(262_144) + "0]}")));
		var monitor = new TaskMonitorAdapter() {
			private int calls;

			@Override
			public void checkCancelled() throws CancelledException {
				if (++calls == 2) {
					throw new CancelledException();
				}
			}
		};
		try {
			LayoutReport.parseReport(utf8("{\"x\":[" + "0,".repeat(1024) + "0]}"), monitor);
		}
		catch (CancelledException expected) {
			return;
		}
		throw new AssertionError("Decoder ignored cancellation during parsing");
	}

	private static InstructionStub instruction(int parsedLength, String parsedBytes) {
		return new InstructionStub() {
			@Override
			public int getParsedLength() {
				return parsedLength;
			}

			@Override
			public byte[] getParsedBytes() {
				return utf8(parsedBytes);
			}
		};
	}

	private static void fingerprints() throws Exception {
		var row = new JsonObject();
		require(!LayoutReport.verifyInstructionBytes(row, null), "Claimed verification without a digest");
		row.addProperty("instruction_sha256", "bad");
		reject(() -> LayoutReport.verifyInstructionBytes(row, instruction(3, "abc")));
		row.addProperty("instruction_sha256", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
		require(LayoutReport.verifyInstructionBytes(row, instruction(3, "abc")), "SHA-256 control failed");
		reject(() -> LayoutReport.verifyInstructionBytes(row, instruction(3, "abd")));
		reject(() -> LayoutReport.verifyInstructionBytes(row, instruction(2, "abc")));
		reject(() -> LayoutReport.verifyInstructionBytes(row, instruction(65_537, "abc")));
		reject(() -> LayoutReport.verifyInstructionBytes(row, new InstructionStub() {
			@Override
			public int getParsedLength() {
				return 3;
			}

			@Override
			public byte[] getParsedBytes() throws MemoryAccessException {
				throw new MemoryAccessException("Fixture has no readable bytes");
			}
		}));
		reject(() -> LayoutReport.verifyInstructionBytes(row, null));
	}

	public static void main(String[] args) throws Exception {
		limits();
		fingerprints();
		System.out.println(mutations());
	}
}
