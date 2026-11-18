// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package binaryrat;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;

import ghidra.app.decompiler.DecompileOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PatchPackedEncode;
import ghidra.program.model.pcode.PcodeDataTypeManager;

/**
 * Asks the current program every question a recorded decompilation asked and checks
 * that every answer is unchanged. When they all are, the decompiler would compute the
 * same output, so the cached output is still correct. Not thread safe; one per thread.
 */
public final class TraceVerifier {
	private final Program program;
	private final PcodeDataTypeManager dataTypes;
	private final RecordingCallback callback;

	public TraceVerifier(Program program, DecompileOptions options) {
		this.program = program;
		this.dataTypes = new PcodeDataTypeManager(program, options.getNameTransformer());
		this.callback = new RecordingCallback(program, program.getLanguage(),
			program.getCompilerSpec(), dataTypes);
	}

	/** Why a trace failed to verify, or null when it verified. */
	public String verify(Function function, List<String> reads, String digest) {
		if (function == null) {
			return "the function no longer exists";
		}
		Comparator comparator = new Comparator(reads);
		dataTypes.clearTemporaryIds();
		callback.setSink(null);
		callback.setFunction(function, function.getEntryPoint(), null);
		callback.setSink(comparator);
		try {
			for (String read : reads) {
				comparator.expect(read);
				try {
					replay(read);
				}
				catch (Mismatch mismatch) {
					return mismatch.getMessage();
				}
				catch (Exception exception) {
					// The decompiler saw recorded failures too; the comparator has the answer.
				}
				if (comparator.mismatch != null) {
					return comparator.mismatch;
				}
				if (!comparator.answered) {
					return "no answer replayed for " + read;
				}
			}
		}
		catch (RuntimeException exception) {
			return "replay failed: " + exception;
		}
		finally {
			callback.setSink(null);
		}
		String replayed = Trace.hex(comparator.combined.digest(), 32);
		return replayed.equals(digest) ? null : "sequence digest differs";
	}

	private static final class Mismatch extends RuntimeException {
		Mismatch(String message) {
			super(message, null, false, false);
		}
	}

	private static final class Comparator implements RecordingCallback.Sink {
		final MessageDigest combined = Trace.sha256();
		final List<String> reads;
		String expected;
		boolean answered;
		String mismatch;

		Comparator(List<String> reads) {
			this.reads = reads;
		}

		void expect(String read) {
			expected = read;
			answered = false;
		}

		@Override
		public boolean recordsDependencies() {
			return false;
		}

		@Override
		public void answer(String request, byte[] digest) {
			if (answered) {
				// Nested queries do not happen; a second answer means a diverged replay.
				mismatch = "unexpected extra answer " + request;
				throw new Mismatch(mismatch);
			}
			answered = true;
			String actual = Trace.record(request, digest);
			if (!actual.equals(expected)) {
				mismatch = "answer changed: " + expected + " -> " + actual;
				throw new Mismatch(mismatch);
			}
			Trace.fold(combined, request, digest);
		}
	}

	private Address address(String encoded) {
		if (encoded.equals("~")) {
			return null;
		}
		if (encoded.equals("!none")) {
			return Address.NO_ADDRESS;
		}
		int split = encoded.indexOf(':');
		AddressSpace space = program.getAddressFactory()
				.getAddressSpace(RecordingCallback.untext(encoded.substring(0, split)));
		if (space == null) {
			throw new Mismatch("address space vanished: " + encoded);
		}
		return space.getAddress(Long.parseUnsignedLong(encoded.substring(split + 1), 16));
	}

	private static PatchPackedEncode encoder() {
		PatchPackedEncode encoder = new PatchPackedEncode();
		encoder.clear();
		return encoder;
	}

	private void replay(String read) throws Exception {
		String[] fields = read.split("\\|", -1);
		// The last field is the recorded answer digest.
		String[] args = Arrays.copyOfRange(fields, 1, fields.length - 1);
		switch (fields[0]) {
			case "B" -> callback.getBytes(address(args[0]), Integer.parseInt(args[1]));
			case "C" -> callback.getComments(address(args[0]), Integer.parseInt(args[1]), encoder());
			case "P" -> callback.getPcode(address(args[0]), encoder());
			case "I" -> callback.getPcodeInject(RecordingCallback.untext(args[0]),
				RecordingCallback.Tape.replaying(args[2], program.getAddressFactory()),
				Integer.parseInt(args[1]), encoder());
			case "K" -> {
				long[] refs = new long[args.length];
				for (int index = 0; index < args.length; index++) {
					refs[index] = Long.parseUnsignedLong(args[index], 16);
				}
				callback.getCPoolRef(refs, encoder());
			}
			case "L" -> callback.getCodeLabel(address(args[0]));
			case "U" -> callback.isNameUsed(RecordingCallback.untext(args[0]),
				Long.parseLong(args[1]), Long.parseLong(args[2]));
			case "N" -> callback.getNamespacePath(Long.parseLong(args[0]), encoder());
			case "M" -> callback.getMappedSymbols(address(args[0]), encoder());
			case "E" -> callback.getExternalRef(address(args[0]), encoder());
			case "T" -> callback.getDataType(RecordingCallback.untext(args[0]),
				Long.parseLong(args[1]), encoder());
			case "R" -> callback.getRegister(RecordingCallback.untext(args[0]), encoder());
			case "G" -> callback.getRegisterName(address(args[0]), Integer.parseInt(args[1]));
			case "X" -> callback.getTrackedRegisters(address(args[0]), encoder());
			case "O" -> callback.getUserOpName(Integer.parseInt(args[0]));
			case "S" -> callback.getStringData(address(args[0]), Integer.parseInt(args[1]),
				RecordingCallback.untext(args[2]), Long.parseLong(args[3]));
			default -> throw new Mismatch("unknown recorded query " + read);
		}
	}
}
