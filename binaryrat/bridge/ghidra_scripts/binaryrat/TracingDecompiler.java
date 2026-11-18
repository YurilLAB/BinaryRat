// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package binaryrat;

import java.io.IOException;
import java.lang.reflect.Field;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;

import ghidra.app.decompiler.*;
import generic.jar.ResourceFile;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.UniqueLayout;
import ghidra.framework.Application;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.XmlEncode;
import ghidra.util.task.TaskMonitor;

/**
 * A stock DecompInterface whose program queries are recorded. Nothing about the
 * decompilation changes: the recording callback answers every query by delegating
 * to Ghidra's own callback and only observes the answers.
 */
public final class TracingDecompiler extends DecompInterface {
	private RecordingCallback recorder;

	/** The output of one decompilation and everything it read. */
	public record Traced(DecompileResults results, Trace trace) {
	}

	@Override
	protected void initializeProcess() throws IOException, DecompileException {
		// openProgram() installs Ghidra's callback and then initializes the process;
		// swap in the recording subclass before the program is registered with it.
		if (decompCallback != null && !(decompCallback instanceof RecordingCallback)) {
			recorder = new RecordingCallback(program, getLanguage(), program.getCompilerSpec(),
				getDataTypeManager());
			decompCallback = recorder;
		}
		super.initializeProcess();
	}

	public synchronized Traced decompile(Function function, int timeoutSeconds,
			TaskMonitor monitor) {
		if (recorder == null) {
			throw new IllegalStateException("openProgram() must succeed first");
		}
		Trace trace = new Trace();
		recorder.setSink(trace);
		try {
			return new Traced(decompileFunction(function, timeoutSeconds, monitor), trace);
		}
		finally {
			recorder.setSink(null);
		}
	}

	/**
	 * Starts the native process if it is not running and returns its PID, or -1 when it
	 * cannot be determined. The PID lets the engine watch the process's memory.
	 */
	public synchronized long processId() {
		try {
			verifyProcess();
			Field field = DecompileProcess.class.getDeclaredField("nativeProcess");
			field.setAccessible(true);
			Object nativeProcess = field.get(decompProcess);
			return nativeProcess instanceof Process process && process.isAlive() ? process.pid() : -1;
		}
		catch (Exception exception) {
			return -1;
		}
	}

	/**
	 * Digest of everything this decompiler sent the native process when it registered
	 * the program: translator, core types, processor and compiler specifications,
	 * options and actions. Results cached under one digest are only valid for a
	 * decompiler registered with exactly the same inputs.
	 */
	public synchronized String registrationDigest() throws IOException {
		MessageDigest digest = Trace.sha256();
		SleighLanguage language = (SleighLanguage) getLanguage();
		XmlEncode encode = new XmlEncode(false);
		language.encodeTranslator(encode, program.getAddressFactory(),
			UniqueLayout.SLEIGH_BASE.getOffset(language));
		add(digest, "translator", encode.toString());
		encode.clear();
		getDataTypeManager().encodeCoreTypes(encode);
		add(digest, "core-types", encode.toString());
		encode.clear();
		add(digest, "pspec", new String(specFile(language).getInputStream().readAllBytes(),
			StandardCharsets.UTF_8));
		getCompilerSpec().encode(encode);
		add(digest, "cspec", encode.toString());
		encode.clear();
		getOptions().encode(encode, this);
		add(digest, "options", encode.toString());
		add(digest, "actions", getSimplificationStyle() + "|c|tree");
		add(digest, "decompiler", getMajorVersion() + "." + getMinorVersion());
		add(digest, "ghidra", Application.getApplicationVersion());
		return Trace.hex(digest.digest(), 32);
	}

	/** The processor specification file; its description class moved packages in 12.2. */
	private static ResourceFile specFile(SleighLanguage language) throws IOException {
		Object description = language.getLanguageDescription();
		try {
			return (ResourceFile) description.getClass().getMethod("getSpecFile").invoke(description);
		}
		catch (ReflectiveOperationException exception) {
			throw new IOException("cannot locate the processor specification", exception);
		}
	}

	private static void add(MessageDigest digest, String label, String value) {
		digest.update(label.getBytes(StandardCharsets.UTF_8));
		digest.update((byte) 0);
		byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
		digest.update(Long.toString(bytes.length).getBytes(StandardCharsets.UTF_8));
		digest.update((byte) 0);
		digest.update(bytes);
	}
}
