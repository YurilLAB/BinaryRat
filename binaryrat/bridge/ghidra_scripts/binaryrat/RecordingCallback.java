// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package binaryrat;

import java.io.IOException;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.DecompileCallback;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;

/**
 * The decompiler's view of the program, recorded. The native decompiler learns about
 * the program only through these callback queries, so the sequence of queries and
 * the answers given is everything a decompilation read. Each answer goes to a
 * {@link Sink}: while decompiling, a {@link Trace}; while checking a cached result,
 * the {@link TraceVerifier} that compares it with what was recorded.
 */
public class RecordingCallback extends DecompileCallback {
	/** Receives each query (as a canonical request string) and the digest of its answer. */
	public interface Sink {
		void answer(String request, byte[] digest) throws IOException;

		/** Program facts the answer depended on; ignored while verifying. */
		default void depends(Address start, long length) {
		}

		default void dependsOnName(String name) {
		}

		/** The answer may depend on facts no event reports precisely. */
		default void unpredictable(String why) {
		}
	}

	private final Program program;
	private final CompilerSpec compilerSpec;
	private Sink sink;

	public RecordingCallback(Program program, Language language, CompilerSpec compilerSpec,
			PcodeDataTypeManager dataTypes) {
		super(program, language, compilerSpec, dataTypes);
		this.program = program;
		this.compilerSpec = compilerSpec;
	}

	/** Directs answers to the sink until the next call; null stops recording. */
	public void setSink(Sink sink) {
		this.sink = sink;
	}

	@Override
	public void setFunction(Function func, Address entry, ghidra.app.decompiler.DecompileDebug dbg) {
		super.setFunction(func, entry, dbg);
		if (sink != null && func != null) {
			for (AddressRange range : func.getBody()) {
				sink.depends(range.getMinAddress(), range.getLength());
			}
			sink.depends(entry, 1);
		}
	}

	// ---- canonical encodings ------------------------------------------------------

	static String address(Address address) {
		if (address == null) {
			return "~";
		}
		if (address == Address.NO_ADDRESS) {
			return "!none";
		}
		return text(address.getAddressSpace().getName()) + ":" +
			Long.toUnsignedString(address.getOffset(), 16);
	}

	static String text(String value) {
		if (value == null) {
			return "~";
		}
		StringBuilder escaped = new StringBuilder(value.length() + 8);
		for (int index = 0; index < value.length(); index++) {
			char ch = value.charAt(index);
			if (ch == '%' || ch == '|' || ch == '~' || ch == ':' || ch == ',' || ch < 0x20) {
				escaped.append('%').append(String.format("%04x", (int) ch));
			}
			else {
				escaped.append(ch);
			}
		}
		return escaped.toString();
	}

	static String untext(String value) {
		if (value.equals("~")) {
			return null;
		}
		StringBuilder plain = new StringBuilder(value.length());
		for (int index = 0; index < value.length(); index++) {
			char ch = value.charAt(index);
			if (ch == '%') {
				plain.append((char) Integer.parseInt(value.substring(index + 1, index + 5), 16));
				index += 4;
			}
			else {
				plain.append(ch);
			}
		}
		return plain.toString();
	}

	private static MessageDigest sha256() {
		try {
			return MessageDigest.getInstance("SHA-256");
		}
		catch (Exception exception) {
			throw new IllegalStateException(exception);
		}
	}

	private static byte[] digest(String tag, byte[] body) {
		MessageDigest digest = sha256();
		digest.update(tag.getBytes(StandardCharsets.UTF_8));
		digest.update((byte) 0);
		if (body != null) {
			digest.update(body);
		}
		return digest.digest();
	}

	private static byte[] encoded(Encoder encoder) throws IOException {
		if (!(encoder instanceof CachedEncoder cached)) {
			throw new IOException("unexpected decompiler encoder " + encoder.getClass().getName());
		}
		java.io.ByteArrayOutputStream bytes = new java.io.ByteArrayOutputStream();
		cached.writeTo(bytes);
		return bytes.toByteArray();
	}

	private byte[] failed(Throwable thrown) {
		if (sink != null) {
			// A failure can precede dependency collection, and may reflect state
			// outside the event footprint. Its recorded answer must replay each time.
			sink.unpredictable("failed callback: " + thrown.getClass().getName());
		}
		return digest("thrown", (thrown.getClass().getName() + ":" + thrown.getMessage())
				.getBytes(StandardCharsets.UTF_8));
	}

	private void answer(String request, byte[] digest) {
		try {
			sink.answer(request, digest);
		}
		catch (IOException exception) {
			throw new java.io.UncheckedIOException(exception);
		}
	}

	private void encodedAnswer(String request, Encoder encoder) throws IOException {
		answer(request, digest("encoded", encoded(encoder)));
	}

	private void dependsOnSymbolsAt(Address addr) {
		if (addr == null) {
			return;
		}
		sink.depends(addr, 1);
		Listing listing = program.getListing();
		Function containing = listing.getFunctionContaining(addr);
		if (containing != null) {
			sink.depends(containing.getEntryPoint(), 1);
			Function thunked = containing.getThunkedFunction(true);
			if (thunked != null) {
				sink.depends(thunked.getEntryPoint(), 1);
			}
			dependsOnNamespace(containing.getParentNamespace());
		}
		Data data = listing.getDataContaining(addr);
		if (data != null) {
			sink.depends(data.getMinAddress(), data.getLength());
			Reference primary = data.getPrimaryReference(0);
			if (primary != null) {
				sink.depends(primary.getToAddress(), 1);
				Function target = listing.getFunctionAt(primary.getToAddress());
				if (target != null) {
					sink.depends(target.getEntryPoint(), 1);
				}
			}
		}
		Symbol primarySymbol = program.getSymbolTable().getPrimarySymbol(addr);
		if (primarySymbol != null) {
			dependsOnNamespace(primarySymbol.getParentNamespace());
		}
	}

	private void dependsOnNamespace(Namespace namespace) {
		while (namespace != null && !namespace.isGlobal()) {
			Symbol symbol = namespace.getSymbol();
			if (symbol != null) {
				sink.depends(symbol.getAddress(), 1);
				sink.dependsOnName(symbol.getName());
			}
			namespace = namespace.getParentNamespace();
		}
	}

	// ---- recorded queries -----------------------------------------------------------

	@Override
	public byte[] getBytes(Address addr, int size) {
		byte[] result = super.getBytes(addr, size);
		if (sink != null) {
			sink.depends(addr, Math.max(size, 1));
			answer("B|" + address(addr) + "|" + size, digest("bytes", result));
		}
		return result;
	}

	@Override
	public void getComments(Address addr, int types, Encoder resultEncoder) throws IOException {
		try {
			super.getComments(addr, types, resultEncoder);
		}
		catch (IOException | RuntimeException exception) {
			if (sink != null) {
				answer("C|" + address(addr) + "|" + types, failed(exception));
			}
			throw exception;
		}
		if (sink != null) {
			Function owner = program.getListing().getFunctionAt(addr);
			if (owner != null) {
				for (AddressRange range : owner.getBody()) {
					sink.depends(range.getMinAddress(), range.getLength());
				}
			}
			sink.depends(addr, 1);
			encodedAnswer("C|" + address(addr) + "|" + types, resultEncoder);
		}
	}

	@Override
	public void getPcode(Address addr, PatchEncoder resultEncoder) {
		super.getPcode(addr, resultEncoder);
		if (sink != null) {
			Instruction instruction = program.getListing().getInstructionAt(addr);
			sink.depends(addr, instruction == null ? 32 : Math.max(instruction.getLength(), 1));
			try {
				encodedAnswer("P|" + address(addr), resultEncoder);
			}
			catch (IOException exception) {
				throw new java.io.UncheckedIOException(exception);
			}
		}
	}

	@Override
	public void getPcodeInject(String nm, Decoder paramDecoder, int type, Encoder resultEncoder)
			throws DecoderException, UnknownInstructionException, IOException,
			ghidra.program.model.mem.MemoryAccessException, ghidra.util.exception.NotFoundException {
		if (sink == null) {
			super.getPcodeInject(nm, paramDecoder, type, resultEncoder);
			return;
		}
		Tape tape = Tape.recording(paramDecoder);
		String request = null;
		try {
			super.getPcodeInject(nm, tape.decoder(), type, resultEncoder);
			request = "I|" + text(nm) + "|" + type + "|" + tape.serialize();
		}
		catch (DecoderException | UnknownInstructionException | IOException |
				ghidra.program.model.mem.MemoryAccessException |
				ghidra.util.exception.NotFoundException | RuntimeException exception) {
			answer("I|" + text(nm) + "|" + type + "|" + tape.serialize(), failed(exception));
			throw exception;
		}
		dependsOnInjection(nm, type, tape);
		encodedAnswer(request, resultEncoder);
	}

	private void dependsOnInjection(String nm, int type, Tape tape) {
		PcodeInjectLibrary library = compilerSpec.getPcodeInjectLibrary();
		InjectPayload payload = library.getPayload(type, nm);
		if (!staticInjectionTemplate(payload)) {
			// Dynamic Java/Dalvik and extension payloads can themselves subclass the
			// SLEIGH payload classes while reading arbitrary Program state. Such reads
			// need replay, not an instanceof-based promise of precise invalidation.
			sink.unpredictable("injection payload " + nm);
			return;
		}
		try {
			InjectContext context = library.buildInjectContext();
			context.decode(Tape.replaying(tape.serialize(), program.getAddressFactory()));
			if (context.baseAddr != null) {
				sink.depends(context.baseAddr, 32);
			}
			if (context.callAddr != null) {
				sink.depends(context.callAddr, 1);
			}
		}
		catch (Exception exception) {
			sink.unpredictable("injection context " + nm);
		}
	}

	/** Only audited exact stock classes use the context/template-only implementation. */
	static boolean staticInjectionTemplate(InjectPayload payload) {
		if (payload == null) {
			return false;
		}
		Class<?> type = payload.getClass();
		return type == InjectPayloadSleigh.class || type == InjectPayloadCallfixup.class ||
			type == InjectPayloadCallother.class || type == InjectPayloadSegment.class ||
			type == InjectPayloadJumpAssist.class;
	}

	@Override
	public void getCPoolRef(long[] refs, Encoder resultEncoder) throws IOException {
		StringBuilder request = new StringBuilder("K");
		for (long ref : refs) {
			request.append('|').append(Long.toUnsignedString(ref, 16));
		}
		try {
			super.getCPoolRef(refs, resultEncoder);
		}
		catch (IOException | RuntimeException exception) {
			if (sink != null) {
				answer(request.toString(), failed(exception));
			}
			throw exception;
		}
		if (sink != null) {
			sink.unpredictable("constant pool");
			encodedAnswer(request.toString(), resultEncoder);
		}
	}

	@Override
	public String getCodeLabel(Address addr) throws IOException {
		String result;
		try {
			result = super.getCodeLabel(addr);
		}
		catch (IOException | RuntimeException exception) {
			if (sink != null) {
				answer("L|" + address(addr), failed(exception));
			}
			throw exception;
		}
		if (sink != null) {
			dependsOnSymbolsAt(addr);
			answer("L|" + address(addr), digest("string", result == null ? null :
				("=" + result).getBytes(StandardCharsets.UTF_8)));
		}
		return result;
	}

	@Override
	public boolean isNameUsed(String name, long startId, long stopId) {
		boolean result;
		try {
			result = super.isNameUsed(name, startId, stopId);
		}
		catch (RuntimeException exception) {
			if (sink != null) {
				answer("U|" + text(name) + "|" + startId + "|" + stopId, failed(exception));
			}
			throw exception;
		}
		if (sink != null) {
			sink.dependsOnName(name);
			answer("U|" + text(name) + "|" + startId + "|" + stopId,
				digest("bool", new byte[] { (byte) (result ? 1 : 0) }));
		}
		return result;
	}

	@Override
	public void getNamespacePath(long id, Encoder resultEncoder) throws IOException {
		try {
			super.getNamespacePath(id, resultEncoder);
		}
		catch (IOException | RuntimeException exception) {
			if (sink != null) {
				answer("N|" + id, failed(exception));
			}
			throw exception;
		}
		if (sink != null) {
			Symbol symbol = program.getSymbolTable().getSymbol(id);
			if (symbol != null && symbol.getObject() instanceof Namespace namespace) {
				dependsOnNamespace(namespace);
			}
			encodedAnswer("N|" + id, resultEncoder);
		}
	}

	@Override
	public void getMappedSymbols(Address addr, Encoder resultEncoder) throws IOException {
		try {
			super.getMappedSymbols(addr, resultEncoder);
		}
		catch (IOException | RuntimeException exception) {
			if (sink != null) {
				answer("M|" + address(addr), failed(exception));
			}
			throw exception;
		}
		if (sink != null) {
			dependsOnSymbolsAt(addr);
			encodedAnswer("M|" + address(addr), resultEncoder);
		}
	}

	@Override
	public void getExternalRef(Address addr, Encoder resultEncoder) throws IOException {
		try {
			super.getExternalRef(addr, resultEncoder);
		}
		catch (IOException | RuntimeException exception) {
			if (sink != null) {
				answer("E|" + address(addr), failed(exception));
			}
			throw exception;
		}
		if (sink != null) {
			dependsOnSymbolsAt(addr);
			encodedAnswer("E|" + address(addr), resultEncoder);
		}
	}

	@Override
	public void getDataType(String name, long id, Encoder resultEncoder) throws IOException {
		try {
			super.getDataType(name, id, resultEncoder);
		}
		catch (IOException | RuntimeException exception) {
			if (sink != null) {
				answer("T|" + text(name) + "|" + id, failed(exception));
			}
			throw exception;
		}
		if (sink != null) {
			encodedAnswer("T|" + text(name) + "|" + id, resultEncoder);
		}
	}

	@Override
	public void getRegister(String name, Encoder resultEncoder) throws IOException {
		try {
			super.getRegister(name, resultEncoder);
		}
		catch (IOException | RuntimeException exception) {
			if (sink != null) {
				answer("R|" + text(name), failed(exception));
			}
			throw exception;
		}
		if (sink != null) {
			encodedAnswer("R|" + text(name), resultEncoder);
		}
	}

	@Override
	public String getRegisterName(Address addr, int size) {
		String result = super.getRegisterName(addr, size);
		if (sink != null) {
			answer("G|" + address(addr) + "|" + size, digest("string", result == null ? null :
				("=" + result).getBytes(StandardCharsets.UTF_8)));
		}
		return result;
	}

	@Override
	public void getTrackedRegisters(Address addr, Encoder resultEncoder) throws IOException {
		try {
			super.getTrackedRegisters(addr, resultEncoder);
		}
		catch (IOException | RuntimeException exception) {
			if (sink != null) {
				answer("X|" + address(addr), failed(exception));
			}
			throw exception;
		}
		if (sink != null) {
			sink.depends(addr, 1);
			encodedAnswer("X|" + address(addr), resultEncoder);
		}
	}

	@Override
	public String getUserOpName(int index) {
		String result = super.getUserOpName(index);
		if (sink != null) {
			answer("O|" + index, digest("string", result == null ? null :
				("=" + result).getBytes(StandardCharsets.UTF_8)));
		}
		return result;
	}

	@Override
	public StringData getStringData(Address addr, int maxChars, String dtName, long dtId) {
		StringData result = super.getStringData(addr, maxChars, dtName, dtId);
		if (sink != null) {
			sink.depends(addr, Math.min(Math.max(maxChars, 1) * 4L + 8, 1L << 16));
			Data data = program.getListing().getDataContaining(addr);
			if (data != null) {
				sink.depends(data.getMinAddress(), data.getLength());
			}
			byte[] body = null;
			if (result != null) {
				body = new byte[result.byteData.length + 1];
				body[0] = (byte) (truncated(result) ? 1 : 0);
				System.arraycopy(result.byteData, 0, body, 1, result.byteData.length);
			}
			answer("S|" + address(addr) + "|" + maxChars + "|" + text(dtName) + "|" + dtId,
				digest("string-data", body));
		}
		return result;
	}

	private static final java.lang.reflect.Field TRUNCATED;
	static {
		try {
			TRUNCATED = StringData.class.getDeclaredField("isTruncated");
			TRUNCATED.setAccessible(true);
		}
		catch (ReflectiveOperationException exception) {
			throw new ExceptionInInitializerError(exception);
		}
	}

	/** The decompiler is sent this flag; Ghidra keeps the field package-private. */
	private static boolean truncated(StringData data) {
		try {
			return TRUNCATED.getBoolean(data);
		}
		catch (IllegalAccessException exception) {
			throw new IllegalStateException(exception);
		}
	}

	// ---- decoder tapes for injection queries ---------------------------------------

	/**
	 * Every call an injection makes on its parameter decoder, with the values returned,
	 * so the same injection context can be rebuilt later without the native process.
	 */
	static final class Tape implements InvocationHandler {
		private final Decoder real;
		private final List<String> calls;
		private final AddressFactory factory;
		private int next;
		private boolean replayable = true;

		private Tape(Decoder real, List<String> calls, AddressFactory factory) {
			this.real = real;
			this.calls = calls;
			this.factory = factory;
		}

		static Tape recording(Decoder real) {
			return new Tape(real, new ArrayList<>(), null);
		}

		static Decoder replaying(String serialized, AddressFactory factory) {
			List<String> calls = new ArrayList<>();
			if (!serialized.isEmpty()) {
				for (String call : serialized.split(",", -1)) {
					calls.add(untext(call));
				}
			}
			return new Tape(null, calls, factory).decoder();
		}

		Decoder decoder() {
			return (Decoder) Proxy.newProxyInstance(Decoder.class.getClassLoader(),
				new Class<?>[] { Decoder.class }, this);
		}

		String serialize() {
			if (!replayable) {
				return "!";
			}
			StringBuilder result = new StringBuilder();
			for (String call : calls) {
				if (result.length() > 0) {
					result.append(',');
				}
				result.append(text(call));
			}
			return result.toString();
		}

		private static String describe(Method method, Object[] args) {
			StringBuilder call = new StringBuilder(method.getName()).append('(');
			if (args != null) {
				for (Object arg : args) {
					if (arg instanceof AttributeId attribute) {
						call.append('a').append(attribute.id());
					}
					else if (arg instanceof ElementId element) {
						call.append('e').append(element.id());
					}
					else {
						call.append(arg);
					}
					call.append(';');
				}
			}
			return call.append(')').toString();
		}

		private static String value(Object result) {
			if (result == null) {
				return "n";
			}
			if (result instanceof Integer || result instanceof Long || result instanceof Boolean) {
				return result.getClass().getSimpleName().charAt(0) + result.toString();
			}
			if (result instanceof String string) {
				return "s" + string;
			}
			if (result instanceof AddressSpace space) {
				return "p" + space.getName();
			}
			if (result instanceof AddressFactory) {
				return "f";
			}
			return null;
		}

		private Object restore(String encoded, Class<?> type) throws DecoderException {
			char kind = encoded.charAt(0);
			String body = encoded.substring(1);
			switch (kind) {
				case 'n':
					return null;
				case 'I':
					return Integer.valueOf(body);
				case 'L':
					return Long.valueOf(body);
				case 'B':
					return Boolean.valueOf(body);
				case 's':
					return body;
				case 'f':
					return factory;
				case 'p': {
					AddressSpace space = factory.getAddressSpace(body);
					if (space == null) {
						throw new DecoderException("unknown address space " + body);
					}
					return space;
				}
				default:
					throw new DecoderException("unreplayable decoder value for " + type);
			}
		}

		@Override
		public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
			if (method.getDeclaringClass() == Object.class) {
				return method.invoke(this, args);
			}
			String call = describe(method, args);
			if (real != null) {
				Object result;
				try {
					result = method.invoke(real, args);
				}
				catch (InvocationTargetException exception) {
					replayable = false;
					throw exception.getCause();
				}
				String value = value(result);
				if (value == null) {
					replayable = false;
				}
				calls.add(call + "=" + value);
				return result;
			}
			if (next >= calls.size()) {
				throw new DecoderException("decoder tape exhausted at " + call);
			}
			String recorded = calls.get(next++);
			int split = recorded.indexOf(")=");
			if (split < 0 || !recorded.substring(0, split + 1).equals(call)) {
				throw new DecoderException("decoder tape diverged: " + call + " vs " + recorded);
			}
			return restore(recorded.substring(split + 2), method.getReturnType());
		}
	}
}
