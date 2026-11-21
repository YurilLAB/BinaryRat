// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
package binaryrat;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;

/**
 * The function-entry selector of the headless scripts: {@code HEX} in the default address space,
 * or {@code SPACE:HEX} (also {@code SPACE::HEX}, as Ghidra shows overlay addresses) in a named
 * one. Overlay spaces repeat the offsets of other spaces, and banked code often repeats
 * function names too, so a function in an overlay bank may only be selectable by its space.
 */
public final class EntryAddress {
	private static final Pattern SELECTOR =
		Pattern.compile("(?:([^:\\s]+)::?)?(?:0[xX])?([0-9a-fA-F]{1,16})");

	private EntryAddress() {
	}

	/** Whether a selector has the form of an address (it may still name no address). */
	public static boolean matches(String selector) {
		return selector != null && SELECTOR.matcher(selector).matches();
	}

	/** The address a selector names; IllegalArgumentException when it names none. */
	public static Address parse(Program program, String selector) {
		Matcher matcher = SELECTOR.matcher(selector == null ? "" : selector);
		if (!matcher.matches()) {
			throw new IllegalArgumentException("function entry must be HEX or SPACE:HEX");
		}
		String name = matcher.group(1);
		AddressSpace space = name == null ? program.getAddressFactory().getDefaultAddressSpace() :
			program.getAddressFactory().getAddressSpace(name);
		if (space == null || !space.isMemorySpace()) {
			throw new IllegalArgumentException("no memory address space named " + name);
		}
		long offset = Long.parseUnsignedLong(matcher.group(2), 16);
		try {
			Address address = space.getAddress(offset);
			if (address.getOffset() == offset) {
				return address;
			}
		}
		catch (AddressOutOfBoundsException outside) {
			// Reported below.
		}
		throw new IllegalArgumentException("function entry does not fit the " + space.getName() + " space");
	}
}
