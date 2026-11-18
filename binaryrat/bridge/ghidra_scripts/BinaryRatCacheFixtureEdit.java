// Rename one function in a disposable project between cache test runs.
// @category BinaryRat.Tests
/* Copyright 2026 YurilLAB. SPDX-License-Identifier: Apache-2.0 */

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;

public class BinaryRatCacheFixtureEdit extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (!isRunningHeadless() || currentProgram == null || args.length != 4 ||
                !args[0].equalsIgnoreCase(currentProgram.getExecutableSHA256()) ||
                !args[3].matches("binaryrat_reopened_[0-9a-f]{16}")) {
            throw new IllegalArgumentException("Expected the disposable fixture's SHA256, " +
                "address space, entry offset and generated name");
        }
        AddressSpace space = currentProgram.getAddressFactory().getAddressSpace(args[1]);
        if (space == null) {
            throw new IllegalArgumentException("Unknown address space " + args[1]);
        }
        Function function = currentProgram.getFunctionManager().getFunctionAt(
            space.getAddress(Long.parseUnsignedLong(args[2], 16)));
        if (function == null || function.isExternal() || function.isThunk()) {
            throw new IllegalArgumentException("Expected a local, non-thunk function");
        }
        function.setName(args[3], SourceType.USER_DEFINED);
        println("BinaryRat fixture function renamed: " + args[3]);
    }
}
