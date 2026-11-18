// Check whole-Program inventory sensitivity on a disposable no-return fixture.
// @category BinaryRat.Tests
/* Copyright 2026 YurilLAB. SPDX-License-Identifier: Apache-2.0 */

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.symbol.SourceType;

public class BinaryRatInventoryProof extends BinaryRatAnalysisProfile {
    private record Mark(Address address, String type, String category, String comment) {}

    @Override
    public AnalysisMode getScriptAnalysisMode() {
        return AnalysisMode.DISABLED;
    }

    @Override
    public void run() throws Exception {
        if (!isRunningHeadless() || getScriptArgs().length != 1) {
            throw new IllegalArgumentException("Expected a disposable Program and an output path");
        }
        var base = currentProgram.getMinAddress();
        var local = currentProgram.getFunctionManager().createFunction("inventory_probe", base,
            new AddressSet(base), SourceType.ANALYSIS);
        var external = currentProgram.getExternalManager().addExtFunction("probe_library",
            "inventory_probe", null, SourceType.ANALYSIS).getFunction();
        var baseline = inventoryDigest();
        var seen = new HashSet<>(List.of(baseline));
        for (var function : List.of(local, external)) {
            function.setNoReturn(true);
            require(seen.add(inventoryDigest()), "No-return flag missing for " + function);
            function.setNoReturn(false);
            require(baseline.equals(inventoryDigest()), "No-return reset failed for " + function);
        }

        var extAddress = external.getEntryPoint();
        var address = base.getAddressSpace().getAddress(extAddress.getOffset());
        var marks = List.of(
            new Mark(address, BookmarkType.ANALYSIS, "fixture", "inferred"),
            new Mark(address.add(1), BookmarkType.ANALYSIS, "fixture", "inferred"),
            new Mark(extAddress, BookmarkType.ANALYSIS, "fixture", "inferred"),
            new Mark(address, BookmarkType.WARNING, "fixture", "inferred"),
            new Mark(address, BookmarkType.ANALYSIS, "other", "inferred"),
            new Mark(address, BookmarkType.ANALYSIS, "fixture", "inferred Ω"));
        var manager = currentProgram.getBookmarkManager();
        for (var mark : marks) {
            var bookmark = add(mark);
            require(seen.add(inventoryDigest()), "Bookmark field missing for " + mark);
            manager.removeBookmark(bookmark);
            require(baseline.equals(inventoryDigest()), "Bookmark removal changed baseline");
        }
        // The last variant replaces the first bookmark's comment, so exclude it here.
        var distinct = marks.subList(0, marks.size() - 1);
        var handles = distinct.stream().map(this::add).toList();
        var ordered = inventoryDigest();
        handles.forEach(manager::removeBookmark);
        distinct.reversed().forEach(this::add);
        require(ordered.equals(inventoryDigest()), "Bookmark insertion order changed inventory");
        Files.writeString(Path.of(getScriptArgs()[0]), ordered);
        println("BINARYRAT_INVENTORY_PROOF passed");
    }

    private Bookmark add(Mark mark) {
        return currentProgram.getBookmarkManager().setBookmark(mark.address(), mark.type(),
            mark.category(), mark.comment());
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }
}
