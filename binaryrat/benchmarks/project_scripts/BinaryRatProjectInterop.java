// Save and check representative analyst work in a disposable 12.2 local project.
//@category BinaryRat.Tests

// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;

public class BinaryRatProjectInterop extends GhidraScript {
    private static final String FIXTURE_SHA256 =
        "8f25756a9fa0229fb8d24425dc3cbc9e31a692f489a25e43ff3ea54029c864a5";
    private static final String NOTE = "Reviewed dispatch\nOwner: Ren\u00e9";
    private static final CategoryPath CATEGORY = new CategoryPath("/Investigation");

    @Override
    public AnalysisMode getScriptAnalysisMode() {
        return AnalysisMode.DISABLED;
    }

    @Override
    protected void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (!isRunningHeadless() || arguments.length != 1 ||
                !FIXTURE_SHA256.equals(currentProgram.getExecutableSHA256()) ||
                !currentProgram.getLanguageID().toString().equals("x86:LE:64:default")) {
            throw new IllegalArgumentException("Expected the disposable x86-64 project fixture");
        }
        Address entry = currentProgram.getMinAddress();
        Address record = entry.add(8);
        switch (arguments[0]) {
            case "seed" -> seed(entry, record);
            case "read" -> end(true); // Close the script transaction before inspecting the Program.
            default -> throw new IllegalArgumentException("Expected seed or read");
        }
        long before = currentProgram.getModificationNumber();
        verify(entry, record);
        require(before == currentProgram.getModificationNumber(), "read changed Program revision");
        println("BINARYRAT_PROJECT_INTEROP_VERIFIED " + arguments[0]);
    }

    private void seed(Address entry, Address record) throws Exception {
        require(disassemble(entry), "disassembly");
        var function = currentProgram.getFunctionManager().createFunction("decode_record", entry,
            new AddressSet(entry, entry.add(1)), SourceType.USER_DEFINED);
        function.setReturnType(WordDataType.dataType, SourceType.USER_DEFINED);

        var type = new StructureDataType(CATEGORY, "Record", 0);
        type.add(ByteDataType.dataType, "tag", null);
        type.add(WordDataType.dataType, "length", "wire byte count");
        var savedType = currentProgram.getDataTypeManager().addDataType(type, null);
        currentProgram.getListing().createData(record, savedType);
        currentProgram.getSymbolTable().createLabel(record, "captured_record", SourceType.USER_DEFINED);
        currentProgram.getListing().setComment(entry, CommentType.PLATE, NOTE);
        currentProgram.getBookmarkManager().setBookmark(entry, BookmarkType.NOTE, "Triage", "Reviewed");
        currentProgram.getReferenceManager().addMemoryReference(entry, record, RefType.READ,
            SourceType.USER_DEFINED, Reference.MNEMONIC);
    }

    private void verify(Address entry, Address record) {
        var listing = currentProgram.getListing();
        var function = currentProgram.getFunctionManager().getFunctionAt(entry);
        require(function != null && "decode_record".equals(function.getName()) &&
            function.getSymbol().getSource() == SourceType.USER_DEFINED &&
            function.getBody().equals(new AddressSet(entry, entry.add(1))) &&
            WordDataType.dataType.isEquivalent(function.getReturnType()) &&
            function.getSignatureSource() == SourceType.USER_DEFINED, "named function and signature");
        require(NOTE.equals(listing.getComment(CommentType.PLATE, entry)), "multiline listing comment");
        var bookmark = currentProgram.getBookmarkManager().getBookmark(entry, BookmarkType.NOTE, "Triage");
        require(bookmark != null && "Reviewed".equals(bookmark.getComment()), "triage bookmark");
        var label = currentProgram.getSymbolTable().getPrimarySymbol(record);
        require(label != null && "captured_record".equals(label.getName()) &&
            label.getSource() == SourceType.USER_DEFINED, "user label");
        var reference = currentProgram.getReferenceManager().getReference(entry, record,
            Reference.MNEMONIC);
        require(reference != null && reference.getReferenceType() == RefType.READ &&
            reference.getSource() == SourceType.USER_DEFINED, "analyst cross-reference");

        var type = currentProgram.getDataTypeManager().getDataType(CATEGORY, "Record");
        var data = listing.getDefinedDataAt(record);
        require(type instanceof Structure && data != null &&
            type.equals(data.getDataType()) && data.getLength() == 3, "applied structure");
        var fields = ((Structure) type).getDefinedComponents();
        require(fields.length == 2, "structure field count");
        require(fields[0].getOffset() == 0 && fields[0].getLength() == 1 &&
            "tag".equals(fields[0].getFieldName()) &&
            ByteDataType.dataType.isEquivalent(fields[0].getDataType()), "tag field");
        require(fields[1].getOffset() == 1 && fields[1].getLength() == 2 &&
            "length".equals(fields[1].getFieldName()) &&
            WordDataType.dataType.isEquivalent(fields[1].getDataType()) &&
            "wire byte count".equals(fields[1].getComment()), "length field");
    }

    private static void require(boolean condition, String item) {
        if (!condition) {
            throw new IllegalStateException("Analyst fixture mismatch: " + item);
        }
    }
}
