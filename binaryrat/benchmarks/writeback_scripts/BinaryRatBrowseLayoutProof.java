// Exercise the installed layout browser model on a reopened disposable Program.
//@category BinaryRat.Tests

// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Objects;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

import binaryrat.writeback.LayoutEvidenceBrowser;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitorAdapter;

public class BinaryRatBrowseLayoutProof extends GhidraScript {
    private record Site(Address address, Address function, int offset, int width,
            String operation, long order, boolean bytesVerified) {}

    @Override
    protected void run() throws Exception {
        String[] reports = getScriptArgs();
        if (!isRunningHeadless() || reports.length == 0) {
            throw new IllegalArgumentException("Use a reopened disposable project and a real packed layout report");
        }
        end(true);
        require(currentProgram.getCurrentTransactionInfo() == null,
            "the browser fixture must start outside a Program transaction");
        long revision = currentProgram.getModificationNumber();
        String undo = currentProgram.getUndoName();
        int rows = 0;
        for (String report : reports) {
            rows += checkRows(Path.of(report), true);
        }
        Path direct = Path.of(reports[0]);
        JsonObject artifact = json(direct);
        Path copy = Files.createTempFile("binaryrat-browse-proof", ".json");
        try {
            JsonObject wrongProgram = artifact.deepCopy();
            wrongProgram.addProperty("program_id", "sha256:" + "0".repeat(64));
            Files.writeString(copy, wrongProgram.toString());
            reject(copy, "different executable or architecture");

            JsonObject missing = artifact.deepCopy();
            JsonObject observation = missing.getAsJsonArray("observations").get(0).getAsJsonObject();
            Address original = address(observation.get("address_space").getAsString(),
                observation.get("address").getAsString());
            Address unmapped = original.getAddressSpace().getMaxAddress();
            require(!currentProgram.getMemory().contains(unmapped), "negative address is mapped");
            String offset = Long.toUnsignedString(unmapped.getOffset(), 16);
            String oldId = observation.get("evidence_id").getAsString();
            String prefix = oldId.substring(0, oldId.lastIndexOf('/', oldId.lastIndexOf('/') - 1) + 1);
            String newId = prefix + offset + "/" + observation.get("pcode_order").getAsLong();
            observation.addProperty("address", offset);
            observation.addProperty("evidence_id", newId);
            boolean replaced = false;
            for (var field : missing.getAsJsonArray("layouts").get(0).getAsJsonObject().getAsJsonArray("fields")) {
                var ids = field.getAsJsonObject().getAsJsonArray("evidence_ids");
                for (int i = 0; i < ids.size(); i++) {
                    if (oldId.equals(ids.get(i).getAsString())) {
                        ids.set(i, new JsonPrimitive(newId));
                        replaced = true;
                    }
                }
            }
            require(replaced, "observation was not cited by the real report");
            Files.writeString(copy, missing.toString());
            reject(copy, "must cite a current instruction");

            JsonObject changedBytes = artifact.deepCopy();
            var evidence = changedBytes.getAsJsonArray("observations").get(0).getAsJsonObject();
            String hash = evidence.get("instruction_sha256").getAsString();
            evidence.addProperty("instruction_sha256", (hash.startsWith("0") ? "1" : "0") + hash.substring(1));
            Files.writeString(copy, changedBytes.toString());
            reject(copy, "Instruction bytes differ");
            evidence.remove("instruction_sha256");
            Files.writeString(copy, changedBytes.toString());
            require(checkRows(copy, false) > 0, "legacy observation could not be inspected");

            JsonObject localOnly = artifact.deepCopy();
            localOnly.remove("follow_depth");
            localOnly.remove("forwarded_calls");
            for (var item : localOnly.getAsJsonArray("observations")) {
                var local = item.getAsJsonObject();
                local.remove("instruction_sha256");
                local.remove("function_address_space");
                local.remove("function_address");
            }
            Files.writeString(copy, localOnly.toString());
            require(checkRows(copy, false) > 0, "legacy local report could not be inspected");
        }
        finally {
            Files.deleteIfExists(copy);
        }
        var cancelled = new TaskMonitorAdapter(true);
        cancelled.cancel();
        try {
            LayoutEvidenceBrowser.read(currentProgram, direct, cancelled);
            throw new AssertionError("Browser ignored a cancelled monitor");
        }
        catch (CancelledException expected) {
            // A cancelled read must not expose a partial table.
        }
        require(revision == currentProgram.getModificationNumber(), "browser changed the Program revision");
        require(Objects.equals(undo, currentProgram.getUndoName()), "browser changed native undo history");
        require(currentProgram.getCurrentTransactionInfo() == null, "browser left a transaction open");

        var row = LayoutEvidenceBrowser.read(currentProgram, direct, monitor).rows().get(0);
        var listing = currentProgram.getListing();
        var instruction = listing.getInstructionAt(row.address());
        int tx = currentProgram.startTransaction("Temporarily remove an evidence instruction");
        try {
            checkRows(direct, true);
            listing.clearCodeUnits(row.address(), instruction.getMaxAddress(), false);
            require(listing.getInstructionAt(row.address()) == null, "stale fixture setup failed");
            long edited = currentProgram.getModificationNumber();
            reject(direct, "must cite a current instruction");
            require(edited == currentProgram.getModificationNumber(), "stale read changed the Program");
        }
        finally {
            currentProgram.endTransaction(tx, false);
        }
        require(checkRows(direct, true) > 0 && Objects.equals(undo, currentProgram.getUndoName()),
            "rollback did not restore the valid evidence and native undo history");
        println("BINARYRAT_BROWSE_LAYOUT_OK reports=" + reports.length + " rows=" + rows);
    }

    private int checkRows(Path path, boolean requireHashes) throws Exception {
        JsonObject report = json(path);
        JsonObject root = report.getAsJsonObject("function");
        var expect = new HashSet<Site>();
        for (var element : report.getAsJsonArray("observations")) {
            JsonObject obs = element.getAsJsonObject();
            var site = address(obs.get("address_space").getAsString(), obs.get("address").getAsString());
            boolean hasHash = obs.has("instruction_sha256");
            require(!requireHashes || hasHash, "newly generated report omitted the instruction digest");
            if (hasHash) {
                var instruction = currentProgram.getListing().getInstructionAt(site);
                String digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(instruction.getParsedBytes()));
                require(digest.equals(obs.get("instruction_sha256").getAsString()),
                    "report digest differs from the saved instruction bytes");
            }
            Address owner = obs.has("function_address") ?
                address(obs.get("function_address_space").getAsString(), obs.get("function_address").getAsString()) :
                address(root.get("address_space").getAsString(), root.get("address").getAsString());
            expect.add(new Site(site, owner,
                obs.get("offset").getAsInt(), obs.get("width").getAsInt(),
                obs.get("operation").getAsString(), obs.get("pcode_order").getAsLong(), hasHash));
        }
        var review = LayoutEvidenceBrowser.read(currentProgram, path, monitor);
        require(review.functionName().equals(root.get("name").getAsString()) &&
            review.parameterIndex() == report.get("parameter_index").getAsInt() &&
            review.revision() == currentProgram.getModificationNumber(), "wrong function, parameter or revision");
        require(!expect.isEmpty(), "expected at least one real p-code observation");
        for (var row : review.rows()) {
            var owner = currentProgram.getFunctionManager().getFunctionContaining(row.address());
            require(currentProgram.getListing().getInstructionAt(row.address()) != null &&
                owner != null && owner.getEntryPoint().equals(row.functionEntry()) &&
                owner.getName(true).equals(row.functionName()) && !row.overlaps(),
                "row did not resolve to a current instruction in its owning function");
            require(expect.remove(new Site(row.address(), row.functionEntry(), row.offset(),
                row.width(), row.operation(), row.pcodeOrder(), row.instructionBytesVerified())),
                "duplicate or incorrect evidence row or instruction verification status");
        }
        require(expect.isEmpty(), "missing evidence rows");
        return review.rows().size();
    }

    private Address address(String space, String offset) {
        return currentProgram.getAddressFactory().getAddressSpace(space)
            .getAddress(Long.parseUnsignedLong(offset, 16));
    }

    private static JsonObject json(Path path) throws IOException {
        return JsonParser.parseString(Files.readString(path)).getAsJsonObject();
    }

    private void reject(Path report, String reason) throws Exception {
        try {
            LayoutEvidenceBrowser.read(currentProgram, report, monitor);
            throw new AssertionError("Browser returned an invalid navigation target");
        }
        catch (IOException expected) {
            require(expected.getMessage().contains(reason), "unrelated rejection: " + expected.getMessage());
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
