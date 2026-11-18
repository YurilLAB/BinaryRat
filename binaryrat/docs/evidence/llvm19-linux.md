# LLVM 19 large-file decompilation probe

The probe imported the whole x86-64 `libLLVM.so.19.1` and decompiled 384 deterministic C API exports. It tested exact parity on a slice of a large executable image. Whole-program auto-analysis and its throughput remain unmeasured.

| Input | Value |
| --- | --- |
| Installed binary | `/usr/lib/x86_64-linux-gnu/libLLVM.so.19.1` |
| Debian package | `libllvm19:amd64` version `1:19.1.7-3+b1` |
| File bytes | 129,673,080 |
| File SHA-256 | `3523f50f635d2a1ea47518a392451f2854b92823ceaf1345fb806099dd1a3b8a` |
| Host | Debian 13 x86-64 with a four-CPU quota and 16 GiB cgroup memory limit |
| Ghidra | Official `Ghidra_12.2_build` distribution with Temurin `25.0.5+8` and a 2 GiB JVM heap |
| BinaryRat code | `2d5f7f72f0c9e17d6acff391e8495b666d4f7b5a` |

## Sample preparation

1. Run GNU `nm --dynamic --defined-only --print-size --format=posix` on the ELF. Select type `T` symbols whose names start with `LLVM` and whose sizes are 64 through 3,072 bytes inclusive. Strip ELF symbol version suffixes, sort by `(address, size, name)` and keep the last symbol at duplicate addresses. This produced 463 eligible entries.
2. Select the entry at index `floor((2*i+1)*463/(2*384))` for `i` from 0 to 383. The sample covers 78,290 symbol bytes. Write the offsets and sizes in lowercase hexadecimal and names in `offset<TAB>size<TAB>name<LF>` format. The sample manifest SHA-256 is `8ff76332e2357bbfd5d6976053c97fe53dd54b060b97282943bba81a031c15d1`.
3. Import the ELF with `analyzeHeadless -noanalysis`. In a disposable project, disassemble from `imageBase + offset` with address bounds from the symbol size and incremental analysis disabled. Define each sampled function using the instructions recovered inside that bound. Preserve the rest of the imported image and symbol table.
4. Reopen the same prepared Program `-readOnly -noanalysis`. In a diagnostic copy of `BinaryRatExport.java`, restrict function selection to those 384 entry addresses. Run `compare-scheduled` with four requested workers, the 60-second per-function deadline, and no persistent cache. The diagnostic copy retained the normal stock Ghidra and BinaryRat decompilation paths.

## Stock serial versus BinaryRat scheduled

| Mode | Export wall seconds | Completed C output | Incomplete |
| --- | ---: | ---: | ---: |
| Stock serial, one worker | 62.065 | 383 | 1 |
| BinaryRat scheduled, four workers | 63.136 | 383 | 1 |

The comparison failed exact byte parity for two functions. `LLVMGetNamedMetadataNumOperands` at `0x1046320` and `LLVMGetDebugLocDirectory` at `0x1046510` differed in generated `auVar` names, declaration order, and their uses. Both modes returned the same low-level bad-instruction-count error for `LLVMLinkModules2` at `0x24525b0`.

The scheduler completed all 384 leases with no deadline or memory stops. It measured a 691,879,936-byte maximum per-worker RSS across leases. The two phase timings came from one paired JVM while development builds shared the host. The probe stopped its planned repeat timings when byte parity failed, so these timings cannot establish a speedup.

## Stock parallel control

A separate JVM reopened the same prepared Program and ran `compare` with four workers through Ghidra's stock `DecompilerCallback` pool. The new stock serial export matched the earlier serial export byte for byte. The stock pool differed from serial on two C bodies, `LLVMAddNamedMetadataOperand` at `0x1046450` and `LLVMGetDebugLocDirectory` at `0x1046510`. Both differences involved temporary names and declaration order. Both stock paths reproduced the same 383 completions and the same `LLVMLinkModules2` error.

| Control mode | Export wall seconds | Sampled peak process-tree RSS bytes |
| --- | ---: | ---: |
| Stock serial | 84.835 | 1,385,074,688 |
| Stock parallel | 53.306 | 1,481,330,688 |

RSS sampling observed the live process tree at 50 ms intervals. These peaks and the scheduled per-worker maximum measure different scopes. The control reproduces a byte-parity failure using stock pooling, leaving exact parallel output open for this workload.

| Export | JSONL SHA-256 |
| --- | --- |
| Both stock serial exports | `e96703186235de3f110bcc901b30ba84f944ce7821fc24700d3902f4effb4d44` |
| BinaryRat scheduled | `d22ac9a4696cf026aace1ca43f899843c02bcc13989e56d6993012efaf1bc76f` |
| Stock parallel | `4d2ace1eb06b6a4245e7ac4030de7df71cfdae2af3382fe0db531f38e7336ccc` |

## Stock process-history control

With official Ghidra 12.2 alone, a fresh `DecompInterface` processed the first
58 sampled functions in ascending order on a read-only copy of the Program.
A second interface processed the same set in descending order. Two further
interfaces each decompiled one of the affected functions as their first
request. For both affected functions, ascending order reproduced the original
serial C. Descending and single-function runs reproduced the scheduled C
byte for byte.

In both functions, the temporary for joined registers `EDX:4,RAX:8` had
storage offset `0x0` in ascending order and `0x10` in descending or fresh
runs. The temporary for `RDX:8,RAX:8` had the opposite offset. Stock Ghidra
allocates these join offsets in first-use order and walks varnodes in
address order when assigning names. Its ordinary native cache flush leaves
the join records in the running decompiler process.
[Join allocation](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.2_build/Ghidra/Features/Decompiler/src/decompile/cpp/translate.cc#L686) ·
[Native flush](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.2_build/Ghidra/Features/Decompiler/src/decompile/cpp/ghidra_process.cc#L255) ·
[Name assignment](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.2_build/Ghidra/Features/Decompiler/src/decompile/cpp/coreaction.cc#L3092)
