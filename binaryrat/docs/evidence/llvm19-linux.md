# LLVM 19 large-file decompilation probe

The probe imported the whole x86-64 `libLLVM.so.19.1` and decompiled 384 deterministic C API exports. It tested exact parity on a slice of a large executable image. Whole-program auto-analysis and its throughput remain unmeasured.

## Repeat the parity check

Use Linux with JDK 25, GNU `nm`, the benchmark Python dependencies, and a
built BinaryRat engine. Obtain the stock installation from the
checksum-verified 12.2 release archive. [Ghidra fetch script](../../tools/fetch_ghidra.py)

```sh
python binaryrat/benchmarks/verify_large_llvm.py \
  --library /usr/lib/x86_64-linux-gnu/libLLVM.so.19.1 \
  --ghidra /path/to/ghidra_12.2_PUBLIC \
  --engine build/binaryrat/binaryrat-engine \
  --output build/llvm-stock-verified
```

The runner checks the input digest and independently opens the same saved
read-only project in each JVM. It compares the complete JSONL files as
bytes, including metadata and the text of any matching errors. It records
wall time and sampled process-tree memory. `--mode scheduled` exercises the
unaudited path and exits nonzero on any difference. Use a fresh output
directory for each invocation. Each output contains the exact exports, the
sample manifest, Ghidra logs, and `report.json`.

## Probe inputs

| Input | Value |
| --- | --- |
| Installed binary | `/usr/lib/x86_64-linux-gnu/libLLVM.so.19.1` |
| Debian package | `libllvm19:amd64` version `1:19.1.7-3+b1` |
| File bytes | 129,673,080 |
| File SHA-256 | `3523f50f635d2a1ea47518a392451f2854b92823ceaf1345fb806099dd1a3b8a` |
| Host | Debian 13 x86-64 with a four-CPU quota and 16 GiB cgroup memory limit |
| Ghidra | Official `Ghidra_12.2_build` distribution with Temurin `25.0.5+8` and a 2 GiB JVM heap |
| BinaryRat code for the initial probe | `2d5f7f72f0c9e17d6acff391e8495b666d4f7b5a` |

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

RSS sampling observed the live process tree at 50 ms intervals. These peaks and the scheduled per-worker maximum measure different scopes. The control reproduces a byte-parity failure using stock pooling on this workload.

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
the join records in the running decompiler process. The source-built fork
now drops them at each flush. [Core patch](../core-patches/decompiler-join-flush.md)
[Join allocation](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.2_build/Ghidra/Features/Decompiler/src/decompile/cpp/translate.cc#L686) ·
[Native flush](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.2_build/Ghidra/Features/Decompiler/src/decompile/cpp/ghidra_process.cc#L255) ·
[Name assignment](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.2_build/Ghidra/Features/Decompiler/src/decompile/cpp/coreaction.cc#L3092)

## Stock-verified follow-up

The checked-in runner prepared the same 384 entries and opened the saved
Program in separate JVMs for the stock reference and the stock-verified run.
Their full exports had identical bytes and the same SHA-256,
`e96703186235de3f110bcc901b30ba84f944ce7821fc24700d3902f4effb4d44`.
The verification sidecar reported 383 matching scheduled rows and one
stock fallback for `LLVMGetDebugLocDirectory` at `0x1046510`. Its SHA-256
matched the published export. Both runs returned 383 C bodies and the same
`LLVMLinkModules2` error.

| Run | Headless wall seconds | Sampled peak process-tree RSS bytes |
| --- | ---: | ---: |
| Official stock serial | 64.16 | 1,319,825,408 |
| BinaryRat stock-verified | 118.16 | 2,017,275,904 |

The verified run admitted four scheduled workers. Its scheduled phase took
48.77 seconds and the stock serial verification phase took 63.65 seconds.
The verification pass covers every included function and costs additional
time. The measurements use one shared import and one decompilation run per
mode. Large-binary auto-analysis performance remains unmeasured.

A separate `--mode scheduled` control with the checked-in runner completed
all 384 leases and returned exit status 1 from the byte comparator. The C
bodies differed for `LLVMGetNamedMetadataNumOperands` and
`LLVMGetDebugLocDirectory`. The number of differing rows can vary with
the work assigned to each native process.

## Overlapping the stock reference and scheduled candidates

On the same saved 129,673,080-byte LLVM fixture, a four-slot verified export
used three candidate workers and one ordered stock reference. Each of the
six exports below ran in a fresh JVM. The order was stock, previous verified,
overlapped verified, then the reverse. Both script versions first ran a
one-function warmup. The previous exporter came from commit
`cfe9849f7dc60f190b014dabad2e73e2df76e87c`. The native engine, library,
Program, stock Ghidra 12.2 installation, 2 GiB heap, 60-second deadline,
128-function chunks and disabled cache were the same across these six runs.

| Export | Wall seconds, runs 1 / 2 | Median seconds | Peak process-tree RSS, GiB, runs 1 / 2 |
| --- | ---: | ---: | ---: |
| Stock serial | 70.11 / 74.78 | 72.45 | 1.29 / 1.40 |
| Previous stock-verified | 117.80 / 115.15 | 116.48 | 1.65 / 1.45 |
| Overlapped stock-verified | 79.01 / 82.13 | 80.57 | 2.22 / 1.99 |

The median verified wall time fell by 35.90 seconds on this sample. The
overlapped run took 8.13 seconds longer than stock alone and used more peak
memory. RSS was sampled every 50 ms across the full process tree and can count
shared pages more than once. Overlapping phase times describe one shared
interval. The headless wall time includes JVM startup and result publication.

Every export produced the same 384 JSONL records, including the same incomplete
`LLVMLinkModules2` result. Their SHA-256 was
`e96703186235de3f110bcc901b30ba84f944ce7821fc24700d3902f4effb4d44`.
Each overlapped pass ran 384 uncached candidate leases and 384 watched reference
leases, reached four concurrent leases and used one stock fallback. The saved
Program hashes stayed unchanged. In an earlier attempt while compiler and GUI
tests were competing for CPU, one candidate in the previous exporter exceeded
the deadline and verification stopped before publishing. The six reported runs
used the unchanged deadline during an exclusive local test window. These two
repetitions measure this decompilation sample. Whole-program analysis and
throughput on other binaries require separate measurements.

After the shared-session fallback and native startup cleanup were integrated,
two more pairs used the same saved Program and deadline. Both verified
exports again matched all 384 stock records. Each reported 384 candidate
leases, 384 watched reference leases, four peak concurrent leases and one
stock fallback.

| With shared-session fallback | Wall seconds, runs 1 / 2 | Median seconds | Peak process-tree RSS, GiB, runs 1 / 2 |
| --- | ---: | ---: | ---: |
| Stock serial | 76.99 / 78.34 | 77.67 | 1.30 / 1.31 |
| Stock-verified | 79.88 / 87.98 | 83.93 | 2.01 / 1.98 |

These four JVM runs alternated order between pairs. The engine SHA-256 was
`3dac1e45924fd6664b91c2408876941eb4d9df46237f8727d3107fabed76b9f0`.
The earlier six runs used engine
`ae75f24e1b69613f010248586e499cfa66f36dfdf9a97efe6423bad5b96e3708`.
The final measured `BinaryRatExport.java` SHA-256 was
`af840257f350741be95081316c4147e78f9ce2de337c90cda3600811c857179d`.
A subsequent diagnostic wording change affects retired decompiler pools.
All four runs used healthy pools.

After fixing concurrent first reads of calling conventions and data settings,
two more pairs on the same saved Program produced the same 384 records and
the same SHA-256. Each verified export ran 384 uncached candidate leases and
384 watched stock-reference leases, reached four concurrent leases and used
one stock fallback. The binary, engine and deadline were unchanged. The
following measurements cover initialization of the metadata indexes.

| With the metadata fixes | Wall seconds, runs 1 / 2 | Median seconds | Peak process-tree RSS, GiB, runs 1 / 2 |
| --- | ---: | ---: | ---: |
| Stock serial | 74.43 / 73.43 | 73.93 | 1.29 / 1.26 |
| Stock-verified | 83.12 / 85.08 | 84.10 | 1.92 / 2.25 |

To compare an earlier exporter, extract its `binaryrat/bridge/ghidra_scripts`
directory from Git and pass it as `--candidate-scripts` to the command above.
Use `--repetitions 2` or more, repeat with the current script directory, and
compare `report.json` and both runs' per-function records.

## Export allocation check

On Linux x86-64 with official Ghidra 12.2 and JDK 25.0.5, a separate
allocation probe opened the same analyzed GCC O0 `types` corpus project
read-only. Each pass opened a fresh native decompiler with the same program
options, visited its 19 internal functions in ascending order, rendered every
C record and compared all fields with the first pass. All records matched.

| Query recording | High p-code tree | Recorded queries per pass | Median calling-thread bytes allocated |
| --- | --- | ---: | ---: |
| On | On | 585 | 7,138,236 |
| On | Off | 585 | 6,749,088 |
| Off | On | 0 | 3,455,548 |
| Off | Off | 0 | 3,047,560 |

The probe read JDK `ThreadMXBean.getCurrentThreadAllocatedBytes()` immediately
before iterating the functions and after rendering the last result. It executed
the four rows top to bottom, then bottom to top, twice. Each median covers
four passes. These counts cover Java allocation on the calling thread. Native
process memory, retained Java heap and whole-program analysis time have different
measurement boundaries. The release integration checks verify whether scheduled
leases actually collected traces.

On `LLVMConstIntOfArbitraryPrecision`, setting Ghidra's native response cap to
1 MiB reproduced a difference between the two output configurations. Full-tree
decompilation reported “Response buffer size exceeded” with no timeout,
cancellation, or startup failure. C-only decompilation completed and returned
72,435 C characters. BinaryRat therefore preserves the stock tree for standalone
exports and omits it only in the candidate phase of stock verification. The
stock error takes precedence when the candidate fits under the cap.
