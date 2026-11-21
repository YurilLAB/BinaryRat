# Decompiler join records at cache flush

BinaryRat modifies three native decompiler files. The upstream baseline is
`Ghidra_12.2_build`, commit `8ca9077040cc43cd790babcfccf19475622a3e9a`.

| File under `Ghidra/Features/Decompiler/src/decompile/cpp/` | Upstream blob |
| --- | --- |
| `translate.hh` | `09018f491ea2d52705d7d13cb5a796c5ceee7e28` |
| `translate.cc` | `12c6a245d115c49a05ff7cce87409e0552ba79d0` |
| `ghidra_process.cc` | `aab4fcfed9091ada8e62cfd3ee88fee438f33519` |

`RegisterProgram` marks the join records that exist after the processor and
compiler specifications are read. `FlushNative` then deletes every later join
record and restores the next join offset. Ghidra's `DecompInterface` sends
this flush after every decompilation that leaves its process running, so each
function starts from the join state of a new decompiler process.

## Why

Stock Ghidra allocates join-space offsets in first-use order and keeps the
records for the life of the native process. Variable names are assigned by
walking varnodes in address order. A function that joins two register pairs,
such as `RDX:8,RAX:8` and `EDX:4,RAX:8`, can name its temporaries in either
order, depending on which functions that process decompiled earlier. The
LLVM 19 evidence shows 2 of 384 functions differing between serial and pooled
stock exports for this reason, which is why `stock-verified` re-runs a serial
pass. [LLVM 19 evidence](../evidence/llvm19-linux.md)

With the patch, the source-built fork prints every function exactly as
official Ghidra prints it from a new decompiler process, in any order, process
or worker count. The extension on official Ghidra is unchanged and still needs
`stock-verified` when ascending serial bytes are required.

## Safety

Before the new step, `FlushNative` deletes the global scope with every function
symbol, prototype and `Funcdata`, the non-core types, comments, decoded strings
and constant-pool entries. These own the join records and join addresses created
while decompiling. The only long-lived `JoinRecord` pointers are in prototype
model entries (`ParamEntry`), which are read from the specifications before the
mark. Options sent after registration decode no addresses. Without a mark,
truncation does nothing, so other users of `AddrSpaceManager` are unaffected.

## Rejected alternatives

- A new decompiler process per function gives the same output with stock code,
  but cost about 250 ms per function: 94.6 s instead of 3.0 s for 384 LLVM
  functions on the same host.
- Restarting a process only after functions that used joins is not sound:
  simplification can remove every varnode of a join it created, so Java cannot
  see all functions that allocated one.
- Renaming temporaries after printing changes stock text and cannot undo other
  effects of varnode order.
- An extension cannot reach the native process state.

## Evidence

Local Windows x86-64 host, official Ghidra 12.2 with Temurin 25.0.5+8. The
native decompiler was built from this tree with MinGW-w64 GCC 16.1.0 using
Gradle's source list. An unpatched build of the same tree reproduced official
output byte for byte on the fixture and on 384 LLVM functions.

| Workload | Official, reused process | Patched, reused process |
| --- | --- | --- |
| Join fixture, 4 functions | `first16` differs from a new process in reverse order | Equal to a new official process in forward, reverse and two-worker order |
| `libLLVM.so.21.1`, 384 LLVM-C exports | No order effect | Equal |
| `libLLVM.so.21.1`, 2,400 C++ exports | 6 ascending, 5 descending and 6 six-worker results differ (8 functions) | Equal in all three orders |

The library's SHA-256 is
`12dca1fc2d9f5d4ff35315fc2aa3a97b615b41ec6a71d3ce545efb62c075d902`. The
2,400 functions are evenly spaced exported text symbols of 64 to 3,072 bytes
with a single name. Every difference was the same swap of 12- and 16-byte
join temporaries, for example LLVM's `SDValue` returned in `RAX` and `EDX`.
Six functions failed the same way in every run (bad instruction count).
Wall times for the 2,400 functions were 154.3 s ascending and 63.3 s with six
workers for official Ghidra, and 147.3 s and 63.2 s for the patched build.
A new official process per function took 127.3 s with six workers.

A test-only build blanked each dropped record instead of freeing it and never
reused join offsets. A stale record pointer or join address would then fail or
change output. It passed the fixture verifier and matched official new-process
output on all 2,400 LLVM functions, descending and with six workers.

## Regression check

```bash
python binaryrat/benchmarks/verify_decompile_order.py \
  --stock-ghidra /path/to/ghidra_12.2_PUBLIC \
  --candidate-ghidra /path/to/BinaryRat-Ghidra \
  --output build/decompile-order
```

The verifier imports a 154-byte raw x86-64 fixture (gcc -O1 code for two
callers that join the same return registers in opposite order) and decompiles
it forward, in reverse, and with a new process per function. Official Ghidra
must still show the order effect. Every candidate digest must equal the
official new-process digest. CI runs it on the Linux and Windows source builds.
[Headless fixture](../../benchmarks/ghidra_scripts/BinaryRatDecompileOrder.java)

The Linux source build also builds upstream's `decomp_test_dbg` from the
patched files and runs its 204 unit tests and 733 data tests against the
`.sla` files compiled in the tree, including the test-only Toy processor that
`funcproto_join` and `funcproto_nojoin` use. All must pass. The BFD loader is
left out because only the interactive console uses it. Built from the upstream
blobs, the same program gives identical results. Making `findAddJoin` add one
byte per piece fails 4 unit tests. The data tests' multi-line patterns need LF
line endings, so the step converts its copy.

## Upstream and removal

[Join allocation](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.2_build/Ghidra/Features/Decompiler/src/decompile/cpp/translate.cc#L686) ·
[Native flush](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.2_build/Ghidra/Features/Decompiler/src/decompile/cpp/ghidra_process.cc#L255)

On upstream release sync, check whether the native flush or join allocation
changed. If official Ghidra stops showing the order effect, the verifier's
control fails: drop the patch and rerun the comparison against the new baseline.
