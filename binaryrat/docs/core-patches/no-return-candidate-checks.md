# No-return analyzer candidate checks

BinaryRat modifies
`Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/analysis/FindNoReturnFunctionsAnalyzer.java`.
The upstream baseline is `Ghidra_12.2_build`, commit
`8ca9077040cc43cd790babcfccf19475622a3e9a`, file blob
`f0840399caf02dd3c47b88143241869ec68df3f3`.
[Upstream source](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.2_build/Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/analysis/FindNoReturnFunctionsAnalyzer.java)

The candidate check uses one exact instruction lookup for each fall-through
address. It resolves the caller's containing function only when inspecting a
read or write reference and removes an unused list of detection reasons. The
change keeps the x86 INT3 mnemonic check and the existing two-pass candidate
order. The stock analyzer still collects and writes no-return flags, flow
overrides, bookmarks, body fixes, and optional flow repairs on its analysis
thread. Cancellation checks also cover the fall-through and incoming-reference
loops. The patch allocates no persistent cache or additional worker.

The 138,981,968-byte Godot 4.6.3 Linux executable with SHA-256
`f64d4ed19fc9df9440321653fcc80df8c6e365ba7b6de0a29e2cfa9fa71bfeb3`
gave a stock no-return analyzer time of 123.666 seconds. Late Java Flight
Recorder sampling attributed 6,302 of 7,626 main-thread samples to this analyzer.
Of these, 817 reached the eager caller lookup and 331 reached the call-target
lookup used only by the unused reasons. The stock Godot run hit its analysis
deadline. Whole-program speedup still requires a completed stock and candidate
comparison on the same input and settings.

Ghidra registers the stock analyzer at its instruction-analysis priority, and
its candidate check and reducer are private. A second extension analyzer would
add work or require disabling the stock analyzer and reimplementing its
options, thresholds, write ordering, and repair behavior.

## Regression check

Build the fork and set `JAVA_HOME` to the JDK used by both Ghidra 12.2
installations. Install the project's test dependencies and run from the
repository root.

```bash
python binaryrat/benchmarks/verify_no_return.py \
  --stock-ghidra /path/to/ghidra_12.2_PUBLIC \
  --candidate-ghidra /path/to/BinaryRat-Ghidra \
  --output build/no-return-differential
```

The headless test creates a disposable x86-64 Program with explicit listing and
reference evidence. The verifier compares exact no-return markers, bookmarks,
flow overrides, and function bodies after an immediate-cancellation control and
an analysis pass. The fixture disables optional flow repair to isolate the
classifier and ordered reducer. The whole-program benchmark uses stock default
options, including flow repair.
[Headless fixture](../../benchmarks/ghidra_scripts/BinaryRatNoReturnParity.java)

Official stock and candidate Ghidra 12.2 passed all 12 cases on Linux x86-64
with Temurin 25.0.5+8. Both reports have SHA-256
`59ee719a5406fc4723992ad5db1c89c6011be2f0777d38ad308d7d5d8332e59b`.

## Focused timing

The Linux benchmark builds a 28,896-byte x86-64 fixture with 1,800 returning
direct calls. Every sixteenth returning call has a nearby unrelated data
reference. It runs stock, candidate, candidate, and stock in separate one-CPU,
512 MiB JVMs. After two warm-up passes each JVM measures four passes that
leave the Program revision unchanged. A separate three-call INT3 control
verifies the no-return flag, bookmark, and three call flow overrides. The
benchmark checks an exact digest of the call destinations, overrides, caller
bodies, and inventory counts across all four runs.
[Timing fixture](../../benchmarks/ghidra_scripts/BinaryRatBenchmarkNoReturn.java)

```bash
python binaryrat/benchmarks/benchmark_no_return.py \
  --stock-ghidra /path/to/ghidra_12.2_PUBLIC \
  --candidate-ghidra /path/to/BinaryRat-Ghidra \
  --output build/no-return-benchmark
```

The initial comparison used Linux x86-64 and Temurin 25.0.5+8. The input
SHA-256 was `a0778a755b78b854d6404d7a72e2dcbca3cabdaf9bdec1c8d211b56d1ba458e5`.
All four runs produced Program effects SHA-256
`e0cde0d6067dbf3c050b9276d713920590e789bcf93b3acd586a4da2dc576129`.

| Run | Analyzer median (ms) | Process wall (s) | Peak process-tree RSS (bytes) |
| --- | ---: | ---: | ---: |
| Stock 1 | 271.778 | 35.620 | 393,396,224 |
| Candidate 1 | 30.753 | 32.456 | 392,429,568 |
| Candidate 2 | 42.389 | 24.628 | 377,520,128 |
| Stock 2 | 118.188 | 43.700 | 383,524,864 |

The median of the JVM medians fell from 195.0 to 36.6 ms on this selected
returning-call pattern. Repeating the comparison with the checked-in runner
produced the same Program effects digest and medians of 214.1 ms for stock
and 74.1 ms for the candidate. Process wall time and sampled RSS include JVM
startup, fixture creation, and validation. CPU contention varied on the shared
host. The measurements establish a speedup for the isolated read path. CI
checks exact effects and records the timing comparison as an artifact.

On upstream release sync, check whether upstream already avoids these reads or
uses the diagnostic reasons. If upstream supersedes the patch, drop it and run
the differential and whole-program comparisons against the new baseline.
