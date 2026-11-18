# BinaryRat

BinaryRat's new engine is C++20. Ghidra's existing Java framework, SLEIGH, native
decompiler, and database are retained. This repository starts at the official
`Ghidra_12.2_build` tag; version and archive hashes are in `UPSTREAM.json`.

## Complete application releases

The fork-build jobs assemble one ZIP per x64 platform from the same commit's
patched Ghidra distribution, native engine, compiled extension, and tested
Temurin 25 JDK. They run the extracted bundle with the bundled runtime, import
and decompile the example, and exercise the default desktop workspace and the
included Python wheel. The `Publish BinaryRat` workflow takes a successful CI
run ID for the current revision of `master` and publishes both verified ZIPs
and their checksums. [Downloads](https://github.com/YurilLAB/BinaryRat/releases)

## Build the C++ engine

Requires CMake 3.24+, a C++20 compiler, and Python 3 for tests. No dependency
download is required by CMake: the two small header dependencies and their
licenses are pinned under `native/third_party`.

```sh
cmake -S . -B build/native -DCMAKE_BUILD_TYPE=Release
cmake --build build/native --config Release --parallel 2
ctest --test-dir build/native -C Release --output-on-failure
```

The executable is `build/native/binaryrat/binaryrat-engine` on Linux, or
`build/native/binaryrat/Release/binaryrat-engine.exe` with a Windows multi-config
generator. Alternatively build this directory with `cmake -S binaryrat`.

```sh
build/native/binaryrat/binaryrat-engine --version
build/native/binaryrat/binaryrat-engine serve --cache build/cache
```

`serve` reads one JSON request per line and emits one correlated JSON response;
lease grants may answer out of order, and scheduler events arrive between responses.
The native engine and the read-only PyGhidra JVM service can each serve multiple requests.
See the [engine protocol](protocol/README.md) and [Python service](python/README.md).

## What is implemented

- Bounded C++ executor with exception propagation and orderly shutdown.
- Admission-controlled C++ executor: worker count from a CPU/RAM budget, per-task
  memory reservations with strict FIFO admission, execution deadlines and
  cancellation, and explicit completed/failed/timed-out/cancelled/rejected
  statuses.
- Lease scheduler in `serve` that runs real Ghidra decompilations under that
  executor: CPU and RAM measured by the engine, a lease per decompilation, the
  native decompiler process's resident memory watched against its reservation,
  deadlines and cancels delivered to the bridge, and stuck processes killed.
- Persistent SHA-256-addressed artifact storage, checksummed records, atomic
  replacement, explicit dependency invalidation, and exclusive process ownership.
- Live decompiler cache: each decompilation's reads recorded through Ghidra's
  callback, a dependency index that removes entries on mapped Program changes,
  and replay against the Program after changes of unknown reach or a restart.
  Set `BINARYRAT_CACHE_DIR` to reuse results in ordinary scheduled exports.
  [Usage and cache report](bridge/README.md)
- A read-only layout extractor over real Ghidra p-code and a C++ aggregator
  that preserves gaps and overlapping alternatives. Each field links to its
  instruction evidence. Scores express uncalibrated support.
- A Java adapter using Ghidra's existing `DecompInterface` and
  `DecompilerCallback`, with a strict raw comparator and stock-verified export.
- An installable extension with the native engine, CodeBrowser decompilation
  exports, layout recovery at the cursor and a navigable field evidence table.
  [Build and install](bridge/README.md#install-the-extension)
- Typed Python access to functions, references, datatypes, and decompilation in
  saved Programs. Separate local clients can share one read-only Ghidra JVM.
  [Python API](python/README.md)
- C/C++ corpus builders with separate DWARF/PDB oracles, stripping checks,
  cross-target manifests, and CI for Linux/Windows.

The bridge's live cache uses schema 2 keys, tracked dependencies, and replay
to verify Program reads across changes and restarts. Stock verification also
checks that output matches the ascending stock process history. Schema 1 keys require
callers to supply complete semantic identities; function bytes and the in-memory
modification number alone cannot establish correctness across reopen/import, and
plain exports are evidence artifacts, not reusable decompilations.

## Ghidra integration checks

Use an official Ghidra 12.2 installation and JDK 25. The bridge is compiled by
Ghidra's script machinery. Except for `cache-proof`, which edits a throwaway
program, the bridge performs read-only exports from CodeBrowser or headless
Ghidra after analysis. [Bridge contract](bridge/README.md)

```sh
python -m pip install -r binaryrat/requirements-test.txt
python binaryrat/tools/build_corpus.py --output build/corpus --toolchain gcc
python binaryrat/benchmarks/verify_ghidra.py \
  --ghidra /path/to/ghidra_12.2_PUBLIC --corpus build/corpus/manifest.json \
  --output build/verification --workers 1 2 4 --repetitions 1 \
  --engine build/native/binaryrat/binaryrat-engine
```

With `--engine`, the verifier checks scheduled output against stock, tests cold
and warm exports in separate JVMs, and exercises deadlines, resident memory limits,
and interrupted leases through Ghidra. CI installs the host extension ZIP into
isolated settings and repeats the cold and warm checks through its bundled
engine. CI also reopens a cached project after a function rename made while the
engine is offline. The verifier checks output records and
script success messages because Ghidra can return zero after a postScript fails.
The small Windows corpus records one known stock Ghidra coverage failure in each
of three MSVC optimization variants. Every exported record participates in the
exact comparison. [MSVC runtime parity evidence](docs/evidence/msvc-crt-parity.md)
Linux CI downloads and hash-checks a pinned 130 MB LLVM library, then compares the
stock-verified export of 384 sampled functions to an independent stock serial run
byte for byte. [LLVM harness and evidence](docs/evidence/llvm19-linux.md)
CI also checks read-only p-code footprints against separate DWARF and PDB
oracles and exercises write-back transaction semantics on a disposable Program.
[Corpus accuracy checks](corpus/README.md)
For repeated diagnostic timing, use `--repetitions 5`. The report explicitly
labels sampled process-tree RSS and separates overall headless-run wall time
from exporter-phase times; it does not claim large-binary speedup.

CTest also runs `native.live_cache_fuzz`, which checks the native engine against
a reference model using seeded sequences of synthetic cache operations. To
repeat a seed, run `python binaryrat/native/tests/live_cache_fuzz.py --engine
PATH_TO_ENGINE --seed 0 --steps 1000`.

## Remaining milestones

The extractor follows bounded direct calls and reports shared-storage candidates
and Itanium and MSVC RTTI. Analysts can review a proposed layout and create a
new structure with native undo. General interprocedural inference, calibrated
confidence, and applying types to existing targets from the GUI and Python remain open.
[Architecture and milestones](docs/ARCHITECTURE.md)

The whole-program profiler records analyzer timings, completion, wall time,
and process-tree RSS. The 130 MB LLVM run reached its analysis deadline.
Whole-program speedup on code-heavy binaries remains unmeasured.
[Whole-program analysis evidence](docs/evidence/full-analysis.md)

## Licensing and contributions

Original BinaryRat code is Apache-2.0. Retain root `LICENSE`, `NOTICE`, and
upstream third-party notices. See `native/third_party/README.md` for vendored
licenses. Modified upstream files carry explicit modification notices.

All new commits go directly to the sole `master` branch with author `yurillab`.
Preserve upstream authors. Do not add co-author or AI-attribution trailers, and
do not create development or synchronization branches. [Sync procedure](docs/UPSTREAM.md).
