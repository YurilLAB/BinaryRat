# BinaryRat

BinaryRat's new engine is C++20. Ghidra's existing Java framework, SLEIGH, native
decompiler, and database are retained. This repository starts at the official
`Ghidra_12.2_build` tag; version and archive hashes are in `UPSTREAM.json`.

## Contents

- [Complete application releases](#complete-application-releases)
- [Build the C++ engine](#build-the-c-engine)
- [What is implemented](#what-is-implemented)
- [Verify against Ghidra](#verify-against-ghidra)
- [Documentation](#documentation)
- [Licensing and contributions](#licensing-and-contributions)

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
  [Usage and cache report](bridge/README.md#live-cache-and-cache-proof)
- A Java adapter using Ghidra's existing `DecompInterface` and
  `DecompilerCallback`, with a strict raw comparator and stock-verified export.
- A read-only layout extractor over real Ghidra p-code that follows bounded direct
  calls and reports shared-storage candidates, and a C++ aggregator that preserves
  gaps and overlapping alternatives. Each field links to its instruction evidence.
  Scores express uncalibrated support.
  [Layout evidence](bridge/README.md#read-only-layout-evidence)
- A native summary solver that carries parameter layout evidence through recursive
  call cycles and shifted pointers, shared by the headless script, PyGhidra and the
  live service. [Summary propagation](protocol/README.md#summary-propagation)
- Itanium and MSVC RTTI evidence reports. [C++ RTTI](bridge/README.md#read-only-c-rtti)
- Reviewed creation of a new structure with provenance and native undo.
  [Reviewed structure creation](bridge/README.md#reviewed-structure-creation)
- An installable extension with the native engine, CodeBrowser decompilation
  exports, layout recovery at the cursor and a navigable field evidence table.
  [Build and install](bridge/README.md#install-the-extension)
- Call-site corrections in CodeBrowser: an instruction's p-code with register names,
  before and after Listing overrides, and a reviewed call prototype applied at one
  call with native undo. [Workflow](docs/ADOPTION.md#follow-a-function-while-reviewing-code)
- Call sites with arguments: every call to a function, including through its thunks,
  as the caller's decompiled statement with the values the decompiler proved constant
  and the strings or symbols they point to. In CodeBrowser, PyGhidra, the CLI and the
  live service. [Call sites](bridge/README.md#call-sites-with-arguments)
- Stack strings: text a function builds on its stack with constant stores, read without
  the decompiler and assembled by the engine, with the instructions that wrote it.
  [Stack strings](bridge/README.md#stack-strings)
- Analysis profiles (Quick Triage, Normal, Deeper Recovery) that restore the
  project's analyzer settings afterwards.
  [Choose how much analysis to run](docs/ADOPTION.md#choose-how-much-analysis-to-run)
- Typed Python access to functions, references, datatypes, and decompilation in
  saved Programs, plus the analyst tools `binaryrat-diff`, `binaryrat-explain`
  and `binaryrat-decompile`. Separate local clients can share one read-only Ghidra
  JVM. [Python API](python/README.md)
- Two documented Ghidra core patches: faster no-return candidate checks, and join
  records dropped at each native flush. [Core patch ledger](docs/core-patches/README.md)
- C/C++ corpus builders with separate DWARF/PDB oracles, stripping checks,
  cross-target manifests, a whole-program auto-analysis profiler, and CI for
  Linux/Windows.

## Verify against Ghidra

Use an official Ghidra 12.2 installation and JDK 25, build the corpus, then run
`binaryrat/benchmarks/verify_ghidra.py` with `--engine`. It compares scheduled
exports, cold and warm, with stock decompilation byte for byte.
[How BinaryRat is verified](docs/VERIFICATION.md)

## Documentation

| Topic | Document |
|---|---|
| Ghidra extension: install, CodeBrowser, headless exports, layouts, RTTI, call sites, stack strings, cache | [Export bridge](bridge/README.md) |
| Python API, analyst commands, live JVM service | [Python client](python/README.md) |
| Engine wire protocol | [Native protocol](protocol/README.md) |
| Ground-truth corpus | [Corpus](corpus/README.md) |
| Checks, CI and raw evidence | [Verification](docs/VERIFICATION.md) |
| Using BinaryRat in a Ghidra team | [Adoption guide](docs/ADOPTION.md) |
| Design, gates and roadmap | [Architecture](docs/ARCHITECTURE.md) |
| Changes to upstream Ghidra files | [Core patch ledger](docs/core-patches/README.md) |
| Upstream synchronization | [Upstream](docs/UPSTREAM.md) |

## Licensing and contributions

Original BinaryRat code is Apache-2.0. Retain root `LICENSE`, `NOTICE`, and
upstream third-party notices. See `native/third_party/README.md` for vendored
licenses. Modified upstream files carry explicit modification notices.

All new commits go directly to the sole `master` branch with author `yurillab`.
Preserve upstream authors. Do not add co-author or AI-attribution trailers, and
do not create development or synchronization branches. [Sync procedure](docs/UPSTREAM.md).
