# BinaryRat

BinaryRat's new engine is C++20. Ghidra's existing Java framework, SLEIGH, native
decompiler, and database are retained. This repository starts at the official
`Ghidra_12.2_build` tag; version and archive hashes are in `UPSTREAM.json`.

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
It is a persistent **native process**, not yet a persistent Ghidra JVM daemon.
See [protocol](protocol/README.md) and [Python client](python/README.md).

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
  replay against the Program after changes of unknown reach or a restart, and a
  `cache-proof` harness comparing every served result with fresh decompilation.
- Pure C++ layout-evidence aggregation: preserve gaps and overlapping
  alternatives, deduplicate support, expose stride conflicts, and abstain when
  an object origin is unknown. Scores are uncalibrated evidence strength.
- A minimal headless Java adapter using Ghidra's existing `DecompInterface` and
  `DecompilerCallback`, with serial/parallel/scheduled exact-output comparison.
- Typed Python value objects, streaming export parsing, and native-engine client.
- C/C++ corpus builders with separate DWARF/PDB oracles, stripping checks,
  cross-target manifests, and CI for Linux/Windows.

Only the bridge's live cache path (schema 2 keys, tracked dependencies and
replay) makes reuse safe across changes and restarts. Schema 1 keys still require
callers to supply complete semantic identities; function bytes and the in-memory
modification number alone cannot establish correctness across reopen/import, and
plain exports are evidence artifacts, not reusable decompilations.

## Ghidra integration checks

Use an official Ghidra 12.2 installation and JDK 25. The bridge is compiled by
Ghidra's script machinery. Except for `cache-proof`, which edits a throwaway
program, it is read-only and requires headless execution after analysis with no
concurrent writer. [Bridge contract](bridge/README.md).

```sh
python -m pip install -r binaryrat/requirements-test.txt
python binaryrat/tools/build_corpus.py --output build/corpus --toolchain gcc
python binaryrat/benchmarks/verify_ghidra.py \
  --ghidra /path/to/ghidra_12.2_PUBLIC --corpus build/corpus/manifest.json \
  --output build/verification --workers 1 2 4 --repetitions 1
```

The verifier checks expected exports and useful completion counts as well as
process exit codes. Ghidra can return exit code zero after a postScript fails.
For repeated diagnostic timing, use `--repetitions 5`. The report explicitly
labels sampled process-tree RSS and separates overall headless-run wall time
from exporter-phase times; it does not claim large-binary speedup.

## Remaining milestones

See [architecture](docs/ARCHITECTURE.md). Interprocedural inference, RTTI/class
recovery, calibrated confidence, protected analysis-coordinated write-back,
native undo/redo integration and proposal-level revert, automatic incremental
invalidation, the persistent Ghidra daemon,
and 100 MB+ benchmark gates are not complete. Debug-oracle generation currently
preserves ground truth; precision/recall scoring is a later implementation gate.

## Licensing and contributions

Original BinaryRat code is Apache-2.0. Retain root `LICENSE`, `NOTICE`, and
upstream third-party notices. See `native/third_party/README.md` for vendored
licenses. Modified upstream files carry explicit modification notices.

All new commits go directly to the sole `master` branch with author `yurillab`.
Preserve upstream authors. Do not add co-author or AI-attribution trailers, and
do not create development or synchronization branches. [Sync procedure](docs/UPSTREAM.md).
