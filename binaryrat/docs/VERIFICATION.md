# How BinaryRat is verified

BinaryRat counts a feature as done only when an automated check or recorded
evidence backs it. This page lists those checks and links to the raw evidence.

## Ghidra integration checks

Use an official Ghidra 12.2 installation and JDK 25. Ghidra compiles the
checkout scripts. The integration checks run exports after analysis and use
disposable Programs for cache mutations and reviewed writes.
[Bridge contract](../bridge/README.md#contract)

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
and interrupted leases through Ghidra. The verifier checks output records and
script success messages because Ghidra can return zero after a postScript fails.

The small Windows corpus records one known stock Ghidra coverage failure in each
of three MSVC optimization variants. Every exported record participates in the
exact comparison. [MSVC runtime parity evidence](evidence/msvc-crt-parity.md)

## What CI checks on every commit

The `BinaryRat` workflow tests every first-parent commit pushed to `master` on
Linux and Windows. Besides the native tests and the integration checks above:

- CI installs the host extension ZIP into isolated settings and repeats the cold
  and warm checks through its bundled engine. It also reopens a cached project
  after a function rename made while the engine is offline. The installed
  program-wide layout survey must report the same fields as the installed
  single-parameter extractor.
- Linux CI downloads and hash-checks a pinned 130 MB LLVM library, then compares
  the stock-verified export of 384 sampled functions to an independent stock
  serial run byte for byte. [LLVM harness and evidence](evidence/llvm19-linux.md)
- CI checks read-only p-code footprints against separate DWARF and PDB oracles
  and exercises write-back transaction semantics on a disposable Program.
  [Corpus accuracy checks](../corpus/README.md)
- Linux CI builds twelve open-source projects from hash-pinned sources, surveys
  every function's register parameters on official Ghidra, and labels each
  proposed field against the project's separate DWARF file. It fits the scores
  on six projects and reports their calibration on the other six. The same run
  requires the survey to match the single-parameter extractor on eight
  functions and to refuse an over-limit request and an existing report.
  [Calibration evidence](evidence/confidence-calibration.md)
- The fork-build jobs assemble the complete application for each x64 platform,
  run the extracted bundle with its bundled runtime, import and decompile the
  example, and exercise the default desktop workspace and the included Python wheel.
  The desktop check follows a shifted call to its field evidence, cancels a type
  preview, then applies it and checks the existing parameter through Undo and Redo.
- The Linux and Windows fork builds check that every function prints as a new
  official decompiler process prints it, in any order.
  [Core patch](core-patches/decompiler-join-flush.md)
- The Linux fork build compiles upstream's own decompiler test program from the
  patched sources and requires all of its unit tests and data tests to pass,
  including the test-only Toy processor's join tests. It checks both pass totals
  and rejects fixture-loading and execution errors in the combined log.

### How CI stays reliable

- Each job builds and downloads first. Every check after that runs even when an
  earlier check failed, so one failure never hides another. A check that reads
  another check's output, such as the analyst commands reading the parity
  exports, runs only when that check passed.
- Every command has its own time limit, so a hang fails in its own step.
- Downloads are pinned by SHA-256 and retried with growing waits
  (`binaryrat/tools/pinned_download.py`). The Gradle distribution is fetched
  once with retries before the first build. Tests are never retried.
- Every job uses the hash-pinned Temurin JDK that the application bundle ships
  (`binaryrat/tools/install_jdk.py`).
- `binaryrat/tools/test_ci_workflow.py` fails when CI stops running a verifier,
  a Python test folder or a native test. It also fails when an action is not
  pinned to a commit, a command has no time limit, a download skips the pinned
  helper, or a check can be skipped by an unrelated failure.

## Timing and memory

For repeated diagnostic timing, use `--repetitions 5`. The report explicitly
labels sampled process-tree RSS and separates overall headless-run wall time
from exporter-phase times; it does not claim large-binary speedup.

The whole-program profiler records analyzer timings, completion, wall time,
and process-tree RSS for stock auto-analysis.
[Whole-program analysis evidence](evidence/full-analysis.md) ·
[No-return analyzer timing](core-patches/no-return-candidate-checks.md)

## Native fuzzing

CTest also runs `native.live_cache_fuzz`, which checks the native engine against
a reference model using seeded sequences of synthetic cache operations. To
repeat a seed, run `python binaryrat/native/tests/live_cache_fuzz.py --engine
PATH_TO_ENGINE --seed 0 --steps 1000`. The seeded `native.protocol_fuzz`,
`native.types_solve_fuzz` and `native.stack_strings_fuzz` tests cover the wire
protocol, the summary solver and stack-string assembly the same way.

The Python tests add seeded checks for the calibration tools. The DWARF range
labeller is compared with plain enumeration on 300 random nested layouts, and
400 mutated survey reports must each be accepted or refused with a clear error.

## Type confidence

The offline evaluator compares layout proposal scores with outcomes labelled by
a separate debug-information oracle. Field scores are fitted on six source
families and checked on six others.
[Confidence calibration](evidence/confidence-calibration.md)
