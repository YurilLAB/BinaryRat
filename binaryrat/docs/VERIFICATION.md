# How BinaryRat is verified

BinaryRat counts a feature as done only when an automated check or recorded
evidence backs it. This page lists those checks and links to the raw evidence.

## Disassembly and analysis validation

Stock parity catches a fork regression. An independent expected value can
also catch an error shared by the fork and upstream. Keep both gates.

| Layer | Current gate | Next coverage |
|---|---|---|
| SLEIGH decoding | Live stock and packaged Ghidra decode 40 x86-64 and 40 AArch64 little-endian test instructions. The test checks boundaries, mnemonic, operands and representative p-code operations. Seven isolated prefixes must leave the Listing undefined. LLVM MC 19.1.7 independently decoded the 80 vectors during development. | Add held-out instruction families, PC-relative targets at two load addresses, and supported context modes. Compare canonical operands, width, target and length so spelling aliases cannot create a false failure. |
| Instruction evidence | Exercise the public Python API through an actual saved Program. Check a CALL changed to BRANCH by a Listing flow override, empty semantics, invalid addresses, unsigned operands, missing output, caps and cancellation. Inject an edit between raw and effective reads and require a stale-read error. | Extend independent ISA expectations to defined flags and explicitly mask unspecified flags. |
| Register explanations | Real x86-64 and AArch64 ranges must agree with Ghidra's concrete emulator and independent arithmetic expectations. Test all 65,536 pairs for eight-bit addition, stale reads, overrides, overlapping writes and refusal of memory or control flow. On both CI hosts, the pinned solver must prove equality and produce a concretely replayable difference. | Expand the supported instructions and register aliases one family at a time with independent vectors and explicit refusal tests. |
| Inferred types | Compare separate DWARF and PDB ground truth on stripped binaries. Property tests generate call graphs with reused loads at different offsets, then change one citation, view or path. Verify the actual load, consumer and call site shown to the analyst and reject inconsistent reports. | Measure per-kind precision, recall and abstentions on held-out families. |
| Portable layout reviews | Regenerate a capture in a reopened project. Change a real field displacement under the same executable identity and require the project check to detect it. Exercise missing witnesses, tampered report contents, oversized and deeply nested input, and mismatched target parameters. | Extend the same read-only checks to additional evidence formats before supporting shared decisions. |
| State and resources | The reviewed write service has live rollback, undo/redo, stale-review and reopen checks. Native scheduling and caches have model tests and seeded fuzzers. | For shared reviews, test duplicate, missing and reordered updates, simultaneous incompatible edits and revocation. Record peak RSS, selected-function latency and cancellation latency separately from whole-program time. |

For a coverage-guided decoder harness, isolate one language and mode in a
worker with fixed time and memory budgets. Start with the checked-in ordinary
instruction encodings. Vary operands, instruction lengths, truncation points
and bytes near a mapping boundary. Accept a defined decode or a documented
refusal. Assert progress, containment of decoded spans, deterministic results
for the same context, and explicit termination. Compare supported instructions
against a separately versioned decoder. For analysis reports, use the native
solver as a producer and independently check the returned relationships before
mutating them. Keep the seed, bytes, language, revision and options for each
failure, minimize it, then replay it in every-commit CI. Coverage-guided campaigns
and their long-running workers are planned.

Every commit runs the decoder, live API and report tests on Linux and Windows.
Both the stock installation and the application bundle run the live Python tests.
The upstream decompiler unit and data suites run in the Linux source job. Longer fuzz
campaigns should publish their seeds, coverage, timeouts and sanitizer logs.
Keep correctness gates separate from timing trends on shared hosts. Release
publication requires the successful CI run for the exact packaged commit.
[CI workflow](../../.github/workflows/binaryrat.yml) ·
[Release gate](../../.github/workflows/binaryrat-release.yml)

On the Linux development host the packaged application took a median 0.61 ms
and p95 3.60 ms to read the five-byte overridden call in the live instruction
fixture. This is 500 reads of the same instruction in an open Program after 50
warmups, with JVM startup and project opening excluded. The summary-report
fixture took a median 0.93 ms to decode, validate and explain one selected
offset across 24 generated graphs (8.7–17.7 kB of JSON), versus 0.83 ms before
checking union provenance and displaying its consumers. These are fixture
measurements on a shared host. Full-program throughput is tracked separately.
[Instruction fixture](../python/tests/test_live_instruction_pcode.py) ·
[Summary report generator](../python/tests/test_summary_provenance_fuzz.py)

On the same shared Linux development host, lifting and explaining a six-instruction
x86-64 range took a median 4.27 ms (p95 6.76 ms). A five-instruction AArch64
range took 1.31 ms (p95 2.01 ms). Each sample used an open Program, 30 warmups
and 200 measured calls. Creating, opening and checking one 4,291-byte layout
handoff offline took a median 6.70 ms (p95 29.91 ms) across 500 trials.
The project check also incurs the time to open the Program and regenerate the
layout. [Arithmetic fixtures](../python/tests/test_live_arithmetic.py) ·
[Project check](../python/tests/test_live_summary_review.py)

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
