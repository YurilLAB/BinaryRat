# Ghidra 12.2 export bridge

`ghidra_scripts/BinaryRatExport.java` is a deliberately small Java adapter to the
existing native Ghidra decompiler. BinaryRat's engine and tooling live in C++.
This initial adapter exports evidence; it does not perform type recovery, cache
decompilation results, modify the Program, or provide a persistent daemon.

## Run

Use the official `Ghidra_12.2_build` distribution and JDK 25. Run this as a
headless **postScript after auto-analysis**, with no other program writer. For
example, from the repository root on Linux:

```sh
mkdir -p /tmp/binaryrat-project /tmp/binaryrat-results
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" /tmp/binaryrat-project export-test \
  -import /absolute/path/to/fixture \
  -scriptPath "$PWD/binaryrat/bridge/ghidra_scripts" \
  -postScript BinaryRatExport.java /tmp/binaryrat-results/fixture compare 4 60 128 \
  -deleteProject
```

On Windows, use `support\analyzeHeadless.bat` and absolute Windows paths. Arguments
to the script are:

```text
OUTPUT serial|parallel|compare|compare-reverse [WORKERS=4] [TIMEOUT_SECONDS=60] [CHUNK_SIZE=128]
```

`serial` and `parallel` write `OUTPUT`. `compare` writes
`OUTPUT.serial.jsonl` and `OUTPUT.parallel.jsonl` from the same analyzed Program,
serial first, and throws on any byte difference. `compare-reverse` uses the same
filenames and checks, but runs parallel first. Alternate comparison modes across
paired benchmark repetitions to reduce ordering bias. Each export prints
`BinaryRat export starting mode=serial|parallel` before creating native processes,
then an `exported` line with wall time, mode, and worker count; the benchmark
harness can use these phase markers for process-tree memory sampling.
Existing destination files are replaced only
after successful completion of that export. Export failures remove their temporary
file. A failed comparison preserves both completed exports for diagnosis.

For existing analyzed projects, use headless `-process PROGRAM -noanalysis
-readOnly` instead of `-import`. Do not mistake `-noanalysis` for proof that a
freshly imported program has been analyzed.

## Contract

- Non-external functions are exported in forward address order, including thunks.
  Synthetic functions in Ghidra's uninitialized `EXTERNAL` memory block are
  excluded along with external-space functions; the exclusion count is logged.
- Serial mode directly reuses a stock `DecompInterface`. Parallel mode uses the
  stock `DecompilerCallback`/`CachingPool` with a local fixed-size executor; it
  does not alter Ghidra's globally shared thread-pool configuration.
- Both modes use identical `DecompileOptions.grabFromProgram`, `decompile` style,
  C-code and syntax-tree settings. Ghidra 12.2 already flushes native function
  cache state at the end of `decompileFunction`; the bridge adds no duplicate flush.
- Work and result buffers are bounded by the chunk size, plus native worker
  memory. This is **not** an adaptive memory budget; size workers accordingly.
- GUI use and active auto-analysis are rejected. The modification number is
  checked during waits and between chunks. This detects concurrent changes and
  aborts export, but is not snapshot isolation. The caller must enforce the
  documented headless, no-concurrent-writer precondition.
- JSONL is UTF-8 with LF newlines and deterministic ASCII JSON escaping. Raw
  decompiled C and prototype strings are preserved, including whitespace, after
  JSON decoding. Diagnostics and failures are retained rather than silently
  omitting functions. A native timeout may make serial and parallel output
  differ; such a comparison correctly fails and requires investigation.

Each record has `schema_version: 1`, `program_id`, `revision`, `address_space`,
`address` (unsigned hexadecimal offset, without `0x`), `body_sha256`, `body_ranges`, `name`,
`completed`, `timed_out`, `cancelled`, `failed_to_start`, `error`, `prototype`, and
`c`. `program_id` uses the executable SHA-256 if available and a `name:` fallback
otherwise; the fallback is not a globally unique cache identity. `revision` is
the captured in-memory modification number, **not** a durable revision or a
semantic digest. It is a nonnegative JSON integer. Compare mode
avoids cross-import revision drift. `body_ranges` holds inclusive hexadecimal
`[minimum, maximum]` pairs in the entry address space; bodies spanning address
spaces are rejected. `error`, `prototype`, and `c` are strings, empty when absent.

`body_sha256` hashes the UTF-8 domain separator `binaryrat-body-v1\0`, followed
for each forward function-body range by `address-space-name\0`, unsigned
hexadecimal minimum offset plus `\0`, decimal byte length plus `\0`, and raw
range bytes. Embedded NULs in address-space names are not supported by this
initial framing. Noncontiguous bodies are included. This fingerprint is not a
complete decompiler cache key: types, callees, symbols, context, options, and
other memory dependencies also affect decompilation.

## Verification

The required integration check is `compare`, run against the official 12.2
installation on the same analyzed Program with multiple worker counts. A passing
check requires byte equality of every exported field, not normalized C text.
Inspect `completed`/failure counts as well: identical failed decompilations are
not evidence of useful decompiler coverage. Validate the JSONL with the C++
consumer and verify the known fixture's function names and nonempty C output.

Timing printed by the script includes JSON serialization, body hashing, and file
I/O. It is diagnostic only; it does not establish faster auto-analysis or provide
process-tree peak-memory evidence. Those need the benchmark harness and
repeatable stock/BinaryRat runs on the declared corpus.
