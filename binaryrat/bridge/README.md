# Ghidra 12.2 export bridge

`ghidra_scripts/BinaryRatExport.java` is a deliberately small Java adapter to the
existing native Ghidra decompiler. BinaryRat's engine and tooling live in C++.
It exports evidence, runs stock decompilations under the C++ engine's CPU/RAM
admission (`scheduled`), and proves the engine's live decompiler cache against
fresh decompilation (`cache-proof`). It does not perform type recovery or provide
a persistent daemon. Its helper classes are in `ghidra_scripts/binaryrat/`; Ghidra
compiles them with the script.

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
OUTPUT serial|parallel|compare|compare-reverse|scheduled|compare-scheduled|cache-proof
       [WORKERS=4] [TIMEOUT_SECONDS=60] [CHUNK_SIZE=128]
```

`scheduled`, `compare-scheduled` and `cache-proof` start the C++ engine named by
the environment variable `BINARYRAT_ENGINE` (a built `binaryrat-engine`).

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

`compare-scheduled` writes `OUTPUT.serial.jsonl` and `OUTPUT.scheduled.jsonl` and
throws on any byte difference, like `compare`.

## Scheduled decompilation

Every decompilation takes a lease from the engine's scheduler first. The engine
measures CPUs and physical memory (affinity and Linux cgroup limits applied) and
admits at most `min(CPUs, WORKERS, (RAM - JVM max heap - other reserve) /
worker reservation)` decompilations at once, first in, first out. Each Java worker
thread waits for its lease; each admitted lease borrows one of that many
stock `DecompInterface` instances and attaches its native decompiler process, whose
resident memory the engine then watches. The engine stops a lease at its deadline,
on cancel, or when that process grows past the lease's reservation; the bridge then
cancels the decompilation, which stops the native process. A holder that does not
release within the grace period has its process killed by the engine. Stopped
decompilations are exported with `timed_out` or `cancelled` set, and a memory stop
with an explanatory `error`. Lease outcomes go to `OUTPUT.schedule.json`.

| Variable | Default | Meaning |
|---|---|---|
| `BINARYRAT_WORKER_BYTES` | 768 MiB | reservation and resident-memory ceiling per decompilation |
| `BINARYRAT_OTHER_RESERVE_BYTES` | 512 MiB | memory kept back for everything else |
| `BINARYRAT_LEASE_TIMEOUT_MS` | `TIMEOUT_SECONDS` | engine deadline per decompilation; the decompiler's own timeout stays as a backstop 30 s later |
| `BINARYRAT_KILL_GRACE_MS` | 5000 | time to release after a stop before the process is killed |

The JVM's maximum heap is the JVM reserve. Output equals `serial` byte for byte
when nothing is stopped; a 1 MiB reservation or a 1 ms deadline stops real
decompilations, which is how the enforcement paths are checked.

## Live cache and `cache-proof`

`binaryrat/TracingDecompiler` is a stock `DecompInterface` whose callback is a
`DecompileCallback` subclass: the native decompiler learns about the Program only
through those callback queries, so recording every query and a digest of its answer
captures everything one decompilation read. The decompiler is deterministic, so if
every recorded query gets the same answer later, it would produce the same output.
Each cached entry (engine schema 2 key: program, entry address, and a digest of
everything the decompiler was registered with: translator, core types, processor
and compiler specifications, options) holds the output, that read trace, and its
dependencies: 256-byte memory lines read or resolved, and symbol names.

`binaryrat/ChangeTracker` turns every Program change record into the dependencies
it touched and reports them to the engine, which removes the entries that read them.
Changes it cannot map precisely (data types, memory blocks, externals, undo/redo
restores, anything unknown) are reported as changes of unknown reach: every entry
becomes unverified and is replayed against the Program before use, then kept or
removed. Ghidra raises the modification number once per change record, so the
tracker can prove every change reached the engine before an entry is trusted
without replay; a gap is treated as a change of unknown reach. Entries left by an
earlier session are always replayed first.

`cache-proof` edits the Program (use a throwaway project) and, after each change,
looks every function up with auditing on and decompiles it fresh:
every served result must equal fresh output byte for byte, and an entry the engine
vouched for must also replay cleanly. Rounds: no change, a bookmark, a comment
outside functions (all must stay cached), renaming and retyping a called function,
a comment in a body, a parameter rename, retyping referenced global data, an unused
data type, patching an instruction, undo, redo, a register value across several
functions, a label, a flow override, editing a used data type, deleting a called
function, a rename while the engine is down, and a negative control that hides one
change from the cache and must be caught. The report (`OUTPUT`) holds counts per
round and the time of fresh decompilation versus cache hits and replays.

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
- All modes use identical `DecompileOptions.grabFromProgram`, `decompile` style,
  C-code and syntax-tree settings. Ghidra 12.2 already flushes native function
  cache state at the end of `decompileFunction`; the bridge adds no duplicate flush.
- Work and result buffers are bounded by the chunk size, plus native worker
  memory. This is **not** an adaptive memory budget; size workers accordingly.
- GUI use and active auto-analysis are rejected. The modification number is
  checked before reading, during waits, between chunks, and before publication.
  This is optimistic validation: a detected change discards the export. It does
  not provide a database snapshot. The caller must enforce the
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
