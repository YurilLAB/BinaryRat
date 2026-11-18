# Ghidra 12.2 export bridge

`ghidra_scripts/BinaryRatExport.java` is a deliberately small Java adapter to the
existing native Ghidra decompiler. BinaryRat's engine and tooling live in C++.
It exports evidence, runs stock decompilations under the C++ engine's CPU/RAM
admission (`scheduled`), and proves the engine's live decompiler cache against
fresh decompilation (`cache-proof`). The bridge also includes a read-only p-code
layout extractor. Its helper classes are in `ghidra_scripts/binaryrat/`. Ghidra
compiles them with the script.

## Install the extension

Build the C++ engine, then use JDK 25 and the repository's Gradle wrapper to
package the engine and bridge for the current 64-bit Linux or Windows host.
Use the official Ghidra 12.2 installation directory and the absolute path to
an engine compiled for the same platform and architecture.

```sh
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.2_PUBLIC
./gradlew -p binaryrat/bridge buildExtension \
  -PbinaryratEngine=/absolute/path/to/binaryrat-engine
```

On Windows use `gradlew.bat` and the path to `binaryrat-engine.exe`.
In the Ghidra project window, open **File → Install Extensions**, add the ZIP
from `binaryrat/bridge/dist`, and restart Ghidra. The ZIP includes the matching
native engine, the bridge sources, and their license notices.

Ghidra discovers `BinaryRatExport.java` in the installed module. Omit
`-scriptPath` and `BINARYRAT_ENGINE` in the headless command below to use
the installed script and bundled executable. To use a custom engine build,
set `BINARYRAT_ENGINE` to its executable path.

## Run in CodeBrowser

Open a Program and let auto-analysis finish. In **Window → Script Manager**,
select `BinaryRatExport.java` in the BinaryRat category and run it. Turn on
**In Tool** for the script to add **Tools → BinaryRat → Export Decompilation**.

Select an export mode and a destination JSONL file. **Stock-verified** runs
scheduled decompilation and then checks it against the stock serial reference.
It can take longer and writes a `.parity.json` report alongside the JSONL.
**Scheduled** writes a `.schedule.json` report, and **Serial** runs a single
stock decompiler process. CodeBrowser asks before replacing an export or its
report. The current Program stays read-only to the exporter. A Program change
detected during export stops publication.

## Run headless

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
OUTPUT serial|parallel|compare|compare-reverse|scheduled|compare-scheduled|stock-verified|cache-proof
       [WORKERS=4] [TIMEOUT_SECONDS=60] [CHUNK_SIZE=128] [SAMPLE_TSV]
```

`scheduled`, `compare-scheduled`, `stock-verified`, and `cache-proof` start the bundled C++ engine
or the executable selected by `BINARYRAT_ENGINE`. Loose scripts require that
variable when no extension is installed.
Set `BINARYRAT_CACHE_DIR` to a dedicated directory to reuse cached results in
`scheduled`, `compare-scheduled`, and the scheduled phase of `stock-verified`. For example:

```sh
export BINARYRAT_ENGINE="$PWD/build/binaryrat/binaryrat-engine"
export BINARYRAT_CACHE_DIR="$PWD/build/decompile-cache"
```

Use `scheduled` in the command above and omit `-deleteProject` to save the
analyzed project. Reopen it with `-process PROGRAM -noanalysis -readOnly` and
the same cache directory. The engine owns that directory exclusively while it
runs. Each session replays entries from disk against the current Program before
reuse. A fresh import can produce different analysis records, which triggers
recomputation where the recorded answers differ.
Only results that pass this check can bypass a decompiler lease. The cache
requires an executable SHA-256, and exports still require an analyzed Program
without a concurrent writer. The `.schedule.json` report includes cache hits,
replays, misses, stores, rejections, and the number of compute leases.

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

### Stock-verified output

Use `stock-verified` for exact bytes from Ghidra 12.2's ascending serial
decompilation. BinaryRat runs the scheduled phase under its ordinary resource
limits and closes the pool before starting a fresh stock serial process.
That process visits every function in order. BinaryRat keeps a scheduled row
when all bytes match and takes the stock row when they differ. The extra full
serial pass determines the cost of verification. Interrupted decompilation or a
detected Program change aborts publication.

`OUTPUT.parity.json` contains the match and fallback counts, up to 32 fallback
addresses, and the SHA-256 of the exact JSONL. Output and report use separate
filesystem renames. The digest lets consumers check that the report belongs to
the export they read.

`SAMPLE_TSV` selects a benchmark subset in any headless export mode. Each
tab-separated line gives a hexadecimal offset relative to the Program image
base, a positive hexadecimal symbol size, and a symbol name. Each offset must
resolve to a distinct exportable function. Both phases visit selected functions
in ascending address order. [LLVM harness and evidence](../docs/evidence/llvm19-linux.md)

### Read-only layout evidence

Run `BinaryRatRecoverLayouts.java OUTPUT_JSON ENTRY_HEX|name:FUNCTION PARAM_INDEX
[TIMEOUT_SECONDS] [FOLLOW_DEPTH=0]` as a headless postScript after auto-analysis. The zero-based
parameter selection declares the object base to analyze. The extractor
decompiles under a CPU and memory lease and follows supported pointer
expressions to high p-code loads and stores. Each proposed byte range carries
instruction and p-code evidence. Unknown pointer bases are omitted. Overlaps
remain visible as alternative interpretations and the reported extent is a
lower bound. The Program is read-only to the extractor.

The report uses an executable SHA-256 identity. Variable accesses appear as
separate bounded ranges, while exact offsets drive field proposals. The
completed file is published without replacing an existing report.

Opt in with `FOLLOW_DEPTH=1` to collect evidence from eligible direct callees
that receive the selected object base unchanged. This bounded pass checks the
calling convention and register storage and keeps the call site and callee
instruction in the report.

For example, select `name:read_packed` and parameter `0` in the stripped C corpus.
The verifier checks the output against separately read DWARF or PDB. [Corpus and
accuracy checks](../corpus/README.md)

## Scheduled decompilation

Every scheduled cache miss takes a lease from the engine's scheduler first. The
engine sizes its budget from CPUs and physical memory. On Linux it applies
CPU affinity and the tightest applicable CPU and RAM limits exposed by the
process's cgroup mounts and their visible ancestors. It admits at most
`min(CPUs, WORKERS, (RAM - JVM max heap - other reserve) /
worker reservation)` decompilations at once, first in, first out. Each Java worker
thread waits for its lease; each admitted lease borrows one of that many
stock `DecompInterface` instances and attaches its native decompiler process, whose
resident memory the engine then watches. The engine stops a lease at its deadline,
on cancel, or when that process grows past the lease's reservation; the bridge then
cancels the decompilation, which stops the native process. A holder that does not
release within the grace period has its process killed by the engine. Stopped
decompilations are exported with `timed_out` or `cancelled` set, and a memory stop
with an explanatory `error`. Their C and prototype fields are empty even when
native output finishes in a race with the stop; stopped output is never cached.
A normally completed lease preserves the native result's own failure flags.
Lease outcomes go to `OUTPUT.schedule.json`.

Interrupted queued borrowers cancel their requests and release any racing grant.
An already cancelled monitor starts no native work, and active monitor cancellation
is forwarded to the engine. A worker returns its decompiler to the idle pool only
after its old lease release is acknowledged, so that lease cannot kill a process
already reused by another function.

| Variable | Default | Meaning |
|---|---|---|
| `BINARYRAT_CACHE_DIR` | unset | Directory for persistent scheduled-export results |
| `BINARYRAT_WORKER_BYTES` | 768 MiB | reservation and resident-memory ceiling per decompilation |
| `BINARYRAT_OTHER_RESERVE_BYTES` | 512 MiB | memory kept back for everything else |
| `BINARYRAT_LEASE_TIMEOUT_MS` | `TIMEOUT_SECONDS` | engine deadline per decompilation; the decompiler's own timeout stays as a backstop 30 s later |
| `BINARYRAT_KILL_GRACE_MS` | 5000 | time to release after a stop before the process is killed |

The JVM's maximum heap is the JVM reserve. The C/C++ fixture suite checks
byte-for-byte equality with `serial`. A large libLLVM sample found differences
in Ghidra's generated temporary names. The raw comparison reports those
differences. A 1 MiB reservation or a 1 ms deadline stops real decompilations,
which is how the enforcement paths are checked.
[libLLVM evidence](../docs/evidence/llvm19-linux.md)

## Live cache and `cache-proof`

`binaryrat/TracingDecompiler` uses the stock `DecompInterface` to record native
queries about the Program and hash their answers. During replay, any changed
answer makes the entry a miss and requests a fresh decompilation.
Each cached entry (engine schema 2 key: program, entry address, and a digest of
the native build, renderer, translator, compiled SLEIGH, core types, processor
and compiler specifications, and options) holds the output, read trace, and
dependencies. Dependencies include 256-byte memory ranges and symbol names.
Unknown injection payload classes require replay before reuse.
For redirected calls, the cache also records the original targets whose call
fixups are consulted during SLEIGH translation, including inherited thunk
fixups. The integration test changes those fixups within one live Program and
checks the refreshed result against stock decompilation.

`binaryrat/ChangeTracker` turns every Program change record into the dependencies
it touched and reports them to the engine, which removes the entries that read them.
Changes it cannot map precisely (data types, memory blocks, externals, undo/redo
restores, anything unknown) are reported as changes of unknown reach: every entry
becomes unverified and is replayed against the Program before use, then kept or
removed. Ghidra raises the modification number once per change record, so the
tracker can prove every change reached the engine before an entry is trusted
without replay; a gap is treated as a change of unknown reach. Entries left by an
earlier session are always replayed first. Replay checks Program queries.
Native process history, including register-join allocation order, can still
affect the bytes. Use stock verification when the ascending serial bytes are
required.

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
- CodeBrowser exports release their empty script transaction before prompting.
  Start after auto-analysis has finished. The exporter checks the modification
  number before reading, during waits, between chunks, and before publication.
  A detected change discards the staged export. Headless callers must keep the
  Program free of concurrent writers.
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

`BinaryRatLeaseChecks.java`, run as a headless postScript with `BINARYRAT_ENGINE`
set, checks interrupted queued requests, an already cancelled monitor, successful
reuse afterwards, authoritative stopped-lease output, and preservation of native
failure flags. It prints `BinaryRat lease lifecycle checks passed` only after all
assertions succeed. The main verification harness runs it on a benign fixture.

Timing printed by the script includes JSON serialization, body hashing, and file
I/O. It is diagnostic only; it does not establish faster auto-analysis or provide
process-tree peak-memory evidence. Those need the benchmark harness and
repeatable stock/BinaryRat runs on the declared corpus.
