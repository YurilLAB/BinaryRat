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
The build emits a SHA-256 sidecar next to the ZIP. After transferring both
files, verify them from the destination directory. On Linux run
`sha256sum --check <archive>.zip.sha256`. On Windows PowerShell, set
`$zip` to the exact ZIP filename and run:

```powershell
$expected = ((Get-Content -LiteralPath "$zip.sha256" -Raw -ErrorAction Stop) -split ' ')[0]
if ((Get-FileHash -LiteralPath $zip -Algorithm SHA256 -ErrorAction Stop).Hash -ne $expected) {
    throw "BinaryRat extension checksum mismatch"
}
```

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

### Inspect a possible structure in CodeBrowser

1. Install the extension and let auto-analysis finish. In **Window → Script Manager**, enable **In Tool** for `BinaryRatRecoverLayouts.java` and `BinaryRatBrowseLayout.java`.
2. Put the cursor inside the function that uses the suspected structure. Choose **Tools → BinaryRat → Recover Layout at Cursor** and enter the zero-based parameter index; the dialog lists the parameters of the Listing signature to help. The suggested report path in your home folder is a new file name, so repeated runs need no edits. For a first look, keep the direct-call depth at zero. Increase it to include supported calls that receive the same object pointer.
3. When the report is saved, its evidence table opens. Filter or sort it by field offset (shown as `+0x1`), access width, operation, instruction text or function. Double-click a row to navigate to its instruction in the Listing.
4. To reopen a saved report later, choose **Tools → BinaryRat → Browse Layout Evidence** and pick the JSON file. The file dialog starts in the folder of the latest recovered report.

For example, the corpus function `read_packed` reads a four-byte field starting at byte offset 1 of parameter 0. The corresponding table row takes you to the load, where you can inspect the surrounding instructions before deciding how to type the field. Overlapping widths remain visible as alternatives.

The table shows exact field accesses. New reports fingerprint each cited instruction whose bytes Ghidra can read. The **Instruction bytes** column shows **Verified** for matching bytes and **Unrecorded** when a report lacks the fingerprint, including older reports. The p-code operation is the one recorded when the report was generated. Generate a fresh report to see how a changed signature or type affects recovery. Both actions leave the Program read-only.

CI opens the installed extension in CodeBrowser, runs both actions on the packed-structure fixture and checks the resulting Listing address. The `gui-layout/report.json` artifact records the recovery and navigation times, including script compilation and dialogs. [Desktop verification](../benchmarks/verify_gui_layout.py)

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
replays, misses, stores, rejections, and the numbers of compute and traced leases.
Scheduled exports collect query traces only when caching is enabled. A trace
or UTF-8 cache record that exceeds the storage budget still produces an export
row and increments the rejected-store count.

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

Run `BinaryRatRecoverLayouts.java OUTPUT_JSON ENTRY_HEX|SPACE:HEX|name:FUNCTION PARAM_INDEX
[TIMEOUT_SECONDS] [FOLLOW_DEPTH=0]` as a headless postScript after auto-analysis.
`ENTRY_HEX` is in the default address space; `SPACE:HEX` (or Ghidra's `SPACE::HEX`)
selects a function in another, such as an overlay bank whose function names
repeat. The other headless scripts below take the same selector. The zero-based
parameter selection declares the object base to analyze. The extractor
decompiles under a CPU and memory lease and follows supported pointer
expressions to high p-code loads and stores. Each proposed byte range carries
instruction and p-code evidence. Unknown pointer bases are omitted. Overlaps
remain visible as alternative interpretations and the reported extent is a
lower bound. The Program is read-only to the extractor.

The report uses an executable SHA-256 identity. Variable accesses appear as
separate bounded ranges, while exact offsets drive field proposals. The
completed file is published without replacing an existing report.

Set `FOLLOW_DEPTH` to 1 through 4 to collect evidence from eligible direct
callees that receive the selected object base unchanged. The pass checks calling
convention and register storage and requires the p-code target to match the
instruction's single decoded direct target. It visits each verified callee once,
keeps all equally short incoming call paths, and bounds the total decompiles,
p-code operations, and evidence. At depths above 1 the call records include the
caller and hop for reconstruction.

`BinaryRatSolveLayouts.java OUTPUT_JSON ENTRY_HEX|SPACE:HEX|name:FUNCTION PARAM_INDEX
[TIMEOUT_SECONDS] [MAX_SUMMARIES=32]` replaces the depth limit with summaries.
It decompiles each reached function parameter once and records direct calls
that pass the parameter plus an exact constant, matching a CALL input's
position to the callee's parameter. The engine's `types.solve` then follows
those edges through recursion: a cycle that hands back the same pointer is
solved, and one that moves it, such as a list walk, is withheld and marks the
report incomplete. A shifted argument such as `value + 1` keeps its exact
offset. Refused calls (unsupported callee or parameter) are listed with a
reason, and calls redirected only in p-code are not followed. The report's
`analysis_mode` is `read_only_summary_layout_evidence`; the evidence table and
reviewed structure creation read depth-mode reports only. Headless only; the
summary, decompile, p-code, edge and evidence limits fail closed.
A call is followed only when the decompiler shows its argument; a register
passed through unchanged in hand-written or optimized code can hide it.
The script, PyGhidra (`ProgramView.solve_layout`) and the `binaryrat-live`
service share one Java service, `binaryrat.SummaryLayouts`.
[Summary verification](../benchmarks/verify_summary_layout.py)

`union_candidates` highlights exact loads at the same offset whose independently
observed consumers interpret the bytes as integers and floating-point values.
Each view points to the load and the typed operation. The candidate captures
shared storage, which a union or a byte reinterpretation can both produce. The
ordinary field alternatives remain in the report. Evidence strength counts
distinct supporting observations. [Confidence calibration](../docs/evidence/confidence-calibration.md)

For example, select `name:read_packed` and parameter `0` in the stripped C corpus.
The verifier checks the output against separately read DWARF or PDB. [Corpus and
accuracy checks](../corpus/README.md)

### Read-only C++ RTTI

Run `BinaryRatRecoverRtti.java OUTPUT_JSON` as a headless postScript after
auto-analysis. The report records class names, direct bases, virtual inheritance,
and validated vtable address points and slots. It retains the address of the
metadata that supports each finding. The collector validates Itanium ELF and
MSVC PE64 metadata on supported architectures and bounds the amount of scanned
memory and reported evidence. [RTTI regression](../benchmarks/verify_rtti.py)

### Reviewed structure creation

Use the installed extension on a saved local Program. Run
`BinaryRatReviewLayout.java preview REPORT STRUCTURE_NAME` as a headless
postScript with `-process PROGRAM -noanalysis`. Review the field extents and
cited instructions, then pass the printed approval code to
`BinaryRatReviewLayout.java accept REPORT STRUCTURE_NAME APPROVAL_CODE`.
Acceptance uses a writable headless processing run. Check the creation message
and Ghidra's save result for persistence.

The approval covers the report bytes, exact destination, and each cited
function's name, prototype, signature source, body ranges, and bytes. This
includes intermediate forwarders. Each forwarding edge must still reach its
recorded callee in both decoded flow and effective p-code.
Acceptance creates a fresh structure under
`/BinaryRat/Reviewed`, with opaque byte-width components and provenance in
one native undoable transaction. It rejects overlaps, variable-offset evidence,
and existing destination names. This action creates the type for later use
in the project.

## Call sites with arguments

**Tools → BinaryRat → Call Sites with Arguments** lists every call to the
function at the cursor, including calls through its thunks. Each row shows the
caller, the caller's decompiled C statement and the arguments: values the
decompiler proved constant, strings at defined data or at a labelled address,
symbols, or the name of the variable passed. Double-click a row to open the
call in the Listing; the table closes when the Program changes. Rows that the
decompiled code cannot explain keep their address and a status: no containing
function, an unsupported caller (thunk, external, uninitialized or above
64 KiB), a failed decompilation, a call the decompiler does not show, or a
caller past the decompile limit.

Headless, `BinaryRatCallSites.java OUTPUT_JSON ENTRY_HEX|SPACE:HEX|name:FUNCTION
[TIMEOUT_SECONDS] [MAX_SITES=64] [MAX_CALLERS=32]` writes the report
(`analysis_mode` `read_only_call_sites`) without replacing a file. Each caller
is decompiled once under a memory-watched lease, the Program revision is
checked around every step, and the reference, site, caller and argument limits
are reported rather than silently applied. The script, PyGhidra
(`ProgramView.call_sites`), `binaryrat-decompile --call-sites` and the
`binaryrat-live` service share one Java service, `binaryrat.CallSites`.
`BinaryRatCallSitesProof.java` checks the statuses, thunks, limits,
cancellation and Program changes on a disposable x86-64 Program.

## Stack strings

**Tools → BinaryRat → Stack Strings** lists text that functions build on their
stack with constant stores, which the decompiler shows only as scattered
assignments. It reads each function's instructions without decompiling,
follows register constants through straight-line code (moves, extensions,
constant arithmetic such as an XOR with a key, and loads from read-only
memory), and records each store that Ghidra's stack analysis marked as a stack
write with a known value. A run ends at a jump target and after a jump or a
call, so values from different paths never mix and a buffer that is filled
again after a call is reported as two strings, not as one mixture. A stack
store of a value that is not known removes the bytes it covers, and what an
instruction computes conditionally (a conditional move) counts as not known.
The engine's `strings.stack` op then replays the stores (a later store
replaces earlier bytes) and reports ASCII and UTF-16LE text of at least the
minimum length, with its stack offset, terminator and the instructions that
wrote it. Double-click a row to open the first store. Loads from writable
memory, values pushed with `push`, text decoded in a loop, and stores through
a pointer that Ghidra did not resolve to the stack are not followed.
Functions in overlay spaces are scanned too. Overlays repeat the offsets of
other spaces, so every address in the report names its space.

Headless, `BinaryRatStackStrings.java OUTPUT_JSON [all|ENTRY_HEX|SPACE:HEX|name:FUNCTION
[MINIMUM_LENGTH=4 [MAX_FUNCTIONS=10000]]]` writes the report (`analysis_mode`
`read_only_stack_strings`) without replacing a file. The script, PyGhidra
(`ProgramView.stack_strings`) and `binaryrat-decompile --stack-strings` share
one Java service, `binaryrat.StackStrings`. `BinaryRatStackStringsProof.java`
checks stores of every width, joins, calls, read-only and writable loads,
limits, cancellation, Program changes, and functions at the same offset in two
overlay spaces and the default space on a disposable x86-64 Program.

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
already reused by another function. A failed process-memory attachment aborts
the export. An unacknowledged release retires the pool and wakes waiting borrowers.

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
dependencies. The digest includes the C, tree, parameter-measure, and jump-load
output actions. Entries written before the action-key update get one cold miss
and are recomputed automatically. Dependencies include 256-byte memory ranges and symbol names.
Unknown injection payload classes require replay before reuse.
For redirected calls, the cache also records the original targets whose call
fixups are consulted during SLEIGH translation, including inherited thunk
fixups. The integration test changes those fixups within one live Program and
checks the refreshed result against stock decompilation.

`binaryrat/ChangeTracker` turns every Program change record into the dependencies
it touched and reports them to the engine, which removes the entries that read them.
Ghidra reports a byte write only where it was made, so the tracker also reports
every address that shows those bytes (`binaryrat/MemoryAliases`): byte-mapped views
of the written range under any byte mapping scheme, bit-mapped views, and blocks
made from the same file bytes, including aliases of aliases. A write whose aliases
cannot all be named within its limits is a change of unknown reach, and any change
to the memory blocks rebuilds the alias index. Changes it cannot map precisely (data types, memory blocks, externals, undo/redo
restores, anything unknown) are reported as changes of unknown reach: every entry
becomes unverified and is replayed against the Program before use, then kept or
removed. Ghidra raises the modification number once per change record, so the
tracker can prove every change reached the engine before an entry is trusted
without replay; a gap is treated as a change of unknown reach. Entries left by an
earlier session are always replayed first. Replay checks Program queries.
On official Ghidra, native process history, including register-join allocation
order, can still affect the bytes. Use stock verification when the ascending
serial bytes are required. The source-built fork drops join records at each
native flush ([core patch](../docs/core-patches/decompiler-join-flush.md)).

The cache is optional: an engine that refuses a cache request (a record it may not
write or delete, for example while a virus scanner holds it) turns that lookup into
a miss and that store into a reported rejection, and decompilation and export go on.
The reasons appear in the export's `store_diagnostics` and `lookup_diagnostics`.
When the removal of an entry the engine vouched for is refused, every entry becomes
unverified; if that report is refused too, the cache is off for the rest of the
session. Only a lost engine connection stops the work.

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

`BinaryRatCacheEdgeProof.java` (headless `-preScript`, builds its own program;
`verify_ghidra.py --engine` and `verify_extension.py` run it) writes the source of
1:1, 2:4 and bit-mapped views, one of two blocks sharing file bytes, a view created
during the session, and through a view itself: each cached reader must miss and
match a fresh decompilation, and a write outside every view must keep all entries.
It then makes the engine refuse `cache.put`, `cache.get` and `cache.evict` on real
files (a directory where a record belongs; an open handle on Windows or a read-only
directory elsewhere): nothing stale may be served and work must go on. The
persistent-cache check also runs a third JVM with every record blocked: its export
must complete and match the first.

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
- All modes use `DecompileOptions.grabFromProgram`, the `decompile` style, and C
  output. Serial, parallel, and standalone scheduled exports retain the stock
  high p-code tree and its native result-size limit. Only the scheduled phase of
  stock verification omits the tree. When a C-only response fits and the full
  stock response exceeds the limit, verification publishes the stock error.
  Layout recovery requests the tree for its p-code evidence. Ghidra 12.2 flushes
  native function cache state at the end of `decompileFunction`.
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
