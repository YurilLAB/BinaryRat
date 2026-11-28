# BinaryRat Python client (experimental 0.1.0)

The standard-library client keeps the **native C++ engine** alive across requests
and reads versioned JSONL exported by the Java bridge. The optional live API
reads saved Ghidra programs through PyGhidra 3.2.0 and Ghidra 12.2.

Install with `python -m pip install ./binaryrat/python`. Python 3.10+ is required.
No runtime Python dependencies are required.

## Analyst tools

Use `binaryrat-diff` and `binaryrat-explain` to inspect saved exports and layout
reports offline. The commands below read the reports directly.

```sh
binaryrat-diff before.serial.jsonl after.serial.jsonl
binaryrat-diff before.serial.jsonl after.serial.jsonl --json
binaryrat-diff before.serial.jsonl after.serial.jsonl --patch
binaryrat-diff before.serial.jsonl after.serial.jsonl --patch --function ram:401000
binaryrat-explain read_packed.json --offset 0x1
```

`binaryrat-diff` lists functions whose exported names, body ranges, byte
digests, prototypes, C text or decompilation status changed. It matches on
address space and entry offset and checks that each file describes a single
revision of the same SHA-256-identified executable. For a useful comparison,
keep the same load addresses and export selection. A function present in only
one capture is reported as added or removed. `--patch` adds a unified diff of
each changed prototype, error and C text with `--context N` lines around each hunk
(default 3). With `--json` it is the `patch` field. Changes that have identical
display lines, such as line-ending differences, show raw text digests. The patch
option rereads both files, verifies they still contain the same bytes, and keeps
only the earlier text of the changed functions in memory. Repeat `--function SPACE:HEX` to review
specific entries, including functions at the same offset in different overlays.
The counts cover the selected entries and the command still validates both full
exports. An entry absent from both files is an error. The exit code is 0 for
identical records, 1 for differences and 2 for invalid inputs.

`binaryrat-explain` shows which recorded instructions support a proposed
field. Supply a byte offset, or omit `--offset` to inspect the layout for the
report’s root function and parameter. A report can include overlapping fields
and bounded indexed accesses. Field support counts measure observed evidence.
[Generate the input reports](../bridge/README.md#read-only-layout-evidence)

It also reads summary reports from `BinaryRatSolveLayouts.java` or
`solve_layout` (below) and prints the call path behind each field, for example
`layout_shift -> layout_shift_middle (ram:10113d, +0) -> layout_leaf (ram:10111c, +24)`,
with recursive call cycles and refused calls.
For a union candidate, each cited load is labeled with its storage view.
When the report records what consumed the load, the same line gives the p-code
operation, instruction address and p-code order. For example, an integer XOR
and a floating-point comparison can use the same bytes. These are alternative
interpretations of shared storage. A source-level union declaration requires
additional evidence.

### Share a layout review

Package an interprocedural summary report from `solve_layout` or
`BinaryRatSolveLayouts.java`. A colleague can read it offline, inspect one
field, or rerun the same recovery against their own saved Program.

```sh
binaryrat-explain capture.json --make-review > handoff.json
binaryrat-explain handoff.json --offset 0x10
binaryrat-explain handoff.json --check-project workspace.gpr /program --install-dir /path/to/ghidra
binaryrat-explain handoff.json --check-review colleague-handoff.json
```

The reader accepts UTF-8 and BOM-marked UTF-16, including files saved by
Windows PowerShell 5 redirection. Its input limit is 8 MiB on disk. To keep
larger reviews compact in PowerShell 5, use
`binaryrat-explain capture.json --make-review | Set-Content -Encoding ascii handoff.json`.
The handoff embeds the capture and SHA-256 digests of its contents and layout.
The project check compares the executable identity, language, compiler spec
and selected function parameter, then reruns the recorded summary limit
through the installed BinaryRat extension. It checks the proposal, recorded
instruction witnesses and report context. An unchanged capture may match
after reopening a Program with a different revision number. Missing witnesses
or incomplete evidence return `unverifiable`.

Both check modes print JSON. The status is `matched` (exit 0), or `changed`,
`incompatible` or `unverifiable` (exit 1). Invalid input or an unavailable
project backend exits 2. `--check-review` accepts a second portable handoff
or a raw summary report. It validates each handoff's embedded checksums and
labels the offline comparison `supplied_report`.
Only `--check-project` opens a Program and regenerates the evidence.
The checksums verify content integrity. The review is read-only.

### Explain a register calculation

For an open CodeBrowser Program, select complete instructions in the Listing,
then use **Tools → BinaryRat → Explain Selected Register Arithmetic**.
Double-click a contributing operation to open its instruction. The bundled
Python API uses the same service on a saved Program. Stock Ghidra 12.2 and
older BinaryRat extensions use the Python implementation of the same model.

Pass the first and last **instruction starts** in a contiguous Listing range,
inclusive, and the register to inspect at its exit. For example, in a saved
Program where `ram:0` adds five to RAX and `ram:4` subtracts two, the
first command shows the expression and the p-code operation for each step.
If `ram:9` adds three to RAX, the second command checks whether the ranges
produce the same final RAX for every initial register value.

```sh
binaryrat-arithmetic Arithmetic.gpr /add ram:0 ram:4 RAX
binaryrat-arithmetic Arithmetic.gpr /add ram:0 ram:4 RAX --compare ram:9 ram:9 RAX --json
```

Inspection uses PyGhidra. Install the optional `proof` extra to compare results
with the pinned Z3 solver. For a source checkout use
`python -m pip install "./binaryrat/python[proof]"` in the PyGhidra environment.
For the packaged application, first install its wheel and bundled PyGhidra
dependencies, then run `python -m pip install "binaryrat[proof]==0.1.0"`
with access to PyPI. Pass `--install-dir` to select the Ghidra installation.

The pilot supports general-purpose registers on the default little-endian
x86-64 and AArch64 v8A languages. It reads effective p-code for up to 32
instructions, 256 operations and 256 expression nodes. Inputs are register
values on entry. Arithmetic wraps at its recorded width. Memory, control
flow, ambiguous partial-register writes and unsupported producers cause an
explicit refusal. A proof compares only the two selected outputs.

The command exits 0 for an explanation or proof, 1 for a difference with a
concretely replayed example, 2 for invalid input, 3 when it cannot explain
or decide, and 130 on interruption. `--timeout-ms` sets the solver deadline
for a comparison (default 1,000 ms, maximum 10,000 ms).

In Python, keep the expressions after closing the Program. The same selections
as the CLI example can be compared in a notebook:

```python
from binaryrat import Address, open_program, prove_equivalence

with open_program("Arithmetic.gpr", "/add") as view:
    left = view.explain_arithmetic(Address("ram", 0), Address("ram", 4), "RAX")
    right = view.explain_arithmetic(Address("ram", 9), Address("ram", 9), "RAX")

proof = prove_equivalence(left, right)
print(proof.status, proof.reason)
```

## Python API

Inspect the instruction containing an address in a saved Program:

```python
from binaryrat import Address, open_program

with open_program("workspace.gpr", "/program") as view:
    ins = view.instruction_pcode(Address("ram", 0x401000))
    if ins is not None:
        for op in ins.effective.operations:
            print(op.site, op.sequence, op.mnemonic, op.output, op.inputs)
        print("Raw operations:", ins.raw.operation_count)
        print("Effective listing truncated:", ins.effective.truncated)
```

`raw` is the instruction's SLEIGH p-code. `effective` includes Listing
overrides. Both preserve operand order, byte widths and address spaces. For a
defined instruction with empty semantics, the result has zero operations.
Undefined bytes return `None`. Each listing returns up to 128 operations and
eight inputs per operation with original counts. Check both truncation flags
when comparing the two listings.

```python
from binaryrat import EngineClient, load_export

for decompilation in load_export("functions.jsonl"):
    print(decompilation.function.entry, decompilation.successful)

with EngineClient("./build/binaryrat-engine", cache_dir="./cache") as engine:
    print(engine.ping())
    # Supply validated program-state identities and the complete analysis options.
    key = dict(schema_version=1, ghidra_version="12.2", program_id="example",
               revision=1, address_space="ram", address="1000",
               body_sha256="a" * 64, options_digest="b" * 64)
    engine.cache_put(key, {"c": "return 0;"}, ["type:example"])
    print(engine.cache_get(key))
    print(engine.cache_invalidate(["type:example"]))
```

Export records are consumed lazily. Function identities retain the program ID,
revision and address-space name; offsets are unsigned Python integers. The parser
rejects malformed records, unsupported schema versions and duplicate identities
within a revision, and reports the physical input line. Unknown fields are accepted.

`EngineClient` serializes requests and checks protocol-v1 envelopes and request
correlation. It inherits stderr, uses no shell, and terminates the connection on
protocol errors or a configurable deadline (60 seconds by default). Native errors
raise `EngineError` with a machine-readable `code`; transport/protocol failures
raise `ProtocolError`. Use the context manager to release process resources.

`recover_types()` returns the native engine's preliminary layout evidence as a
mapping. It is not a recovered C++ class model or calibrated type probability.
`TypeProposal` is a value object reserved for reviewable proposals, not a claim
that proposal generation or database application is already implemented.

API version `0.1.0` is experimental and distinct from native protocol version `1`.
The inline annotations and `py.typed` marker cover this facade. Upstream Ghidra
stubs and PyGhidra remain separate packages; they are not bundled or duplicated.

## Live Program access

Install the optional dependency with `python -m pip install './binaryrat/python[live]'`,
or install `pyghidra==3.2.0` from the official distribution's
`Ghidra/Features/PyGhidra/pypkg/dist` wheel directory. Set `JAVA_HOME` to JDK 25
and `GHIDRA_INSTALL_DIR` to Ghidra 12.2, or supply the installation explicitly.
For the complete BinaryRat archive, use its `ghidra/` directory as the
installation. Set `JAVA_HOME_OVERRIDE` to the sibling `jdk/` directory
to select the bundled JDK in PyGhidra.

```python
from binaryrat import open_program

with open_program("workspace.gpr", "/program") as program:
    page = program.functions(limit=20)
    if page.items:
        entry = page.items[0].entry
        print(program.xrefs_to(entry).items)
        print(program.decompile(entry).c)
    print(program.data_types(limit=20).items)
```

The context owns the saved local Program and returns immutable Python values.
Close it to release Ghidra storage. Later contexts reuse the JVM in the same
Python process, including REPL and notebook sessions. Functions, xrefs, and
type listings accept an offset and return the next offset when additional
records exist. Each page returns up to 1,000 values. Ghidra maintains its own
type and reference indexes in memory. Listing offsets stop at 100,000,
with `Page.truncated` set when the scan limit prevents another page.
Outgoing xrefs check the reference count before requesting its Java array.
Type listings check the Ghidra type index count before taking an additional
copy. Ghidra can build the entire sorted index to answer the count. Exact
type lookups are available when a listing exceeds the collection limit.

All methods perform read-only inspection of saved, non-linked Programs.
The view checks the Program modification number before and after reads.
Open a new context after saving a different Program revision. An optional
`threading.Event` can interrupt a decompilation and cancel a listing between
records. The default `backend="auto"` uses the shared BinaryRat scheduler
when the extension is installed and uses Ghidra's stock backend on a plain
Ghidra installation. Set `backend="scheduled"` to require the extension,
or `backend="stock"` to run the stock backend with a 4 MiB native reply
ceiling. Startup, engine, cache and running-analysis errors from the scheduled
backend reach the caller. A context closes its decompilation session before
releasing its Program.

`view.function_containing(address)` finds the function whose body holds an
address, and `view.functions_named(name)` finds functions by simple or
qualified name; a name can repeat across namespaces.

`view.decompilation_backend` reports the selected backend.
`view.decompile_with_metrics(entry)` includes the result and its cache
status. Set `BINARYRAT_CACHE_DIR` before launching Python to persist scheduled
results. Use a directory dedicated to one running engine. Reopening a saved
Program can reuse persisted results after replay checks.

`view.solve_layout(entry, parameter_index=0, max_summaries=32, timeout_seconds=30)`
recovers summary layout evidence through the extension's Java
`binaryrat.SummaryLayouts` service, the same code as `BinaryRatSolveLayouts.java`.
It asserts that the parameter points at an object's start, decompiles each
reached function parameter once and lets the engine follow calls through
recursion. The result is a `SummaryLayoutReport`: fields, union candidates,
call components, refused calls, and `call_path(state)` or
`evidence_for(offset, width)` for provenance. Every report is validated before
it is returned, and `load_summary_report(path)` applies the same checks to a
saved file. A report changed after recovery, a missing extension, or a
recovery the service refuses raises `StaleProgramError`, `LiveProgramError` or
`LayoutRecoveryError`.

`view.call_sites(entry, max_sites=64, max_callers=32, timeout_seconds=30)`
lists every call to a function through the extension's Java `binaryrat.CallSites`
service, the same code as `BinaryRatCallSites.java`. Calls through thunks of
the function count as calls to it, and each caller is decompiled once under a
memory-watched lease. Each `CallSite` carries the caller's C statement and its
arguments: a value the decompiler proved constant, or a pointer to a defined
string or labelled address with that string or symbol, or the name of the
variable passed. `argument.render()` writes the value as a C call shows it.
Calls the decompiled code does not show, calls outside any function, callers
that fail to decompile and callers past `max_callers` keep their address and a
status with the reason. Validation and errors follow `solve_layout`;
`load_call_sites_report(path)` reads a saved report and a refused listing raises
`CallSitesError`.

`view.stack_strings(entry=None, minimum_length=4, max_functions=10_000, timeout_seconds=None)` lists
text built on the stack with constant stores, in one function or in every
function, through the extension's Java `binaryrat.StackStrings` service and the
engine's `strings.stack` op. Each `StackString` has its function, stack offset,
encoding (`ascii` or `utf16le`), text, terminator and the instructions that
wrote it; `render()` quotes it as a C literal. `load_stack_strings_report(path)`
reads a saved report and a refused scan raises `StackStringsError`. A timeout
from 1 to 60 seconds requests cooperative cancellation and raises
`TimeoutError` when exceeded. The engine client exposes the op directly as
`EngineClient.stack_strings(groups)`.

## Decompile from the CLI

`binaryrat-decompile` is available after installing the wheel. With PyGhidra
installed and your Ghidra 12.2 installation selected, run

```console
binaryrat-decompile workspace.gpr /program ram:0x401000 --json
binaryrat-decompile workspace.gpr /program parse_header
binaryrat-decompile workspace.gpr /program 0x401a2c
binaryrat-decompile workspace.gpr /program --list --match parse
binaryrat-decompile workspace.gpr /program parse_header --call-sites
binaryrat-decompile workspace.gpr /program --stack-strings
```

The CLI requires the shared scheduler by default. Pass `--install-dir` to
select a Ghidra installation explicitly. Select the function by any address
in its body, such as a call site from a crash report, or by name
(`ns::f` for a qualified name). An address is an unsigned hexadecimal offset;
omit the address space to use the Program's image-base space. A name that is
also valid hexadecimal, such as `add`, needs the `name:` prefix. A shared name
is refused with the matching entries. `--list` prints each function's entry
and signature without decompiling, and `--match` keeps names that contain the
text. `--call-sites` prints each call to the function with its caller, C
statement and constant arguments (`--max-sites`, `--max-callers`), or the
validated report with `--json`. `--stack-strings` lists strings built on the
stack in FUNCTION or, without it, in every function (`--min-length`,
`--max-functions`). By default the command writes C on success. The
JSON form includes the backend, cache status and decompiler flags. Exit status is
0 on success, 1 for an incomplete decompilation, no calls or no strings, 2
for invalid input or an unavailable Program or backend, and 130 on interruption.

## Read a Program already open in PyGhidra

In a PyGhidra script with a Program handle in the same JVM, pass it directly
to the foreground service. Run this on a worker after auto-analysis has
finished.

```python
from binaryrat import Address, decompile_program

result = decompile_program(currentProgram, Address("ram", 0x401000))
print(result.result.c)
```

The call reads the Program's current in-memory revision and releases its own
consumer while preserving the caller's ownership. Use the saved-project
commands for a project in a separate desktop process.

## Keep a local JVM open between Python processes

Launch the read service for a specific saved Program. Capture its standard
output privately and pass the `binaryrat-live` ready line to authorized clients.

```text
binaryrat-live workspace.gpr /program --idle-timeout 300
```

```python
from binaryrat.live_service import LiveClient, LiveEndpoint

endpoint = LiveEndpoint.from_ready_line(ready_line)
client = LiveClient(endpoint)
print(client.info())
print(client.functions(limit=10).items)
```

The ready line carries a random token and the loopback port. Each connection
serves one bounded read over protocol version 1. Clients share one JVM and one
Program context. The ready line identifies the backend. Set `--backend scheduled`
to require the BinaryRat extension. The service processes requests serially, limits request
packets to 16 KiB and responses to 1 MiB, caps listing offsets at 100,000,
and passes a maximum 60-second function timeout to Ghidra. Exact-address and type lookups are
available independently of the listing offset. `client.solve_layout(entry)` returns the same
validated report as `view.solve_layout`, at most 64 summaries per request; give the client a
timeout that covers the whole recovery. A refused recovery is the error `layout_failed`.
`client.call_sites(entry)` returns the same report as `view.call_sites`, at most 256 sites
and 64 decompiled callers per request; a refused listing is the error `call_sites_failed`.
`client.stack_strings(entry=None, minimum_length=4, max_functions=32, timeout_seconds=30)`
returns a validated stack-string report from the saved Program. Pass a function
entry to select one function or omit it to scan up to 64 functions in entry order.
Set `max_functions` between 1 and 64 and `timeout_seconds` between 1 and 60.
A refused scan returns `stack_strings_failed`, an expired scan returns
`timed_out`, and a report above the response limit returns `response_too_large`.
Set the client timeout to cover the scan and the native engine's separate
bounded request and shutdown waits.
The daemon starts with a 1,024 MiB JVM heap ceiling. Use `--max-heap-mb`
to configure it.
It closes its Program and listener after the idle interval or on Ctrl+C.
The idle deadline still applies while the daemon reads a partial request.
After authorized work finishes, the next idle interval begins.

Run tests from the repository root:

```console
PYTHONPATH=binaryrat/python/src python -m unittest discover -s binaryrat/python/tests -v
```

Set `BINARYRAT_GHIDRA_INSTALL_DIR` to a Ghidra 12.2 installation to run the
live integration tests, including a service used by separate clients. Use the
packaged application or install the compiled extension for the scheduled and
foreground integration checks.

On PowerShell set `$env:PYTHONPATH="binaryrat/python/src"` before running the
`python -m unittest ...` command. All new files are licensed under Apache-2.0;
see the repository's LICENSE and NOTICE files.
