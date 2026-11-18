# BinaryRat Python client (experimental 0.1.0)

The standard-library client keeps the **native C++ engine** alive across requests
and reads versioned JSONL exported by the Java bridge. The optional live API
reads saved Ghidra programs through PyGhidra 3.2.0 and Ghidra 12.2.

Install with `python -m pip install ./binaryrat/python`. Python 3.10+ is required.
No runtime Python dependencies are required.

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
records. Each Program context reuses one stock decompiler, with a per-call
deadline and Ghidra's 4 MiB reply ceiling. Closing the context stops the
decompiler and releases its Program.

## Keep a local JVM open between Python processes

Launch the read service for a specific saved Program. Capture its standard
output privately and pass the `binaryrat-live` ready line to authorized clients.

```text
python -m binaryrat.live_service workspace.gpr /program --idle-timeout 300
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
Program context. The service processes requests serially, limits request
packets to 16 KiB and responses to 1 MiB, caps listing offsets at 100,000,
and passes a maximum 60-second function timeout to Ghidra. Exact-address and type lookups are
available independently of the listing offset.
The daemon starts with a 1,024 MiB JVM heap ceiling. Use `--max-heap-mb`
to configure it.
It closes its Program and listener after the idle interval or on Ctrl+C.

Run tests from the repository root:

```console
PYTHONPATH=binaryrat/python/src python -m unittest discover -s binaryrat/python/tests -v
```

Set `BINARYRAT_GHIDRA_INSTALL_DIR` to the official Ghidra 12.2 installation to
run the live integration tests, including a service used by separate clients.

On PowerShell set `$env:PYTHONPATH="binaryrat/python/src"` before running the
`python -m unittest ...` command. All new files are licensed under Apache-2.0;
see the repository's LICENSE and NOTICE files.
