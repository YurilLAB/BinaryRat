# BinaryRat Python client (experimental 0.1.0)

The standard-library client keeps the **native C++ engine** alive across requests.
It does not keep Ghidra or a JVM alive, invoke PyGhidra, or mutate a Ghidra program.
The Java bridge exports versioned decompilation records separately, validating
the Program modification number before and after reading; these are not database
snapshots. These boundaries are
intentional MVP limits; a persistent Ghidra owner remains future work.

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

Run tests from the repository root:

```console
PYTHONPATH=binaryrat/python/src python -m unittest discover -s binaryrat/python/tests -v
```

On PowerShell set `$env:PYTHONPATH="binaryrat/python/src"` before running the
`python -m unittest ...` command. All new files are licensed under Apache-2.0;
see the repository's LICENSE and NOTICE files.
