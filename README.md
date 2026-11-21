<!-- Modified by YurilLAB for BinaryRat: project overview and branding. -->
# BinaryRat

<img src="binaryrat/docs/assets/logo.png" alt="BinaryRat logo, a gray rat with red eyes and a black headband" width="360">

BinaryRat is an open-source reverse-engineering project for Linux and Windows, built on Ghidra 12.2. Its C++20 engine manages decompilation scheduling and caching, and a Java extension connects it to Ghidra's native decompiler. [Ghidra 12.2 upstream](https://github.com/NationalSecurityAgency/ghidra/tree/Ghidra_12.2_build)

**Standalone BinaryRat previews for Windows x64 and Linux x64.** Verified ZIPs are published on GitHub Releases after both platform builds pass CI. Each ZIP includes the patched Ghidra build, BinaryRat's native engine and compiled extension, the default desktop workspace, JDK 25, and local help with an example binary. Extract the ZIP and launch `binaryrat.bat` on Windows or `./binaryrat` on Linux. [Releases](https://github.com/YurilLAB/BinaryRat/releases)

## Contents

- [What BinaryRat does](#what-binaryrat-does)
- [What CI verifies](#what-ci-verifies)
- [Documentation](#documentation)
- [License](#license)

## What BinaryRat does

- **Parallel decompilation** schedules native decompiler processes within CPU and memory budgets and enforces per-function deadlines.
- **Persistent caching** tracks program changes and validates recorded decompiler queries before reusing results across sessions.
- **Stock-verified exports** check every JSONL record against serial Ghidra output and report where stock results were used.
- **Layout recovery in CodeBrowser** examines a function parameter at the cursor and lets you jump from a proposed field to the load or store that supports it.
- **C++ recovery** reports Itanium and MSVC class relationships and vtables.
- **Reviewed type creation** lets an analyst approve a new structure with provenance and native Ghidra undo.
- **Call sites with arguments** list every call to a function with the values the decompiler proved constant and the strings or symbols they point to.
- **Stack strings** recover text a function builds on its stack, with the instructions that wrote it.
- **Call-site corrections** show an instruction's p-code with register names, before and after Listing overrides, and apply or replace a reviewed prototype at one call with native undo. Indirect calls start from the decompiler's view of their arguments.
- **Desktop and scripting access** provides BinaryRat actions in CodeBrowser, headless exports, and typed Python access through PyGhidra.
- **BinaryRat analyst tools** compare two decompiler exports with `binaryrat-diff` (`--patch` shows the changed C) and show which instructions support a proposed field with `binaryrat-explain`. Both work offline on saved reports. `binaryrat-decompile` decompiles a function from a saved project, selected by name or by any address inside it.

## What CI verifies

Every commit to `master` is built and tested on Linux and Windows.

- Byte-for-byte stock parity on 384 sampled functions from a 130 MB LLVM library, checked against a separate serial stock run. [Benchmark evidence](binaryrat/docs/evidence/llvm19-linux.md)
- Read-only p-code layout footprints against separate DWARF and PDB ground truth. [Corpus](binaryrat/corpus/README.md)
- The complete application ZIP for each platform, launched with its bundled JDK to import and decompile an example.
- The patched no-return analyzer runs faster on a controlled call-heavy fixture. [Analyzer benchmark](binaryrat/docs/core-patches/no-return-candidate-checks.md)

## Documentation

| Topic | Document |
|---|---|
| Build the engine and run the tests | [Engine and tooling](binaryrat/README.md) |
| Install and use the Ghidra extension | [Export bridge](binaryrat/bridge/README.md) |
| Python API and analyst commands | [Python client](binaryrat/python/README.md) |
| Checks, CI and raw evidence | [Verification](binaryrat/docs/VERIFICATION.md) |
| Using BinaryRat in a Ghidra team | [Adoption guide](binaryrat/docs/ADOPTION.md) |
| Design, gates and roadmap | [Architecture](binaryrat/docs/ARCHITECTURE.md) |
| Changes to upstream Ghidra files | [Core patch ledger](binaryrat/docs/core-patches/README.md) |
| Questions and bug reports | [Support](.github/SUPPORT.md) |

## License

BinaryRat is licensed under [Apache 2.0](LICENSE). [Upstream and third-party notices](NOTICE)
