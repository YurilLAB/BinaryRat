<!-- Modified by YurilLAB for BinaryRat: project overview and branding. -->
# BinaryRat

<img src="binaryrat/docs/assets/logo.png" alt="BinaryRat logo, a gray rat with red eyes and a black headband" width="360">

BinaryRat is an open-source reverse-engineering project for Linux and Windows, built on Ghidra 12.2. Its C++20 engine manages decompilation scheduling and caching, and a Java extension connects it to Ghidra's native decompiler. [Ghidra 12.2 upstream](https://github.com/NationalSecurityAgency/ghidra/tree/Ghidra_12.2_build)

## What BinaryRat does

- **Parallel decompilation** schedules native decompiler processes within CPU and memory budgets and enforces per-function deadlines.
- **Persistent caching** tracks program changes and validates recorded decompiler queries before reusing results across sessions.
- **Stock-verified exports** check every JSONL record against serial Ghidra output and report where stock results were used.
- **Layout recovery in CodeBrowser** examines a function parameter at the cursor and lets you jump from a proposed field to the load or store that supports it.
- **C++ recovery** reports Itanium and MSVC class relationships and vtables.
- **Reviewed type creation** lets an analyst approve a new structure with provenance and native Ghidra undo.
- **Desktop and scripting access** provides exports from CodeBrowser and headless Ghidra, plus typed Python access to saved Programs through PyGhidra.
- **BinaryRat analyst tools** compare two decompiler exports with `binaryrat-diff` and show which instructions support a proposed field with `binaryrat-explain`. Both work offline on saved reports.

## Project status

Linux CI checks byte-for-byte stock parity on 384 sampled functions from a 130 MB LLVM library. Stock verification uses a separate serial pass. [Benchmark evidence](binaryrat/docs/evidence/llvm19-linux.md)

The no-return analyzer runs faster on a controlled call-heavy fixture. Whole-program speed on code-heavy binaries, broader type inference, and calibrated confidence remain open. [Analyzer benchmark](binaryrat/docs/core-patches/no-return-candidate-checks.md) · [Architecture and milestones](binaryrat/docs/ARCHITECTURE.md)

## Guides

- [Build and test BinaryRat](binaryrat/README.md) · [Install the Ghidra extension](binaryrat/bridge/README.md#install-the-extension)
- [Adopt BinaryRat in a Ghidra team](binaryrat/docs/ADOPTION.md) · [Contact the maintainer](.github/SUPPORT.md)

## License

BinaryRat is licensed under [Apache 2.0](LICENSE). [Upstream and third-party notices](NOTICE)
