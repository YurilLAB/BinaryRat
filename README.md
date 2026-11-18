<!-- Modified by YurilLAB for BinaryRat: project overview and branding. -->
# BinaryRat

<img src="binaryrat/docs/assets/logo.png" alt="BinaryRat logo, a gray rat with red eyes and a black headband" width="360">

BinaryRat is an open-source reverse-engineering project for Linux and Windows, built on Ghidra 12.2. Its C++20 engine manages decompilation scheduling and caching, and a Java extension connects it to Ghidra's native decompiler. [Ghidra 12.2 upstream](https://github.com/NationalSecurityAgency/ghidra/tree/Ghidra_12.2_build)

## What BinaryRat does

- **Parallel decompilation** schedules native decompiler processes within CPU and memory budgets and enforces per-function deadlines.
- **Persistent caching** tracks program changes and validates recorded decompiler queries before reusing results across sessions.
- **Stock-verified exports** check every JSONL record against serial Ghidra output and report where stock results were used.
- **Desktop and scripting access** provides exports from CodeBrowser and headless Ghidra, plus a typed Python client for export records and the native engine.

## Project status

Linux CI checks byte-for-byte stock parity on 384 sampled functions from a 130 MB LLVM library. Stock verification uses a separate serial pass. [Benchmark evidence](binaryrat/docs/evidence/llvm19-linux.md)

Interprocedural type recovery, C++ class recovery, protected type write-back, and a persistent Ghidra JVM are on the development roadmap. [Architecture and milestones](binaryrat/docs/ARCHITECTURE.md)

## Guides

- [Build and test BinaryRat](binaryrat/README.md)
- [Install and use the Ghidra extension](binaryrat/bridge/README.md#install-the-extension)

## License

BinaryRat is licensed under [Apache 2.0](LICENSE). [Upstream and third-party notices](NOTICE)
