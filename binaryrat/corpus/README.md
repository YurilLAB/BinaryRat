# BinaryRat ground-truth corpus

These Apache-2.0 fixtures exercise primitive/pointer/function-pointer types,
recursive structs, unions, arrays and packed fields, plus C++ RTTI, virtual
functions, multiple inheritance and virtual inheritance. They are a small
reproducible starting corpus, not an accuracy benchmark or a large-binary
performance result.

From the repository root, using Python 3.10 or newer:

```sh
python binaryrat/tools/build_corpus.py --output build/corpus --toolchain gcc --toolchain clang --optional-toolchain gcc-aarch64
python -m unittest discover -s binaryrat/tools -p "test_*.py"
```

GCC and Clang use `-O0`, `-O1`, `-O2`, `-O3` with DWARF 4. GNU `objcopy` and
`strip` separate the debug file and strip the analysis copy. The Linux AArch64
toolchain is `aarch64-linux-gnu-{gcc,g++,objcopy,strip}`. Making it required with
`--toolchain gcc-aarch64` fails if unavailable; an optional missing toolchain
is recorded as **unavailable**, never as a successful test.

Run the following in an initialized MSVC x64 developer environment on Windows:

```powershell
python binaryrat/tools/build_corpus.py --output build/corpus --toolchain msvc
```

Use an MSVC x64-to-ARM64 developer environment and `--toolchain msvc-aarch64`
for AArch64 PE/PDB fixtures. MSVC uses `/Od`, `/O1`, `/O2`, `/Ox`; these are its
documented modes, not claimed equivalents of GCC's optimization levels. MSVC
stores debug information in a separate PDB. The analysis PE copy additionally
has its debug directory and referenced CodeView/PDB lookup payloads zeroed,
preventing an accidental oracle lookup. This procedure supports ordinary
user-mode PE32+ fixture executables, not signed binaries or kernel drivers.

Each variant has separate `oracle/` and `analysis/` directories. `manifest.json`
records compiler versions, commands, optimization modes, target architecture,
source and artifact SHA-256 hashes, debug files and executable-section hashes.
Compilation and stripping must preserve executable sections exactly. Native
oracle and stripped executables must produce identical successful results;
cross-target execution is explicitly recorded as `not-run-cross-target`.

Consumers must use only `artifacts[].binary` as the inference input. Resolve
artifact paths relative to the manifest's `root`, which points to the generated
corpus directory. Keep `oracle_binary` and `debug_file` outside the inference
process and disable debug/symbol-server discovery. Successful corpus generation
means compilation, oracle separation and stripping checks passed. The
read-only layout verifier runs inference on the stripped C artifact with
`read_packed` parameter 0 selected. It reads `PackedRecord` from the separate
DWARF or PDB after Ghidra exits and scores exact field byte offsets and widths.
The PE oracle uses LLVM's `llvm-pdbutil`. Semantic type scoring, confidence calibration, whole-program
fixtures and the required 100MB+ benchmark suite remain to be implemented.

The fixture ABI and layout depend on compiler and target. Read the debug files
for ground truth; do not assume hard-coded host offsets. Optimized debug
information can omit source facts. Future scoring must report missing facts
and denominator exclusions explicitly rather than silently treating them as
correct recoveries.

## C++ RTTI evidence

Run `BinaryRatRecoverRtti.java OUTPUT_JSON` as a headless postScript on a
Ghidra 12.2 Program. The script reports ABI-encoded class names, direct bases,
virtual-base flags, known offsets, and vtable address points with their first
executable slot. Each record carries the metadata address that supports it.
Virtual bases keep their ABI displacement fields and have no fixed object offset.

The collector covers little-endian x86-64 and AArch64. Itanium ELF needs applied
absolute relocations to the runtime type-info vtables. MSVC PE32+ needs DIR64
relocations, revision-1 complete object locators, and valid hierarchy descriptors.
Table results describe address points with executable first slots and can include
construction tables. The collector stops at 200,000 relocation visits, 1,024
classes, 16,384 total base records, or 4,096 tables. It bounds hierarchy depth
and checks the Program revision before publishing a new file.

```sh
python binaryrat/benchmarks/verify_rtti.py --ghidra /path/to/ghidra_12.2_PUBLIC \
  --corpus build/corpus/manifest.json --output build/ghidra-report/rtti
```

The verifier compares the stripped C++ fixture against its known single,
multiple, and virtual inheritance. It also corrupts one RTTI field, checks
stale and cancelled reads, and compares saved project hashes before and after
collection.
