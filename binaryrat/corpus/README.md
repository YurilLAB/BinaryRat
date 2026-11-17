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
means compilation, oracle separation and stripping checks passed. DWARF/PDB
type extraction, precision/recall scoring, confidence calibration, whole-program
fixtures and the required 100MB+ benchmark suite remain to be implemented.

The fixture ABI and layout depend on compiler and target. Read the debug files
for ground truth; do not assume hard-coded host offsets. Optimized debug
information can omit source facts. Future scoring must report missing facts
and denominator exclusions explicitly rather than silently treating them as
correct recoveries.
