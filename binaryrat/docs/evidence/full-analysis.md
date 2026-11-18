# Whole-program auto-analysis baseline

The BinaryRat profiler imports each complete input into a disposable project and
runs stock Ghidra auto-analysis. The analysis wall time comes from the pre- and
post-script bracket. Process wall time and sampled peak process-tree RSS include
startup, import, and report collection. Ghidra's `StoredAnalyzerTimes` records
elapsed time by task, including time spent waiting for analyzer-owned workers.
The profiler records completion markers, deadlines, errors, loader diagnostics,
analysis options, and a selected inventory of the resulting Program.
[Profiler](../../benchmarks/profile_auto_analysis.py) ·
[Ghidra timing API](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.2_build/Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/analysis/StoredAnalyzerTimes.java)

The runs used Linux 6.18.57 on x86-64, a 4-CPU cgroup quota, 16 GiB cgroup
memory limit, official Ghidra `Ghidra_12.2_build`, Java 25.0.5+8-LTS, Python
3.12.14, and psutil 6.1.1. Process-tree RSS was sampled every 50 ms. These are
single-run measurements from a shared development environment.

## Inputs and outcomes

| Input | Bytes | SHA-256 |
| --- | ---: | --- |
| Debian `libllvm19` `1:19.1.7-3+b1` `/usr/lib/x86_64-linux-gnu/libLLVM.so.19.1` | 129,673,080 | `3523f50f635d2a1ea47518a392451f2854b92823ceaf1345fb806099dd1a3b8a` |
| BinaryRat data-heavy ELF control generated below | 104,871,768 | `5a1fdbd1de9b827edc9de23664a8c6967aba9936131328c53b7042e45e3140a4` |

| Run | Outcome | Analysis wall or deadline | Process wall | Peak process-tree RSS |
| --- | --- | ---: | ---: | ---: |
| Whole LLVM, stock headless pilot, 4-CPU cap, 8 GiB heap | Ghidra timed out and reported an analyzer exception | 360 s deadline | 397.519 s | 3,589,378,048 bytes |
| Whole data-heavy control, profiler, 3-CPU cap, 4 GiB heap | Completed | 15.202 s | 28.165 s | 944,132,096 bytes |

The LLVM pilot used stock headless logging and process sampling. It returned
process status `0` despite the analysis deadline and the `Disassemble Entry
Points` exception, `body must contain the entry point`. The ELF loader reported
unsupported TLS relocations during import. Treat the task times as observations
of a partial run. The data-heavy control completed with 12 functions and 66
instructions. Its version 1 inventory SHA-256 was
`e06996acf0b658ef7e8787744b8b2acafc52b329b3e4b7fd7cbdf73698bc8c78`.
The control exercises full import, analysis, and evidence collection on a large
mapped image with little code.

## Measured tasks to investigate

| Ghidra task | LLVM elapsed |
| --- | ---: |
| Disassemble | 270.312 s |
| Disassemble Entry Points | 55.400 s |
| GCC Exception Handlers | 29.884 s |
| Function Start Pre Search | 2.719 s |

The first two tasks account for about 91% of the recorded LLVM task time. A JVM
stack sample at about 299 s showed the main analysis thread in
`DisassembleCommand`, `CodeManager.addInstructions`, and memory-reference
insertion. `CodeManager.addInstructions` takes the Program write lock and
preserves instruction conflicts and delay-slot handling. Profile decode and
ordered writes separately before changing this path. The comparatively cheap
serial function-start search is a lower priority on this pilot. The stock
entry-point failure and timeout leave comparable completed LLVM runs as a
prerequisite for evaluating a speedup.
[Disassembly command](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.2_build/Ghidra/Features/Base/src/main/java/ghidra/app/cmd/disassemble/DisassembleCommand.java) ·
[Instruction insertion](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/database/code/CodeManager.java#L408)

### Longer LLVM trial

A fresh stock import of the same LLVM digest used an 8 GiB heap, a 3-CPU
Ghidra limit, and a 1,320-second analysis deadline. It ran for 1,353.168 seconds
end to end and peaked at 8,862,904,320 bytes of sampled process-tree RSS.
Ghidra logged 1,982 application error lines, including function-body repair
overlaps, and exited with status 0 after reporting the analysis timeout.
The profiler classified the result as failed.

The largest task times recorded before interruption were Call-Fixup Installer
(545.544 s), Non-Returning Functions - Discovered (423.770 s), and Disassemble
(181.786 s). Other verification jobs shared the host. The results identify
work to investigate and leave whole-program LLVM equivalence open. [Focused no-return benchmark](../core-patches/no-return-candidate-checks.md)

### No-return candidate on the whole data-heavy control

Two fresh stock imports and two fresh candidate imports completed with identical
inventories on the 104,871,768-byte control. Each had 12 functions, 66
instructions, and the version 1 inventory digest recorded above. The runs used a 2 GiB
heap, a 2-CPU Ghidra limit, and alternating order. The candidate loaded the
updated analyzer class in an otherwise stock installation.

| Installation | Analysis wall range | Sampled peak process-tree RSS range |
| --- | ---: | ---: |
| Stock | 15.089–85.628 s | 1,011,892,224–1,056,477,184 bytes |
| No-return candidate | 19.953–31.614 s | 859,295,744–1,055,428,608 bytes |

The control validates equivalent completed work on a large mapped image.
Host contention and the small instruction count make this comparison
unsuitable for estimating an analysis speedup.

Inventory version 2 includes no-return flags on internal and external functions
and every bookmark's address, type, category and comment. Stock and the
candidate with fall-through cycle detection each completed a fresh import of
the same control with digest `b02bd5acd4e3865856fb11ec88128e35f1510d046f9d21e1cd523e53007ba8c8`.
During this shared-host run, analysis took 130.11 s for stock and 152.70 s
for the candidate. Sampled peak process-tree RSS was 1,073,168,384 and
850,042,880 bytes respectively.
The focused fixture verifies that each field changes the digest and that
reinserting identical bookmarks in a different order preserves it.
The profiler reports the number of completed independent comparisons. A single
baseline or a comparison interrupted by a timeout leaves parity unverified.
[Inventory regression](../../benchmarks/ghidra_scripts/BinaryRatInventoryProof.java)

## Reproduce

From the repository root, set `JAVA_HOME` to a JDK 25 installation. Use an
official Ghidra 12.2 installation and install psutil from
`binaryrat/requirements-test.txt`. The profiler checks the input hash and
fingerprints the application and benchmark script. Its nonzero exit status
distinguishes incomplete work or an inventory mismatch from a comparable run.

```bash
python binaryrat/benchmarks/profile_auto_analysis.py \
  --ghidra /path/to/ghidra_12.2_PUBLIC \
  --input /usr/lib/x86_64-linux-gnu/libLLVM.so.19.1 \
  --expected-sha256 3523f50f635d2a1ea47518a392451f2854b92823ceaf1345fb806099dd1a3b8a \
  --output build/full-analysis-llvm --analysis-timeout 360 --process-timeout 445 \
  --max-cpus 4 --heap 8G
```

For the data-heavy control, build with GCC 14.2.0 and GNU ld 2.44 on Debian
x86-64. The executable contains a 100 MiB initialized lookup table. The
benchmark imports the executable without running it.

```bash
mkdir -p build/full-analysis-control
cat > build/full-analysis-control/dataset.c <<'EOF'
#include <stddef.h>

const unsigned char dataset[104857600] = {
    [0] = 17, [104857599] = 23,
};

unsigned int read_sample(size_t offset) {
    return offset < sizeof(dataset) ? dataset[offset] : 0;
}

int main(int count, char **argv) {
    (void)argv;
    return (int)read_sample((size_t)count);
}
EOF
LC_ALL=C cc -O1 -fno-pie -no-pie -Wl,--build-id=none -s \
  -o build/full-analysis-control/large-dataset build/full-analysis-control/dataset.c
python binaryrat/benchmarks/profile_auto_analysis.py \
  --ghidra /path/to/ghidra_12.2_PUBLIC \
  --input build/full-analysis-control/large-dataset \
  --expected-sha256 5a1fdbd1de9b827edc9de23664a8c6967aba9936131328c53b7042e45e3140a4 \
  --output build/full-analysis-control-result --analysis-timeout 110 --process-timeout 175 \
  --max-cpus 3 --heap 4G
```

`--candidate-ghidra` adds a second Ghidra 12.2 installation and
`--repetitions` enables repeated independent imports with alternating order.
The selected inventory covers function entries and bodies, signatures, no-return
flags, bookmarks, instruction boundaries and flow overrides, defined data, and
references from Program memory.
