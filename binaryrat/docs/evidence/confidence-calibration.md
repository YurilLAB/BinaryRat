# Type proposal confidence calibration

BinaryRat's layout solver reports `evidence_strength` as `n / (n + 1)`, where
`n` is the number of distinct p-code evidence IDs for a proposed byte range.
The value expresses support. Repeated accesses can agree on a byte range while
leaving the signedness, declared member type, and enclosing layout ambiguous.
Use separate proposal kinds and truth rules for field footprints, union views,
and class relationships.

## Prepare the evidence

The offline evaluator accepts schema version 1. Declare the score implementation
and oracle predicate for each kind. Each case is an eligible oracle target. Give
it a stable ID even when the analysis abstains. Use an empty `proposals` array
for an abstention and `null` for a proposal without a numeric score.

```json
{
  "schema_version": 1,
  "kinds": {
    "struct.field_footprint": {
      "score_kind": "uncalibrated_evidence_strength",
      "truth_rule": "Byte offset and width match a declared oracle field."
    }
  },
  "cases": [
    {
      "case_id": "project/GCC-O2/main:parameter-0",
      "source_family": "project",
      "source_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "binary_sha256": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
      "split": "holdout",
      "kind": "struct.field_footprint",
      "proposals": [{"proposal_id": "bytes:1:4", "score": 0.5, "correct": true}]
    }
  ]
}
```

Assign `fit` and `holdout` by source family before reviewing outcomes. Give
related versions, forks, compiler variants, optimization levels, and target
architectures the same family. Record the binary SHA-256 and the SHA-256 of the
fixture source or a canonical manifest of its source files. The evaluator
rejects families spanning both splits and any source or binary digest assigned
to multiple families. Use an independent source-level oracle to label every
emitted proposal as correct or incorrect under its declared truth rule.

```sh
python binaryrat/benchmarks/calibrate_type_confidence.py --input cases.json > calibration.json
```

## Read the report

The evaluator fits each kind independently using ten fixed raw score bins. A
larger raw score represents stronger support. It assigns equal total fit weight
to each family and adds one neutral pseudo-family whose proposals fall in the
bins like the fit families' own, so every estimate moves toward one half by
`1 / (families + 1)`. It pools adjacent supported bins until their fitted
estimates are monotone. Fitting requires at least five scored families, two
families with each outcome, and three scored families for each supported bin.
Unsupported bins abstain. The fit uses only fit-partition cases and labels.

The held-out report gives case and proposal counts, abstention coverage, and
the fraction of numerically scored proposals with fitted estimates. Brier
error averages squared error within each family and then across families.
Compare the fitted estimates with `paired_raw_brier` and
`paired_raw_reliability_error` on the same scored proposals. The raw
evidence-strength comparison treats the support score as a numerical baseline.
Each family has total weight one. It contributes to a bin in proportion to
the share of that family's proposals in the bin. Observed correctness and mean score
use those same contributions within each bin. `reliability_error` is the
mass-weighted mean of the absolute gaps between these rates. The console
comparison uses paired proposals, and the JSON report also retains diagnostics
for every raw score.
`thresholds` gives, for each fixed score, the precision of the proposals at or
above it and the share of correct proposals it keeps. That recall counts
proposed fields only: fields the analysis never proposed are not in the dataset.
An empty group reports a null estimate. Approximate 95% intervals resample the
contributing held-out families with a fixed seed and require at least eight.
Reliability-bin intervals retain each family's contribution to that bin.
The fitted model stays fixed during resampling. Sparse holdouts remain descriptive.

## Packed structure diagnostic

Stage a `verify_type_accuracy.py` report and its corpus manifest by supplying the
exact fixture source snapshot. Staging verifies source, binary, and debug
hashes, checks the layout report against its p-code evidence, recomputes the
score from the recorded support, and reads the separate debug oracle again.
Use `--pdbutil` for CodeView when the tool is outside `PATH`.

```sh
python binaryrat/benchmarks/stage_packed_calibration.py \
  --manifest build/corpus/manifest.json \
  --accuracy-report build/ghidra-report/type-accuracy/report.json > packed-cases.json
python binaryrat/benchmarks/calibrate_type_confidence.py \
  --input packed-cases.json > packed-calibration.json
```

The GCC and Clang diagnostic staged 18 proposed fields from nine real builds.
All 18 matched their separate DWARF oracle. The builds form one source family,
so the report shows raw support diagnostics and insufficient fit evidence.

## Source-family calibration

Twelve independent open-source projects measure the score on code BinaryRat's
authors did not write. `binaryrat/corpus/families.json` lists them: zlib, the
GNU demangler and lzfse from this repository, and bzip2, expat, jansson,
libtomcrypt, libyaml, Lua, lz4, MuJS and zstd from release archives pinned by
SHA-256. Each project is one family.

```sh
python binaryrat/tools/build_families.py --output build/families
python binaryrat/benchmarks/verify_family_calibration.py \
  --ghidra /path/to/ghidra_12.2_PUBLIC --engine build/native/binaryrat/binaryrat-engine \
  --families build/families/manifest.json --output build/family-calibration
```

**Build.** Each family's listed sources are compiled with GCC `-O2` and DWARF 4
into one x86-64 shared object. No project build script runs and nothing is
executed. The stripped copy is the analysis input; the debug file stays in a
separate directory for the oracle.

**Split.** Families are ordered by the SHA-256 of their ID; the first half is
the fit partition and the rest is held out. The rule depends on the names alone
and a test enforces it, so no outcome can move a family.

**Inference.** `BinaryRatSurveyLayouts.java` runs on the stripped file in
official Ghidra 12.2. It decompiles every function once and aggregates the exact
accesses made through each pointer-sized register parameter of that function.
Callees are not followed, so each access supports one proposal.

**Oracle.** After Ghidra exits, the DWARF reader lists every parameter that the
location list places in an integer argument register at the function's entry
address and that is declared as a pointer to a structure, union or class. Each
such parameter is one case. Reading the register from the location list keeps
labels right when the compiler changes a signature: GCC's clones with removed
arguments describe only the parameters they still take. A proposed byte range is
correct when it is exactly one declared member, array element or base subobject
of the pointee at any nesting depth. A range that spans members, covers part of
one, or lies beyond a fixed-size pointee is incorrect. A flexible array has no
declared end, including when its enclosing structure is a terminal member of
another structure or a member of a union under GCC's C extension.

**Exclusions, all counted in the report.** Functions with identical
instructions, linked addresses masked, are kept once across all families before
the split. Ranges that touch bit-field storage are not judged. Pointees that are
incomplete in the function's unit or have virtual bases give no case. A
parameter the survey did not see is an abstention: a case without proposals.
The oracle also abstains if one range needs more than 32,768 distinct layout
states to be checked.

### Archived CI measurement

GitHub Actions recorded these cases with GCC and Ghidra 12.2 in November
2026. The corrected evaluator recomputed the metrics from the archived
`cases.json`. Its labels predate the DWARF fix for multidimensional arrays.
Use the full calibration command above to regenerate cases with the current
oracle. [Archived cases and report](https://github.com/YurilLAB/BinaryRat/actions/runs/44996105423/artifacts/14745296688)

| | Fit families | Held-out families |
|---|---|---|
| Families | bzip2, libtomcrypt, libyaml, MuJS, zlib, zstd | expat, GNU demangler, jansson, Lua, lz4, lzfse |
| Cases (pointer parameters) | 1,701 | 1,384 |
| Cases with proposals | 1,084 | 864 |
| Proposed fields | 8,056 | 3,152 |

The fit on six families maps the support count to an estimate:

| Accesses supporting the field | Raw score | Fitted estimate |
|---|---|---|
| 1 | 0.50 | 0.763 |
| 2 | 0.67 | 0.844 |
| 3 or more | 0.75 and above | 0.902 |

| Held-out metric | Raw score | Fitted estimate |
|---|---|---|
| Reliability error | 0.21781 | 0.03651 |
| Brier error | 0.19095 | 0.13475 |

All 3,152 held-out proposals received fitted estimates. With six held-out
families, the comparison is descriptive.

### Limits

- One compiler, one optimization level and one architecture. Clang, other
  levels, AArch64 and MSVC builds are not measured.
- Six held-out families are below the eight needed for intervals, so the
  held-out numbers are descriptive.
- Only a function's own accesses are measured. Evidence carried from callees by
  direct-call forwarding or the summary solver is not calibrated.
- Byte ranges only. Member types, names and signedness are not scored.
- The truth rule assumes the parameter points at one object. A parameter that
  walks an array of structures yields ranges beyond the pointee, counted wrong.

The first run used the earlier prior, one neutral pseudo-family per bin. On this
data it outweighed the sparse high-score bins and merged every bin into one
estimate of 0.711. It was replaced by the single pseudo-family described above
before these results were recorded; the family list and the split did not
change.

Layout reports still print the uncalibrated support score.
