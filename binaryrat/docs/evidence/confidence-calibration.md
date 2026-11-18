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
to each family, adds one neutral pseudo-family per supported bin, and pools
adjacent supported bins until their fitted estimates are monotone. Fitting
requires at least five scored families, two families with each outcome, and
three scored families for each supported bin. Unsupported bins abstain. The
fit uses only fit-partition cases and labels.

The held-out report gives case and proposal counts, abstention coverage, and
the fraction of numerically scored proposals with fitted estimates. Brier
error averages squared error within each family and then across families.
Compare the fitted Brier estimate with `paired_raw_brier` on the same scored
proposals. The raw evidence-strength comparison treats the support score as
a numerical baseline. Reliability bins report the observed correctness rate,
mean score, proposal count, and family support. An empty group reports a null
estimate. Approximate 95% intervals resample the held-out family means with a
fixed seed, conditional on the fitted model and a minimum of eight families.
Sparse holdouts remain descriptive.

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
Production fields retain their uncalibrated support scores.
