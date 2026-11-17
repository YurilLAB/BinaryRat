# Core patch ledger

**Current Ghidra runtime/core patches: none.**

The new C++ project, Python package, headless script, corpus and CI are additive.
The root README has a marked BinaryRat introduction; upstream LICENSE/NOTICE are
preserved unchanged. The root CMake entry point is new and does not alter Gradle.

Upstream CI adaptations (not runtime patches):

- `.github/workflows/build-ghidra.yml`: the original single-host job runs only
  upstream; BinaryRat's dedicated workflow builds the full fork on Linux/Windows
  for each SHA, avoiding duplicate builds.
- `.github/workflows/dependency-submission.yml`: forks generate and upload their
  dependency report without submitting it to the optional, initially disabled
  GitHub dependency graph. Official upstream behavior is retained.

Every future runtime/core patch needs its own record: exact file and upstream
blob, behavior, rationale, rejected extension alternatives, tests and benchmark
evidence, upstream reference, and removal/revalidation criteria. Modified files
must carry a prominent BinaryRat modification notice. Never blindly reapply a
patch after an upstream merge.
