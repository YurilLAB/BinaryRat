# Core patch ledger

## Runtime patches

- [No-return analyzer candidate checks](no-return-candidate-checks.md)
- [Decompiler join records at cache flush](decompiler-join-flush.md)

## Branding

The source-built fork and its bundle show the logo from the README. These are resource
and text changes, not runtime patches. `binaryrat/tools/make_branding.py` renders every
image from `binaryrat/docs/assets/logo.png` (`--check` finds stale images), and
`binaryrat/tools/test_make_branding.py` checks their sizes, licence entries and references.

| Upstream file | Change |
| --- | --- |
| `Ghidra/Framework/Gui/src/main/resources/images/BinaryRat*.png` | New icons (16 to 256 pixels) and splash image, listed as Apache License 2.0 in the module's `certification.manifest` |
| `Ghidra/Features/Base/data/base.icons.theme.properties` | Application, window and home icons |
| `Ghidra/Framework/Docking/data/docking.theme.properties` | Icon drawn by window animations |
| `Ghidra/Configurations/Public_Release/src/main/resources/defaultTools/CodeBrowser.tool` | CodeBrowser tool icon |
| `Ghidra/Features/Base/src/main/java/ghidra/framework/main/InfoPanel.java` | Splash and About image |
| `Ghidra/Features/Base/src/main/java/ghidra/framework/main/GhidraApplicationInformationDisplayFactory.java` | Splash and About titles |

The application name, settings directory and version text stay Ghidra's, so projects,
scripts and user settings carry over unchanged. The bundle's desktop check
(`binaryrat/distribution/tests/WorkspaceProbe.java`) verifies the titles and icons.

The new C++ project, Python package, headless script, corpus and CI are additive.
The root README is now a BinaryRat overview marked as modified; upstream LICENSE/NOTICE are
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
