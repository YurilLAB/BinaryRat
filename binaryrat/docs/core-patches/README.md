# Core patch ledger

## Runtime patches

- [No-return analyzer candidate checks](no-return-candidate-checks.md)
- [Decompiler join records at cache flush](decompiler-join-flush.md)
- [Calling conventions during concurrent reads](calling-convention-cache.md)
- [Decompiler reads of data settings](settings-name-cache.md)

## Branding

The source-built fork and its bundle show the README logo, `binaryrat/docs/assets/logo.png`.
These are resource and text changes, not runtime patches. Every GUI copy of the logo is that
file byte for byte; Ghidra scales it at runtime. `binaryrat/tools/test_branding.py` checks the
copies and every reference.

| Upstream file | Change |
| --- | --- |
| `Ghidra/Framework/Gui/src/main/resources/images/BinaryRatLogo.png` | The README logo, listed as Apache License 2.0 in the module's `certification.manifest` |
| `Ghidra/Features/Base/data/base.icons.theme.properties` | Application, window and home icons: `BinaryRatLogo.png[size(N,N)]` |
| `Ghidra/Framework/Docking/data/docking.theme.properties` | Icon drawn by window animations |
| `Ghidra/Configurations/Public_Release/src/main/resources/defaultTools/CodeBrowser.tool` | CodeBrowser tool icon |
| `Ghidra/Features/Base/src/main/java/ghidra/framework/main/InfoPanel.java` | Splash and About image, the logo scaled to 500 pixels |
| `Ghidra/Features/Base/src/main/java/ghidra/framework/main/GhidraApplicationInformationDisplayFactory.java` | Splash and About titles |

The extension JAR (`images/binaryrat/logo.png`) and the bundle's `help/logo.png` carry the same
file. `verify_extension.py` compares the JAR copy with the README logo.

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
