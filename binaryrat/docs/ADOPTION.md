# Using BinaryRat with a Ghidra team

## Open a binary in the complete application

Download the Windows x64 or Linux x64 ZIP from a BinaryRat release and extract the whole archive to a writable directory. Run `binaryrat.bat` on Windows or `./binaryrat` on Linux. The bundle includes Temurin JDK 25 and uses it for both desktop and headless launches. Use `--version` for the exact BinaryRat revision and runtime version. [BinaryRat releases](https://github.com/YurilLAB/BinaryRat/releases)

Choose **File → New Project** to create a local project, then **File → Import File** and select a binary. Open the imported Program in CodeBrowser. The bundled default workspace exposes BinaryRat's actions under **Tools → BinaryRat**. The `help` directory in the bundle includes a walkthrough and sample. For a terminal workflow, use `binaryrat-headless.bat` or `./binaryrat-headless` with the standard Ghidra headless arguments.

### Choose how much analysis to run

Use **Tools → BinaryRat → Analyze with Profile**. For a first import, decline the automatic analysis prompt before selecting a profile if you want Quick Triage to govern the initial pass.

| Profile | Analysis behavior |
| --- | --- |
| Quick Triage | Keeps basic disassembly and references. Skips available debug-symbol imports, function and calling-convention identification, parameter recovery, and Windows x86 RTTI analysis. |
| Normal | Uses the project's configured analyzers. |
| Deeper Recovery | Enables available decompiler parameter recovery, Windows x86 RTTI analysis, and stack parameter creation. |

BinaryRat restores the project's analyzer settings when the pass finishes. Ghidra shows progress and can cancel a running pass. Headless imports accept `-preScript BinaryRatProfile.java quick`, `normal`, or `deep`.

### Follow a function while reviewing code

Open **Tools → BinaryRat → Inspect Selected Function**. The panel follows the Listing and cancels obsolete requests when you move to another function. For an open Program using the same execution settings, selected functions enter ahead of queued batch work. Running decompilations retain their leases. Requests wait while Program access is busy. The panel shows the current status, a request time limit, and a Cancel control. The engine also limits concurrency based on available CPU and memory.

Scheduled headless exports, the desktop function panel, and the scheduled Python and CLI backends use the Java decompilation service. Set `BINARYRAT_CACHE_DIR` to enable persistent decompilation caching and let the native engine own that directory. Separate processes that need concurrent access can use separate cache directories. The Python service opens saved projects read-only. A Python script already running with a live Ghidra Program can use `decompile_program` with that Program. [Python and CLI guide](../python/README.md)

## Keep the workflows your analysts know

Teams using Ghidra 12.2 can start by installing the BinaryRat extension in their existing distribution. Analysts keep their CodeBrowser tools, Script Manager and headless commands. Export a Program through **Tools → BinaryRat → Export Decompilation** after enabling the script’s **In Tool** option. The fork distribution adds the changes that require Ghidra core, including the no-return analyzer optimization. [Extension and analyst workflows](../bridge/README.md) · [Core patch details](core-patches/no-return-candidate-checks.md)

To investigate a suspected structure, put the cursor in a function that uses it. **Recover Layout at Cursor** collects evidence for the selected parameter. **Browse Layout Evidence** takes you from an offset in the saved report to the instruction that accessed it. Both actions leave your types and annotations in place. [Using the field evidence table](../bridge/README.md#inspect-a-possible-structure-in-codebrowser)

## Try an existing investigation

Close the local Ghidra project, then copy its `.gpr` marker and same-named `.rep` directory together. Open the copy in the 12.2 fork. For read-only headless inspection, invoke the fork’s `support/analyzeHeadless` (`support\analyzeHeadless.bat` on Windows) with the copy’s parent directory, the project name, `-process PROGRAM_NAME -readOnly -noanalysis`. Keep the original available when trying changes to analysis or types.

The compatibility test saves a stock project with a named function, user-defined signature, applied structure, label, cross-reference, multiline comment and bookmark. It opens the project read-only in the fork, then reopens it in stock Ghidra. It checks the values and hashes the saved files at each step. Ghidra may rotate two backup index files. The test covers local projects from 12.2. Shared repositories, older database upgrades and other vendors’ databases require separate qualification. [Saved project test](../benchmarks/verify_project_interop.py)

## Qualify an internal plugin

Install the plugin built for stock 12.2 into a separate fork profile. Enable it in the same tool configuration your analysts use, run its essential actions on the project copy, and check the resulting data and services. BinaryRat’s fixture compiles a plugin against the stock Java API once, then loads the same JAR in both distributions. It checks plugin discovery, registration, service calls and removal. A plugin that calls Ghidra internals, bundles native code or depends on another extension needs its own test on each deployment platform. [Plugin compatibility test](../benchmarks/verify_plugin_compatibility.py)

An internal plugin can also consume the same evidence as BinaryRat’s desktop table. Compile against the matching extension JAR and call `binaryrat.writeback.LayoutEvidenceBrowser.read(program, reportPath, monitor)` on a worker thread. The returned review’s `rows()` list contains one entry per cited field access. Each entry supplies the instruction address, field offset and width, operation, function entry and byte-verification status. Use the returned Program revision to detect later edits. Pin the BinaryRat build when using this Java interface. [Java model](../bridge/src/main/java/binaryrat/writeback/LayoutEvidenceBrowser.java)

## Deploy to an offline workstation

Transfer the complete application ZIP and its adjacent `.zip.sha256` file from the same release. Verify the ZIP against the checksum before extracting. For an existing Ghidra 12.2 installation, the release's CI run also provides an extension-only ZIP. Transfer its checksum alongside the extension. [BinaryRat releases](https://github.com/YurilLAB/BinaryRat/releases) · [Extension build and checksum verification](../bridge/README.md#install-the-extension)

The bundle includes the offline analyst wheel under `python`. With Python 3.10 or later, run `python -m pip install --no-index --find-links python binaryrat` from the bundle directory in a fresh virtual environment. Live Python analysis additionally uses the PyGhidra wheels in the bundled Ghidra installation. [Analyst commands](../python/README.md#analyst-tools)

BinaryRat’s code uses Apache 2.0. When redistributing a package, keep its license, notices and third-party attributions, and identify files you modify. For a complete Ghidra distribution, retain the bundled component notices and review the licenses for the parts you deploy. Check the licenses for your organization’s plugins separately. Contact YurilLAB if procurement requires a vendor agreement or deployment support. [License](../../LICENSE) · [Notices](../../NOTICE) · [Bundled license texts](../../licenses) · [Maintainer contact](../../.github/SUPPORT.md)
