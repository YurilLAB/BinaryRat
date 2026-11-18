# Using BinaryRat with a Ghidra team

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

Obtain the extension ZIP for the target OS and architecture and its adjacent `.zip.sha256` file from the same trusted CI run. Transfer both alongside a compatible Ghidra 12.2 installation and JDK 25. Record the commit and retain the trusted checksum separately if you need to detect replacement of both transferred files. [Extension build and checksum verification](../bridge/README.md#install-the-extension)

For the standalone analyst commands, unpack the CI artifact `binaryrat-analyst-wheel-<commit>` into a directory named `wheelhouse` on the destination. With Python 3.10 or later, run `python -m pip install --no-index --find-links wheelhouse binaryrat` in a fresh virtual environment. The wheel works on both Linux and Windows. To build the same package from your checkout, run `python -m pip wheel --no-deps --wheel-dir wheelhouse ./binaryrat/python` on the build host. [Analyst commands](../python/README.md#analyst-tools)

BinaryRat’s code uses Apache 2.0. When redistributing a package, keep its license, notices and third-party attributions, and identify files you modify. For a complete Ghidra distribution, retain the bundled component notices and review the licenses for the parts you deploy. Check the licenses for your organization’s plugins separately. Contact YurilLAB if procurement requires a vendor agreement or deployment support. [License](../../LICENSE) · [Notices](../../NOTICE) · [Bundled license texts](../../licenses) · [Maintainer contact](../../.github/SUPPORT.md)
