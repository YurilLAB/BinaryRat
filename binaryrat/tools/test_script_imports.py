# Copyright 2026 YurilLAB
# SPDX-License-Identifier: Apache-2.0
"""Entry scripts in bridge/ghidra_scripts must compile from a checkout -scriptPath.

Headless verifiers run them on a plain Ghidra, where only the helper sources in
ghidra_scripts/binaryrat are compiled next to them. Classes that exist only in
BinaryRat.jar (bridge/src/main/java) must be loaded by name, never referenced.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "binaryrat/bridge/ghidra_scripts"
HELPERS = SCRIPTS / "binaryrat"
JAR_ONLY = ROOT / "binaryrat/bridge/src/main/java/binaryrat"

# Comments and string or character literals, so that names inside them are ignored.
_NOISE = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', re.S)
_REFERENCE = re.compile(r"\bbinaryrat\.([A-Za-z_]\w*)(?:\.([A-Za-z_]\w*))?")


def code(path: Path) -> str:
    return _NOISE.sub(" ", path.read_text(encoding="utf-8"))


def unavailable_references(text: str) -> set[str]:
    """Return binaryrat.* names that a checkout -scriptPath compilation cannot resolve."""
    helpers = {path.stem for path in HELPERS.glob("*.java")}
    missing = set()
    for match in _REFERENCE.finditer(text):
        first, second = match.group(1), match.group(2)
        if first in helpers:
            continue
        # binaryrat.<package>.<Class> or binaryrat.<package>.* lives only in the JAR.
        name = f"binaryrat.{first}" + (f".{second}" if second else "")
        missing.add(name)
    return missing


class CheckoutScriptImportsTest(unittest.TestCase):
    def test_entry_scripts_and_helpers_reference_only_checkout_sources(self):
        sources = sorted(SCRIPTS.glob("*.java")) + sorted(HELPERS.glob("*.java"))
        self.assertGreaterEqual(len(sources), 5)
        for source in sources:
            with self.subTest(script=source.name):
                self.assertEqual(unavailable_references(code(source)), set(),
                                 "load BinaryRat.jar classes by name in checkout scripts")

    def test_recover_layouts_loads_the_jar_only_table_by_name(self):
        text = (SCRIPTS / "BinaryRatRecoverLayouts.java").read_text(encoding="utf-8")
        self.assertIn('"binaryrat.writeback.LayoutEvidenceTable"', text)
        self.assertTrue((JAR_ONLY / "writeback/LayoutEvidenceTable.java").is_file())

    def test_checker_flags_jar_only_imports_and_ignores_strings_and_comments(self):
        def check(text):
            return unavailable_references(_NOISE.sub(" ", text))

        self.assertEqual(check("import binaryrat.writeback.LayoutEvidenceTable;\nimport binaryrat.EngineClient;\n"),
                         {"binaryrat.writeback.LayoutEvidenceTable"})
        self.assertEqual(check("import binaryrat.analysis.*;"), {"binaryrat.analysis"})
        self.assertEqual(check("var x = binaryrat.desktop.Icons.LOGO;"), {"binaryrat.desktop.Icons"})
        self.assertEqual(check('String s = "binaryrat.writeback.X"; // binaryrat.desktop.Y\n'
                               '/* binaryrat.analysis.Z */ char c = \'"\';'), set())
        self.assertEqual(check("import binaryrat.LayoutEvidence;\nbinaryrat.LayoutEvidence.ForwardedCall call;"),
                         set())


if __name__ == "__main__":
    unittest.main()
