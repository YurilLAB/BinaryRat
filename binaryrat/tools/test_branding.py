# Copyright 2026 YurilLAB
# SPDX-License-Identifier: Apache-2.0
"""The GUI uses the README logo file itself, never a redrawn copy."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
LOGO = ROOT / "binaryrat/docs/assets/logo.png"
GUI = ROOT / "Ghidra/Framework/Gui"
COPIES = (
    GUI / "src/main/resources/images/BinaryRatLogo.png",
    ROOT / "binaryrat/bridge/src/main/resources/images/binaryrat/logo.png",
    ROOT / "binaryrat/distribution/help/logo.png",
)
SIZES = (16, 24, 32, 40, 48, 64, 128, 256)


class BrandingTest(unittest.TestCase):
    def test_readme_shows_the_logo(self):
        self.assertIn('src="binaryrat/docs/assets/logo.png"', (ROOT / "README.md").read_text(encoding="utf-8"))

    def test_every_copy_is_the_readme_logo(self):
        logo = LOGO.read_bytes()
        for copy in COPIES:
            with self.subTest(copy=copy.relative_to(ROOT).as_posix()):
                self.assertEqual(copy.read_bytes(), logo)

    def test_the_fork_ships_only_the_logo_with_a_license_entry(self):
        self.assertEqual(sorted(path.name for path in (GUI / "src/main/resources/images").glob("BinaryRat*")),
                         ["BinaryRatLogo.png"])
        manifest = (GUI / "certification.manifest").read_text(encoding="utf-8").splitlines()
        self.assertEqual([line for line in manifest if "BinaryRat" in line],
                         ["src/main/resources/images/BinaryRatLogo.png||Apache License 2.0||||END|"])

    def test_icons_splash_and_tool_scale_the_logo(self):
        icons = (ROOT / "Ghidra/Features/Base/data/base.icons.theme.properties").read_text(encoding="utf-8")
        for name, size in (("home", 16), *((str(size), size) for size in SIZES)):
            self.assertRegex(icons, rf"(?m)^icon\.base\.application\.{name} = "
                                    rf"BinaryRatLogo\.png\[size\({size},{size}\)\]\s*$")
        docking = (ROOT / "Ghidra/Framework/Docking/data/docking.theme.properties").read_text(encoding="utf-8")
        self.assertRegex(docking, r"(?m)^icon\.dragon\.256 = BinaryRatLogo\.png\[size\(256,256\)\]\s*$")
        tool = ROOT / "Ghidra/Configurations/Public_Release/src/main/resources/defaultTools/CodeBrowser.tool"
        self.assertEqual(re.findall(r"<ICON LOCATION=\"([^\"]+)\"", tool.read_text(encoding="utf-8")),
                         ["images/BinaryRatLogo.png"])
        info = ROOT / "Ghidra/Features/Base/src/main/java/ghidra/framework/main/InfoPanel.java"
        self.assertIn('"images/BinaryRatLogo.png"', info.read_text(encoding="utf-8"))
        icons_class = ROOT / "binaryrat/bridge/src/main/java/binaryrat/desktop/BinaryRatIcons.java"
        self.assertIn('"images/binaryrat/logo.png"', icons_class.read_text(encoding="utf-8"))
        help_page = ROOT / "binaryrat/distribution/help/GettingStarted.html"
        self.assertIn('src="logo.png"', help_page.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
