# Copyright 2026 YurilLAB
# SPDX-License-Identifier: Apache-2.0
"""The fork's branding images exist at the sizes its theme and build expect.

These checks use only the standard library. `make_branding.py --check` compares pixels.
"""
from pathlib import Path
import re
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import make_branding  # noqa: E402

ROOT = make_branding.ROOT
GUI = ROOT / "Ghidra/Framework/Gui"


def png_header(path: Path) -> tuple[int, int, int, int]:
    """Width, height, bit depth and colour type from a PNG's IHDR chunk."""
    data = path.read_bytes()[:33]
    if data[:8] != b"\x89PNG\r\n\x1a\n" or data[12:16] != b"IHDR":
        raise AssertionError(f"{path} is not a PNG")
    width, height, depth, colour = struct.unpack(">IIBB", data[16:26])
    return width, height, depth, colour


class BrandingTest(unittest.TestCase):
    def test_images_have_the_declared_sizes_and_alpha(self):
        expected = {make_branding.GUI_IMAGES / f"BinaryRatIcon{size}.png": size
                    for size in make_branding.APPLICATION_SIZES}
        expected.update({make_branding.EXTENSION_IMAGES / f"logo{size}.png": size
                         for size in make_branding.EXTENSION_SIZES})
        expected[make_branding.GUI_IMAGES / "BinaryRatSplash.png"] = make_branding.SPLASH_SIZE
        expected[make_branding.HELP_LOGO] = make_branding.HELP_LOGO_SIZE
        for path, size in expected.items():
            with self.subTest(path=path.name):
                self.assertEqual(png_header(path), (size, size, 8, 6))

    def test_every_fork_image_has_a_license_entry(self):
        manifest = (GUI / "certification.manifest").read_text(encoding="utf-8").splitlines()
        images = sorted(make_branding.GUI_IMAGES.glob("BinaryRat*.png"))
        self.assertEqual(len(images), len(make_branding.APPLICATION_SIZES) + 1)
        for image in images:
            entry = f"src/main/resources/images/{image.name}||Apache License 2.0||||END|"
            self.assertEqual(manifest.count(entry), 1, entry)

    def test_theme_and_splash_point_at_the_images(self):
        icons = (ROOT / "Ghidra/Features/Base/data/base.icons.theme.properties").read_text(encoding="utf-8")
        for size in ("home", *map(str, make_branding.APPLICATION_SIZES)):
            image = "BinaryRatIcon16.png" if size == "home" else f"BinaryRatIcon{size}.png"
            self.assertRegex(icons, rf"(?m)^icon\.base\.application\.{size} = {re.escape(image)}\s*$")
        docking = (ROOT / "Ghidra/Framework/Docking/data/docking.theme.properties").read_text(encoding="utf-8")
        self.assertRegex(docking, r"(?m)^icon\.dragon\.256 = BinaryRatIcon256\.png\s*$")
        info = ROOT / "Ghidra/Features/Base/src/main/java/ghidra/framework/main/InfoPanel.java"
        self.assertIn('"images/BinaryRatSplash.png"', info.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
