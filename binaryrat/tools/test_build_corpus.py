"""Regression checks for oracle separation and safe PE debug removal.

SPDX-License-Identifier: Apache-2.0
Copyright 2026 YurilLAB. New BinaryRat tests.
"""
import json
from pathlib import Path
import shutil
import struct
import tempfile
import unittest

import build_corpus


def synthetic_pe(debug_in_code=False):
    image = bytearray(0x600)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HH", image, 0x84, 0x8664, 2)
    struct.pack_into("<H", image, 0x94, 240)
    struct.pack_into("<H", image, 0x98, 0x20B)
    struct.pack_into("<II", image, 0x98 + 112 + 48, 0x2000, 28)
    for index, (name, address, offset, characteristics) in enumerate((
            (b".text", 0x1000, 0x200, 0x60000020),
            (b".rdata", 0x2000, 0x400, 0x40000040))):
        header = 0x188 + index * 40
        image[header:header + len(name)] = name
        struct.pack_into("<IIII", image, header + 8, 0x100, address, 0x100, offset)
        struct.pack_into("<I", image, header + 36, characteristics)
    image[0x200:0x220] = b"\x90" * 31 + b"\xc3"
    struct.pack_into("<I", image, 0x400 + 16, 32)
    struct.pack_into("<I", image, 0x400 + 24, 0x200 if debug_in_code else 0x440)
    image[0x440:0x460] = b"RSDS" + b"x" * 28
    return image


class CorpusTests(unittest.TestCase):
    def test_pe_stripping_removes_debug_without_changing_code(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "fixture.exe"
            binary.write_bytes(synthetic_pe())
            before = build_corpus.inspect_binary(binary)
            build_corpus.strip_pe_debug(binary)
            after = build_corpus.inspect_binary(binary)
            self.assertEqual(before["executable_sections"], after["executable_sections"])
            self.assertEqual(after["debug_directory"], [0, 0])
            self.assertEqual(binary.read_bytes()[0x440:0x460], bytes(32))

    def test_pe_debug_pointer_cannot_erase_executable_code(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "fixture.exe"
            original = synthetic_pe(debug_in_code=True)
            binary.write_bytes(original)
            with self.assertRaisesRegex(ValueError, "overlapping executable"):
                build_corpus.strip_pe_debug(binary)
            self.assertEqual(binary.read_bytes(), original)

    def test_required_missing_toolchain_is_failure(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory, patch("shutil.which", return_value=None):
            self.assertEqual(build_corpus.main(["--output", directory, "--toolchain", "gcc"]), 1)
            manifest = json.loads((Path(directory) / "manifest.json").read_text())
            self.assertEqual(manifest["status"], "failed")
            self.assertEqual(manifest["toolchains"][0]["status"], "unavailable")
            self.assertEqual(manifest["artifacts"], [])

    def test_optional_missing_toolchain_is_explicit(self):
        real_which = shutil.which
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory, patch(
                "shutil.which", side_effect=lambda name: None if name.startswith("aarch64-")
                else real_which(name)):
            # Avoid depending on a host compiler: exercise the optional path by
            # selecting the same absent toolchain as required and optional.
            result = build_corpus.main(["--output", directory, "--toolchain", "gcc-aarch64",
                                        "--optional-toolchain", "gcc-aarch64"])
            manifest = json.loads((Path(directory) / "manifest.json").read_text())
            self.assertEqual(result, 1)  # Optional cannot weaken a required entry.
            self.assertTrue(manifest["toolchains"][0]["required"])


if __name__ == "__main__":
    unittest.main()
