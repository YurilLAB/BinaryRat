"""Pinned-download integrity and archive extraction checks.

SPDX-License-Identifier: Apache-2.0
Copyright 2026 YurilLAB. New BinaryRat tests.
"""
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import fetch_ghidra


class DownloadTests(unittest.TestCase):
    def test_hash_mismatch_extracts_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "invalid.zip"
            archive.write_bytes(b"not the pinned release")
            output = Path(directory) / "output"
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                fetch_ghidra.extract_verified(archive, output)
            self.assertFalse(output.exists())

    def test_executable_mode_survives_zip_extraction(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "fixture.zip"
            with zipfile.ZipFile(archive, "w") as package:
                entry = zipfile.ZipInfo(fetch_ghidra.DIRECTORY + "/support/analyzeHeadless")
                entry.external_attr = 0o100755 << 16
                package.writestr(entry, b"#!/bin/sh\nexit 0\n")
            checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
            with patch.object(fetch_ghidra, "SHA256", checksum):
                result = fetch_ghidra.extract_verified(archive, Path(directory) / "output")
            launcher = result / "support" / "analyzeHeadless"
            self.assertEqual(launcher.read_bytes(), b"#!/bin/sh\nexit 0\n")
            if os.name != "nt":
                self.assertEqual(launcher.stat().st_mode & 0o777, 0o755)

    def test_archive_path_cannot_escape_output(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "fixture.zip"
            with zipfile.ZipFile(archive, "w") as package:
                package.writestr(fetch_ghidra.DIRECTORY + "/../../escape", b"unexpected")
            checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
            with patch.object(fetch_ghidra, "SHA256", checksum):
                with self.assertRaisesRegex(ValueError, "unexpected path"):
                    fetch_ghidra.extract_verified(archive, Path(directory) / "output")
            self.assertFalse((Path(directory) / "escape").exists())


if __name__ == "__main__":
    unittest.main()
