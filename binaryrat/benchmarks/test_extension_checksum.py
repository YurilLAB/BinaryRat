# Copyright 2026 YurilLAB
# SPDX-License-Identifier: Apache-2.0
"""Checks for the detached checksum shipped alongside a BinaryRat extension."""
import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from verify_extension import verify_archive_checksum


class ExtensionChecksumTests(unittest.TestCase):
    def test_portable_single_archive_record(self):
        with TemporaryDirectory(prefix="offline transfer ") as directory:
            for name, newline in (("BinaryRat linux_x86_64.zip", b"\n"),
                                  ("BinaryRat win_x86_64.zip", b"\r\n")):
                with self.subTest(name=name):
                    archive = Path(directory) / name
                    data = bytes(range(256)) * 513
                    archive.write_bytes(data)
                    digest = hashlib.sha256(data).hexdigest()
                    archive.with_suffix(".zip.sha256").write_bytes(
                        f"{digest} *{name}".encode() + newline)
                    self.assertEqual(verify_archive_checksum(archive), digest)
                    archive.write_bytes(data[:-1])
                    with self.assertRaises(ValueError):
                        verify_archive_checksum(archive)

    def test_rejects_missing_truncated_extra_or_mismatched_record(self):
        with TemporaryDirectory() as directory:
            archive = Path(directory) / "BinaryRat.zip"
            archive.write_bytes(b"")
            sidecar = archive.with_suffix(".zip.sha256")
            with self.assertRaises(FileNotFoundError):
                verify_archive_checksum(archive)
            digest = hashlib.sha256(b"").hexdigest().encode()
            valid = digest + b" *BinaryRat.zip\n"
            for record in (b"", valid[:32], digest + b" *../BinaryRat.zip\n",
                           digest + b" *other.zip\n", valid + valid, valid + b"\0"):
                with self.subTest(record=record):
                    sidecar.write_bytes(record)
                    with self.assertRaises(ValueError):
                        verify_archive_checksum(archive)
