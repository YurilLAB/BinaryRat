"""Exercise package validation and launcher isolation with portable test inputs.

Copyright 2026 YurilLAB
SPDX-License-Identifier: Apache-2.0
"""

import io
import os
from pathlib import Path
import random
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from zipfile import ZipFile, ZipInfo

from build_bundle import (
    HERE, LINUX, WINDOWS, Writer, add_tree, archive_entries, checked_path, executable_format,
)
from verify_bundle import extract, verify


class ArchiveTests(unittest.TestCase):
    def test_rejects_unsafe_and_aliased_names(self):
        for name in ("", "/absolute", "../outside", "ok/../outside", "ok/./alias", "ok//alias",
                     "ok/$ignored\x00", "C:/absolute", "ok\\outside", "ok/trailing-dot.",
                     "ok/trailing-space ", "ok/NUL.txt", "ok/COM2.log", "ok/NUL .txt", "ok/test:ads"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                checked_path(name)
        for names in (("Ghidra/A", "Ghidra/a"), ("Ghidra/safe", "Ghidra/SAFE/path")):
            with self.subTest(names=names), tempfile.TemporaryFile() as stream:
                with ZipFile(stream, "w") as archive:
                    for name in names:
                        archive.writestr(name, "data")
                with ZipFile(stream) as archive, self.assertRaises(ValueError):
                    archive_entries(archive)

    def test_rejects_symlinks_in_archives(self):
        with tempfile.TemporaryFile() as stream:
            with ZipFile(stream, "w") as archive:
                entry = ZipInfo("BinaryRat/link")
                entry.create_system = 3
                entry.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(entry, "../outside")
            with ZipFile(stream) as archive, self.assertRaises(ValueError):
                archive_entries(archive)

    @unittest.skipUnless(os.name == "nt" or sys.platform == "linux", "supported hosts")
    def test_checksum_failure_clears_an_existing_success_report(self):
        with tempfile.TemporaryDirectory() as scratch:
            work = Path(scratch)
            archive = work / "bundle.zip"
            archive.write_bytes(b"bundle")
            archive.with_suffix(".zip.sha256").write_bytes(b"wrong digest")
            report = work / "report.json"
            report.write_bytes(b'{"passed": true}')
            with self.assertRaisesRegex(ValueError, "checksum"):
                verify(archive, work, work / "extracted")
            self.assertFalse(report.exists())
            self.assertFalse((work / "extracted").exists())

    def test_native_magic_machine_and_bounded_pe_offsets(self):
        elf = b"\x7fELF\x02\x01" + bytes(12) + b"\x3e\x00"
        self.assertTrue(executable_format(elf, LINUX))
        self.assertFalse(executable_format(elf[:-1], LINUX))
        self.assertFalse(executable_format(elf[:-2] + b"\xb7\x00", LINUX))
        pe = b"MZ" + bytes(58) + struct.pack("<I", 64) + b"PE\0\0\x64\x86"
        self.assertTrue(executable_format(pe, WINDOWS))
        self.assertFalse(executable_format(pe[:-2] + b"\x64\xaa", WINDOWS))
        self.assertFalse(executable_format(pe[:60] + struct.pack("<I", 2**32 - 1), WINDOWS))
        generator = random.Random(0xB1A2)
        for _ in range(500):
            noise = generator.randbytes(generator.randrange(4080))
            for host in (LINUX, WINDOWS):
                self.assertFalse(executable_format(noise, host))

    def test_writer_is_repeatable_and_extraction_keeps_executable_bits(self):
        def archive():
            data = io.BytesIO()
            with ZipFile(data, "w") as package:
                writer = Writer(package)
                writer.bytes("run", b"#!/bin/sh\n", executable=True)
                writer.bytes("other", b"plain")
                with self.assertRaises(ValueError):
                    writer.bytes("RUN", b"duplicate")
            return data.getvalue()

        self.assertEqual(archive(), archive())
        with tempfile.TemporaryDirectory(prefix="bundle spaces ") as scratch:
            work = Path(scratch)
            file = work / "bundle.zip"
            file.write_bytes(archive())
            root = extract(file, work / "extracted")
            self.assertEqual(root.name, "BinaryRat")
            self.assertEqual((root / "other").read_bytes(), b"plain")
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE((root / "run").stat().st_mode), 0o755)
                self.assertEqual(stat.S_IMODE((root / "other").stat().st_mode), 0o644)

    @unittest.skipIf(os.name == "nt", "requires Unix file symlinks")
    def test_jdk_style_in_tree_file_link_is_copied_outside_link_rejected(self):
        with tempfile.TemporaryDirectory() as scratch:
            work = Path(scratch).resolve()
            tree = work / "jdk"
            tree.mkdir()
            (tree / "LICENSE").write_text("license data", encoding="utf-8")
            (tree / "COPY").symlink_to("LICENSE")
            stream = io.BytesIO()
            with ZipFile(stream, "w") as package:
                add_tree(Writer(package), tree, "jdk/")
            with ZipFile(stream) as package:
                self.assertEqual(package.read("BinaryRat/jdk/COPY"), b"license data")
                self.assertTrue(stat.S_ISREG(package.getinfo("BinaryRat/jdk/COPY").external_attr >> 16))
            (work / "outside").write_text("private", encoding="utf-8")
            (tree / "ESCAPE").symlink_to("../outside")
            with ZipFile(io.BytesIO(), "w") as package, self.assertRaisesRegex(ValueError, "outside"):
                add_tree(Writer(package), tree, "jdk/")

    @unittest.skipUnless(os.name == "posix", "shell launcher test")
    def test_launchers_forward_arguments_and_select_pinned_install(self):
        with tempfile.TemporaryDirectory(prefix="binaryrat launch ") as scratch:
            root = Path(scratch) / "bundle with spaces"
            launches = root / "launchers"
            launches.mkdir(parents=True)
            jdk = root / "jdk/bin"
            jdk.mkdir(parents=True)
            (jdk / "java").touch(mode=0o755)
            (root / "VERSION.txt").write_text("exact revision\n", encoding="utf-8")
            for name in ("binaryrat", "binaryrat-headless", "launch"):
                dest = launches / name if name == "launch" else root / name
                shutil.copyfile(HERE / "launchers" / name, dest)
                dest.chmod(0o755)
            probe = """#!/bin/sh
printf '%s\\n' "$JAVA_HOME" "$BINARYRAT_BUNDLE_DIR" "${BINARYRAT_ENGINE:-bundled}" "$XDG_CONFIG_HOME" "$@"
"""
            for name in ("ghidraRun", "support/analyzeHeadless"):
                target = root / "ghidra" / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(probe, encoding="utf-8")
                target.chmod(0o755)
            env = os.environ | {
                "JAVA_HOME": "/other-java",
                "BINARYRAT_ENGINE": "/other-engine",
                "XDG_CONFIG_HOME": str(root / "config"),
                "XDG_CACHE_HOME": str(root / "cache"),
            }
            expected = [str(root / "jdk"), str(root), "bundled", str(root / "config/BinaryRat"),
                        "a file with spaces", "second"]
            for name in ("binaryrat", "binaryrat-headless"):
                with self.subTest(name=name):
                    launch = str(root / name)
                    run = subprocess.run([launch, "--version"], env=env, text=True, capture_output=True,
                                         timeout=10, check=True)
                    self.assertEqual(run.stdout, "exact revision\n")
                    run = subprocess.run([launch, "a file with spaces", "second"], env=env, text=True,
                                         capture_output=True, timeout=10, check=True)
                    self.assertEqual(run.stdout.splitlines(), expected)

    @unittest.skipUnless(os.name == "nt", "Windows launcher test")
    def test_batch_launchers_keep_local_settings_and_return_exit_status(self):
        with tempfile.TemporaryDirectory(prefix="binaryrat launch ") as scratch:
            root = Path(scratch) / "bundle with spaces"
            launches = root / "launchers"
            launches.mkdir(parents=True)
            jdk = root / "jdk/bin"
            jdk.mkdir(parents=True)
            (jdk / "java.exe").touch()
            for name in ("binaryrat.bat", "binaryrat-headless.bat", "launch.bat"):
                source = HERE / "launchers" / name
                dest = launches / name if name == "launch.bat" else root / name
                dest.write_bytes(source.read_text(encoding="utf-8").replace("\n", "\r\n").encode())
            for name, label in (("ghidraRun.bat", "desktop"), ("support/analyzeHeadless.bat", "headless")):
                target = root / "ghidra" / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((f"@echo off\r\necho {label}\r\n"
                                    'echo "%JAVA_HOME%"\r\necho "%~1"\r\necho "%~2"\r\n'
                                    "if defined BINARYRAT_ENGINE exit /b 4\r\nexit /b 3\r\n").encode())
            env = os.environ | {
                "JAVA_HOME": "invalid",
                "BINARYRAT_ENGINE": "invalid",
                "XDG_CONFIG_HOME": str(root / "config"),
                "XDG_CACHE_HOME": str(root / "cache"),
            }
            for name, label in (("binaryrat.bat", "desktop"), ("binaryrat-headless.bat", "headless")):
                with self.subTest(name=name):
                    run = subprocess.run([str(root / name), "an argument with spaces", "last"],
                                         env=env, text=True, capture_output=True, timeout=10, check=False)
                    self.assertEqual(run.returncode, 3, run.stderr)
                    self.assertEqual(run.stdout.splitlines(),
                                     [label, f'"{root / "jdk"}"', '"an argument with spaces"', '"last"'])


if __name__ == "__main__":
    unittest.main()
