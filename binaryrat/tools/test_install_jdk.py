"""The pinned CI JDK: same build as the bundle, verified layout, reuse and GitHub env.

SPDX-License-Identifier: Apache-2.0
Copyright 2026 YurilLAB. New BinaryRat tests.
"""
import io
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from zipfile import ZipFile

import install_jdk

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "distribution"))
import build_bundle  # noqa: E402


RELEASE = f'IMPLEMENTOR="Eclipse Adoptium"\nIMPLEMENTOR_VERSION="Temurin-{install_jdk.VERSION}"\n'


def zip_fixture(path: Path, home: str, release: str = RELEASE) -> None:
    with ZipFile(path, "w") as package:
        package.writestr(f"{home}/release", release)
        package.writestr(f"{home}/bin/javac.exe", b"MZ")


def tar_fixture(path: Path, home: str, release: str = RELEASE) -> None:
    with tarfile.open(path, "w:gz") as package:
        for name, data in ((f"{home}/release", release.encode()), (f"{home}/bin/javac", b"\x7fELF")):
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            entry.mode = 0o755
            package.addfile(entry, io.BytesIO(data))


class PinTests(unittest.TestCase):
    def test_ci_installs_the_jdk_the_bundle_ships(self):
        self.assertEqual(install_jdk.VERSION, build_bundle.JDK_VERSION)
        self.assertEqual(install_jdk.SOURCES, (build_bundle.JDK_SOURCE_NAME, build_bundle.JDK_SOURCE_SHA256))

    def test_every_archive_is_named_for_the_pinned_build(self):
        stamp = install_jdk.VERSION.replace("+", "_")
        self.assertEqual(install_jdk.HOME_NAME, "jdk-" + install_jdk.VERSION)
        for name, sha256 in [*install_jdk.ARCHIVES.values(), install_jdk.SOURCES]:
            self.assertIn(stamp, name)
            self.assertRegex(sha256, r"^[0-9a-f]{64}$")
        self.assertIn(install_jdk.VERSION.replace("+", "%2B"), install_jdk.BASE_URL)


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.requests = []

    def serve(self, build):
        def fake_fetch(url, destination, sha256, **options):
            self.requests.append(url)
            build(destination)
            return destination
        return patch.object(install_jdk, "fetch", fake_fetch)

    def test_windows_zip_installs_and_is_reused(self):
        with self.serve(lambda path: zip_fixture(path, install_jdk.HOME_NAME)):
            home = install_jdk.install(self.root, "windows")
            again = install_jdk.install(self.root, "windows")
        self.assertEqual(home, again)
        self.assertEqual(len(self.requests), 1)
        self.assertTrue((home / "bin/javac.exe").is_file())
        self.assertEqual([p.name for p in self.root.iterdir()], [install_jdk.HOME_NAME])

    def test_linux_tarball_installs(self):
        with self.serve(lambda path: tar_fixture(path, install_jdk.HOME_NAME)):
            home = install_jdk.install(self.root, "linux")
        self.assertTrue((home / "bin/javac").is_file())
        if os.name != "nt":
            self.assertEqual((home / "bin/javac").stat().st_mode & 0o777, 0o755)

    def test_paths_outside_the_jdk_directory_are_refused(self):
        with self.serve(lambda path: zip_fixture(path, "elsewhere")):
            with self.assertRaisesRegex(SystemExit, "unexpected path"):
                install_jdk.install(self.root, "windows")
        with self.serve(lambda path: tar_fixture(path, install_jdk.HOME_NAME + "-evil")):
            with self.assertRaisesRegex(SystemExit, "unexpected path"):
                install_jdk.install(self.root, "linux")

    def test_a_different_build_is_refused(self):
        other = RELEASE.replace(install_jdk.VERSION, "25.0.5+8")
        with self.serve(lambda path: zip_fixture(path, install_jdk.HOME_NAME, other)):
            with self.assertRaisesRegex(SystemExit, "did not contain"):
                install_jdk.install(self.root, "windows")

    def test_an_installed_different_build_is_replaced(self):
        stale = self.root / install_jdk.HOME_NAME
        (stale / "bin").mkdir(parents=True)
        (stale / "bin/javac.exe").write_bytes(b"MZ")
        (stale / "release").write_text(RELEASE.replace(install_jdk.VERSION, "25.0.4+7"))
        with self.serve(lambda path: zip_fixture(path, install_jdk.HOME_NAME)):
            home = install_jdk.install(self.root, "windows")
        self.assertEqual(len(self.requests), 1)
        self.assertTrue(install_jdk.installed(home, "windows"))

    def test_github_environment_points_later_steps_at_the_jdk(self):
        env_file, path_file = self.root / "env", self.root / "path"
        home = self.root / install_jdk.HOME_NAME
        with patch.dict(os.environ, {"GITHUB_ENV": str(env_file), "GITHUB_PATH": str(path_file)}):
            install_jdk.publish(home)
        self.assertEqual(env_file.read_text(encoding="utf-8"), f"JAVA_HOME={home}\n")
        self.assertEqual(path_file.read_text(encoding="utf-8"), f"{home / 'bin'}\n")


if __name__ == "__main__":
    unittest.main()
