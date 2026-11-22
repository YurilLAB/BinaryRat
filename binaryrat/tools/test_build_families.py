"""Checks for the calibration family list and its builder.

SPDX-License-Identifier: Apache-2.0
Copyright 2026 YurilLAB. New BinaryRat tests.
"""
import copy
import hashlib
import io
import json
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import unittest

import build_families


def minimal(**changes):
    family = {"id": "one", "split": "fit", "language": "c", "license": "MIT",
              "origin": {"repository": "binaryrat/corpus/fixtures"}, "sources": ["*.c"]}
    family.update(changes)
    return {"schema_version": 1, "split_rule": build_families.SPLIT_RULE, "families": [family]}


def archive_origin(name="pkg-1.0.tar.gz"):
    return {"archive": {"name": name, "url": f"https://example.org/files/{name}",
                        "sha256": "a" * 64, "prefix": "pkg-1.0"}}


class FamilyListTests(unittest.TestCase):
    def test_tracked_list_is_valid_and_follows_the_split_rule(self):
        families = build_families.load_families(build_families.DEFAULT_FAMILIES)
        identifiers = [family["id"] for family in families]
        self.assertGreaterEqual(len(identifiers), 10)
        splits = build_families.expected_splits(identifiers)
        self.assertEqual({family["id"]: family["split"] for family in families}, splits)
        self.assertGreaterEqual(sum(split == "holdout" for split in splits.values()), 5)
        self.assertGreaterEqual(sum(split == "fit" for split in splits.values()), 5)
        for family in families:
            archive = family["origin"].get("archive")
            if archive:
                self.assertTrue(archive["url"].startswith("https://"))
            else:
                root = build_families.PROJECT / family["origin"]["repository"]
                self.assertTrue(root.is_dir(), root)
                self.assertTrue(build_families.select_sources(root, family))

    def test_split_depends_only_on_the_identifiers(self):
        names = ["alpha", "beta", "gamma", "delta", "epsilon"]
        expected = build_families.expected_splits(names)
        self.assertEqual(expected, build_families.expected_splits(list(reversed(names))))
        ordered = sorted(names, key=lambda name: hashlib.sha256(name.encode()).hexdigest())
        self.assertEqual([expected[name] for name in ordered], ["fit"] * 3 + ["holdout"] * 2)

    def test_a_moved_split_is_refused(self):
        with self.assertRaisesRegex(ValueError, "must be in the fit split"):
            build_families.parse_families(minimal(split="holdout"))

    def test_malformed_lists_are_refused(self):
        bad = [
            minimal(id="Upper"), minimal(id=""), minimal(language="rust"), minimal(license=""),
            minimal(sources=[]), minimal(sources=["../x.c"]), minimal(sources=["/etc/x.c"]),
            minimal(sources=["a.c", "a.c"]), minimal(exclude=["a/../../b.c"]),
            minimal(include=["../include"]), minimal(include=["inc/*"]),
            minimal(defines=["1BAD"]), minimal(defines=["A=$(id)"]), minimal(defines=["A=b c"]),
            minimal(flags=["-o"]), minimal(flags=["-wrapper"]), minimal(flags=["-include"]),
            minimal(flags=["@file"]), minimal(flags=["-I/etc"]), minimal(flags=["-fplugin=x.so"]),
            minimal(origin={}), minimal(origin={"repository": "../outside"}),
            minimal(origin={"repository": "a", "archive": {}}),
            minimal(config_headers={"../evil.h": []}), minimal(config_headers={"a.h": ["BAD NAME"]}),
            minimal(unknown=1),
        ]
        for name, value in (("url", "http://example.org/files/pkg-1.0.tar.gz"),
                            ("url", "https://example.org/files/other.tar.gz"),
                            ("sha256", "A" * 64), ("name", "pkg.zip"), ("prefix", "../pkg")):
            origin = archive_origin()
            origin["archive"][name] = value
            bad.append(minimal(origin=origin))
        for document in bad:
            with self.subTest(document=document["families"][0]), self.assertRaises(ValueError):
                build_families.parse_families(document)
        for document in ({}, [], minimal() | {"schema_version": 2}, minimal() | {"split_rule": "manual"},
                         minimal() | {"families": []}, minimal() | {"schema_version": True}):
            with self.subTest(document=document), self.assertRaises(ValueError):
                build_families.parse_families(document)

    def test_duplicate_identities_are_refused(self):
        first = minimal()["families"][0]
        second = copy.deepcopy(first)
        with self.assertRaisesRegex(ValueError, "source root"):
            second["id"] = "two"
            build_families.parse_families(minimal() | {"families": [first, second]})
        with self.assertRaisesRegex(ValueError, "one archive"):
            left = dict(first, origin=archive_origin())
            right = dict(first, id="two", origin=archive_origin())
            build_families.parse_families(minimal() | {"families": [left, right]})

    def test_config_header_and_flag_forms_are_accepted(self):
        splits = build_families.expected_splits(["one"])
        document = minimal(split=splits["one"], flags=["-std=gnu17", "-fno-strict-aliasing"],
                           defines=["A", "B=1", 'S="1.2"'],
                           config_headers={"config.h": ["HAVE_X=1", "HAVE_Y"]})
        self.assertEqual(len(build_families.parse_families(document)), 1)


class SourceSelectionTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name).resolve() / "project"
        (self.root / "lib" / "deep").mkdir(parents=True)
        for name in ("lib/a.c", "lib/b.c", "lib/deep/c.c", "lib/main.c", "lib/readme.txt"):
            (self.root / name).write_bytes(b"int value;\n")

    def family(self, **changes):
        return dict({"language": "c", "sources": ["lib/**/*.c"]}, **changes)

    def names(self, family):
        return [path.relative_to(self.root).as_posix()
                for path in build_families.select_sources(self.root, family)]

    def test_patterns_and_exclusions(self):
        self.assertEqual(self.names(self.family()), ["lib/a.c", "lib/b.c", "lib/deep/c.c", "lib/main.c"])
        self.assertEqual(self.names(self.family(exclude=["lib/main.c", "lib/deep/*.c"])),
                         ["lib/a.c", "lib/b.c"])
        self.assertEqual(self.names(self.family(sources=["lib/b.c", "lib/a.c", "lib/*.c"],
                                                exclude=["lib/main.c"])), ["lib/a.c", "lib/b.c"])

    def test_missing_wrong_or_empty_selections_are_refused(self):
        for family in (self.family(sources=["lib/missing.c"]), self.family(sources=["lib/*.txt"]),
                       self.family(sources=["lib/a.c"], exclude=["lib/a.c"])):
            with self.subTest(family=family), self.assertRaises(ValueError):
                build_families.select_sources(self.root, family)

    def test_source_digest_ignores_line_endings_but_not_content_or_names(self):
        sources = build_families.select_sources(self.root, self.family())
        first = build_families.source_digest(self.root, sources)
        (self.root / "lib/a.c").write_bytes(b"int value;\r\n")
        self.assertEqual(first, build_families.source_digest(self.root, sources))
        (self.root / "lib/a.c").write_bytes(b"int other;\n")
        self.assertNotEqual(first, build_families.source_digest(self.root, sources))
        self.assertNotEqual(first, build_families.source_digest(self.root, sources[1:]))


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.scratch = Path(scratch.name).resolve()

    def archive(self, entries):
        path = self.scratch / "source.tar.gz"
        with tarfile.open(path, "w:gz") as bundle:
            for name, kind, payload in entries:
                member = tarfile.TarInfo(name)
                member.type = kind
                if kind == tarfile.REGTYPE:
                    member.size = len(payload)
                    bundle.addfile(member, io.BytesIO(payload))
                else:
                    member.linkname = payload
                    bundle.addfile(member)
        return path

    def test_regular_files_are_extracted_and_links_are_dropped(self):
        path = self.archive([("pkg/a.c", tarfile.REGTYPE, b"int a;\n"),
                             ("pkg/link.c", tarfile.SYMTYPE, "/etc/passwd"),
                             ("pkg/hard.c", tarfile.LNKTYPE, "pkg/a.c")])
        destination = self.scratch / "out"
        build_families.extract_archive(path, destination)
        self.assertEqual(sorted(item.name for item in (destination / "pkg").iterdir()), ["a.c"])

    def test_entries_outside_the_destination_are_refused(self):
        for name in ("../escape.c", "/absolute.c", "pkg/../../escape.c"):
            with self.subTest(name=name):
                path = self.archive([(name, tarfile.REGTYPE, b"int a;\n")])
                destination = self.scratch / ("out" + hashlib.sha256(name.encode()).hexdigest()[:8])
                try:
                    build_families.extract_archive(path, destination)
                except tarfile.TarError:
                    pass
                # A relocated absolute name is acceptable; a file outside never is.
                self.assertFalse((self.scratch / "escape.c").exists())
                self.assertFalse(Path("/absolute.c").exists())
                for item in destination.rglob("*"):
                    self.assertIn(destination, item.resolve().parents)

    def test_existing_destination_and_oversized_archives_are_refused(self):
        path = self.archive([("pkg/a.c", tarfile.REGTYPE, b"int a;\n")])
        (self.scratch / "taken").mkdir()
        with self.assertRaises(FileExistsError):
            build_families.extract_archive(path, self.scratch / "taken")
        limit = build_families.MAX_EXTRACTED_BYTES
        build_families.MAX_EXTRACTED_BYTES = 4
        try:
            with self.assertRaisesRegex(ValueError, "expands beyond"):
                build_families.extract_archive(path, self.scratch / "big")
        finally:
            build_families.MAX_EXTRACTED_BYTES = limit


@unittest.skipUnless(sys.platform == "linux" and all(
    shutil.which(tool) for tool in ("gcc", "objcopy", "strip")), "needs a Linux GCC toolchain")
class BuildTests(unittest.TestCase):
    def test_a_family_builds_into_separate_analysis_and_oracle_files(self):
        with tempfile.TemporaryDirectory() as directory:
            scratch = Path(directory).resolve()
            source = scratch / "src"
            source.mkdir()
            (source / "one.c").write_text(
                "#include \"config.h\"\nstruct pair { int left; long right; };\n"
                "long read_right(struct pair *value) { return value->right + HAVE_VALUE; }\n",
                encoding="utf-8")
            family = {"id": "tiny", "split": "fit", "language": "c", "license": "MIT",
                      "origin": {"repository": "unused"}, "sources": ["*.c"],
                      "flags": ["-std=gnu17"], "config_headers": {"config.h": ["HAVE_VALUE=2"]}}
            tools = {"c": shutil.which("gcc"), "c++": shutil.which("g++"),
                     "objcopy": shutil.which("objcopy"), "strip": shutil.which("strip")}
            output = scratch / "out"
            output.mkdir()
            artifact = build_families.build_family(family, source, output, "gcc", tools, "O2", 2)
            self.assertEqual((artifact["id"], artifact["family"], artifact["format"]),
                             ("gcc/O2/tiny", "tiny", "ELF64"))
            binary, debug = output / artifact["binary"], output / artifact["debug_file"]
            self.assertNotEqual(binary.parent, debug.parent)
            self.assertEqual(artifact["binary_sha256"], hashlib.sha256(binary.read_bytes()).hexdigest())
            stripped = build_families.inspect_binary(binary)
            self.assertEqual(stripped["debug_sections"], [])
            self.assertTrue(build_families.inspect_binary(debug)["debug_sections"])
            self.assertEqual(stripped["executable_sections"], artifact["executable_sections"])
            self.assertNotIn(str(scratch).encode(), binary.read_bytes())
            self.assertFalse((output / "gcc/O2/tiny/objects").exists())
            json.dumps(artifact)


if __name__ == "__main__":
    unittest.main()
