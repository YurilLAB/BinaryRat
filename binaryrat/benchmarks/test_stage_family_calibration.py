# Copyright 2026 YurilLAB
# SPDX-License-Identifier: Apache-2.0

import copy
import hashlib
import json
from pathlib import Path
import random
import shutil
import subprocess
import sys
import tempfile
import unittest

from calibrate_type_confidence import evaluate
from dwarf_targets import read_dwarf_targets
from stage_family_calibration import KIND, parse_survey, stage, survey_name


SHA = "ab" * 32
OBJECT = f"sha256:{SHA}/ram/101000/param/0"


def field(offset, width, sites, object_id=OBJECT):
    cited = [f"{object_id}/ram/{site:x}/{order}" for site, order in sites]
    return {"offset": offset, "width": width, "evidence_ids": cited,
            "evidence_strength": len(cited) / (len(cited) + 1)}


def parameter(index, register, fields, object_id=OBJECT):
    return {"index": index, "register": register, "object_id": object_id,
            "layout": {"fields": fields} if fields is not None else None}


def function(address, parameters, **changes):
    record = {"address_space": "ram", "address": f"{address:x}", "name": "f", "status": "surveyed",
              "body_sha256": hashlib.sha256(str(address).encode()).hexdigest(),
              "code_sha256": None, "parameters": parameters}
    record.update(changes)
    return record


def survey(functions, binary=SHA, **changes):
    report = {"schema_version": 1, "analysis_mode": "read_only_layout_survey",
              "score_kind": "uncalibrated_evidence_strength", "follow_depth": 0,
              "program_id": "sha256:" + binary, "image_base": "100000",
              "original_image_base": "0", "functions": functions}
    report.update(changes)
    return report


def valid_survey():
    return survey([
        function(0x101000, [parameter(0, "RDI", [field(0, 4, [(0x101004, 1), (0x101008, 2)]),
                                                 field(8, 8, [(0x10100c, 3)])])]),
        function(0x102000, [], status="refused", reason="limit"),
        function(0x103000, [parameter(0, "RDI", None, f"sha256:{SHA}/ram/103000/param/0")],
                 code_sha256="c0" * 32),
    ])


class SurveyParsingTests(unittest.TestCase):
    def test_valid_report_is_indexed_by_address(self):
        parsed = parse_survey(valid_survey(), SHA)
        self.assertEqual(parsed["bias"], 0x100000)
        self.assertEqual(sorted(parsed["functions"]), [0x101000, 0x102000, 0x103000])
        first = parsed["functions"][0x101000]
        self.assertEqual(first["parameters"]["RDI"], [{"offset": 0, "width": 4, "score": 2 / 3},
                                                      {"offset": 8, "width": 8, "score": 0.5}])
        self.assertTrue(first["identity"].startswith("body:"))
        # The masked-instruction identity wins over the exact bytes when both exist.
        self.assertEqual(parsed["functions"][0x103000]["identity"], "code:" + "c0" * 32)
        self.assertEqual(parsed["functions"][0x103000]["parameters"], {"RDI": []})
        self.assertEqual(parsed["functions"][0x102000]["status"], "refused")

    def rejected(self, mutate, message=None):
        report = valid_survey()
        mutate(report)
        with self.assertRaisesRegex(ValueError, message or ""):
            parse_survey(report, SHA)

    def test_wrong_program_mode_or_score_semantics(self):
        self.rejected(lambda r: r.update(program_id="sha256:" + "cd" * 32), "different Program")
        self.rejected(lambda r: r.update(analysis_mode="read_only_layout_evidence"))
        self.rejected(lambda r: r.update(follow_depth=1))
        self.rejected(lambda r: r.update(follow_depth=False))
        self.rejected(lambda r: r.update(score_kind="probability"))
        self.rejected(lambda r: r.update(schema_version=2))
        self.rejected(lambda r: r.update(original_image_base=None), "original ELF image base")
        self.rejected(lambda r: r.update(image_base="0x100000"))
        self.rejected(lambda r: r.update(functions={}))

    def test_one_access_supports_one_proposal(self):
        def reuse(report):
            fields = report["functions"][0]["parameters"][0]["layout"]["fields"]
            fields[1]["evidence_ids"] = [fields[0]["evidence_ids"][0]]
        self.rejected(reuse, "one access supports several proposals")

        def repeat(report):
            first = report["functions"][0]["parameters"][0]["layout"]["fields"][0]
            first["evidence_ids"] = [first["evidence_ids"][0]] * 2
        self.rejected(repeat, "nonempty and unique")

        def foreign(report):
            first = report["functions"][0]["parameters"][0]["layout"]["fields"][0]
            first["evidence_ids"][0] = f"sha256:{SHA}/ram/999999/param/0/ram/101004/1"
        self.rejected(foreign, "another object")

    def test_scores_must_follow_the_support_formula(self):
        def inflate(report):
            report["functions"][0]["parameters"][0]["layout"]["fields"][0]["evidence_strength"] = 0.9
        self.rejected(inflate, "evidence-strength formula")
        for value in (None, "0.5", True, float("nan")):
            def replace(report, value=value):
                report["functions"][0]["parameters"][0]["layout"]["fields"][1]["evidence_strength"] = value
            self.rejected(replace)

    def test_malformed_fields_functions_and_parameters(self):
        fields = lambda r: r["functions"][0]["parameters"][0]["layout"]["fields"]
        self.rejected(lambda r: fields(r)[0].update(offset=-1))
        self.rejected(lambda r: fields(r)[0].update(offset=True))
        self.rejected(lambda r: fields(r)[0].update(width=0))
        self.rejected(lambda r: fields(r)[0].update(width=1 << 33))
        self.rejected(lambda r: fields(r)[0].update(evidence_ids=[]))
        self.rejected(lambda r: fields(r)[1].update(offset=0, width=4), "duplicate surveyed field")
        self.rejected(lambda r: r["functions"].append(copy.deepcopy(r["functions"][1])),
                      "duplicate surveyed function")
        self.rejected(lambda r: r["functions"][0].update(status="done"))
        self.rejected(lambda r: r["functions"][0].update(address="xyz"))
        self.rejected(lambda r: r["functions"][1].update(
            parameters=[parameter(0, "RSI", None)]), "invalid surveyed parameters")
        self.rejected(lambda r: r["functions"][0]["parameters"].append(
            parameter(1, "RDI", None)), "duplicate or invalid parameter register")
        self.rejected(lambda r: r["functions"][0]["parameters"].append(
            parameter(0, "RSI", None)), "duplicate or invalid parameter register")
        self.rejected(lambda r: r["functions"][0]["parameters"][0].update(register="rdi!"))
        self.rejected(lambda r: r["functions"][0]["parameters"][0].update(layout=[]))
        self.rejected(lambda r: r["functions"][2].update(code_sha256="C0" * 32), "invalid code digest")
        self.rejected(lambda r: r["functions"][2].update(code_sha256=7))
        self.rejected(lambda r: r["functions"][0].update(body_sha256="short"), "invalid body digest")
        self.rejected(lambda r: r["functions"].__setitem__(0, []))
        self.rejected(lambda r: r["functions"][0].update(
            parameters=[parameter(slot, f"R{slot}", None) for slot in range(9)]))

    def test_functions_in_other_spaces_are_ignored_but_still_checked(self):
        report = valid_survey()
        report["functions"][1]["address_space"] = "OTHER"
        report["functions"][1]["address"] = "101000"
        self.assertEqual(sorted(parse_survey(report, SHA)["functions"]), [0x101000, 0x103000])

    def test_seeded_mutations_fail_only_with_value_errors(self):
        replacements = (None, True, 0, -1, 1.5, "", "x", [], {}, [[]], {"fields": 3}, 1 << 70)
        for seed in range(400):
            randomizer = random.Random(seed)
            report = valid_survey()
            for _ in range(randomizer.randint(1, 3)):
                node = report
                # Walk to a random container, then replace or delete one of its entries.
                for _ in range(randomizer.randint(0, 6)):
                    children = (list(node.values()) if type(node) is dict else list(node))
                    children = [child for child in children if type(child) in (dict, list) and child]
                    if not children:
                        break
                    node = randomizer.choice(children)
                keys = list(node) if type(node) is dict else list(range(len(node)))
                if not keys:
                    continue
                key = randomizer.choice(keys)
                if randomizer.random() < 0.2:
                    del node[key]
                else:
                    node[key] = randomizer.choice(replacements)
            try:
                parsed = parse_survey(report, SHA)
            except ValueError:
                continue
            for record in parsed["functions"].values():
                for fields in record["parameters"].values():
                    for item in fields:
                        self.assertTrue(0 < item["score"] < 1 and item["width"] > 0, (seed, item))


SOURCE = r"""
struct inner { short low; short high; };
struct outer { int tag; struct inner pair; long values[3]; unsigned flag : 3; };
struct opaque;
#define KEEP __attribute__((noinline))
KEEP long read_outer(struct outer *item) { return item->values[1] + item->pair.high; }
KEEP int twin(struct outer *item) { return item->tag; }
KEEP int missing(struct outer *item) { return item->tag + 1; }
KEEP int refused(struct outer *item) { return item->tag + 2; }
KEEP int other_register(struct outer *item) { return item->tag + 3; }
KEEP int unreadable(struct outer *item) { return item->tag + 4; }
KEEP int opaque_user(struct opaque *handle) { return handle != 0; }
KEEP long two(struct outer *left, struct outer *right) { return left->tag + right->values[0]; }
"""


@unittest.skipUnless(sys.platform == "linux" and all(
    shutil.which(tool) for tool in ("gcc", "objcopy", "strip")), "needs a Linux GCC toolchain")
class StagingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory()
        cls.root = Path(cls.scratch.name).resolve()
        cls.artifacts = []
        for family, split, extra in (("alpha", "fit", ""), ("beta", "holdout", "int beta_only;\n")):
            work = cls.root / "gcc" / "O2" / family
            (work / "oracle").mkdir(parents=True)
            (work / "analysis").mkdir()
            (work / "source.c").write_text(SOURCE + extra, encoding="utf-8")
            original = work / "oracle" / f"{family}.so"
            subprocess.run(["gcc", "-O2", "-g", "-gdwarf-4", "-fPIC", "-fno-lto", "-shared",
                            "-std=gnu17", "source.c", "-o", str(original)], cwd=work, check=True)
            debug, stripped = work / "oracle" / f"{family}.debug", work / "analysis" / f"{family}.so"
            subprocess.run(["objcopy", "--only-keep-debug", str(original), str(debug)], check=True)
            subprocess.run(["strip", "--strip-all", "-o", str(stripped), str(original)], check=True)
            digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
            cls.artifacts.append({
                "id": f"gcc/O2/{family}", "family": family, "split": split, "format": "ELF64",
                "source_sha256": digest(work / "source.c"),
                "binary": stripped.relative_to(cls.root).as_posix(), "binary_sha256": digest(stripped),
                "debug_file": debug.relative_to(cls.root).as_posix(), "debug_sha256": digest(debug)})
        cls.manifest = cls.root / "manifest.json"
        cls.manifest.write_text(json.dumps({"schema_version": 1, "kind": "calibration-families",
                                            "status": "passed", "artifacts": cls.artifacts}))

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()

    def setUp(self):
        surveys = tempfile.TemporaryDirectory(dir=self.root)
        self.addCleanup(surveys.cleanup)
        self.surveys = Path(surveys.name)
        self.reports = {}
        for artifact in self.artifacts:
            oracle = read_dwarf_targets(self.root / artifact["debug_file"])
            entries = {item["name"]: item["low_pc"] + 0x100000 for item in oracle["functions"]}
            sha = artifact["binary_sha256"]
            build = lambda name, slot=0: f"sha256:{sha}/ram/{entries[name]:x}/param/{slot}"
            site = lambda name, step: (entries[name] + step, step)
            reader, twin, pair = build("read_outer"), build("twin"), build("two")
            # Every body is distinct, except "twin", which both families contain.
            body = lambda name: hashlib.sha256(f"{artifact['family']}:{name}".encode()).hexdigest()
            functions = [
                function(entries["read_outer"], [parameter(0, "RDI", [
                    field(16, 8, [site("read_outer", 1), site("read_outer", 2)], reader),
                    field(6, 2, [site("read_outer", 3)], reader),
                    field(0, 8, [site("read_outer", 4)], reader),
                    field(32, 1, [site("read_outer", 5)], reader)], reader)],
                         body_sha256=body("read_outer")),
                function(entries["twin"], [parameter(0, "RDI", [
                    field(0, 4, [site("twin", 1)], twin)], twin)], body_sha256="11" * 32),
                function(entries["refused"], [], status="refused", reason="limit",
                         body_sha256=body("refused")),
                function(entries["other_register"],
                         [parameter(1, "RSI", None, build("other_register", 1))],
                         body_sha256=body("other_register")),
                function(entries["unreadable"], [parameter(0, "RDI", None, build("unreadable"))],
                         body_sha256=None),
                function(entries["opaque_user"], [parameter(0, "RDI", None, build("opaque_user"))],
                         body_sha256=body("opaque_user")),
                function(entries["two"], [
                    parameter(0, "RDI", [field(0, 4, [site("two", 1)], pair)], pair),
                    parameter(1, "RSI", [field(8, 8, [site("two", 2)], build("two", 1)),
                                         field(12, 2, [site("two", 3)], build("two", 1))],
                              build("two", 1))], body_sha256=body("two")),
            ]
            self.reports[artifact["family"]] = (survey(functions, sha), entries)
        self.write()

    def write(self):
        for artifact in self.artifacts:
            path = self.surveys / survey_name(artifact["id"])
            path.write_text(json.dumps(self.reports[artifact["family"]][0]), encoding="utf-8")

    def cases(self, dataset, family):
        return {case["case_id"].split("/", 3)[3]: case for case in dataset["cases"]
                if case["source_family"] == family}

    def key(self, family, name, register="RDI"):
        return f"{self.reports[family][1][name]:x}/{register}"

    def test_labels_abstentions_and_exclusions(self):
        dataset, summary = stage(self.manifest, self.surveys)
        alpha = self.cases(dataset, "alpha")
        reader = alpha[self.key("alpha", "read_outer")]
        self.assertEqual(reader["proposals"], [
            {"proposal_id": "bytes:16:8", "score": 2 / 3, "correct": True},
            {"proposal_id": "bytes:6:2", "score": 0.5, "correct": True},
            {"proposal_id": "bytes:0:8", "score": 0.5, "correct": False}])
        self.assertEqual((reader["split"], reader["kind"]), ("fit", KIND))
        self.assertEqual(alpha[self.key("alpha", "two")]["proposals"],
                         [{"proposal_id": "bytes:0:4", "score": 0.5, "correct": True}])
        self.assertEqual(alpha[self.key("alpha", "two", "RSI")]["proposals"], [
            {"proposal_id": "bytes:8:8", "score": 0.5, "correct": True},
            {"proposal_id": "bytes:12:2", "score": 0.5, "correct": False}])
        for name in ("missing", "refused", "other_register"):
            self.assertEqual(alpha[self.key("alpha", name)]["proposals"], [], name)
        self.assertNotIn(self.key("alpha", "opaque_user"), alpha)
        self.assertNotIn(self.key("alpha", "unreadable"), alpha)
        counts = summary["families"]["alpha"]
        self.assertEqual(counts["excluded_proposals"], {"bitfield storage": 1})
        self.assertEqual(counts["excluded_targets"], {"pointee type is incomplete": 1})
        self.assertEqual(counts["abstentions"], {"no function at the entry address": 1,
                                                 "function refused by the survey": 1,
                                                 "register is not a surveyed parameter": 1})
        self.assertEqual(counts["excluded_functions"]["function has no identity"], 1)
        self.assertEqual((counts["cases"], counts["cases_with_proposals"], counts["proposals"],
                          counts["correct_proposals"]), (7, 4, 7, 5))
        report = evaluate(dataset)["kinds"][KIND]
        self.assertEqual(report["model"]["status"], "insufficient_fit_support")

    def test_a_function_seen_in_two_families_is_kept_once(self):
        dataset, summary = stage(self.manifest, self.surveys)
        self.assertIn(self.key("alpha", "twin"), self.cases(dataset, "alpha"))
        beta = self.cases(dataset, "beta")
        self.assertNotIn(self.key("beta", "twin"), beta)
        self.assertIn(self.key("beta", "read_outer"), beta)
        self.assertEqual(
            summary["families"]["beta"]["excluded_functions"]["duplicate of a function kept elsewhere"], 1)
        self.assertNotIn("duplicate of a function kept elsewhere",
                         summary["families"]["alpha"]["excluded_functions"])
        # The same body twice in one binary is also one sample.
        report, entries = self.reports["alpha"]
        next(item for item in report["functions"]
             if item["address"] == f"{entries['two']:x}")["body_sha256"] = "11" * 32
        self.write()
        dataset, summary = stage(self.manifest, self.surveys)
        alpha = self.cases(dataset, "alpha")
        kept = [name for name in ("twin", "two") if self.key("alpha", name) in alpha]
        self.assertEqual(len(kept), 1)
        self.assertEqual(
            summary["families"]["alpha"]["excluded_functions"]["duplicate of a function kept elsewhere"], 1)

    def test_bindings_to_the_built_artifacts_are_enforced(self):
        report, _ = self.reports["beta"]
        report["program_id"] = "sha256:" + "00" * 32
        self.write()
        with self.assertRaisesRegex(ValueError, "different Program"):
            stage(self.manifest, self.surveys)
        (self.surveys / survey_name("gcc/O2/beta")).unlink()
        with self.assertRaises((OSError, ValueError)):
            stage(self.manifest, self.surveys)

    def test_manifest_requirements(self):
        for change in ({"status": "failed"}, {"kind": "corpus"}, {"schema_version": 2},
                       {"artifacts": []},
                       {"artifacts": [dict(self.artifacts[0], split="test")]},
                       {"artifacts": [dict(self.artifacts[0], id="gcc/O2/other")]},
                       {"artifacts": [dict(self.artifacts[0], debug_sha256="00" * 32)]},
                       {"artifacts": [dict(self.artifacts[0], debug_file=self.artifacts[0]["binary"])]},
                       {"artifacts": [self.artifacts[0], self.artifacts[0]]}):
            manifest = self.root / "other-manifest.json"
            document = json.loads(self.manifest.read_text()) | change
            manifest.write_text(json.dumps(document))
            with self.subTest(change=change), self.assertRaises(ValueError):
                stage(manifest, self.surveys)


if __name__ == "__main__":
    unittest.main()
