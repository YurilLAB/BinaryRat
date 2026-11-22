# Copyright 2026 YurilLAB
# SPDX-License-Identifier: Apache-2.0

import copy
import unittest

from stage_family_calibration import KIND
from verify_family_calibration import (CROSS_CHECK_TARGETS, check, compare_layout,
                                       cross_check_targets)


def family(split, proposals=10, cases=4, surveyed=20):
    return {"split": split, "proposals": proposals, "cases": cases, "surveyed_functions": surveyed}


def summary():
    names = [f"fit{i}" for i in range(6)] + [f"held{i}" for i in range(6)]
    return {"families": {name: family("fit" if name.startswith("fit") else "holdout")
                         for name in names}}


def calibration(model="fit", holdout="descriptive_only", families=6):
    return {"kinds": {KIND: {"model": {"status": model},
                             "holdout": {"status": holdout, "calibrated": {"families": families}}}}}


def field(offset, width, count):
    cited = [f"object/ram/{offset + index:x}/{index}" for index in range(count)]
    return {"offset": offset, "width": width, "evidence_ids": cited,
            "evidence_strength": count / (count + 1)}


def survey_report():
    def function(address, parameters, space="ram"):
        return {"address_space": space, "address": address, "parameters": parameters}

    def parameter(index, fields):
        return {"index": index, "layout": {"fields": fields} if fields is not None else None}

    return {"program_id": "sha256:" + "ab" * 32, "score_kind": "uncalibrated_evidence_strength",
            "functions": [
                function("1000", [parameter(0, [field(0, 4, 1)]), parameter(1, [field(8, 8, 2), field(0, 8, 1)])]),
                function("2000", [parameter(0, None)]),
                function("3000", [parameter(2, [field(0, 4, 1), field(4, 4, 1), field(8, 4, 3)])]),
                function("0500", [parameter(0, [field(0, 1, 1), field(1, 1, 1)])]),
                function("4000", [parameter(0, [field(0, 4, 9)] * 1)], space="OTHER"),
                function("5000", [parameter(0, [])]),
            ]}


def single_report(survey, address, slot, fields):
    return {"program_id": survey["program_id"], "score_kind": survey["score_kind"],
            "function": {"address_space": "ram", "address": address}, "parameter_index": slot,
            "follow_depth": 0, "layouts": [{"fields": copy.deepcopy(fields)}]}


class StructuralCheckTests(unittest.TestCase):
    def test_complete_measurement_has_no_problems(self):
        self.assertEqual(check(calibration(), summary()), [])
        self.assertEqual(check(calibration(holdout="evaluated", families=8), summary()), [])

    def test_each_missing_requirement_is_reported(self):
        cases = []
        missing = summary()
        missing["families"]["fit0"]["surveyed_functions"] = 0
        cases.append((calibration(), missing, "fit0: no surveyed function"))
        empty = summary()
        empty["families"]["held1"]["cases"] = 0
        cases.append((calibration(), empty, "held1: no surveyed function or no oracle case"))
        few = summary()
        for name in ("held0", "held1"):
            few["families"][name]["proposals"] = 0
        cases.append((calibration(), few, "only 4 held-out families"))
        cases.append((calibration(model="insufficient_fit_support"), summary(), "not fitted"))
        cases.append((calibration(holdout="insufficient_holdout_predictions"), summary(),
                      "held-out evaluation failed"))
        cases.append((calibration(families=4), summary(), "fewer than five held-out families"))
        for report, staged, expected in cases:
            with self.subTest(expected=expected):
                problems = check(report, staged)
                self.assertTrue(any(expected in problem for problem in problems), problems)

    def test_fit_families_do_not_count_as_held_out(self):
        moved = summary()
        for name in ("held0", "held1"):
            moved["families"][name]["split"] = "fit"
        self.assertTrue(any("only 4 held-out" in problem for problem in check(calibration(), moved)))


class CrossCheckTests(unittest.TestCase):
    def test_targets_are_the_richest_parameters_in_a_fixed_order(self):
        targets = cross_check_targets(survey_report())
        self.assertEqual([(address, slot, len(fields)) for address, slot, fields in targets],
                         [("3000", 2, 3), ("0500", 0, 2), ("1000", 1, 2), ("1000", 0, 1)])
        shuffled = survey_report()
        shuffled["functions"].reverse()
        self.assertEqual(cross_check_targets(shuffled), targets)

    def test_target_count_is_bounded(self):
        report = survey_report()
        report["functions"] = [{"address_space": "ram", "address": f"{index:x}",
                                "parameters": [{"index": 0, "layout": {"fields": [field(0, 4, 1)]}}]}
                               for index in range(40)]
        self.assertEqual(len(cross_check_targets(report)), CROSS_CHECK_TARGETS)
        self.assertEqual(cross_check_targets({"functions": []}), [])

    def test_equal_layouts_pass_and_every_difference_fails(self):
        survey = survey_report()
        address, slot, fields = cross_check_targets(survey)[0]
        compare_layout(single_report(survey, address, slot, fields), survey, address, slot, fields)

        def differs(mutate):
            single = single_report(survey, address, slot, fields)
            mutate(single)
            with self.assertRaises(RuntimeError):
                compare_layout(single, survey, address, slot, fields)

        differs(lambda report: report["layouts"][0]["fields"].pop())
        differs(lambda report: report["layouts"][0]["fields"].reverse())
        differs(lambda report: report["layouts"][0]["fields"][0].update(width=8))
        differs(lambda report: report["layouts"][0]["fields"][0].update(offset=1))
        differs(lambda report: report["layouts"][0]["fields"][2]["evidence_ids"].pop())
        differs(lambda report: report["layouts"][0]["fields"][2].update(evidence_strength=0.5))
        differs(lambda report: report["layouts"].append({"fields": []}))
        differs(lambda report: report.update(layouts=[]))
        differs(lambda report: report.update(program_id="sha256:" + "cd" * 32))
        differs(lambda report: report.update(parameter_index=slot + 1))
        differs(lambda report: report.update(follow_depth=1))
        differs(lambda report: report.update(score_kind="probability"))
        differs(lambda report: report["function"].update(address="3004"))


if __name__ == "__main__":
    unittest.main()
