#!/usr/bin/env python3
# Copyright 2026 YurilLAB
# SPDX-License-Identifier: Apache-2.0
"""Exercise installed BinaryRat analysis profiles on a disposable Ghidra project."""
import json
from pathlib import Path
import re
import tempfile

from verify_ghidra import measured_run

SCRIPTS = Path(__file__).resolve().parent / "ghidra_scripts"


def verify_profiles(headless: Path, fixture: Path, output: Path, environment: dict[str, str]) -> dict:
    """The caller supplies a Ghidra environment containing the installed BinaryRat extension."""
    output.mkdir(parents=True, exist_ok=True)
    profiles: dict[str, dict] = {}
    with tempfile.TemporaryDirectory(prefix="analysis profile ", dir=output) as temp:
        def run(profile: str, args: list[str]) -> tuple[dict, str]:
            log = output / f"{profile}.log"
            measured = measured_run([
                str(headless), temp, profile, "-import", str(fixture),
                "-scriptPath", str(SCRIPTS), "-max-cpu", "1", "-deleteProject",
                "-preScript", "BinaryRatProfileProof.java", "seed", *args,
            ], log, 180, environment)
            return measured, log.read_text(encoding="utf-8", errors="replace")

        for profile in ("quick", "normal", "deep"):
            measured, log = run(profile, [
                "-preScript", "BinaryRatProfile.java", profile, "120",
                "-postScript", "BinaryRatProfileProof.java", "verify", profile,
            ])
            match = re.findall(rf"BINARYRAT_ANALYSIS_PROFILE_PROOF {profile} functions=(\d+) analyzers=(\d+)", log)
            if (measured["returncode"] or len(match) != 1 or "REPORT SCRIPT ERROR" in log or
                    log.count(f"BinaryRat analysis profile completed: {profile}") != 1 or
                    "ANALYZING all memory and code" in log):
                raise RuntimeError(f"Analysis profile {profile} failed. See {output / (profile + '.log')}")
            functions, analyzers = map(int, match[0])
            profiles[profile] = {"functions": functions, "analyzers": analyzers,
                                 "wall_seconds": measured["wall_seconds"]}

        measured, log = run("cancel", ["-noanalysis", "-preScript", "BinaryRatProfileProof.java", "cancel"])
        if (measured["returncode"] or log.count("BINARYRAT_ANALYSIS_PROFILE_CANCEL_PROOF") != 1 or
                "REPORT SCRIPT ERROR" in log):
            raise RuntimeError(f"Cancelled profile failed restoration proof. See {output / 'cancel.log'}")
        measured, log = run("invalid", ["-preScript", "BinaryRatProfile.java", "unknown"])
        if ("Analysis profile must be quick, normal, or deep." not in log or
                "Processing aborted as a result of pre-script." not in log or
                "ANALYZING all memory and code" in log or "BinaryRat analysis profile completed:" in log):
            raise RuntimeError(f"Invalid profile did not stop processing. See {output / 'invalid.log'}")

    report = {"passed": True, "profiles": profiles, "cancellation_restored_options": True,
              "invalid_profile_aborted": True}
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report
