#!/usr/bin/env python3
# Copyright 2026 YurilLAB
# SPDX-License-Identifier: Apache-2.0
"""Install the extension in isolated Ghidra settings and run stock parity."""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tempfile
from zipfile import ZipFile

from verify_analysis_profiles import verify_profiles
from verify_ghidra import (PROJECT, check_call_sites, check_persistent_cache, measured_run,
                           saved_project_hashes, sha256)
from verify_layout_parser import verify_parser
from verify_plugin_compatibility import jdk
from verify_type_accuracy import json_file, verified_fields


def verify_archive_checksum(archive: Path) -> str:
    digest = sha256(archive)
    # Compare against the requested archive. Never open a path supplied by the sidecar.
    expected = f"{digest} *{archive.name}".encode("utf-8")
    with archive.with_suffix(archive.suffix + ".sha256").open("rb") as stream:
        record = stream.read(len(expected) + 3)
    if record not in (expected + b"\n", expected + b"\r\n"):
        raise ValueError(f"Incorrect SHA-256 checksum or archive name for {archive.name}")
    return digest


def verify_admission_queue(ghidra: Path, jar: Path, output: Path) -> dict:
    source = Path(__file__).with_name("service_fixture") / "AdmissionQueueProof.java"
    log = output / "admission-queue.log"
    with tempfile.TemporaryDirectory(prefix="admission proof ", dir=output) as directory:
        libraries = sorted((ghidra / "Ghidra/Framework").glob("*/lib"))
        classpath = os.pathsep.join(map(str, [directory, jar, *(lib / "*" for lib in libraries)]))
        with log.open("wb") as diagnostics:
            subprocess.run([jdk("javac"), "-proc:none", "-classpath", classpath, "-d", directory,
                            str(source)], stdout=diagnostics, stderr=subprocess.STDOUT,
                           check=True, timeout=120)
            run = subprocess.run([jdk("java"), "-Xmx128m", "-classpath", classpath,
                                  "binaryrat.AdmissionQueueProof"], stdout=diagnostics,
                                 stderr=subprocess.STDOUT, timeout=60)
    if run.returncode or "BINARYRAT_ADMISSION_QUEUE_OK" not in log.read_text(encoding="utf-8"):
        raise RuntimeError(f"packaged admission order or cancellation proof failed (see {log})")
    return {"passed": True, "log": log.name}


def verify_review_cli(project: list[str], report: Path, output: Path, environment: dict[str, str]) -> dict:
    name = "BinaryRatCliReview"
    preview_log = output / "review-preview.log"
    preview = measured_run(project + ["-postScript", "BinaryRatReviewLayout.java", "preview",
                                      str(report), name], preview_log, 300, environment)
    preview_text = preview_log.read_text(encoding="utf-8", errors="replace")
    codes = re.findall(r'"approvalCode"\s*:\s*"([a-f0-9]{64})"', preview_text)
    if (preview["returncode"] or len(codes) != 1 or "REPORT SCRIPT ERROR" in preview_text or
            "Imported layout evidence for analyst review" not in preview_text):
        raise RuntimeError(f"packaged layout preview failed (see {preview_log})")

    accept_log = output / "review-accept.log"
    accepted = measured_run(project + ["-postScript", "BinaryRatReviewLayout.java", "accept",
                                       str(report), name, codes[0]], accept_log, 300, environment)
    marker = "BINARYRAT_REVIEWED_LAYOUT_CREATED /BinaryRat/Reviewed/" + name
    accept_text = accept_log.read_text(encoding="utf-8", errors="replace")
    if (accepted["returncode"] or marker not in accept_text or "REPORT SCRIPT ERROR" in accept_text or
            "Save succeeded for processed file:" not in accept_text):
        raise RuntimeError(f"packaged layout acceptance failed (see {accept_log})")
    reopen_log = output / "review-reopen.log"
    measured_run(project + ["-postScript", "BinaryRatReviewLayout.java", "preview", str(report),
                            name], reopen_log, 300, environment)
    if "The destination type or its prior review record already exists" not in reopen_log.read_text(
            encoding="utf-8", errors="replace"):
        raise RuntimeError(f"reviewed layout did not survive project reopen (see {reopen_log})")
    return {"passed": True, "preview_log": preview_log.name, "accept_log": accept_log.name,
            "reopen_log": reopen_log.name}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ghidra", required=True, type=Path)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--corpus", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    windows = os.name == "nt"
    machine = {"amd64": "x86_64", "x86_64": "x86_64",
               "arm64": "arm_64", "aarch64": "arm_64"}[platform.machine().lower()]
    os_dir = f"{'win' if windows else 'linux'}_{machine}"
    engine_name = "binaryrat-engine.exe" if windows else "binaryrat-engine"
    engine_entry = f"BinaryRat/os/{os_dir}/{engine_name}"
    archive = args.archive.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    report_path = output / "report.json"
    report_path.unlink(missing_ok=True)
    archive_sha256 = verify_archive_checksum(archive)
    with ZipFile(archive) as package:
        names = set(package.namelist())
        if (len(names) != len(package.namelist()) or engine_entry not in names or
                "BinaryRat/Module.manifest" not in names or
                any(name.startswith(("BinaryRat/installed_scripts/", "BinaryRat/ghidra_scripts/binaryrat/"))
                    and name.endswith(".java")
                    for name in names) or
                {name for name in names if name.endswith(".java") and
                 name.count("/") == 2} != {
                     "BinaryRat/ghidra_scripts/BinaryRatBrowseLayout.java",
                     "BinaryRat/ghidra_scripts/BinaryRatCallSites.java",
                     "BinaryRat/ghidra_scripts/BinaryRatExport.java",
                     "BinaryRat/ghidra_scripts/BinaryRatProfile.java",
                     "BinaryRat/ghidra_scripts/BinaryRatRecoverLayouts.java",
                     "BinaryRat/ghidra_scripts/BinaryRatRecoverRtti.java",
                     "BinaryRat/ghidra_scripts/BinaryRatReviewLayout.java",
                     "BinaryRat/ghidra_scripts/BinaryRatSolveLayouts.java"}):
            raise RuntimeError("unexpected extension contents")
        with ZipFile(io.BytesIO(package.read("BinaryRat/lib/BinaryRat.jar"))) as library:
            if not {"binaryrat/writeback/ProtectedLayoutWriteBack.class",
                    "binaryrat/writeback/LayoutEvidenceBrowser.class",
                    "binaryrat/writeback/LayoutEvidenceTable.class",
                    "binaryrat/writeback/CallPrototypeOverride.class",
                    "binaryrat/analysis/AnalysisProfiles.class",
                    "binaryrat/DecompilationSession.class",
                    "binaryrat/RttiEvidence.class",
                    "binaryrat/SummaryLayouts.class",
                    "binaryrat/CallSites.class",
                    "binaryrat/desktop/CallSitesTable.class"} <= set(library.namelist()):
                raise RuntimeError("extension is missing a shared Java service")
            if (library.read("images/binaryrat/logo.png") !=
                    (PROJECT / "binaryrat/docs/assets/logo.png").read_bytes()):
                raise RuntimeError("extension icons must use the README logo unchanged")
        for name in ("LICENSE", "NOTICE"):
            if package.read(f"BinaryRat/{name}") != (PROJECT / name).read_bytes():
                raise RuntimeError(f"missing or altered extension {name}")
        third_party = PROJECT / "binaryrat/native/third_party"
        for license_file in third_party.rglob("LICENSE*"):
            relative = license_file.relative_to(third_party).as_posix()
            if package.read(f"BinaryRat/licenses/{relative}") != license_file.read_bytes():
                raise RuntimeError(f"altered bundled license {relative}")
        engine_sha256 = hashlib.sha256(package.read(engine_entry)).hexdigest()

    parser_proof = verify_parser(args.ghidra, archive, output)
    manifest = json.loads(args.corpus.read_text(encoding="utf-8"))
    if manifest.get("status") != "passed" or not manifest.get("artifacts"):
        raise RuntimeError("corpus manifest is incomplete or failed")
    artifact = manifest["artifacts"][0]
    corpus = Path(manifest["root"]).resolve()
    fixture = (corpus / artifact["binary"]).resolve()
    if (corpus not in fixture.parents or
            hashlib.sha256(fixture.read_bytes()).hexdigest() != artifact["binary_sha256"]):
        raise RuntimeError("corpus fixture outside root or failed its SHA-256 check")

    headless = args.ghidra.resolve() / "support" / (
        "analyzeHeadless.bat" if windows else "analyzeHeadless")
    install_scripts = Path(__file__).resolve().parent / "ghidra_scripts"
    writeback_scripts = Path(__file__).resolve().parent / "writeback_scripts"
    with tempfile.TemporaryDirectory(prefix="extension test ", dir=output) as temporary:
        root = Path(temporary)
        settings = root / "settings"
        cache = root / "cache"
        settings.mkdir()
        cache.mkdir()
        environment = os.environ | {"XDG_CONFIG_HOME": str(settings), "XDG_CACHE_HOME": str(cache)}
        environment.pop("BINARYRAT_ENGINE", None)
        environment.pop("BINARYRAT_CACHE_DIR", None)
        install_log = output / "install.log"
        install = measured_run(
            [str(headless), str(root), "install", "-scriptPath", str(install_scripts),
             "-preScript", "BinaryRatInstallExtensionFixture.java", str(archive), "-deleteProject"],
            install_log, 300, environment)
        if (install["returncode"] or "BinaryRat test extension installed" not in
                install_log.read_text(encoding="utf-8", errors="replace")):
            raise RuntimeError(f"Ghidra extension installation failed; see {install_log}")
        installed = list(settings.rglob(engine_name))
        if (len(installed) != 1 or not os.access(installed[0], os.X_OK) or
                hashlib.sha256(installed[0].read_bytes()).hexdigest() != engine_sha256):
            raise RuntimeError("installed native engine is missing or differs from the archive")
        admission_proof = verify_admission_queue(args.ghidra.resolve(),
                                                 installed[0].parents[2] / "lib/BinaryRat.jar", output)
        correction_log = output / "call-prototype-override.log"
        correction = measured_run(
            [str(headless), str(root), "call-correction", "-scriptPath", str(writeback_scripts),
             "-preScript", "BinaryRatCallOverrideProof.java", "-deleteProject"],
            correction_log, 120, environment)
        correction_text = correction_log.read_text(encoding="utf-8", errors="replace")
        correction_cases = re.findall(r"BINARYRAT_CALL_OVERRIDE_OK malformed_cases=(\d+)", correction_text)
        if correction["returncode"] or len(correction_cases) != 1 or "REPORT SCRIPT ERROR" in correction_text:
            raise RuntimeError(f"packaged call-site correction proof failed (see {correction_log})")
        correction_proof = {"passed": True, "malformed_signature_cases": int(correction_cases[0]),
                            "log": correction_log.name, "wall_seconds": correction["wall_seconds"]}
        # The same proof as the checkout run, compiled against the installed BinaryRat.jar
        # (no bridge -scriptPath) so it also checks the desktop table's rows.
        proof_scripts = root / "call-site scripts"
        proof_scripts.mkdir()
        (proof_scripts / "BinaryRatCallSitesProof.java").write_bytes(
            (PROJECT / "binaryrat/bridge/ghidra_scripts/BinaryRatCallSitesProof.java").read_bytes())
        call_sites_proof = check_call_sites(headless, proof_scripts, output, 300, environment)
        if not call_sites_proof["table"]:
            raise RuntimeError("installed call-site proof did not reach the desktop table")

        proof = check_persistent_cache(headless, fixture, None, "installed", output, 2, 300,
                                       environment)
        layout_proof = None
        browse_proof = None
        service_proof = None
        profiles_proof = None
        writeback_proof = None
        if artifact["id"].endswith("/types"):
            profiles_proof = verify_profiles(headless, fixture, output / "analysis-profiles", environment)
            layout = output / "installed-layout.json"
            layout.unlink(missing_ok=True)
            layout_log = output / "installed-layout.log"
            scripts = ["-postScript", "BinaryRatRecoverLayouts.java", str(layout), "name:read_packed",
                       "0", "60"]
            proof_args = [str(layout)]
            if artifact["id"] == "gcc/O0/types":
                forwarded = output / "installed-forwarded-layout.json"
                forwarded.unlink(missing_ok=True)
                scripts.extend(["-postScript", "BinaryRatRecoverLayouts.java", str(forwarded),
                                "name:forward_packed", "0", "60", "1"])
                proof_args.append(str(forwarded))
                # Older saved corpora contain the one-hop control. Always require
                # two hops for the current fixture, and for any build that exported it.
                source = PROJECT / "binaryrat/corpus/fixtures/types.c"
                if (artifact["source_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest() or
                        any("-Wl,--export-dynamic-symbol=forward_packed_twice" in step["argv"]
                            for step in artifact["commands"])):
                    two_hops = output / "installed-two-hop-layout.json"
                    two_hops.unlink(missing_ok=True)
                    scripts.extend(["-postScript", "BinaryRatRecoverLayouts.java", str(two_hops),
                                    "name:forward_packed_twice", "0", "60", "2"])
                    proof_args.append(str(two_hops))
            extraction = measured_run(
                [str(headless), str(root), "installed-layout", "-import", str(fixture), *scripts],
                layout_log, 300, environment)
            if extraction["returncode"] or any(not Path(file).is_file() for file in proof_args):
                raise RuntimeError(f"packaged layout extractor did not complete (see {layout_log})")
            fields = verified_fields(json_file(layout), artifact)
            if {(field["offset"], field["width"]) for field in fields} != {(0, 1), (1, 4)}:
                raise RuntimeError(f"packaged extractor did not recover the packed fields (see {layout_log})")
            layout_proof = {"passed": True, "fields": len(fields), "report": layout.name}
            writeback_log = output / "protected-layout.log"
            project = [str(headless), str(root), "installed-layout", "-process", fixture.name, "-noanalysis"]
            before = saved_project_hashes(root, "installed-layout")
            service_log = output / "shared-decompilation-service.log"
            service = measured_run([
                *project, "-readOnly", "-scriptPath", str(writeback_scripts),
                "-postScript", "BinaryRatSharedServiceProof.java",
            ], service_log, 300, environment | {"BINARYRAT_CACHE_DIR": str(root / "shared evidence cache")})
            service_text = service_log.read_text(encoding="utf-8", errors="replace")
            if (service["returncode"] or service_text.count("BINARYRAT_SHARED_SERVICE_OK") != 1 or
                    "REPORT SCRIPT ERROR" in service_text):
                raise RuntimeError(f"packaged shared decompilation proof failed (see {service_log})")
            service_proof = {"passed": True, "log": service_log.name,
                             "wall_seconds": service["wall_seconds"]}
            browse_log = output / "browse-layout.log"
            browse = measured_run([
                *project, "-readOnly", "-scriptPath", str(writeback_scripts),
                "-postScript", "BinaryRatBrowseLayout.java",
                "-postScript", "BinaryRatBrowseLayoutProof.java", *proof_args,
            ], browse_log, 300, environment)
            browse_text = browse_log.read_text(encoding="utf-8", errors="replace")
            match = re.findall(r"BINARYRAT_BROWSE_LAYOUT_OK reports=(\d+) rows=(\d+)", browse_text)
            if (browse["returncode"] or len(match) != 1 or int(match[0][0]) != len(proof_args) or
                    int(match[0][1]) < len(proof_args) or
                    "Browse Layout Evidence requires a CodeBrowser window." not in browse_text or
                    "Processing read-only project file:" not in browse_text or
                    "REPORT SCRIPT ERROR" in browse_text):
                raise RuntimeError(f"packaged evidence browser proof failed (see {browse_log})")
            after = saved_project_hashes(root, "installed-layout")
            if before != after:
                changed = sorted(name for name in before.keys() | after.keys()
                                 if before.get(name) != after.get(name))
                raise RuntimeError(f"read-only evidence or decompilation changed saved project files: {changed}")
            browse_proof = {"passed": True, "reports": len(proof_args), "rows": int(match[0][1]),
                            "unchanged_project_files": len(before), "wall_seconds": browse["wall_seconds"],
                            "log": browse_log.name}
            writeback = measured_run(
                [*project,
                 "-scriptPath", str(writeback_scripts), "-postScript", "BinaryRatProtectedLayoutProof.java",
                 *proof_args], writeback_log, 300, environment)
            if (writeback["returncode"] or "BINARYRAT_PROTECTED_LAYOUT_PROOF_OK" not in
                    writeback_log.read_text(encoding="utf-8", errors="replace")):
                raise RuntimeError(f"packaged write-back service proof failed (see {writeback_log})")
            writeback_proof = {"passed": True, "log": writeback_log.name,
                               "two_hop_approval_verified": len(proof_args) == 3,
                               "wall_seconds": writeback["wall_seconds"],
                               "cli": verify_review_cli(project, layout, output, environment)}
        # An explicit typo must be reported even if a bundled engine is available.
        rejected = root / "rejected.jsonl"
        reject_log = output / "invalid-override.log"
        measured_run(
            [str(headless), str(root), "invalid-override", "-import", str(fixture), "-postScript",
             "BinaryRatExport.java", str(rejected), "scheduled", "2", "60", "16", "-deleteProject"],
            reject_log, 300, environment | {"BINARYRAT_ENGINE": str(root / "missing" / engine_name)})
        if (rejected.exists() or Path(str(rejected) + ".schedule.json").exists() or
                "BinaryRat engine is not an executable file:" not in
                reject_log.read_text(encoding="utf-8", errors="replace")):
            raise RuntimeError(f"explicit invalid engine override did not fail; see {reject_log}")

    report = {"passed": True, "platform": os_dir, "archive": archive.name,
              "archive_sha256": archive_sha256,
              "engine_sha256": engine_sha256, "fixture": artifact["id"],
              "isolated_install": True, "explicit_invalid_override_rejected": True,
              "stock_parity_and_persistence": proof, "packaged_layout_evidence": layout_proof,
              "packaged_layout_browser": browse_proof, "layout_parser": parser_proof,
              "protected_layout_writeback": writeback_proof, "shared_decompilation": service_proof,
              "interactive_admission": admission_proof, "analysis_profiles": profiles_proof,
              "call_site_correction": correction_proof, "call_sites": call_sites_proof}
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Installed BinaryRat extension passed stock parity and persistence: {report_path}")


if __name__ == "__main__":
    main()
