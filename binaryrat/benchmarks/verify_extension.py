#!/usr/bin/env python3
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
import tempfile
from zipfile import ZipFile

from verify_ghidra import PROJECT, check_persistent_cache, measured_run
from verify_type_accuracy import json_file, verified_fields


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
    with ZipFile(archive) as package:
        names = set(package.namelist())
        if (len(names) != len(package.namelist()) or engine_entry not in names or
                "BinaryRat/Module.manifest" not in names or
                "BinaryRat/ghidra_scripts/binaryrat/RttiEvidence.java" not in names or
                any(name.startswith("BinaryRat/installed_scripts/") and name.endswith(".java")
                    for name in names) or
                {name for name in names if name.endswith(".java") and
                 name.count("/") == 2} != {
                     "BinaryRat/ghidra_scripts/BinaryRatExport.java",
                     "BinaryRat/ghidra_scripts/BinaryRatRecoverLayouts.java",
                     "BinaryRat/ghidra_scripts/BinaryRatRecoverRtti.java",
                     "BinaryRat/ghidra_scripts/BinaryRatReviewLayout.java"}):
            raise RuntimeError("unexpected extension contents")
        with ZipFile(io.BytesIO(package.read("BinaryRat/lib/BinaryRat.jar"))) as library:
            if "binaryrat/writeback/ProtectedLayoutWriteBack.class" not in library.namelist():
                raise RuntimeError("extension is missing the protected layout write-back service")
        for name in ("LICENSE", "NOTICE"):
            if package.read(f"BinaryRat/{name}") != (PROJECT / name).read_bytes():
                raise RuntimeError(f"missing or altered extension {name}")
        third_party = PROJECT / "binaryrat/native/third_party"
        for license_file in third_party.rglob("LICENSE*"):
            relative = license_file.relative_to(third_party).as_posix()
            if package.read(f"BinaryRat/licenses/{relative}") != license_file.read_bytes():
                raise RuntimeError(f"altered bundled license {relative}")
        engine_sha256 = hashlib.sha256(package.read(engine_entry)).hexdigest()

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
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    report_path = output / "report.json"
    report_path.unlink(missing_ok=True)
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

        proof = check_persistent_cache(headless, fixture, None, "installed", output, 2, 300,
                                       environment)
        layout_proof = None
        writeback_proof = None
        if artifact["id"].endswith("/types"):
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
              "engine_sha256": engine_sha256, "fixture": artifact["id"],
              "isolated_install": True, "explicit_invalid_override_rejected": True,
              "stock_parity_and_persistence": proof, "packaged_layout_evidence": layout_proof,
              "protected_layout_writeback": writeback_proof}
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Installed BinaryRat extension passed stock parity and persistence: {report_path}")


if __name__ == "__main__":
    main()
