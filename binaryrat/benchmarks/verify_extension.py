#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Install the extension in isolated Ghidra settings and run stock parity."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import tempfile
from zipfile import ZipFile

from verify_ghidra import PROJECT, check_persistent_cache, measured_run
from verify_type_accuracy import json_file, verified_fields


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
                {name for name in names if name.endswith(".java") and
                 name.count("/") == 2} != {
                     "BinaryRat/ghidra_scripts/BinaryRatExport.java",
                     "BinaryRat/ghidra_scripts/BinaryRatRecoverLayouts.java"}):
            raise RuntimeError("unexpected extension contents")
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
        if artifact["id"].endswith("/types"):
            layout = output / "installed-layout.json"
            layout.unlink(missing_ok=True)
            layout_log = output / "installed-layout.log"
            extraction = measured_run(
                [str(headless), str(root), "installed-layout", "-import", str(fixture), "-readOnly",
                 "-postScript", "BinaryRatRecoverLayouts.java", str(layout), "name:read_packed",
                 "0", "60", "-deleteProject"], layout_log, 300, environment)
            if extraction["returncode"] or not layout.is_file():
                raise RuntimeError(f"packaged layout extractor did not complete (see {layout_log})")
            fields = verified_fields(json_file(layout), artifact)
            if {(field["offset"], field["width"]) for field in fields} != {(0, 1), (1, 4)}:
                raise RuntimeError(f"packaged extractor did not recover the packed fields (see {layout_log})")
            layout_proof = {"passed": True, "fields": len(fields), "report": layout.name}
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
              "stock_parity_and_persistence": proof, "packaged_layout_evidence": layout_proof}
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Installed BinaryRat extension passed stock parity and persistence: {report_path}")


if __name__ == "__main__":
    main()
