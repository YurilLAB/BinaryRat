#!/usr/bin/env python3
"""Fetch the pinned official integration baseline, preserving executable modes.

SPDX-License-Identifier: Apache-2.0
Copyright 2026 YurilLAB. New BinaryRat tooling.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import zipfile

from pinned_download import DownloadError, fetch


URL = ("https://github.com/NationalSecurityAgency/ghidra/releases/download/"
       "Ghidra_12.2_build/ghidra_12.2_PUBLIC_20261016.zip")
SHA256 = "2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67"
DIRECTORY = "ghidra_12.2_PUBLIC"


def extract_verified(archive: Path, output: Path) -> Path:
    checksum = hashlib.sha256()
    with archive.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(chunk)
    if checksum.hexdigest() != SHA256:
        raise ValueError("official Ghidra 12.2 archive SHA-256 mismatch")
    output.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as package:
        # Reject unexpected paths even though the whole archive is hash-pinned.
        for entry in package.infolist():
            target = (output / entry.filename).resolve()
            if output.resolve() not in target.parents or entry.filename.split("/")[0] != DIRECTORY:
                raise ValueError("unexpected path in Ghidra archive")
        package.extractall(output)
        for entry in package.infolist():
            mode = (entry.external_attr >> 16) & 0o777
            if mode:
                os.chmod(output / entry.filename, mode)
    result = output / DIRECTORY
    if not (result / "support" / "analyzeHeadless").is_file():
        raise ValueError("Ghidra archive does not contain the expected headless launcher")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--archive", type=Path, help="reuse a locally downloaded, hash-verified archive")
    args = parser.parse_args()
    output = args.output.resolve()
    archive = args.archive or output.parent / "ghidra_12.2.zip"
    if args.archive is None:
        # Retries transient failures; a partial or altered download is never kept.
        try:
            fetch(URL, archive, SHA256)
        except DownloadError as error:
            raise SystemExit(str(error))
    print(extract_verified(archive, output))


if __name__ == "__main__":
    main()
