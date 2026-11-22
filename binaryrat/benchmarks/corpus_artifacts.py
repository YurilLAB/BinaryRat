# Copyright 2026 YurilLAB
# SPDX-License-Identifier: Apache-2.0
"""Hash-checked access to the analysis input and the oracle file of one corpus artifact."""

import hashlib
from pathlib import Path


def digest(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def checked_file(root: Path, artifact: dict, path_key: str, digest_key: str) -> Path:
    path = (root / artifact[path_key]).resolve(strict=True)
    if root not in path.parents or not path.is_file() or digest(path) != artifact[digest_key]:
        raise ValueError(f"corpus path or SHA-256 check failed for {path_key}")
    return path


def checked_artifact_pair(root: Path, artifact: dict) -> tuple[Path, Path]:
    binary = checked_file(root, artifact, "binary", "binary_sha256")
    debug = checked_file(root, artifact, "debug_file", "debug_sha256")
    if binary.parent == debug.parent or artifact["binary_sha256"] == artifact["debug_sha256"]:
        raise ValueError("analysis input and oracle must be separate artifacts with distinct content")
    return binary, debug
