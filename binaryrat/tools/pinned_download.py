#!/usr/bin/env python3
"""Download a hash-pinned file, retrying transient network failures.

A file is only ever moved to its destination after its SHA-256 matches the pin,
so a reset connection or a truncated transfer never leaves a usable partial file.

SPDX-License-Identifier: Apache-2.0
Copyright 2026 YurilLAB. New BinaryRat tooling.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
from pathlib import Path
import sys
import time
from typing import Callable
import urllib.error
import urllib.request


ATTEMPTS = 4
FIRST_DELAY = 5.0
CHUNK = 1024 * 1024


class DownloadError(RuntimeError):
    pass


def file_sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def permanent(error: BaseException) -> bool:
    """HTTP client errors other than timeout and rate limiting will not improve on retry."""
    return (isinstance(error, urllib.error.HTTPError) and 400 <= error.code < 500
            and error.code not in (408, 429))


def fetch(url: str, destination: Path, sha256: str, *, attempts: int = ATTEMPTS,
          timeout: float = 60.0, first_delay: float = FIRST_DELAY,
          opener: Callable = urllib.request.urlopen,
          sleep: Callable[[float], None] = time.sleep) -> Path:
    """Return destination holding url's content, which must hash to sha256."""
    sha256 = sha256.lower()
    if len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256):
        raise ValueError("expected a 64-digit hexadecimal SHA-256")
    if attempts < 1:
        raise ValueError("attempts must be at least 1")
    destination = Path(destination)
    if destination.is_file() and file_sha256(destination) == sha256:
        return destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    partial = destination.with_name(destination.name + ".part")
    last: BaseException | None = None
    for attempt in range(1, attempts + 1):
        try:
            digest = hashlib.sha256()
            with opener(url, timeout=timeout) as source, partial.open("wb") as target:
                for chunk in iter(lambda: source.read(CHUNK), b""):
                    digest.update(chunk)
                    target.write(chunk)
            if digest.hexdigest() != sha256:
                raise DownloadError(f"SHA-256 mismatch: got {digest.hexdigest()}")
            partial.replace(destination)
            return destination
        except (OSError, http.client.HTTPException, DownloadError) as error:
            last = error
            partial.unlink(missing_ok=True)
            if permanent(error) or attempt == attempts:
                break
            delay = first_delay * 3 ** (attempt - 1)
            print(f"download attempt {attempt}/{attempts} of {url} failed: {error}; "
                  f"retrying in {delay:g} s", file=sys.stderr, flush=True)
            sleep(delay)
    raise DownloadError(f"could not download {url}: {last}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--attempts", type=int, default=ATTEMPTS)
    args = parser.parse_args()
    try:
        print(fetch(args.url, args.output, args.sha256, attempts=args.attempts))
    except DownloadError as error:
        raise SystemExit(str(error))


if __name__ == "__main__":
    main()
