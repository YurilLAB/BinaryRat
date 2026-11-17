#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check BinaryRat authorship, branch policy, release pin, and bundled licenses."""
import argparse
import hashlib
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit", help="new BinaryRat commit to check; upstream history is exempt")
    parser.add_argument("--local", action="store_true", help="require sole local master branch")
    args = parser.parse_args()
    if args.local:
        branches = git("for-each-ref", "--format=%(refname:short)", "refs/heads").splitlines()
        if branches != ["master"] or git("symbolic-ref", "--short", "HEAD") != "master":
            raise SystemExit("BinaryRat work must use the sole existing default branch master")
    if args.commit:
        name, email = git("show", "-s", "--format=%an%n%ae", args.commit).splitlines()
        if name != "yurillab" or email.lower() != "stoney20.js@gmail.com":
            raise SystemExit("new BinaryRat commits must use the approved yurillab author")
        message = git("show", "-s", "--format=%B", args.commit)
        if re.search(r"(?im)^\s*(co-authored-by|generated-by|ai-attribution|ai-assisted-by|assisted-by):", message):
            raise SystemExit("co-author and AI-attribution trailers are prohibited")
    for name in ("LICENSE", "NOTICE"):
        expected = subprocess.check_output(["git", "show", "Ghidra_12.2_build:" + name], cwd=ROOT)
        if (ROOT / name).read_bytes() != expected:
            raise SystemExit(f"upstream {name} must be preserved")
    headers = {
        "nlohmann/json.hpp": "9bea4c8066ef4a1c206b2be5a36302f8926f7fdc6087af5d20b417d0cf103ea6",
        "picosha2/picosha2.h": "b13c180161ffac8d0adc81e033e493c409457c4d1258ab9781ac80579ba3bdd8",
    }
    for name, expected in headers.items():
        actual = hashlib.sha256((ROOT / "binaryrat/native/third_party" / name).read_bytes()).hexdigest()
        if actual != expected:
            raise SystemExit(f"vendored dependency changed: {name}")
    print("Repository policy checks passed")


if __name__ == "__main__":
    main()
