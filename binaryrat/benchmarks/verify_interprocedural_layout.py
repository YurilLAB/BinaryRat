#!/usr/bin/env python3
# Copyright 2026 YurilLAB
# SPDX-License-Identifier: Apache-2.0
"""Exercise bounded call traversal on a stripped ELF fixture under Ghidra."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

from verify_ghidra import PROJECT, measured_run

LANGUAGES = {62: "x86:LE:64:default", 183: "AARCH64:LE:64:v8A"}


def capture(directory: Path, name: str) -> dict:
    return json.loads((directory / f"{name}.json").read_text(encoding="utf-8"))


def fields(report: dict) -> set[tuple[int, int]]:
    return {(item["offset"], item["width"])
            for layout in report["layouts"] for item in layout["fields"]}


def connected(report: dict) -> list[dict]:
    target = report["function"]
    nodes = {0: {(target["address_space"], target["address"])}}
    edges = report["forwarded_calls"]
    seen = set()
    for edge in edges:
        hop = edge["hop"]
        caller = (edge["caller_address_space"], edge["caller_address"])
        callee = (edge["callee_address_space"], edge["callee_address"])
        site = (edge["address_space"], edge["address"], edge["pcode_order"])
        if (hop < 1 or hop > report["follow_depth"] or caller not in nodes.get(hop - 1, ()) or
                any(callee in depth for earlier, depth in nodes.items() if earlier < hop) or
                (caller, site) in seen or edge["callee_parameter_index"] != 0):
            raise RuntimeError(f"invalid or cyclic forwarding provenance: {edge}")
        seen.add((caller, site))
        nodes.setdefault(hop, set()).add(callee)
    return edges


def check_results(directory: Path, language: str) -> dict:
    reports = [capture(directory, f"chain-{depth}") for depth in range(5)]
    for depth, report in enumerate(reports):
        expected = {(16, 4)} if depth >= 3 else set()
        if (report["language_id"] != language or report["follow_depth"] != depth or
                fields(report) != expected or len(report["forwarded_calls"]) != min(depth, 3)):
            raise RuntimeError(f"chain did not obey the requested depth {depth}")
        if depth >= 2:
            connected(report)
            if report["decompile_attempts"] != 1 + min(depth, 3):
                raise RuntimeError(f"chain performed unexpected work at depth {depth}")
    if any("hop" in call for call in reports[1]["forwarded_calls"]):
        raise RuntimeError("depth-one forwarding no longer has the original report shape")
    if reports[3]["observations"] != reports[4]["observations"]:
        raise RuntimeError("extra depth changed the evidence of the same chain")

    limited, deepest = (capture(directory, name) for name in ("deep-limited", "deepest"))
    if (len(connected(limited)) != 3 or fields(limited) or len(connected(deepest)) != 4 or
            deepest["decompile_attempts"] != 5 or fields(deepest) != {(16, 4)}):
        raise RuntimeError("a four-hop chain did not stop at the requested depth")

    diamond = capture(directory, "diamond")
    edges = connected(diamond)
    second_hop = [edge for edge in edges if edge["hop"] == 2]
    if (len(edges) != 4 or len(second_hop) != 2 or
            len({edge["callee_address"] for edge in second_hop}) != 1 or
            len(diamond["observations"]) != 1 or diamond["decompile_attempts"] != 4 or
            fields(diamond) != {(16, 4)}):
        raise RuntimeError("diamond did not keep both paths with a single leaf observation")

    shifted = capture(directory, "shifted")
    if (len(connected(shifted)) != 3 or len(shifted["observations"]) != 1 or
            fields(shifted) != {(16, 4)}):
        raise RuntimeError("shifted parameter gained attribution or blocked the unchanged path")

    for name, count in (("cycle", 1), ("cycle-reverse", 1), ("cycle-nested", 2)):
        cycle = capture(directory, name)
        edges = connected(cycle)
        if (len(edges) != count or cycle["decompile_attempts"] != count + 1 or
                fields(cycle) != {(0, 4), (16, 4)}):
            raise RuntimeError(f"{name} produced a cycle or lost evidence, got {edges} and {fields(cycle)}")

    redirected = capture(directory, "redirected")
    if len(connected(redirected)) != 1 or fields(redirected) or redirected["observations"]:
        raise RuntimeError("redirected second hop contributed layout evidence")

    return {"language_id": language, "chain_deepest_hop": len(deepest["forwarded_calls"]),
            "diamond_decompile_attempts": diamond["decompile_attempts"],
            "diamond_paths": len(second_hop), "diamond_observations": len(diamond["observations"]),
            "shifted_input_excluded": True, "cycle_excluded": True, "overridden_hop_excluded": True}


def verify(args: argparse.Namespace) -> None:
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    summary = output / "report.json"
    summary.unlink(missing_ok=True)
    launcher = args.ghidra.resolve() / "support" / "analyzeHeadless"
    fixture = PROJECT / "binaryrat/corpus/fixtures/layout_paths.c"
    scripts = ";".join(map(str, (PROJECT / "binaryrat/bridge/ghidra_scripts",
                                 PROJECT / "binaryrat/corpus/ghidra_scripts")))
    log = output / "ghidra.log"

    with tempfile.TemporaryDirectory(prefix="layout paths ", dir=output) as working:
        directory = Path(working)
        binary = directory / "layout_paths"
        subprocess.run([args.cc, "-g", "-O0", "-fpie", "-pie", "-nostdlib",
                        "-Wl,-e,fixture_entry,--no-dynamic-linker,--export-dynamic",
                        "-o", str(binary), str(fixture)], check=True, timeout=60)
        subprocess.run([args.strip, "--strip-all", str(binary)], check=True, timeout=60)
        with binary.open("rb") as executable:
            header = executable.read(20)
        machine = int.from_bytes(header[18:20], "little")
        if header[:6] != b"\x7fELF\x02\x01" or machine not in LANGUAGES:
            raise RuntimeError("expected a little-endian x86-64 or AArch64 ELF fixture")
        language = LANGUAGES[machine]

        command = [str(launcher), working, "fixture", "-import", str(binary),
                   "-scriptPath", scripts, "-readOnly", "-deleteProject"]

        def recover(name: str, function: str, depth: int) -> None:
            command.extend(["-postScript", "BinaryRatRecoverLayouts.java",
                            str(directory / f"{name}.json"), f"name:{function}", "0", "15", str(depth)])

        for depth in range(5):
            recover(f"chain-{depth}", "layout_start", depth)
        recover("deep-limited", "layout_deeper", 3)
        recover("deepest", "layout_deeper", 4)
        recover("diamond", "layout_diamond", 4)
        recover("shifted", "layout_shift", 4)
        recover("cycle", "layout_cycle_a", 4)
        recover("cycle-reverse", "layout_cycle_b", 4)
        recover("cycle-nested", "layout_cycle_entry", 4)
        recover("fanout-limit", "layout_fanout", 2)
        recover("attempt-limit", "layout_broad", 2)
        recover("invalid-depth", "layout_start", 5)
        command.extend(["-postScript", "BinaryRatOverrideLayoutCallFixture.java",
                        "layout_middle", "layout_leaf", "layout_alternate"])
        recover("redirected", "layout_top", 3)

        environment = os.environ | {"BINARYRAT_ENGINE": str(args.engine.resolve()),
                                    "XDG_CONFIG_HOME": str(directory / "config"),
                                    "XDG_CACHE_HOME": str(directory / "cache")}
        measured = measured_run(command, log, args.timeout, environment)
        log_text = log.read_text(encoding="utf-8", errors="replace")
        if measured["returncode"] or "BINARYRAT_LAYOUT_CALL_OVERRIDE_SET" not in log_text:
            raise RuntimeError(f"Ghidra verification did not complete (see {log})")
        limits = {
            "fanout-limit": "exceeds the four direct-callee layout limit",
            "attempt-limit": "exceeds the decompilation attempt limit",
            "invalid-depth": "follow depth must be between 0 and 4",
        }
        for name, diagnostic in limits.items():
            if (directory / f"{name}.json").exists() or diagnostic not in log_text:
                raise RuntimeError(f"{name} did not fail closed (see {log})")
        if list(directory.glob(".binaryrat-layout-*")):
            raise RuntimeError("layout extraction left a temporary workspace")
        report = check_results(directory, language)
        report["limits_rejected"] = list(limits)

    summary.write_text(json.dumps(report | {"passed": True}, indent=2) + "\n", encoding="utf-8")
    print(f"Passed interprocedural layout verification for {report['language_id']} in {summary}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ghidra", required=True, type=Path)
    parser.add_argument("--engine", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--strip", default="strip")
    parser.add_argument("--timeout", default=180, type=int)
    verify(parser.parse_args())


if __name__ == "__main__":
    main()
