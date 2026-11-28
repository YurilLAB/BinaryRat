"""CI must run every BinaryRat check, and run it in a way that a flaky network or one
failing verifier cannot hide.

These tests read the workflow files and the source tree: a new verifier, test folder
or native test that CI does not run fails here before it can silently go unchecked.

SPDX-License-Identifier: Apache-2.0
Copyright 2026 YurilLAB. New BinaryRat tests.
"""
from fnmatch import fnmatch
from pathlib import Path
import re
import subprocess
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]
BINARYRAT = ROOT / "binaryrat"
WORKFLOWS = ROOT / ".github/workflows"
OWN_WORKFLOWS = sorted(WORKFLOWS.glob("binaryrat*.yml"))
MAIN = WORKFLOWS / "binaryrat.yml"
# Entry points CI deliberately does not run, with the reason.
MANUAL = {
    "profile_auto_analysis.py": "samples a whole-program run for local evidence; its parser has unit tests",
}


def load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def steps(workflow: dict):
    for job_name, job in workflow["jobs"].items():
        for index, step in enumerate(job.get("steps", [])):
            yield job_name, index, step


def label(step: dict) -> str:
    return step.get("name") or step.get("uses") or step.get("run", "").splitlines()[0]


def run_text() -> str:
    return "\n".join(step.get("run", "") for path in OWN_WORKFLOWS for _, _, step in steps(load(path)))


def tracked(pattern: str) -> list[Path]:
    """Committed files only: builds leave copies such as binaryrat/python/build/lib."""
    names = subprocess.run(["git", "ls-files", "-z", "--", pattern], cwd=ROOT, check=True,
                           capture_output=True).stdout.decode().split("\0")
    return sorted(ROOT / name for name in names if name)


def entry_points() -> list[Path]:
    """Every runnable BinaryRat Python script outside the test files."""
    found = []
    for path in tracked("binaryrat/**.py"):
        if path.name.startswith("test_") or "tests" in path.parts:
            continue
        # Package commands are checked by test_every_package_command_has_tests.
        if path.is_relative_to(BINARYRAT / "python/src"):
            continue
        if 'if __name__ == "__main__"' in path.read_text(encoding="utf-8", errors="replace"):
            found.append(path)
    return found


def discover_calls(text: str) -> list[tuple[list[str], str]]:
    """(folders, file pattern) of every `unittest discover` call in a step's command."""
    calls = []
    for line in text.splitlines():
        match = re.search(r"unittest discover -s (\S+)(?: -p ['\"]?([^'\"\s]+))?", line)
        if match:
            calls.append(([match.group(1)], match.group(2) or "test*.py"))
    for body in re.findall(r"\[([^\[\]]*\"discover\"[^\[\]]*)\]", text):
        folder = re.search(r'"-s",\s*("[^"]+"|\w+)', body).group(1)
        pattern = re.search(r'"-p",\s*"([^"]+)"', body)
        if folder.startswith('"'):
            folders = [folder.strip('"')]
        else:
            loop = re.search(rf"for {folder} in \(([^)]*)\)", text)
            folders = re.findall(r'"([^"]+)"', loop.group(1))
        calls.append((folders, pattern.group(1) if pattern else "test*.py"))
    return calls


class CoverageTests(unittest.TestCase):
    def test_hosted_parity_checks_require_the_multi_worker_path(self):
        verify = load(MAIN)["jobs"]["verify"]["steps"]
        for name in ("Verify exact stock output on the pinned LLVM 19 large-binary sample",
                     "Stock versus BinaryRat Ghidra integration and benchmark evidence"):
            step, = [step for step in verify if step.get("name") == name]
            with self.subTest(step=name):
                self.assertEqual(step.get("env", {}).get("BINARYRAT_REQUIRE_VERIFIED_OVERLAP"), "1")

    def test_proof_backend_is_required_in_verify_jobs(self):
        verify = load(MAIN)["jobs"]["verify"]["steps"]
        for name in ("Python API and live native-client tests",
                     "Exercise the live Python API and local JVM service"):
            step, = [step for step in verify if step.get("name") == name]
            with self.subTest(step=name):
                self.assertEqual(step.get("env", {}).get("BINARYRAT_REQUIRE_Z3"), "1")

    def test_live_suites_run_in_stock_and_packaged_ghidra(self):
        suites = [p.name for p in tracked("binaryrat/python/tests/test_live*.py")]
        self.assertIn("test_live_instruction_pcode.py", suites)
        for job, step_name in (
            ("verify", "Exercise the live Python API and local JVM service"),
            ("build-ghidra-source", "Run bundle tooling and required shared Python service tests"),
        ):
            step, = [s for job_name, _, s in steps(load(MAIN))
                     if job_name == job and s.get("name") == step_name]
            patterns = [pattern for folders, pattern in discover_calls(step["run"])
                        if "binaryrat/python/tests" in folders]
            with self.subTest(job=job):
                self.assertEqual([suite for suite in suites
                                  if not any(fnmatch(suite, pattern) for pattern in patterns)], [])

    def test_every_entry_point_runs_in_ci(self):
        """Reached means named in a workflow command, or in a script CI already runs."""
        scripts = entry_points()
        self.assertGreater(len(scripts), 20)
        texts = {path: path.read_text(encoding="utf-8", errors="replace") for path in scripts}
        reached, frontier = set(), [run_text()]
        while frontier:
            text = frontier.pop()
            for path in scripts:
                if path not in reached and re.search(rf"\b{re.escape(path.stem)}\b", text):
                    reached.add(path)
                    frontier.append(texts[path])
        unreached = [str(p.relative_to(ROOT)) for p in scripts if p not in reached and p.name not in MANUAL]
        self.assertEqual(unreached, [], "add these to .github/workflows/binaryrat.yml or to MANUAL")
        for name in MANUAL:
            self.assertTrue(any(p.name == name for p in scripts), f"stale MANUAL entry {name}")

    def test_every_package_command_has_tests(self):
        """Each `binaryrat-*` command module is exercised by the discovered package tests."""
        project = (BINARYRAT / "python/pyproject.toml").read_text(encoding="utf-8")
        section = project.split("[project.scripts]", 1)[1].split("\n[", 1)[0]
        modules = re.findall(r'=\s*"binaryrat\.(\w+):main"', section)
        self.assertGreaterEqual(len(modules), 4)
        tests = [path.read_text(encoding="utf-8") for path in tracked("binaryrat/python/tests/test_*.py")]
        for module in modules:
            self.assertTrue(any(re.search(rf"\b{module}\b", text) for text in tests), module)
        mains = [p.stem for p in tracked("binaryrat/python/src/**.py")
                 if 'if __name__ == "__main__"' in p.read_text(encoding="utf-8")]
        self.assertEqual(sorted(set(mains) - set(modules)), [], "runnable modules missing from [project.scripts]")

    def test_every_python_test_folder_is_discovered(self):
        discovered: dict[str, list[str]] = {}
        for path in OWN_WORKFLOWS:
            for _, _, step in steps(load(path)):
                for folders, pattern in discover_calls(step.get("run", "")):
                    for folder in folders:
                        discovered.setdefault(folder.rstrip("/"), []).append(pattern)
        missing = []
        tests = tracked("binaryrat/**/test_*.py")
        self.assertGreater(len(tests), 20)
        for test in tests:
            if test.parent == BINARYRAT / "native/tests":
                continue
            folder = test.parent.relative_to(ROOT).as_posix()
            if not any(fnmatch(test.name, pattern) for pattern in discovered.get(folder, [])):
                missing.append(test.relative_to(ROOT).as_posix())
        self.assertEqual(missing, [], "no unittest discover step runs these")

    def test_every_native_test_is_registered_with_ctest(self):
        cmake = (BINARYRAT / "CMakeLists.txt").read_text(encoding="utf-8")
        listed = set(re.search(r"set\(native_tests ([^)]*)\)", cmake).group(1).split())
        listed |= set(re.findall(r"list\(APPEND native_tests (\w+)\)", cmake))
        tests = BINARYRAT / "native/tests"
        for source in tests.glob("*_test.cpp"):
            self.assertIn(source.stem.removesuffix("_test"), listed, source.name)
        for script in tests.glob("*.py"):
            self.assertRegex(cmake, rf"add_test\(NAME native\.\w+ COMMAND [^\n]*\n?[^\n]*{script.name}",
                             script.name)


class ReliabilityTests(unittest.TestCase):
    def test_third_party_actions_are_pinned_to_full_commits(self):
        for path in OWN_WORKFLOWS:
            for job, _, step in steps(load(path)):
                uses = step.get("uses")
                if uses and not uses.startswith("./"):
                    self.assertRegex(uses, r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$", f"{path.name} {job}")

    def test_every_job_and_command_has_a_timeout(self):
        """A hang fails in its own step within minutes instead of using the job's limit."""
        for path in OWN_WORKFLOWS:
            workflow = load(path)
            for job_name, job in workflow["jobs"].items():
                self.assertIn("timeout-minutes", job, f"{path.name} job {job_name}")
            if path != MAIN:
                continue
            for job_name, _, step in steps(workflow):
                if "run" in step:
                    self.assertIn("timeout-minutes", step, f"{job_name}: {label(step)}")
                    self.assertLessEqual(step["timeout-minutes"], workflow["jobs"][job_name]["timeout-minutes"])

    def test_one_failing_check_does_not_skip_the_others(self):
        """After the setup steps, each check runs unless setup or a check it reads failed."""
        for job_name, job in load(MAIN)["jobs"].items():
            ids = [step.get("id") for step in job.get("steps", [])]
            if "ready" not in ids:
                self.assertEqual(job_name, "commits")
                continue
            for step in job["steps"][ids.index("ready") + 1:]:
                if step.get("uses", "").startswith("actions/upload-artifact@"):
                    continue
                condition = step.get("if", "")
                self.assertIn("!cancelled()", condition, f"{job_name}: {label(step)}")
                self.assertRegex(condition, r"steps\.\w+\.outcome == 'success'", f"{job_name}: {label(step)}")
                for needed in re.findall(r"steps\.(\w+)\.outcome", condition):
                    self.assertIn(needed, ids[:job["steps"].index(step)], f"{job_name}: {label(step)}")

    def test_downloads_are_hash_pinned_and_retried(self):
        text = run_text()
        for tool in ("curl", "wget", "Invoke-WebRequest", "urlretrieve"):
            self.assertNotRegex(text, rf"\b{tool}\b", "download through binaryrat/tools/pinned_download.py")
        for line in text.splitlines():
            if "apt-get" in line and ("update" in line or "install" in line):
                self.assertIn("Acquire::Retries", line)
        for path in OWN_WORKFLOWS:
            for _, _, step in steps(load(path)):
                self.assertFalse(step.get("uses", "").startswith("actions/setup-java@"),
                                 "CI must use the bundle's JDK from binaryrat/tools/install_jdk.py")

    def test_gradle_distribution_is_fetched_with_retries_before_first_use(self):
        for job_name, job in load(MAIN)["jobs"].items():
            first_gradle = warm = None
            for index, step in enumerate(job.get("steps", [])):
                text = step.get("run", "")
                if "retry_command.py" in text and "gradlew" in text and warm is None:
                    warm = index
                elif "gradlew" in text and first_gradle is None:
                    first_gradle = index
            if first_gradle is not None:
                self.assertIsNotNone(warm, job_name)
                self.assertLess(warm, first_gradle, job_name)


if __name__ == "__main__":
    unittest.main()
