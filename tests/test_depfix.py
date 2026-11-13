"""`agentharden fix` upgrading vulnerable npm packages itself, before the agent runs."""
import builtins
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

from agentharden import depfix, fix
from agentharden.models import Finding, ScanResult

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_safety import POSIX, agent_script, git, make_repo  # noqa: E402


def dep(name, version, fixed, file="web/package-lock.json", kind="direct", eco="npm", severity="critical"):
    return Finding(rule_id=f"DEP-{eco}", title=f"{name}@{version}: 1 known vulnerability", severity=severity,
                   category="dependency", file=file,
                   extra={"package": name, "version": version, "ecosystem": eco, "fixed_in": fixed,
                          "dependency": kind})


def pkg_json(deps=None, dev=None):
    return json.dumps({"name": "web", "dependencies": deps or {}, "devDependencies": dev or {}})


class PlanTest(unittest.TestCase):
    def repo(self, files):
        root = Path(tempfile.mkdtemp())
        for name, text in files.items():
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_text(text)
        return str(root)

    def test_direct_range_install_and_transitive_update(self):
        root = self.repo({"web/package.json": pkg_json({"axios": "^1.6.0", "lodash": "~4.17.0"})})
        steps, skipped = depfix.plan(root, [dep("axios", "1.19.0", "1.20.0"), dep("lodash", "4.17.20", "4.17.21"),
                                            dep("follow-redirects", "1.16.0", "1.16.2", kind="transitive")])
        self.assertEqual(skipped, [])
        self.assertEqual([s.args for s in steps], [
            ["install", *depfix.FLAGS, "axios@^1.20.0", "lodash@~4.17.21"],
            ["update", *depfix.FLAGS, "follow-redirects"]])
        self.assertTrue(all(s.folder == "web" for s in steps))
        for flag in ("--ignore-scripts", "--package-lock-only"):
            self.assertIn(flag, depfix.FLAGS)

    def test_exact_pin_stays_exact(self):
        root = self.repo({"web/package.json": pkg_json({"axios": "1.19.0"})})
        steps, _ = depfix.plan(root, [dep("axios", "1.19.0", "1.20.0")])
        self.assertEqual(steps[0].args, ["install", *depfix.FLAGS, "--save-exact", "axios@1.20.0"])

    def test_root_lockfile_runs_in_root(self):
        root = self.repo({"package.json": pkg_json({"axios": "^1.6.0"})})
        steps, _ = depfix.plan(root, [dep("axios", "1.19.0", "1.20.0", file="package-lock.json")])
        self.assertEqual(steps[0].folder, "")
        self.assertTrue(steps[0].shown().startswith("npm install"))

    def assert_skipped(self, files, finding, words):
        steps, skipped = depfix.plan(self.repo(files), [finding])
        self.assertEqual(steps, [])
        self.assertEqual(len(skipped), 1)
        self.assertIn(words, skipped[0].reason)

    def test_major_upgrade_is_left_alone(self):
        self.assert_skipped({"web/package.json": pkg_json(dev={"vite": "^5.0.0"})}, dep("vite", "5.4.21", "6.4.5"),
                            "major upgrade")
        self.assert_skipped({"web/package.json": pkg_json({"esbuild": "^0.21.0"})},
                            dep("esbuild", "0.21.5", "0.25.0", kind="transitive"), "major upgrade")

    def test_project_npmrc_blocks_the_step(self):
        for where in ("web/.npmrc", ".npmrc"):
            self.assert_skipped({"web/package.json": pkg_json({"axios": "^1.6.0"}), where: "git=./evil.sh\n"},
                                dep("axios", "1.19.0", "1.20.0"), ".npmrc")

    def test_git_and_path_dependencies_block_the_step(self):
        for spec in ("github:someone/thing", "git+https://example.invalid/x.git", "someone/thing", "file:../x",
                     "https://example.invalid/x.tgz"):
            self.assert_skipped({"web/package.json": pkg_json({"axios": "^1.6.0", "x": spec})},
                                dep("axios", "1.19.0", "1.20.0"), "with git or from a path")

    def test_hostile_names_and_versions_never_reach_npm(self):
        files = {"web/package.json": pkg_json({"axios": "^1.6.0"})}
        for name, version, fixed in (("--registry=https://evil.invalid", "1.0.0", "1.0.1"),
                                     ("axios", "1.19.0", "1.20.0 --registry=x"), ("a&calc", "1.0.0", "1.0.1"),
                                     ("axios", "1.19.0; rm -rf /", "1.20.0")):
            self.assert_skipped(files, dep(name, version, fixed, kind="transitive"), "unexpected form")

    def test_other_cases_are_skipped_with_a_reason(self):
        files = {"web/package.json": pkg_json({"my-axios": "npm:axios@^1.6.0", "pinned": "latest"})}
        self.assert_skipped(files, dep("axios", "1.19.0", "1.20.0"), "another name")
        self.assert_skipped(files, dep("pinned", "1.0.0", "1.0.1"), "does not rewrite")
        self.assert_skipped(files, dep("axios", "1.19.0", ""), "no fixed version")
        self.assert_skipped(files, dep("django", "4.2.0", "4.2.1", file="requirements.txt", eco="PyPI"),
                            "only npm")
        self.assert_skipped(files, dep("axios", "1.19.0", "1.20.0", file="web/yarn.lock"), "only npm")
        self.assert_skipped({}, dep("axios", "1.19.0", "1.20.0"), "no readable package.json")

    @unittest.skipUnless(POSIX, "uses a POSIX executable")
    def test_npm_inside_the_repo_is_refused(self):
        root = Path(self.repo({"web/package.json": "{}"}))
        bindir = root / "node_modules" / ".bin"
        bindir.mkdir(parents=True)
        (bindir / "npm").write_text("#!/bin/sh\n")
        (bindir / "npm").chmod(0o755)
        self.assertIsNone(depfix.npm_path(str(root), {"PATH": str(bindir)}))


FAKE_NPM = '''\
#!{python}
import json, os, sys
with open({log!r}, "a") as fh:
    fh.write(json.dumps({{"cwd": os.getcwd(), "argv": sys.argv[1:]}}) + "\\n")
lock = json.load(open("package-lock.json"))
lock["packages"]["node_modules/axios"]["version"] = "1.21.1"
json.dump(lock, open("package-lock.json", "w"), indent=2)
'''


@unittest.skipUnless(POSIX, "the fake npm is a POSIX script")
class FixUpgradesDepsTest(unittest.TestCase):
    def setUp(self):
        self.bindir = Path(tempfile.mkdtemp())
        self.log = self.bindir / "npm.log"
        npm = self.bindir / "npm"
        npm.write_text(FAKE_NPM.format(python=sys.executable, log=str(self.log)))
        npm.chmod(0o755)
        self._path = os.environ["PATH"]
        os.environ["PATH"] = f"{self.bindir}{os.pathsep}{self._path}"
        self._scan = fix._scan
        fix._scan = self.fake_scan

    def tearDown(self):
        os.environ["PATH"] = self._path
        fix._scan = self._scan

    @staticmethod
    def fake_scan(root, external, known):
        """Report axios as vulnerable while the lockfile still pins 1.19.0."""
        lock = json.loads((Path(root) / "web" / "package-lock.json").read_text())
        found = [dep("axios", "1.19.0", "1.20.0")] \
            if lock["packages"]["node_modules/axios"]["version"] == "1.19.0" else []
        return ScanResult(root=root, stack={}, findings=found, engines={}, files_scanned=1, duration=0.0)

    def repo(self, **extra):
        lock = {"lockfileVersion": 3, "packages": {"": {"dependencies": {"axios": "^1.6.0"}},
                                                    "node_modules/axios": {"version": "1.19.0"}}}
        return make_repo({".gitignore": ".agentharden/\n", "web/package.json": pkg_json({"axios": "^1.6.0"}),
                          "web/package-lock.json": json.dumps(lock), **extra})

    def run_fix(self, root, agent, **kw):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = fix.run(str(root), agent=agent, external=False, **{"yes": True, **kw})
        return rc, buf.getvalue()

    def calls(self):
        return [json.loads(ln) for ln in self.log.read_text().splitlines()] if self.log.exists() else []

    def marker_agent(self, root):
        marker = root.parent / f"{root.name}-agent-ran"
        return marker, agent_script(f"open({str(marker)!r}, 'w')")

    def test_npm_clears_the_finding_and_the_agent_never_starts(self):
        root = self.repo()
        marker, agent = self.marker_agent(root)
        rc, out = self.run_fix(root, agent)
        self.assertEqual(rc, 0, out)
        self.assertFalse(marker.exists(), out)
        calls = self.calls()
        self.assertEqual(len(calls), 1)
        self.assertEqual(os.path.realpath(calls[0]["cwd"]), os.path.realpath(root / "web"))
        self.assertEqual(calls[0]["argv"], ["install", *depfix.FLAGS, "axios@^1.20.0"])
        self.assertIn("axios 1.19.0: fixed", out)
        self.assertIn("cd web && npm ci", out)
        self.assertIn("agentharden/fix-", git(root, "branch", "--show-current"))
        self.assertIn("1.21.1", (root / "web" / "package-lock.json").read_text())
        self.assertNotIn("FIX_PROMPT.md", out)

    def test_no_deps_leaves_it_to_the_agent(self):
        root = self.repo()
        marker, agent = self.marker_agent(root)
        rc, out = self.run_fix(root, agent, upgrade_deps=False, branch=False)
        self.assertEqual(self.calls(), [])
        self.assertTrue(marker.exists(), out)
        self.assertEqual(rc, 1, out)

    def test_hostile_npmrc_means_npm_never_runs(self):
        root = self.repo(**{"web/.npmrc": "git=./pwn.sh\nregistry=https://evil.invalid/\n"})
        marker, agent = self.marker_agent(root)
        rc, out = self.run_fix(root, agent, branch=False)
        self.assertEqual(self.calls(), [])
        self.assertIn("Not upgraded automatically", out)
        self.assertIn(".npmrc", out)
        self.assertTrue(marker.exists(), out)

    def test_npm_failure_hands_the_task_to_the_agent(self):
        (self.bindir / "npm").write_text(f"#!{sys.executable}\nimport sys\nprint('E404 not found')\nsys.exit(1)\n")
        root = self.repo()
        seen = root.parent / f"{root.name}-prompt"
        agent = agent_script(f'''
            import pathlib, sys
            pathlib.Path({str(seen)!r}).write_text(pathlib.Path(sys.argv[1]).read_text())
        ''')
        rc, out = self.run_fix(root, agent, branch=False)
        self.assertIn("npm failed (exit code 1)", out)
        self.assertIn("E404", out)
        self.assertIn("axios", seen.read_text())
        self.assertNotIn("npm ci", out)
        self.assertEqual(rc, 1, out)

    def test_confirmation_names_the_npm_step_and_the_folder(self):
        root = self.repo()
        asked = []

        class TTY(io.StringIO):
            def isatty(self):
                return True

        real_input, real_stdin = builtins.input, sys.stdin
        builtins.input = lambda q: asked.append(q) or "n"
        sys.stdin = TTY()
        try:
            rc, out = self.run_fix(root, agent_script("pass"), yes=False)
        finally:
            builtins.input, sys.stdin = real_input, real_stdin
        self.assertEqual(rc, 1, out)
        self.assertIn("Aborted", out)
        self.assertEqual(len(asked), 1)
        self.assertIn("Run the npm commands above", asked[0])
        self.assertIn(f"edit files in {root.name}/?", asked[0])
        self.assertEqual(self.calls(), [])


if __name__ == "__main__":
    unittest.main()
