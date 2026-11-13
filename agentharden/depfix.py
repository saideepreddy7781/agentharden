"""Dependency upgrades that `agentharden fix` runs itself, before the agent's first round.

An agent cannot finish a dependency task by editing files. Claude Code in acceptEdits mode may not run commands,
and every lockfile entry carries the integrity hash the registry publishes, so a hand-edited lockfile fails
`npm ci`. agentharden therefore runs the package manager for the agent.

What runs, and why it is safe on a repository you do not trust:
- npm only, for a package-lock.json or npm-shrinkwrap.json with a package.json beside it.
- `npm install` (direct dependencies) and `npm update` (transitive ones), both with `--package-lock-only
  --ignore-scripts --no-audit --no-fund`. npm reads version metadata from the registry and rewrites package.json
  and the lockfile. It downloads no package tarballs, runs no lifecycle scripts and leaves node_modules alone, so
  no code from a package or from the repository runs.
- Skipped when a .npmrc sits in the lockfile's folder or any folder above it inside the repository: a project
  .npmrc can point npm at another registry or name programs npm runs (`git`, `script-shell`). Also skipped when
  package.json has git, URL or path dependencies, which npm fetches with git.
- Only upgrades within the installed major version (within the minor for 0.x). A major upgrade can break the
  app, so it stays a task for the agent and for you.
- Package names and versions are checked against strict patterns before they reach the command line. npm comes
  from PATH and is refused if it resolves to a file inside the repository.
- npm gets the test command's reduced environment (no tokens). A private registry needs its variables listed in
  AGENTHARDEN_PASS_ENV, and its .npmrc means this step is skipped anyway.
"""
from __future__ import annotations

import json
import os
import re
import shutil
from dataclasses import dataclass, field

from .deps import _semver_key

LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json")
FLAGS = ["--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"]
TIMEOUT = 300
_NAME = re.compile(r"^(?:@[A-Za-z0-9][A-Za-z0-9._~-]*/)?[A-Za-z0-9][A-Za-z0-9._~-]*$")
_VERSION = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$")
_RANGE_SPEC = re.compile(r"^[\^~]?\d+(?:\.(?:\d+|x|\*))*(?:-[0-9A-Za-z.-]+)?$")
_DEP_FIELDS = ("dependencies", "devDependencies", "optionalDependencies")


@dataclass
class Step:
    folder: str              # repo-relative folder npm runs in, "" for the root
    args: list               # npm arguments, without the npm executable
    packages: list = field(default_factory=list)  # (name, from version, minimum fixed version)

    def shown(self) -> str:
        where = f"cd {self.folder} && " if self.folder else ""
        return where + "npm " + " ".join(self.args)


@dataclass
class Skipped:
    package: str
    version: str
    file: str
    reason: str


def _same_line(version: str, fixed: str) -> bool:
    a, b = _semver_key(version), _semver_key(fixed)
    if a is None or b is None:
        return False
    a, b = a[0], b[0]
    if a[0] != b[0]:
        return False
    return a[0] != 0 or (len(a) > 1 and len(b) > 1 and a[1] == b[1])


def _read_json(path: str):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _npmrc_between(root: str, folder: str) -> str:
    """Repo-relative path of the first .npmrc from `folder` up to the root, or ""."""
    parts = folder.split("/") if folder else []
    for i in range(len(parts), -1, -1):
        rel = "/".join(parts[:i] + [".npmrc"])
        if os.path.lexists(os.path.join(root, *rel.split("/"))):
            return rel
    return ""


def _fetched_with_git(pkg: dict) -> str:
    """Name of the first dependency npm would fetch with git, from a URL or from a path, or ""."""
    for fld in _DEP_FIELDS:
        section = pkg.get(fld)
        if not isinstance(section, dict):
            continue
        for name, spec in section.items():
            if not isinstance(spec, str):
                return str(name)
            s = spec.strip()
            if s.startswith("npm:") or s in ("", "*", "latest", "x"):
                continue
            if re.match(r"^(git[+:]|github:|gitlab:|bitbucket:|gist:|https?:|file:|link:|\.{0,2}/|~/)", s) or \
                    re.match(r"^[\w.-]+/[\w.-]+(#.*)?$", s):
                return str(name)
    return ""


def npm_path(root: str, env: dict) -> str | None:
    """npm from PATH, or None if it is missing or lives inside the repository."""
    found = shutil.which("npm", path=env.get("PATH"))
    if not found:
        return None
    real, top = os.path.realpath(found), os.path.realpath(root)
    if real == top or real.startswith(top + os.sep):
        return None
    return found


def plan(root: str, findings: list) -> tuple:
    """(steps, skipped) for the dependency findings agentharden can upgrade itself. Pass counted, in-scope ones."""
    groups = {}
    skipped = []
    for f in findings:
        if f.category != "dependency":
            continue
        ex = f.extra or {}
        name, version, fixed = str(ex.get("package", "")), str(ex.get("version", "")), str(ex.get("fixed_in") or "")
        lock = f.file.replace("\\", "/")
        folder, _, base = lock.rpartition("/")
        if ex.get("ecosystem") != "npm" or base not in LOCKFILES:
            skipped.append(Skipped(name, version, lock, "only npm lockfiles are upgraded automatically"))
        elif not fixed:
            skipped.append(Skipped(name, version, lock, "no fixed version is published"))
        elif not (_NAME.match(name) and _VERSION.match(version) and _VERSION.match(fixed)):
            skipped.append(Skipped(name, version, lock, "the package name or version has an unexpected form"))
        elif not _same_line(version, fixed):
            skipped.append(Skipped(name, version, lock,
                                   f"the fix needs a major upgrade ({version} → {fixed}), which can break the app"))
        else:
            groups.setdefault(folder, []).append((f, name, version, fixed))

    steps = []
    for folder in sorted(groups):
        items = groups[folder]
        pkg = _read_json(os.path.join(root, *(folder.split("/") if folder else []), "package.json"))
        if not isinstance(pkg, dict):
            reason = "there is no readable package.json beside the lockfile"
        else:
            npmrc, git_dep = _npmrc_between(root, folder), _fetched_with_git(pkg)
            reason = (f"{npmrc} can change where npm downloads from and which programs it runs" if npmrc else
                      f"package.json fetches `{git_dep}` with git or from a path" if git_dep else "")
        if reason:
            skipped.extend(Skipped(n, v, f.file, reason) for f, n, v, _ in items)
            continue
        declared = {}
        for fld in _DEP_FIELDS:
            section = pkg.get(fld)
            for n, spec in (section.items() if isinstance(section, dict) else ()):
                declared.setdefault(n, spec)
        ranged, exact, nested = [], [], []
        for f, n, v, fixed in items:
            spec = declared.get(n)
            if (f.extra or {}).get("dependency") != "direct":
                nested.append((n, v, fixed))
            elif not isinstance(spec, str):
                skipped.append(Skipped(n, v, f.file, "installed under another name (an npm alias)"))
            elif not _RANGE_SPEC.match(spec.strip()):
                skipped.append(Skipped(n, v, f.file, f"package.json asks for `{spec}`, which agentharden does not "
                                                     "rewrite"))
            elif spec.strip()[0].isdigit():
                exact.append((n, v, fixed))
            else:
                ranged.append((n, v, fixed, "~" if spec.strip().startswith("~") else "^"))
        if ranged:
            steps.append(Step(folder, ["install", *FLAGS, *(f"{n}@{p}{fx}" for n, _, fx, p in ranged)],
                              [(n, v, fx) for n, v, fx, _ in ranged]))
        if exact:
            steps.append(Step(folder, ["install", *FLAGS, "--save-exact", *(f"{n}@{fx}" for n, _, fx in exact)],
                              exact))
        if nested:
            steps.append(Step(folder, ["update", *FLAGS, *sorted({n for n, _, _ in nested})], nested))
    return steps, skipped


def run(root: str, steps: list, npm: str, env: dict, spawn, redact, say) -> list:
    """Run the steps with `spawn` (fix._spawn). Returns the steps that failed."""
    failed = []
    for step in steps:
        cwd = os.path.join(root, *(step.folder.split("/") if step.folder else []))
        say(f"  $ {step.shown()}")
        try:
            rc, out, timed_out = spawn([npm, *step.args], cwd, env, None, TIMEOUT, capture=True)
        except OSError as exc:
            rc, out, timed_out = 127, str(exc), False
        if rc == 0 and not timed_out:
            continue
        failed.append(step)
        why = f"did not finish within {TIMEOUT}s" if timed_out else f"failed (exit code {rc})"
        say(f"    npm {why}:")
        for line in redact(out).strip().splitlines()[-12:]:
            say("      " + line[:300])
    return failed
