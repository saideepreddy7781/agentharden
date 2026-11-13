# Changelog

## 0.5.1

- Removed the CISA Known Exploited Vulnerabilities list. `agentharden update` now downloads only from OSV.dev (and
  Semgrep's rules from GitHub when asked), and contacts no government website. Packages keep the severity their
  advisory gives them; nothing is raised to critical because of an outside list. The next `agentharden update`
  deletes CISA data left in the local database by older versions.
- A test records every URL `agentharden update` requests and checks that only OSV.dev is on the list.

## 0.5.0

Privacy of what reaches an AI tool
- Fixed: since 0.3.0 a secret inside a route path (for example `/hook/<key>`) reached `FIX_PROMPT.md` and
  `report.json` unmasked, and a secret in a file name could reach any output. Masking used to run on code snippets
  only. It now runs once on every output: each data block in the prompt, the terminal summary, `report.json` and
  SARIF, so text from any field is covered.
- Personal email addresses in quoted code are masked (`p***@acme.com`). Reserved example domains are left alone.
- After every scan the terminal prints a `Privacy` line: prompt size, how many files are quoted, how many secret
  values and emails were masked, and that nothing is sent until you paste it.
- `agentharden --no-code` writes a prompt with file and line only, for teams that may not paste code into a chat AI.
- New tests plant keys and an email in a route path, a file name, a code line and a data-flow trace and check every
  output, and run a full scan with every network call made to fail.
- New `docs/HOW-IT-WORKS.md`: the data flow end to end, what leaves the machine and when, how each engine finds
  issues, and the limits.

## 0.4.0

- Running `agentharden` in a terminal now copies the fix prompt to the clipboard by itself and keeps one-key
  options open: `c` copies it again, `r` scans again, shows the level change and copies the new prompt, `o` opens
  the prompt, and any other key quits. The loop is: run it, paste into any AI coding tool, press `r` when the AI is
  done, repeat.
- The keys appear only for a person at a terminal: not in CI, not in a pipe, not with `--fail-on`, `--strict`,
  `--json`, `--print-prompt` or `-q`, and the pre-commit hook passes `--no-copy`. Exit codes are unchanged.
- "Copied" is printed only when a clipboard tool accepted the text. agentharden tries pbcopy, wl-copy, xclip, xsel
  and clip in turn, and sends clip.exe UTF-16 so characters like `·` and `→` survive on Windows.
- The summary no longer suggests one tool by name: it says to paste the prompt into any AI coding tool, and points
  to the security audit when there are no scanner tasks.

## 0.3.0

- `FIX_PROMPT.md` now has a **Security audit** section, so the prompt you paste into any AI coding tool covers the
  flaws a scanner cannot see. It holds a map of the attack surface (routes with file, line, visible auth check and
  URL ids, plus uploads, downloads, outbound requests, AI API calls, CORS, token and password code), a checklist
  built on OWASP ASVS 5.0 and the CWE Top 25, notes for each detected framework, and rules that make every issue
  cite file:line and the attacker's request and every fix come with a test. The report ends with a verdict per route.
- Routes are found for FastAPI, Flask, Django, Express, Fastify, Koa, Hono, NestJS, Next.js (route handlers,
  `pages/api`, server actions), Spring, Rails, Laravel and Go. Browser code that calls an API is not counted as a
  route. `report.json` includes the map under `surface`.
- `agentharden scan --no-audit` leaves the section out. `agentharden fix` never includes it.
- The two display fixes in `agentharden fix` output from 0.2.1 are included.
- Attack benchmark: a new injection case puts a fence-breaking instruction in a route path. 37 of 37 pass.

## 0.2.1

- `agentharden fix` now upgrades vulnerable npm packages itself, before the agent starts. In 0.2.0 a dependency
  finding could not be fixed at all: Claude Code in `acceptEdits` mode may not run npm, and a lockfile cannot be
  edited by hand. agentharden runs `npm install` for direct dependencies and `npm update` for transitive ones,
  with `--package-lock-only --ignore-scripts --no-audit --no-fund`, so npm downloads no packages and runs no
  scripts. When that clears every in-scope finding, the agent is not started.
- The step is skipped, with the reason printed, for major upgrades, a `.npmrc` in the repo, git, URL or path
  dependencies, npm aliases, and non-npm lockfiles. Those findings go to the agent as before. `--no-deps` turns the
  step off.
- The confirm prompt names the folder ("edit files in resume-app/?") instead of printing "in .?", and says when
  npm will run.
- After an npm upgrade, `fix` prints the `npm ci` command to run, because node_modules is not touched.

## 0.2.0: first release as agentharden

The project was called `hardn` until this release. The PyPI name `hardn` and the `hardn` command belong to an
unrelated company, so the tool is now `agentharden`. Every name moved with it: the command, the Python package,
`.agentharden/` for output, `.agentharden-ignore`, `.agentharden-baseline.json`, the `agentharden:ignore` comment,
`~/.agentharden` for advisory data and `AGENTHARDEN_*` environment variables.

Safety of the fix loop
- Everything taken from the scanned repo reaches the prompt inside fenced, labelled data blocks that cannot be
  broken out of, with control and invisible characters removed. The agent is told those blocks are untrusted.
- `agentharden fix` checks each round for cheating: added suppression comments, edits to ignore, baseline and
  scanner config files, deleted or emptied source and tests, commented-out code, and changes to the test command.
  A round that cheats gets no credit, and the run fails if the cheat stays.
- Agents and tests run with an allowlisted environment, in their own process group, with timeouts.
- Repo config for Claude Code (hooks, permissions, MCP servers) is not loaded. Codex uses
  `--sandbox workspace-write` because `--full-auto` was removed in Codex 0.144.
- New `benchmarks/attacks`: 10 injection cases, 20 cheating agents and 6 legitimate controls. All 36 pass. Version
  0.1.0 stopped none of the 30 attacks.

Security of the scanner itself
- Scanning no longer runs programs named in the scanned repo's `.git/config` (`core.fsmonitor`, filters, hooks).
- Only regular files are read, never through a symlink out of the scanned folder, with bounded reads. Output files
  refuse symlinks and are written with mode 0600. Terminal output strips control sequences.
- Optional engines run with agentharden's own configuration, so a repo's `.gitleaks.toml` or `.bandit` cannot
  switch them off.
- `scan --untrusted` ignores the repo's own ignore file, baseline and suppression comments.

Honest results
- Checks that could not run are listed as blind spots on every scan and cap the level at L2. `--strict` exits 3.
  With no advisory data, 0.1.0 reported "L3 Hardened 95/100".
- Findings in tests, docs, examples, vendored code and dev dependencies are listed separately and do not set the
  level or fail CI. Secrets count everywhere, except generic sample values in docs and examples.
- The summary always shows how many findings were suppressed inline, excluded by `.agentharden-ignore` or baselined.

Detection, measured on a frozen holdout of 188 labelled cases (seed 20261110)
- Python taint recall 65.3% → 93.9%, JavaScript taint 60.5% → 81.6%, code rules 82.1% → 97.4%,
  secrets 70.8% → 87.5% with precision 58.6% → 87.5%.
- Reflected XSS, FastAPI `Annotated` parameters, import aliases, `.format` and concatenated SQL, same-file helpers.
- A committed `.env` with a provider key is found; private-key bodies are fully redacted.

Dependencies
- New lockfile support: pnpm, bun.lock, Pipfile.lock, pdm.lock, pom.xml, gradle.lockfile, go.sum, nested
  requirements files. Dev and transitive packages are marked. Severity comes from CVSS vectors.
- The suggested upgrade is the smallest version that clears every advisory.
- Exact advisory agreement with the live OSV API on 1,716 sampled packages: 92.5% → 94.2%, or 97.6% → 99.4% when
  advisories published after the local database was downloaded are left out (measured 2026-11-11).

CI and packaging
- `--diff` compares from the merge base and handles quoted and unprefixed paths. Baselines survive file moves.
- SARIF validates against the 2.1.0 schema and carries `security-severity`. The Action uploads it.
- Actions are pinned by commit SHA. Releases run only on `vX.Y.Z` tags. Dependabot is removed.
- Large repos scan about three times faster (next.js: 156 s → 48 s).

## 0.1.0: first public release as hardn (2026-10-27)

- Secrets, about 50 code rules, posture checks, offline dependency audit (OSV.dev + CISA KEV).
- Taint analysis for Python (AST) and JavaScript/TypeScript (line based).
- `FIX_PROMPT.md` scoped to the next security level; `fix` drives Claude Code, aider or Codex.
- Baselines, `--diff`, `init`, the GitHub Action, optional Semgrep, Gitleaks, Bandit and Trivy.
