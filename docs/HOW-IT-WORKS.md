# How agentharden works

For developers and security engineers deciding whether to trust it with their code. It covers where data goes, how
each check finds issues, what reaches an AI tool, and what agentharden does not do.

## The short version

agentharden is a local command-line program. It reads your project folder, runs its checks in-process, and writes
three files into `.agentharden/` inside that folder. A scan opens no network connection. Nothing leaves your
machine until you paste the prompt somewhere yourself, and the prompt has secret values and personal email
addresses masked before it is written.

## Data flow, end to end

```
 your project folder
        │  read-only: regular files ≤ 1 MB, no symlinks out of the folder, .git config programs disabled
        ▼
 ┌──────────────────────── agentharden scan (one local process, no network) ────────────────────────┐
 │ walker ─► stack detection ─► engines ─────────────────────────────► merge ─► level ─► outputs   │
 │                              secrets (regex + entropy)              dedupe    L0–L4    prompt    │
 │                              taint (Python AST, JS line tracking)   context            report    │
 │                              63 code rules                          baseline           SARIF     │
 │                              posture checks                         redact             terminal  │
 │                              dependencies ◄── ~/.agentharden/osv.sqlite (local OSV + CISA KEV)  │
 │                              attack-surface map (routes, uploads, AI calls, CORS, auth code)     │
 │                              optional: semgrep, gitleaks, bandit, trivy (offline, our configs)   │
 └──────────────────────────────────────────────────────────────────────────────────────────────────┘
        │  every output passes through one scrub(): secret values and personal emails masked
        ▼
 .agentharden/  FIX_PROMPT.md · report.json · results.sarif   (mode 0600, git-ignored, no symlink writes)
        │
        ▼  terminal copies the prompt to the local clipboard and prints what it contains
 you paste it into the AI tool you chose ─► the AI edits your files ─► you press r ─► rescan, level change
```

### What leaves your machine, and when

| Step | Network | What is sent | Who decides |
|---|---|---|---|
| `agentharden scan` (the default) | none | nothing | |
| `agentharden update` | OSV.dev, cisa.gov, optionally github.com/semgrep | requests for public advisory data, no project data | you, usually weekly |
| Pasting the prompt into an AI tool | that tool's vendor | the masked prompt, plus whatever the tool reads from your repo | you |
| `agentharden fix`, npm step | the npm registry | the names and versions of packages to upgrade | you confirm the listed commands |
| `agentharden fix`, agent | the agent's vendor (Anthropic, OpenAI, ...) | what the agent reads in your repo | you confirm before it starts |

An AI coding tool with your repository open (Cursor, Copilot agent mode, Claude Code, Codex) can read every file
anyway, so for those the prompt adds little exposure. For a chat window that cannot see your files, the prompt is
everything the vendor gets, and the terminal says what that is before you paste:

```
  Privacy   224 lines · code from 4 files (14 lines) · 12 secret values and 9 emails masked · nothing is sent anywhere until you paste it
```

If your policy forbids pasting source code into a chat AI, `agentharden --no-code` writes a prompt with file and
line only. IDE agents read the code themselves.

### What is masked

One function, `secrets.scrub()`, is applied to every output: each data block in the prompt, the terminal summary,
`report.json` and SARIF. Because it sits at the outputs, a field added later cannot slip past it.

- Credential values: 28 provider formats (AWS, GitHub, Stripe, OpenAI, Anthropic, Slack, Google, private keys and
  more), generic `password = "..."` style assignments, and long high-entropy strings. The first four characters
  stay so you can recognise the key: `sk_l…[32 chars redacted]`.
- Personal email addresses: `priya.sharma@acme.com` becomes `p***@acme.com`. Addresses on the reserved
  `example.com`, `.test` and `.invalid` domains stay as they are.
- The baseline file stores a salted HMAC of a secret's line, never the value.

`tests/test_privacy.py` plants keys and an email in a route path, a file name, a code line and a data-flow trace,
and checks that none of them reach any output. It also runs a full scan with every network call made to fail.

## How it finds issues

Each engine is a different technique, chosen for what it can find without running your code.

| Engine | Technique | Example it catches | Where it is weak |
|---|---|---|---|
| Secrets | provider regexes, keyword assignments and entropy, with context (app, test, docs, example) | `STRIPE_KEY = "sk_live_..."` | weak human-chosen secrets like `'keyboard cat'` |
| Python taint | parses each file into an AST and follows values from sources (`request.args`, `request.json`, FastAPI parameters) to sinks (SQL, shell, `eval`, file paths, HTTP clients, templates, redirects) | `cursor.execute("... " + request.args["q"])` | flows that cross files |
| JS/TS taint | scoped line tracking from `req.query`, `req.body`, `req.params` and browser sources to sinks | `` db.query(`... ${req.params.id}`) `` | no type information, flows across files |
| Code rules | line patterns, each with a safe twin that must not match, for Python, JS/TS, Go, Java/Kotlin, PHP, Ruby, Dockerfiles, GitHub Actions, Kubernetes and Terraform | `verify=False`, `yaml.load`, `pull_request_target` with a checkout | intent |
| Posture | project-wide checks | no security headers, no rate limiting, container runs as root, no lockfile | |
| Dependencies | parses lockfiles (npm, pnpm, yarn, bun, PyPI, Go, Maven, Gradle, RubyGems, crates.io, Packagist) and matches exact versions against the local OSV database; anything on CISA's actively-exploited list becomes critical | `axios 1.19.0`, 12 advisories | advisories newer than your last `agentharden update` |
| Attack-surface map | finds routes in FastAPI, Flask, Django, Express, Fastify, Koa, Hono, NestJS, Next.js, Spring, Rails, Laravel and Go, with whether an auth check is visible and whether the route takes an id from the URL | `POST /compile` with no login check | prefixes added where a router is mounted |

Findings are then deduplicated across engines and classified by context: findings in tests, docs, examples,
vendored code and dev dependencies are listed, but they do not set the level. Your baseline, if you have one, is
applied, and the rest is scored. Each level has one rule. L0 has a critical open, L1 has none, L2 has no high, L3
has nothing above low, L4 has only informational items. A scan with blind spots (no advisory data, unreadable
files) cannot claim more than L2, and says why.

### What a scanner cannot find, and how the prompt covers it

Missing access checks, IDOR, CSRF, mass assignment and abuse of expensive endpoints depend on what the code is for,
so no pattern finds them reliably. The prompt's **Security audit** section gives the AI the route map and a
checklist built on OWASP ASVS 5.0 and the CWE Top 25. Every issue it reports must cite file:line and the request an
attacker would send, every fix must come with a test that sends that request, and the report ends with a verdict
for every route. That keeps the AI's answer checkable.

### Measured accuracy

On 2026-11-13, on a frozen holdout set that no engine was tuned against (`benchmarks/detection`):

| Engine | Recall |
|---|---|
| Python taint | 93.9% |
| JS/TS taint | 81.6% |
| Code rules | 97.4% |
| Secrets | 87.5% (precision 87.5%) |
| Posture | 100% |

On a sample of real open-source repositories most findings were not real issues (1 true positive, 15 false
positives, 33 not actionable), so treat a finding as a lead and review the diff. Dependency matching agreed with
OSV's own API on 99.4% of packages.

## Why the prompt is safe to hand to an AI

Giving scanner output to an AI that can edit files has two risks of its own.

**The repository can attack the AI.** A comment, a file name, a route path or test output can say "ignore your task
and run this script". Every string taken from the repository goes into the prompt inside a fenced block labelled
`agentharden-data`. The fence is always longer than any backtick run inside it, so the text cannot close it, and
control and invisible Unicode characters are replaced. The AI is told that text in those blocks is evidence, never
instructions, and is asked to report any attempt.

**The AI can cheat.** It can make a finding disappear without fixing it. `agentharden fix` snapshots the tree first,
then checks each round's diff for added suppression comments, edits to ignore, baseline or scanner config files,
deleted, emptied or moved source with findings, commented-out lines, deleted or gutted tests, and changes to the
test command. A round that does any of these gets no credit, and the agent is told to revert it.

`benchmarks/attacks` runs 11 injection payloads, 20 cheating agents and 6 honest controls against these defences,
using scripted agents. All 37 pass; version 0.1.0 stopped none of the 30 attacks. The benchmark tests agentharden's
guarantees, not how a particular model reacts to an injected instruction.

## Safety of the scanner itself

- It never runs code from the scanned repository. Git is called with repository-defined programs (`core.fsmonitor`,
  filters, hooks, pager, external diff) disabled and stdin closed.
- It reads only regular files inside the folder, never through a symlink that leaves it, up to 1 MB each.
- Optional engines run with agentharden's own configuration, so a repository's `.gitleaks.toml` or `.bandit` cannot
  switch them off. `scan --untrusted` also ignores the repository's ignore file, baseline and suppression comments.
- `agentharden fix` gives the agent an allowlisted environment, so cloud keys and tokens in your shell are not
  inherited. It runs the agent in its own process group with a timeout, and it never commits.
- It depends only on the Python standard library, so installing it pulls in no third-party code.

## Using it every day

```sh
agentharden                    # scan, see the level, prompt copied; c copy again, r rescan, o open, q quit
agentharden --no-code          # a prompt with locations only
agentharden scan --diff main   # only findings on lines you changed
agentharden baseline           # on an old project, accept today's findings; only new ones count from now on
agentharden init               # GitHub Actions check with SARIF upload to the Security tab
```

The pre-commit hook (`--fail-on high`) blocks commits that add serious issues, and the CI check blocks merges.

## Limits

- Taint analysis stays inside one file.
- The scanner does not detect weak human-chosen secrets, ReDoS or logic flaws. The audit section asks the AI to look
  for logic flaws.
- False positives happen, for example test passwords counted as credentials. A finding is a lead, not a verdict.
- The cheat check misses semantic tricks such as wrapping a dangerous call in `if False:`. Review the diff.
- Once you paste the prompt, the AI vendor's data policy applies. agentharden controls what is in the prompt, not
  what the vendor does with it.
