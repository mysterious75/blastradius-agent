# BlastRadius Verified PR

One closed loop over a pull-request diff:

```
scan (diff-scoped, baseline-aware)
  -> prove (sandbox PoC, [VULNERABLE] marker or it stays a candidate)
  -> patch (PatchLoop: generate -> verify x3 -> retry x3)
  -> re-test (patch applied to a scratch copy of the real tree, same scanners)
  -> dependency impact (manifest diff base vs head)
  -> verdict MERGE (0) / BLOCK (1) / ERROR (2)
```

## Why re-test

A patch that passes checks on an isolated snippet can still fail when
applied to the real file (wrong context, shifted lines, second sink). The
re-test applies each generated patch to a throwaway copy of the repository
(the original is never modified) and verifies it at two evidence levels.

### Level 1 — exploit replay (strongest, `method="exploit-replay"`)

The sandbox PoC templates only need a callable named `target`. Replay
harnesses the **real** patched function (AST-extracted, aliased to `target`)
and executes against it:

1. the canonical exploit payloads (same oracle as the confirm step —
   tandem fairness: identical inputs, identical detector, pre vs post);
2. a fixed **bypass battery** of mutated variants (XBOW-style: a fix that
   only blocks the exact original payload must still be caught — e.g. a
   quote-doubling fix falls to the double-quote variant);
3. a benign input (`"alice"`) that must still work (regression).

`FIXED` requires all three. Pre-patch, the same replay runs against the
original code: a `[VULNERABLE]` run proves the real code — not a synthetic
reconstruction — is genuinely exploitable (reported as `real_poc: true`).

Replay scope is deliberately narrow and deterministic: Python files whose
flagged line sits in a module-level function with a side-effect-free top
level (imports, defs, constant assignments). Anything else is
`INCONCLUSIVE` by construction — and `INCONCLUSIVE` never becomes `FIXED`.
A harness that cannot load, or benign behavior that breaks, also yields
`INCONCLUSIVE` (fail-closed), never a pass.

### Level 2 — static rescan (weaker, `method="static-rescan"`)

Fallback when replay is inapplicable or inconclusive: the same scanners run
over the patched tree (this is the whole of Snyk Agent Fix / Mobb / Pixee
verification). `FIXED` here means only scanner silence — labeled as such so
nobody mistakes it for exploit evidence.

The gate judges PR **content** and is fail-closed: a confirmed finding
present in the diff BLOCKS — even when a verified fix exists. A fix proven
on a scratch tree is evidence the *patch* works (handed to reviewers and
the autofix flow: apply it to the PR, re-run, merge), never evidence the
*PR* is safe. Only code actually in the diff can unblock — the same rule
Semgrep, Snyk, and CodeRabbit enforce (a suggestion is not a fix).

### Oracle semantics (known limits, documented not hidden)

- sqli treats raised exceptions as signal (error-based detection). A patch
  that *breaks* execution therefore reads as STILL_VULNERABLE — the safe
  direction, with the exception text preserved in evidence.
- The bypass battery is context-honest: only payloads executable in the
  sink context are included (no `javascript:`-URL payload for an HTML-body
  sink, where reflection is inert, not exploitable).
- Line-surgical rule patches (single-line allowlist/escape rewrites) skip
  snippet-level PatchLoop retries — a bare line has no standalone function
  to execute, so retries are pure waste. Their verdict comes from re-test,
  and `needs_human` stays visible in the report.

## Usage

```bash
python -m blastradius.verified_pr --repo . --base origin/main \
    --baseline-ref origin/main --fail-on high --out verified-pr
```

Artifacts in `--out`:

- `verified-comment.md` — PR comment body (verdict, findings, re-test, impact)
- `verified-results.json` — machine-readable summary
- `verified.sarif` — SARIF 2.1.0 for code scanning (when confirmed findings exist)

Flags: `--kev-file/--epss-online/--fail-on-kev` (KEV blocks only KEV-matched
findings **without** a verified fix), `--no-retest` (reduces to a scan gate),
`--notify` (Slack/Teams/email verdict via configured channels),
`--post-status` (GitHub commit status `blastradius/verified-pr` for branch
protection).

## CI wiring

- GitHub: `.github/workflows/verified-pr.yml` (reusable pattern: checkout
  full history, run module, upload SARIF, comment). Require the
  `blastradius/verified-pr` status in branch protection for merge blocking.
  It composes with the existing `pr-security-scan` + autofix flow: autofix
  opens fix PRs, Verified PR re-tests and gates.
- Bitbucket: `bitbucket-pipelines.yml` at the repo root (merge the
  `verified-pr` step into your pipeline; the step exit code is the gate).

## Real-GitHub validation (beta, Oct 2026)

Validated end-to-end on real pull requests against a test branch (4 draft
PRs, all closed, branches deleted, `main` untouched):

| PR | Fixture | Gate | Observed |
|---|---|---|---|
| vuln sqli | introduced sqli | BLOCK exit 1 | failed check, `blastradius/verified-pr: failure` status, BLOCK comment with real-code proof |
| same PR + proven fix pushed | fix in diff | PASS exit 0 | success status **on the head SHA**, MERGE comment ("No new candidate findings") |
| weak quote-doubling | variant-alive fix | BLOCK exit 1 | confirmed **via bypass-variant** on runners, BLOCK comment |
| clean | benign code | PASS exit 0 | MERGE comment |
| multi (sqli + xss + fixture passwords) | 2 findings | BLOCK exit 1 | `blocking=2`, comment contains **zero** secret occurrences, `[REDACTED]` present; run logs likewise clean |

Branch protection requiring `verified` + `blastradius/verified-pr` was
temporarily enabled on the test branch: the failing PR read **BLOCKED**
(unmergeable), the fixed PR read **CLEAN**. SARIF uploads ingest cleanly
into code scanning (`verified-pr.yml:verified` analyses recorded).

Real runs caught three bugs local CI could not (runners install `.[all]`
without PyYAML, and exercise the real APIs):

1. SARIF enrichment crashed on missing `yaml` (`attack_map.py`) — gate
   exited 2 after writing artifacts (fail-closed, but wrong code and no
   status post). Fixed with graceful degradation + regression test.
2. Code scanning rejected our SARIF: `security-severity` must be a JSON
   **string** (`"9.0"`), not a number — server error "expected string".
3. `gh` inside Actions ignores `GITHUB_TOKEN` unless `GH_TOKEN` is set —
   the status post silently never happened. Workflow now sets it, and the
   status targets the PR **head SHA** (`BLASTRADIUS_STATUS_SHA`) so
   protection evaluates it on the head commit.

## Performance (measured, not claimed)

`scan_repo` accepts `only_files`: the pipeline scans **only the diff**
when one exists (identical per-file findings — locked by an equality
test), falling back to a full scan without a diff. The re-test pre/post
scans are scoped the same way.

Measured on django (shallow clone, 7,084 files, **906 eligible**):

| Metric | Before | After |
|---|---|---|
| Full `scan_repo` (906 files) | 104–111s (~8.5 files/s) | unchanged (fallback path) |
| 2-file PR with 1 sqli, end-to-end | **355.5s** | **52.3s (6.8x)** |
| Peak RSS, same run | 51 MB | 45 MB |

Runtime scales with **diff size, not repo size**: the ~50s is sandbox
spawns + PatchLoop/pytest + replay runs (per-finding, bounded), not the
900 untouched files. A 10k-eligible-file repo would take ~20 min
full-scan (projection, not measured) but a typical small PR stays near
~1 min. Memory is a non-issue (<60 MB observed).

## Fork-PR model

Same-repo branches run with the declared token; **fork PRs** get
GitHub-enforced read-only tokens and no secrets (official model — the
workflow never uses `pull_request_target`). Posture:

- 4 minimal scopes (`contents:read`, `pull-requests:write`,
  `security-events:write`, `statuses:write`); only 3 optional LLM secrets
  + `GITHUB_TOKEN` referenced; nothing else.
- Comment/SARIF posts are `continue-on-error`; the status post is
  try-wrapped; the gate verdict comes from the process exit code only —
  so a denied write degrades the extras, never the verdict.
- Proven live with a hostile PR (15 MB single-line file, prompt-injection
  comment, binary, unicode filename, fixture password): the run
  completed in 82s with the correct BLOCK; the injection file was honestly
  downgraded to synthetic-confirm + static-rescan (never real-code); the
  fixture password appears **zero** times in comments and logs.

UNVERIFIED: a true cross-account fork PR (single test identity, no orgs
available to fork into) — the fork path above is enforced by GitHub's
platform, reviewed statically, and unit-tested for graceful denial, but
no live fork run exists yet.

## Honest limits

- Manifest-level dependency impact only (added/removed/upgraded) — no
  reachability claims (unlike Endor/Semgrep Pro).
- Single-repo diff scope; cross-repo blast radius stays in
  `python -m blastradius.blast_radius`.
- Rule-based patches without LLM keys often cannot be applied in-file, so
  those findings stay UNVERIFIABLE and block — by design.
