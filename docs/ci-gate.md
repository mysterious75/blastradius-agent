# BlastRadius CI Security & Quality Gate

A production-oriented, reusable gate for pull requests:

```
PR diff → deterministic analyzers (+ optional AI review)
       → normalized findings → deterministic policy → PASS/FAIL → reports
```

## The one rule that matters

**The LLM never decides PASS/FAIL.** AI findings and deterministic findings
are evaluated identically by `blastradius/ci/policy.py` against configured
severity/confidence thresholds. An unavailable or malformed AI response is an
analysis error — under the default fail-closed policy the gate fails rather
than quietly passing.

## Architecture

```mermaid
flowchart LR
    PR[PR diff / change set] --> DIFF[diff collector\nblastradius/ci/diff.py]
    DIFF --> DET[deterministic analyzers\nblastradius/ci/analyzers.py\n(reuses blastradius.scanners)]
    DIFF --> AI[optional AI review\nblastradius/ci/llm.py\nAnthropicAdapter]
    DET --> NORM[normalized findings\nblastradius/ci/models.py]
    AI --> NORM
    NORM --> POLICY[deterministic policy\nblastradius/ci/policy.py]
    POLICY --> VERDICT{PASS / POLICY_FAILURE /\nANALYSIS_ERROR}
    VERDICT --> REP[reports JSON + Markdown\nblastradius/ci/reporting.py]
    VERDICT --> NOTIFY[optional notifications\nSlack / Teams / email]
```

| Layer | Location | Notes |
|---|---|---|
| Core analysis | `blastradius/ci/{diff,analyzers,models}.py` | provider-neutral, no CI specifics |
| Provider adapters | `blastradius/ci/llm.py` (`AnthropicAdapter`, `OpenAICompatibleAdapter`) | generic `LLMProvider` interface; add OpenAI/Gemini/local adapters without touching core |
| CI adapters | `.github/workflows/ci-review.yml`, `bitbucket-pipelines.yml.example` | thin wrappers around the same core |
| Policy engine | `blastradius/ci/policy.py` + `blastradius-ci.yml` | deterministic, validated config |
| Reporting | `blastradius/ci/reporting.py` | JSON + Markdown + GitHub job summary |
| Notifications | `blastradius/ci/notify.py` + `blastradius/notify` | optional, failure-isolated |
| CLI | `blastradius ci review\|gate`, `python -m blastradius.ci` | exit 0/1/2 |

Implemented now: everything above except PR comments/check annotations
(optional, deliberately omitted to keep permissions read-only).

## Installation

```bash
pip install -e ".[dev]"   # includes pyyaml (policy files) + pytest
```

No new runtime dependencies were added: the Anthropic adapter speaks the
Messages API over stdlib `urllib` (injectable transport for tests). The
official `anthropic` SDK is *not* required; semantics match its messages
endpoint. If your environment standardizes on the SDK, wrap it in the
`LLMProvider.review()` interface — core stays untouched.

## Configuration

### Secrets (environment only, never committed)

| Variable | Required | Purpose |
|---|---|---|
| `ANTHROPIC_API_KEY` | only for AI review | Claude review; absent = deterministic-only mode |
| `BLASTRADIUS_AI_MODEL` | no | model override (falls back to `BLASTRADIUS_MODEL`) |
| `TEAMS_WEBHOOK_URL` / `SLACK_WEBHOOK_URL` / SMTP_* | no | gate notifications |

See `.env.example` for placeholders. Privacy note: the selected diff hunks
are sent to the configured LLM provider when AI review is enabled. Diffs are
size-bounded, secrets are redacted from logs/errors/reports, and deterministic
mode sends nothing anywhere.

### Policy (`blastradius-ci.yml`)

Copy `blastradius-ci.example.yml` → `blastradius-ci.yml` and adjust. Without
a policy file the built-in safe defaults apply (fail on critical/high ≥ 0.80
confidence, fail-closed on errors).

## GitHub setup

1. Copy `.github/workflows/ci-review.yml` into your repo (third-party actions
   are SHA-pinned; the pins were verified against the GitHub API).
2. Add `ANTHROPIC_API_KEY` as a repository secret for AI review (optional).
3. Add `blastradius-ci.yml` (optional — safe defaults otherwise).
4. Branch protection: Settings → Branches → Require status checks →
   select the `ci-gate` job. Failed audits then block merges.

Fork safety: the workflow uses the `pull_request` event (not
`pull_request_target`), `contents: read` only, never executes PR code, and
never comments. Fork PRs lack secrets → deterministic-only mode, still gated.

## Bitbucket setup

1. Copy `bitbucket-pipelines.yml.example` → `bitbucket-pipelines.yml`.
2. Repository settings → Repository variables: `ANTHROPIC_API_KEY` (Secured,
   optional), `BLASTRADIUS_AI_MODEL` / `CI_BASE_REF` (optional).
3. Merge gating: Repository settings → Branch permissions → require passing
   builds (Premium). Without Premium, enforce green builds by policy — see the
   template comments for the merge-check API alternative.
4. Bitbucket withholds secured variables from fork builds, so fork PRs run
   deterministic-only automatically.

Exit codes: `0` PASS · `1` POLICY_FAILURE · `2` ANALYSIS_ERROR. Any non-zero
exit fails the pipeline step.

## CLI

```bash
# Analyze only (exit 0 unless the analysis itself errors)
python -m blastradius.ci review --repo . --base origin/main --out ci-gate
blastradius ci review --diff-file change.diff --no-ai --out ci-gate

# Analyze + enforce policy (exit 0/1/2)
python -m blastradius.ci gate --repo . --base origin/main \
  --policy blastradius-ci.yml --out ci-gate --notify --run-ref "org/repo#123"
```

Useful flags: `--diff-file` (offline/tests), `--exclude` (extra path regex),
`--no-ai` (deterministic only), `--ai-provider openai-compatible`,
`--notify` (send summary to configured channels).

## Demo (local fixtures only, no network, no key)

```bash
# Vulnerable change -> POLICY_FAILURE (exit 1)
python -m blastradius.ci gate --repo demos/ci-gate \
  --diff-file demos/ci-gate/vuln.diff --policy blastradius-ci.example.yml \
  --no-ai --out /tmp/ci-vuln; echo $?

# Fixed change -> PASS (exit 0)
python -m blastradius.ci gate --repo demos/ci-gate \
  --diff-file demos/ci-gate/fixed.diff --policy blastradius-ci.example.yml \
  --no-ai --out /tmp/ci-fixed; echo $?

# Missing API key with AI enabled -> deterministic-only PASS (exit 0) with a
# visible warning. (A *configured* provider that then fails still exits 2.)
python -m blastradius.ci gate --repo demos/ci-gate \
  --diff-file demos/ci-gate/fixed.diff --out /tmp/ci-nokey; echo $?
```

Expected: `1`, `0`, `0` (with a deterministic-only warning on the third).
Nothing leaves the machine in any of these runs.

## Security model

- Repository content, comments, filenames, and PR text are **untrusted input**:
  prompts wrap diffs in `<UNTRUSTED_DIFF>` delimiters with an explicit
  instruction hierarchy, and `validate_target_code` caps/bombs prompt-injection
  patterns before anything reaches a model.
- Secret-shaped values are redacted **locally before the AI request is built**;
  the provider transport only ever sees `[REDACTED]` placeholders, with file
  headers and line numbers preserved for useful review.
- AI findings are mechanically grounded against the change set: fabricated
  files/lines are dropped, and a reply with zero usable findings is an
  analysis error — the model cannot invent evidence that triggers the gate.
- Oversized diffs, unreadable files, and malformed AI JSON are **analysis
  errors**, never silent passes (fail-closed default; `fail-open`
  requires explicit opt-in and is reported as a warning). A missing optional
  credential is NOT an error: the gate visibly degrades to deterministic-only
  mode instead.
- Findings carry `source: deterministic|ai` so triagers can tell them apart;
  CWE/OWASP are only set when evidence supports them, never fabricated.
- Reports truncate evidence (500 chars) and redact secrets; notifications
  carry summaries only, never source or credentials.
- Deterministic findings are limited to **added lines** — the gate judges the
  PR, not pre-existing code.
- The gate never executes PR code: deterministic analysis is pure pattern
  matching over source text (locked in by a regression test that runs a
  `os.system`/`eval` payload through the gate and asserts no marker file
  appears).

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Exit 2, "no diff source" | neither `--diff-file` nor git history | pass `--diff-file` or fetch full history (`fetch-depth: 0`) |
| Exit 2, "oversized change set" | PR exceeds policy budgets | split the PR, or raise limits consciously in policy |
| AI review skipped with warning | no credentials for the AI provider | expected without a key (deterministic-only); add the secret or run `--no-ai` to silence |
| Exit 2 although a key is set | provider call failed (quota, outage, bad key) | genuine failure, fail-closed by design; check provider status/quota |
| AI findings dropped with warning | model returned invalid entries | invalid entries are rejected; valid ones still evaluated |
| Gate passes but AI was down | `on_error: fail-open` in policy | intended only with risk acceptance; default is fail-closed |

## Limitations / not implemented

- PR comments and check annotations (optional; omitted to keep least privilege).
- Query-depth DoS-style AI abuse probes and H2-specific smuggling in CI scope
  (deterministic scanners cover code patterns; live behavior stays in `web/`).
- The official `anthropic` SDK is not vendored (stdlib transport instead; same
  endpoint semantics). `npm`-side or SDK-specific features are out of scope.
- Notifications support Slack/Teams/Discord/Telegram/email/GitHub-issues via
  the existing notifier; PagerDuty/Opsgenie are future work.
