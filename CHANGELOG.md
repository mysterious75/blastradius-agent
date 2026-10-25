# Changelog

All notable changes to BlastRadius Agent are documented here.

## [Unreleased]

### Changed
- Name-only taint is now restricted to strong source names (`payload`,
  `user_input`, `userInput`, `untrusted`, `tainted`, `attacker`). Generic
  helper names (`host`, `url`, `data`, `path`, `filename`) require an
  assignment-chain source. Removed the certbot/Celery classes of false
  positives; `tests/test_taint_refinement.py` encodes the new contract.
- Task workflow is mandatory in `AGENTS.md`: read `PROJECT_RULES.md`, copy
  `CHECKLIST.md`, add unit/integration/e2e (+ adversarial, + many-users, +
  bounded-time where relevant), run the full suite and quality gate, then
  attack the change with `scripts/self_attack.py`. `make check` runs the
  suite plus quick self-attack.

### Fixed
- Static scan could hang on a large top-level data module: pip's
  `_vendor/idna/uts46data.py` (16.9k lines) took ~920 s because
  `_find_func_start` rescanned upward for every sink on every line (O(nÂ²),
  853M regex calls under cProfile). It now uses a per-thread prefix index
  keyed by list identity, and `_scan_file` skips taint refinement when a
  rule already scored 0. The file scans in ~3 s; all 432 pip files in 27 s.
  Guards: `tests/test_scan_performance.py`,
  `tests/test_scan_concurrency.py` (8 threads, no cache bleed).
- Real-world false-positive classes (source substring matches, literal/
  read-only DOM writes, config/numeric CRLF values, `string.Template` and
  `Template(loader=)` as SSTI, `Object.prototype` reads, `sendfile` as path
  traversal, routing-helper-only IDOR) are fixed and covered by
  `tests/test_real_world_fp_regressions.py`; the 20-repo study dropped from
  182 to 24 candidates (docs/REAL-WORLD-STUDY.md).
- Self-attack cases shared the real `~/.blastradius` cache/learned-rules
  store, making verdicts order-dependent (Windows 3.12 returned rc=0 on the
  prompt-injection case twice). Each case now gets a private
  `BLASTRADIUS_HOME` and fixed `PYTHONHASHSEED`; full run 10/10 HELD.
- Release tests expected a 2-version CI matrix and the moving
  `pypa/...@release/v1` tag; both were updated for the 3.13 matrix and
  SHA-pinned actions.
- `pip-audit` on an editable install refused to audit the unpublished
  project itself; CI now audits a frozen `pip freeze --exclude-editable`
  snapshot.
- Verified PR gate now fails closed when `--base`/`--baseline-ref` does not
  resolve: previously the ref lookup fell back to a full scan and could exit
  0; it now raises and exits 2 (`test_e2e_invalid_base_ref_fails_closed`).
- Unicode paths no longer cause a fail-open: `git diff` quotes non-ASCII
  filenames (`"\303\251vil.py"`), so diff-scoping dropped the finding and
  merged. Fixed with `-z` + `core.quotePath=false`, and UTF-8 decoding for
  every git subprocess (non-UTF8 console could crash the diff collector).
  Regression: `test_unicode_filename_diff_is_not_fail_open`; the self-attack
  `unicode-filename` case now blocks.
- Quality gate no longer ignores untracked files (new files bypassed the
  tier/secret checks locally) and its secret scan had lost the patch diff;
  both restored and covered by
  `test_untracked_files_are_scanned_not_fail_open`.

### Added
- `CHECKLIST.md` (copy into every task/PR) and `docs/REAL-WORLD-STUDY.md`
  (method, 182 â†’ 24 result, fixed FP classes, performance defect, limits).
- 17 real-world FP regression tests, 4 performance tests, and 2
  multi-user scanner tests; suite now **1206 passed, 1 skipped**.
- Launch-readiness program: `docs/library/MANIFEST.md` (22 free/official
  standards, NIST/OWASP/CISA/OpenSSF + DeFi sources), `READING-NOTES.md`
  (control-by-control mapping), and `docs/LAUNCH-READINESS.md` (verdict,
  evidence, P0/P1/P2 gaps, claim matrix). Re-fetch with
  `python scripts/fetch_reference_library.py`; raw files stay local.
- CI hardening: `pip-audit --local --strict` job, Python **3.13** in the
  test matrix, Windows test job, coverage gate **60% â†’ 80%** (measured 85%),
  and every GitHub Actions `uses:` pinned to a commit SHA.
- Supply-chain/image hygiene: `.dockerignore`, non-root `USER` + healthcheck
  in the main Dockerfile.
- README proof-scope callout: static 19/12 vs Python-first executed proof.
- Enforced project rules: `PROJECT_RULES.md` (non-negotiables, unit +
  integration + e2e pyramid, Definition of Done), `docs/SELF-ATTACK.md`
  (attacker personas, hostile-input matrix, concurrent-user isolation), and
  `scripts/quality_gate.py` (lint, test-reference, tier markers, high-signal
  secrets, untracked files, JSON/checklist output, exit 0/1/2).
- `scripts/self_attack.py`: attacks the gate with unicode paths, huge lines,
  binary-only and prompt-injection diffs, missing base refs, and N concurrent
  PRs with per-repo canaries (own/foreign leak detection), `--quick`/`--full`,
  `--json`, `--keep`; wired into `.github/workflows/quality-gate.yml`.

- Real-GitHub beta validation of the Verified PR gate (4 draft PRs on a
  disposable branch, all closed, `main` untouched): vulnerableâ†’BLOCK,
  proven-fix-pushedâ†’PASS, weak-patchâ†’BLOCK via bypass-variant confirm,
  cleanâ†’PASS, multi-findingâ†’BLOCK with gate math, secrets redacted in
  comment/logs, branch protection showing BLOCKED vs CLEAN. Real runs
  exposed and fixed three bugs: missing-PyYAML crash in SARIF enrichment
  (now degrades gracefully), `security-severity` must be a JSON string for
  code scanning, and `gh` needs explicit `GH_TOKEN` in Actions (status now
  targets the PR head SHA).
- Content-based gate correction: a confirmed finding present in the diff
  BLOCKS even when a verified fix exists â€” a scratch-tree fix proves the
  patch, never the PR (same rule Semgrep/Snyk enforce). Blocking entries
  carry `fix_verified` so reviewers see proven patches; KEV blocks on any
  match.
- Bypass-variant confirmation: when the canonical PoC is dead but a
  mutated variant still reaches the real sink, the finding confirms via
  the bypass battery (weak-fix blind spot closed), with method + evidence
  recorded (`real-code` / `bypass-variant` / `synthetic`).
- Diff-scoped scanning for PR-scale performance: `scan_repo(only_files=â€¦)`
  (per-file-identical results, equality-tested). Measured on django (906
  eligible files): 2-file PR end-to-end 355.5s â†’ 52.3s (6.8x), peak RSS
  51â†’45 MB. Real hostile-PR run (15 MB file, prompt injection, binary,
  fixture password) completes correctly with secrets absent everywhere.
- True cross-owner fork PR validated on runners: gate `BLOCK`/exit 1,
  status post degraded with HTTP 403, comment 403 under
  `continue-on-error`, verdict unaffected (read-only token by design).
- Large-repo measured: 10,001 eligible synthetic files â€” full scan 30.6s
  (327 files/s), diff-scoped PR gate 34.1s, peak RSS â‰¤60 MB.
- Replay coverage widened: instance methods with trivial constructors,
  `staticmethod`/`classmethod`, and an inert `if __name__ == "__main__"`
  guard (proven not executed). Unsupported shapes/languages still fail
  closed as `INCONCLUSIVE` â†’ `UNVERIFIABLE`.
- KEV annotation corrected to say what it is: a **category** signal
  (CWE/keyword), capped at 5 CVEs, explicitly "not this exact code" â€” in
  both the Verified PR comment and `pr_scan` output.
- BlastRadius Verified PR gate (`blastradius/verified_pr/`,
  `python -m blastradius.verified_pr`): closes the scanâ†’proveâ†’patch loop with
  **re-testing** â€” each generated patch is applied to a scratch copy of the
  real tree (original never modified) and verified at two evidence levels:
  exploit replay (real payloads executed against the real patched function:
  canonical PoC + mutated bypass battery + benign check) with static rescan
  as a labeled weaker fallback. Only FIXED findings are excused, so the gate
  is fail-closed. Adds a manifest-level dependency-impact diff (base vs head),
  KEV blocking limited to findings without a verified fix, Markdown/JSON/
  SARIF artifacts, optional verdict notifications and GitHub commit status
  (`blastradius/verified-pr`), `.github/workflows/verified-pr.yml`,
  `bitbucket-pipelines.yml`, and `docs/verified-pr.md`.
- CI gate hardening audit fixes (`blastradius/ci/`):
  - missing optional AI credentials now degrade visibly to deterministic-only
    mode (warning in stdout + report) instead of ANALYSIS_ERROR, via a new
    `LLMProvider.is_configured()`; genuine configured-provider failures stay
    fail-closed. Dropped warnings are now threaded into reports (they were
    silently lost).
  - secret-shaped values are redacted locally before the AI request is built
    (structure preserved); identifier-glued names (`db_password`,
    `my_api_key`) are now caught.
  - AI findings are mechanically grounded against the ChangeSet (real changed
    file + real added line required); hallucinated evidence is dropped and a
    reply with zero usable findings is an analysis error.
  - partial malformed AI output yields warnings, not analysis errors, while
    fully unusable responses remain errors.
  - no-execution regression test locks in that the gate never runs PR code
    (verified: scanners are pure pattern matching).
- CI security & quality gate (`blastradius/ci/` + `blastradius ci review|gate`):
  provider-neutral PR pipeline (diff â†’ deterministic analyzers reusing
  `blastradius.scanners` + optional Claude review via `AnthropicAdapter`)
  â†’ normalized findings â†’ deterministic policy engine (only PASS/FAIL
  decider) â†’ JSON + Markdown reports + optional Slack/Teams/email
  notifications. Exit 0 = PASS, 1 = POLICY_FAILURE, 2 = ANALYSIS_ERROR.
  Includes `blastradius-ci.example.yml` policy, SHA-pinned GitHub Actions
  template (`.github/workflows/ci-review.yml`), Bitbucket Pipelines template,
  local PASS/FAIL demo fixtures, and `docs/ci-gate.md`.
- Optional Zhipu GLM provider (`zhipu` in `blastradius/providers/registry.py`):
  OpenAI-compatible BigModel endpoint with `ZHIPU_API_KEY`; default provider
  selection is unchanged and no network is used without a key.
- Local staged-disclosure packages (`blastradius/hunter/disclosure.py`):
  impact-first HackerOne-style drafts with numbered reproduction steps,
  severity/CWE metadata, sanitized evidence manifest, pre-submit checklist,
  and local-only status tracking. Staging redacts cookies, bearer tokens,
  and email addresses, rejects theoretical language/placeholders, and never
  submits a report.
- Broader lending-market coverage (`blastradius/contagion/loaders/collateral.py`):
  comma-separated/multi-project DeFiLlama filters plus canonical protocol
  labels (`sparklend` â†’ SparkLend, `compound-v2/v3` â†’ Compound, Aave/Morpho aliases).
  Backstop configuration now supports Base/Arbitrum/Optimism RPC endpoints and
  requires `verified_by` provenance for non-Ethereum sources; no unverified
  cross-chain addresses are included.
- Fail-closed SBOM verification (`scripts/verify_release.py`): offline CycloneDX
  structure validation (format/spec/root identity/components/purls/duplicates)
  with optional `--require-sbom-components`; the release workflow now verifies
  distributions and the generated SBOM before attaching artifacts.
- CI hygiene: `blast-check` now triggers only on the audited KelpDAO seed
  files (not every `data/**` change), so unrelated data updates cannot trip
  the known-critical seed gate.
- Network-service scanner (`blastradius/net/`): Tsunami-style plugin foundation â€”
  bounded TCP connect with mandatory connect/read timeouts, read-first banner grab
  plus one light service probe per port, Nmap-style banner fingerprinting, and
  service-filtered detectors (cleartext FTP/Telnet, anonymous FTP via a read-only
  no-password probe, missing SMTP STARTTLS). SSH is fingerprinted but never
  probed; no brute force, no exploit payloads. `python -m blastradius.net`
  requires `--scope` for any non-lab target. Dynamic benchmark gains the
  `live-netservices` target (11/11 at F1 1.000).
- Live GraphQL checks (`blastradius/web/graphql.py`, opt-in `--graphql-probe`):
  endpoint discovery via the universal `__typename` probe, then read-only
  introspection, field-suggestion (Clairvoyance pattern), and alias-batching
  (10 aliased `__typename` fields â€” the rate-limit-bypass primitive) checks,
  plus an offline sensitive-resolver review helper. Dynamic benchmark gains
  the `live-graphql` target (14/14 at F1 1.000).
- Live request-smuggling checks (`blastradius/web/smuggle.py`, opt-in
  `--smuggle-probe`): Kettle-ordered CL.TE timing probe then TE.CL
  differential probe over raw timeout-enforced sockets, our own connection
  only â€” no poisoning, no victim requests, no depth/DoS or H2 variants.
  Dynamic benchmark gains the `live-smuggle` target (16/16 at F1 1.000).
- Live race-condition checks (`blastradius/web/race.py`, explicit `--race-url`
  + `--race-marker`): one gated parallel burst (thread barrier, default 10,
  capped 25) at analyst-named single-use URLs, counting marker-bearing
  successes â€” the coupon double-redeem / wallet double-spend primitive
  (CWE-367). The crawler never auto-races; without a success oracle no
  finding is possible. Dynamic benchmark gains the `live-race` target with
  an   atomic twin that must stay silent (17/17 at F1 1.000).
- Live CSRF checks (`blastradius/web/csrf.py`, `--csrf-probe` passive +
  explicit `--csrf-url`/`--csrf-marker`/`--csrf-cookie` active): zero-risk
  synchronizer-token-field analysis on crawled POST forms, plus the token
  harness (missing token, garbage token, GET override, GET+_method=POST
  SameSite-Lax-bypass shape) against analyst-named URLs with a victim
  session â€” sessionless 200s never count. Dynamic benchmark gains the
  `live-csrf` target with a token-enforcing twin (20/20 at F1 1.000).
- Live MFA checks (`blastradius/web/mfa.py`, explicit `--mfa-verify-url` /
  `--mfa-dashboard-url` / `--mfa-reuse-otp` config): bounded wrong-OTP rate
  probe (default 8, cap 20 â€” wrong acceptance is broken-verification HIGH,
  silence-free K attempts is no-rate-limit MEDIUM), pre-MFA step-skip, and
  double-submit OTP reuse. HTTP error statuses surface as responses (a 429
  IS the throttle signal); transport silence never becomes a finding.
  Dynamic benchmark gains the   `live-mfa` target with a throttling twin
  (23/23 at F1 1.000).
- Fail-closed scope enforcement (`enforce_scope` in `blastradius/scope.py`):
  URL targets (and bare hostnames) with no registered `--scope` program are
  now BLOCKED instead of silently scanned â€” closing the opt-in gap across
  the hunter, web, agents, pipeline, net, and auto-hunt CLIs. Local paths
  and lab targets (loopback, RFC-2606 names, RFC-1918 LAN) stay exempt via
  the shared `is_lab_target`. The autonomous hunt CLI requires `--scope`
  unconditionally.
- Scheduled heartbeat hunt repaired: the CI `scheduled_hunt` job hunted
  random PyPI-metadata URLs (whose dead/suffixed links made git prompt for
  credentials and kill the job) with no scope. It now hunts three fixed
  deliberately-vulnerable training repos via the new explicit `--repo`
  flag (discovery skipped, each repo scope-gated) with a registered
  `ci-training` scope and `GITHUB_TOKEN` git credentials (auto-provided by
  Actions, no manual secret needed).
- Scope matching fix: entries were lowercased but target paths compared
  case-sensitively, so mixed-case repo URLs (every Hello-World style repo)
  never matched â€” `_normalize` now lowers both sides.
- Sandbox image repaired (`sandbox/Dockerfile`): it COPYied per-run PoC
  files that only exist inside the temp-dir volume mount, so the image
  could never build â€” locally or in CI, where `continue-on-error: true`
  silently hid the failure and the "sandbox proof" gate ran UNSANDBOXED.
  COPY lines removed (the mount supplies the files), PoC runtime deps
  added (jinja2, lxml, defusedxml), and the CI build step is now hard
  required instead of best-effort.
- Solidity smart-contract scanner (`blastradius/scanners/solidity.py`): Slither-aligned
  reentrancy (structural checks-effects-interactions analysis), tx.origin auth, controlled
  delegatecall, arbitrary send, weak randomness, unchecked low-level calls, unchecked ERC20
  transfers, divide-before-multiply, incorrect exponentiation, timestamp dependency,
  pre-0.8 integer overflow, unprotected upgrade, and hardcoded private keys.
- Registry: `solidity` vuln type (CWE-841) added, taking the static registry to
  **19 vuln types / 12 languages**.
- Dynamic benchmark extended to 6 live local targets (SQLi, mass assignment, cache
  poisoning added to IDOR/JWT/SSRF) â€” 7 expected / 7 reported, F1 1.000.
- Exfiltration guardrail (`blastradius/security/exfil_guard.py`): deny-by-default
  egress classification, public-host/visibility enforcement, command screening, audited
  and fail-closed.
- Shadow-repository recon (`--shadow`): contributors to public repos/Gists/releases with
  bounded, detection-only secret scoring.

## [1.0.0] - 2026-08-09

### Added
- Complete 7-phase autonomous security pipeline (scan â†’ prove â†’ patch â†’ verify â†’ report â†’ disclose)
- 10 vulnerability types (SQLi, XSS, SSRF, SSTI, XXE, IDOR, JWT, GraphQL, Path Traversal, Command Injection)
- 15 LLM provider support with auto-selection and fallback chain
- Docker sandbox with gVisor isolation

## [Unreleased]
### Fixed
- Vuln-type registry count corrected to 18 (SQLi, XSS, SSRF, IDOR, SSTI, XXE, JWT, GraphQL, secret, secret_history, deserialization, cmd_injection, traversal, crlf, auth_bypass, nosqli, proto_pollution, ci_injection); added missing `secret` display title
- `pyyaml` declared in `[dev]` extras (was an undeclared test dependency)

## [1.1.0] - 2026-09-30
### Added
- Live dynamic checks in `blastradius/web/`: 2-identity IDOR/BOLA authz-diff, SSRF with OOB + redirect-follow oracle, JWT (alg:none / RS256->HS256 confusion / weak-secret / kid), A->B->C exploit-chain linking
- `--scope` scope-registry gates on all URL-accepting CLIs (hunter, web, recon, auto_hunt, agents, pipeline)
- DeFi snapshot ingestion (`contagion/loaders/snapshot.py`, `aave.py`) with PRICES/BACKS edges; `data/token_backing.json`
- Dynamic benchmark gate (`benchmarks/run_dynamic.py`, 3 live targets) wired into CI
- 61+ new tests; suite 739 passed, static benchmark F1=1.0, dynamic benchmark F1=1.0
- Web dashboard with WebSocket live progress
- MCP server for AI assistant integration (Claude, Cursor, Continue, Windsurf)
- Plugin system (Jira, Linear, CSV export)
- Self-improvement learning loop (false-positive reduction over time)
- Notification system (Slack, Discord, Telegram, Email, GitHub issues)
- Scheduled auto-hunt via GitHub Actions
- REST API with API-key auth
- SARIF / CSV / JSON / HTML / Markdown finding export
- Unified `blastradius` CLI with rich output
- Parallel scanning with file-content caching

