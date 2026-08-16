# AGENTS.md — for coding agents working in this repo

BlastRadius Agent is an autonomous security engineer: it scans codebases for
vulnerabilities, **proves** exploitability by executing a PoC in a sandbox,
generates **patches**, and **re-verifies** them. It never claims a finding
without an execution marker (`[VULNERABLE]`) — anything unproven is reported
as a *candidate*.

## Core loop

```
scan (static, 8+ vuln types / 11 languages)
  -> prove (sandbox PoC, gVisor/Docker, fail-closed)
  -> patch (PatchLoop: generate -> verify x3 checks -> retry x3)
  -> verify (ast.parse + exploit re-run + pytest regression)
  -> report (Markdown disclosure / SARIF / dashboard / SQLite)
```

## Commands

```bash
python -m blastradius.hunter --target <url|path>        # scan + sandbox-validate + report
python -m blastradius.pipeline_cli --target <url|path>  # full end-to-end pipeline
python -m blastradius.review --target <path>            # LLM review gate (CONFIRMED/REJECTED, fail-closed)
python -m blastradius.recon --strategy all              # target discovery
python -m blastradius.blast_radius --repo ./path        # dependency blast-radius map
python -m blastradius.dashboard                         # local dashboard :8080
python -m blastradius.cli.wizard                        # provider/notification setup
scripts/pr_scan.py --repo . --base origin/main          # PR diff-scoped scan (GitHub Action)
python benchmarks/run.py --verify                       # reproducible benchmark
python -m pytest tests/ -q                              # 428 tests, offline
```

## Architecture map

- `blastradius/hunter/` — CVEHunter: repo clone, static scan, findings
- `blastradius/scanners/` — 6 self-contained regex scanners + cache + parallel
- `blastradius/sandbox/` — SandboxRunner: docker `--network none --read-only`
  (gVisor runsc), **fail-closed**: unsandboxed local execution is opt-in only
- `blastradius/patcher/` — PatchLoop / PatchVerifier (3 checks, needs_human gate)
- `blastradius/providers/` — 15 LLM providers, auto-select, rate limit, cost
- `blastradius/db/` — SQLite persistence + dedup; `blastradius/learning/` —
  self-improving scanner (learned FP rules)
- `blastradius/dashboard/`, `blastradius/api/` — local UI + REST API (Bearer auth)
- `blastradius/mcp/` — MCP stdio server (7 tools)
- `blastradius/github_app/` — webhook + PR commenter; `scripts/pr_scan.py` —
  PR scan used by the `pr-security-scan` GitHub Action

## Guardrails (do not bypass)

- **Authorized use only** — scan targets the user owns or has written
  permission to test (see DISCLAIMER.md).
- **Sandbox is fail-closed** — never "confirm" a finding without the
  `[VULNERABLE]` execution marker; candidates must stay labeled candidates.
- **Scope registry** — `blastradius scope` default-deny for URL targets.
- **Tests** — keep them offline and mock-free where possible; run
  `python -m pytest tests/ -q` before finishing any change.

## Benchmark

`benchmarks/` contains a ground-truth corpus + runner. Before/after any
scanner change run `python benchmarks/run.py --verify` and make sure the
numbers don't regress (CI enforces an F1 gate).
