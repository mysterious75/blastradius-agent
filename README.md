> [!WARNING]
> **Legal Disclaimer — Authorized Use Only**
>
> BlastRadius Agent is designed exclusively for:
> - Security research on systems you OWN
> - Authorized penetration testing with WRITTEN permission
> - Scanning your own repositories and codebases
> - Academic and educational research in isolated environments
>
> **Unauthorized use against systems you do not own or have explicit
> written permission to test is ILLEGAL** under the Computer Fraud and
> Abuse Act (CFAA), UK Computer Misuse Act, India IT Act 2000, and
> equivalent laws worldwide.
>
> The authors assume NO liability for misuse. By using this tool,
> you agree to comply with all applicable laws and regulations.
> Use responsibly. Hack ethically.

See [DISCLAIMER.md](DISCLAIMER.md) for the full legal terms and
[SECURITY.md](SECURITY.md) for reporting and disclosure policies.

# BlastRadius Agent

Autonomous security engineer: **scan → prove exploitability → patch → verify →
report**, powered by the existing **Prometheus** scanners (imported and wrapped
as CAI `function_tool`s — the scanners themselves are never modified).

## Quick start (5 commands)

```bash
cd blastradius-agent

# 1. Install (no CAI needed for scanning/tests; add cai-framework for the agent)
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -e .[dev]                             # or: make setup

# 2. Run the tests (no network / Docker / API keys required)
python -m pytest tests -q

# 3. Scan a repo (local path or GitHub URL) and write disclosure reports
python -m blastradius.hunter --target ./path/to/repo

# 4. Map dependency blast radius
python -m blastradius.blast_radius --repo ./path/to/repo

# 5. Run everything end-to-end through the pipeline
python -m blastradius.pipeline_cli --target ./path/to/repo
```

## CLI commands

| Command | What it does |
|---|---|
| `python -m blastradius.hunter --target <url\|path>` | Clone (URL) + scan repo, sandbox-validate, save disclosure reports for confirmed-exploitable findings |
| `python -m blastradius.hunter` | Same, default target = `targets.py[0]` (WebGoat) |
| `python -m blastradius.blast_radius --repo <path>` | Parse dependencies and print blast radius ("Package X v1.2 affects N repos") |
| `python -m blastradius.pipeline_cli --target <url\|path>` | Run the full pipeline end-to-end (scan → exploit → patch → report) |
| `uvicorn blastradius.github_app.webhook:app --reload` | GitHub App webhook server (`/webhook`, `/health`) |
| `python test_agent.py "Scan ... for SQL injection"` | Run the CAI master agent (needs cai-framework + `OPENCODE_API_KEY`) |
| `make setup` | venv + `cai-framework` + deps |
| `make test` | `pytest tests/ -v` |
| `make scan TARGET=https://github.com/org/repo` | CVE hunter |
| `make blast REPO=./path` | Blast radius |
| `make server` | uvicorn webhook (hot reload) |
| `make docker` | Build `blastradius-sandbox` image |

## Architecture

```
┌────────────────────────────────────────────────────────────────────────────┐
│                     ENTRY POINTS                                           │
│   CLI (hunter / blast_radius / pipeline)      FastAPI webhook (GitHub App) │
└──────────────┬───────────────────────────────┬─────────────────────────────┘
               │                                │  X-Hub-Signature-256 verified
               ▼                                ▼
┌──────────────────────────────  FullPipeline (blastradius/pipeline.py) ─────┐
│  validate target ─► CVEHunter (clone + static scan, conf ≥ 0.7)            │
│  ─► sandbox exploit check ─► PatchLoop (generate → verify → retry ×3)      │
│  ─► DisclosureReport + SummaryReporter ─► reports/                         │
│  ─► BlastRadiusGraph (package → repo)                                       │
└──────┬───────────────────────┬──────────────────────────┬──────────────────┘
       ▼                       ▼                          ▼
┌─────────────┐        ┌─────────────────┐        ┌──────────────────┐
│  Prometheus │        │ SandboxRunner    │        │ BlastRadiusGraph │
│  scanners   │        │ docker --network │        │ Neo4j / in-memory│
│  (56 total) │        │ none --read-only │        │ requirements.txt │
│  sqli/xss/  │        │ --memory --runsc │        │ package.json     │
│  ssrf/advers│        │ (local fallback) │        │ go.mod / Pipfile │
└─────────────┘        └─────────────────┘        └──────────────────┘
        ▲                       ▲
        └── CAI function_tools (prometheus_wrappers, sandbox_tool, patch_tool)
```

## Environment variables

| Variable | Purpose | Default |
|---|---|---|
| `OPENCODE_API_KEY` | LLM key for patch generation + agent (OpenCode DeepSeek V4 Flash) | — |
| `OPENCODE_BASE_URL` | LLM chat-completions endpoint | `https://opencode.ai/zen/go/v1/chat/completions` |
| `OPENCODE_MODEL` | LLM model | `deepseek-v4-flash` |
| `CAI_MODEL` | Model for the CAI agent | `deepseek-v4-flash` |
| `CAI_LICENSE_OFF` | Run CAI without an Alias license | `1` |
| `PROMETHEUS_ROOT` | Prometheus repo root (parent of its `src/` package) | `../prometheus` |
| `AUTH_TOKEN` | Pass-through for Prometheus's scanner auth gate | — |
| `GITHUB_WEBHOOK_SECRET` | HMAC secret for webhook signatures | — |
| `GITHUB_TOKEN` | Token for posting PR comments | — (dry-run without) |
| `NEO4J_URI` / `NEO4J_USER` / `NEO4J_PASSWORD` | Blast-radius graph DB | `bolt://localhost:7687` / `neo4j` / — |
| `BLASTRADIUS_ALLOWED_ROOTS` | Allowed dirs for local repo paths (`os.pathsep`-separated) | system temp dir + cwd |
| `SANDBOX_TIMEOUT` / `SANDBOX_MEMORY_LIMIT_MB` | Sandbox limits | `10` / `128` |

## Components

| Module | Purpose |
|---|---|
| `blastradius/tools/` | CAI tools: `prometheus_sqli/xss/ssrf_scan`, `prometheus_adversarial_validate`, `run_exploit_sandbox`, `generate_and_verify_patch` |
| `blastradius/sandbox/` | `SandboxRunner` (Docker + gVisor, local fallback), exploit templates, `sandbox/Dockerfile` |
| `blastradius/hunter/` | `CVEHunter` (clone + static scan), `DisclosureReport`, `targets.py`, CLI |
| `blastradius/patcher/` | `PatchGenerator` (LLM + rule fallback), `PatchVerifier` (syntax/exploit/regression), `PatchLoop` |
| `blastradius/github_app/` | FastAPI webhook + `PRCommenter` |
| `blastradius/blast_radius/` | `BlastRadiusGraph` (Neo4j/in-memory) + dependency parser + CLI |
| `blastradius/pipeline.py` | `FullPipeline` end-to-end orchestrator (progress callbacks) |
| `blastradius/reporting/` | `SummaryReporter` (per-run markdown summary) |
| `blastradius/security/` | Input validation: GitHub URLs, target code (50KB, prompt-injection), repo paths |
| `blastradius/agent.py` | CAI master agent (Phase 1) |

### Notes on the scanners

- Prometheus is a `src`-layout repo that is not pip-installed; `PROMETHEUS_ROOT`
  is added to `sys.path` and scanners are imported as `src.scanner.*`.
- Prometheus's SQLi/XSS/SSRF tools are **URL scanners** (they need a running
  target), so local repo files are scanned with static sink/source rules that
  mirror those detections; candidates are validated with Prometheus's
  `AdversarialValidator` and sandbox PoCs.
- CAI registration is lazy: tools are `function_tool`-decorated when
  `cai-framework` is installed and stay plain callables otherwise — the whole
  test suite runs without CAI.

## Blueprint phase mapping

| Phase | Blueprint weeks | Delivered |
|---|---|---|
| 1 — Foundation | 1–3 | CAI tools wrapping the 4 key Prometheus scanners + master agent |
| 2 — Exploit sandbox | 4–5 | `SandboxRunner`, exploit templates, `run_exploit_sandbox` |
| 3 — CVE hunt | 6–8 | `CVEHunter`, disclosure reports, hunter CLI |
| 4 — Patch + verify | 9–11 | `PatchGenerator`/`PatchVerifier`/`PatchLoop`, `generate_and_verify_patch` |
| 5 — GitHub App + blast radius | 12–16 | FastAPI webhook, `PRCommenter`, `BlastRadiusGraph` + CLI |
| 6 — Integration + hardening | — | `FullPipeline`, `SummaryReporter`, input validation, Makefile |

Blueprint code samples were corrected against the real APIs: the import path
is `src.scanner.sqli` (not `prometheus.scanners.sql_injection`); the entry
point is `SQLiScanner(rps=..., timeout=...).scan_url(url, params)` (not
`SQLiScanner(url, method=...).run()`); exploits are rendered from auditable
templates; and the LLM endpoint is the OpenCode DeepSeek V4 Flash
`/chat/completions` URL (provider `@ai-sdk/openai-compatible`).

## Security & safety

- Authorized testing only. The agent never auto-merges patches — everything is
  flagged for human review.
- Sandbox: no network egress, read-only FS, memory cap, gVisor runtime (when
  available); local fallback is for trusted CI code only.
- Input hardening: GitHub URLs are host/private-IP/path-traversal checked;
  target code is capped at 50KB and scanned for prompt-injection patterns
  before ever reaching an LLM; local repo paths must resolve inside
  `BLASTRADIUS_ALLOWED_ROOTS`.
- Disclosure reports are research artifacts: a live exploit must be confirmed
  manually and coordinated with maintainers before any public disclosure.
