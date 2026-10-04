# 🔴 BlastRadius Agent

[![CI](https://img.shields.io/github/actions/workflow/status/mysterious75/blastradius-agent/ci.yml?branch=main&label=CI)](https://github.com/mysterious75/blastradius-agent/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)
[![Release](https://img.shields.io/github/v/release/mysterious75/blastradius-agent)](https://github.com/mysterious75/blastradius-agent/releases)

> Autonomous security engineer: scan → prove → patch → verify

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

## Contents

- [What it does](#what-it-does)
- [Why BlastRadius](#why-blastradius-deterministic-validation)
- [DeFi Contagion & Config Audit](#-defi-contagion--config-audit-phase-6)
- [Installation](#installation)
- [Usage](#all-cli-commands)
- [Dynamic Web Testing](#dynamic-web-testing)
- [Benchmark](#benchmark)
- [Trust & Safety](#trust--safety)
- [Contributing](#contributing)
- [License](#license)

## What it does

BlastRadius clones repositories, statically scans them for vulnerabilities
across 19 types and 12 languages, proves exploitability in a sandboxed PoC,
auto-generates and verifies patches, and tracks the whole lifecycle — from
target discovery to CVE disclosure — in a local SQLite database with a web
dashboard, multi-channel notifications, and a self-improving scanner.

Solidity contracts are first-class: `*.sol` files are routed to a dedicated
Slither-aligned detector (`blastradius/scanners/solidity.py`) rather than the
web-shaped line scorers, covering reentrancy (structural
checks-effects-interactions analysis), `tx.origin` authorization, controlled
`delegatecall`, arbitrary-send, weak randomness, unchecked low-level calls and
ERC20 transfers, divide-before-multiply, incorrect exponentiation, timestamp
dependency, pre-0.8 integer overflow, unprotected upgrade, and hardcoded
private keys.

## Why BlastRadius: deterministic validation

LLM-based scanners produce hypotheses; BlastRadius produces **proof**.
Every finding is either executed in a sandbox (carrying the `[VULNERABLE]`
marker) or honestly labeled a *candidate* — never silently asserted.
This fail-closed discipline is enforced by tests, by the benchmark gate,
and by the patch loop, which re-runs the exploit after every fix.

## 🔴 DeFi Contagion & Config Audit (Phase 6)

Supply-chain blast radius (`blastradius/blast_radius`, Package → Repo) has an
on-chain counterpart: **`blastradius/contagion/`** — `Token → Market → Protocol → Chain`.

Two questions every deployment should answer beforehand — which no product
on the market currently does:

> **1.** *If this token fails, how much TVL, how many protocols, and how many chains go down?*
> **2.** *Can this cross-chain/protocol config survive one compromised signer?*

### Contagion graph + bad-debt simulation

```bash
# cascade map (the KelpDAO shape)
python -m blastradius.contagion map --token *** --data data/seed_kelpdao_case.json --ascii

# reachability + exposure score
python -m blastradius.contagion score --token *** --data data/seed_kelpdao_case.json

# how much bad debt liquidation cannot clear if "token -> 0"
python -m blastradius.contagion baddebt --token *** --data data/seed_kelpdao_case.json
```

The bad-debt model captures the exact mechanic that left Aave's WETH reserve
with unliquidatable bad debt after KelpDAO: the collateral is gone while the
debt taken against it remains, leaving liquidators nothing to seize.
`backstop_buffer_usd` reports how much a safety module / umbrella can absorb.

### Config auditor

```bash
python -m blastradius.contagion audit --config data/seed_kelpdao_config.json
```

Anchor case **KelpDAO / LayerZero (18 Apr 2026)** — a `1-of-1` DVN config,
$292M drained. No contract bug was involved; every contract behaved as designed.
This auditor catches that class of misconfiguration **before deployment**:

| Rule | Severity | What it catches |
|---|---|---|
| `DVN-INSUFFICIENT-REDUNDANCY` | CRITICAL | attestors < 2 — **where KelpDAO failed** |
| `DVN-THRESHOLD-UNREACHABLE` | CRITICAL | `optional_dvn_threshold > optional_dvn_count` |
| `MULTISIG-THRESHOLD-UNREACHABLE` | CRITICAL | threshold > signers — emergency action dead |
| `DVN-CORRELATED-PATHWAYS` | HIGH | one operator secures many pathways |
| `DVN-DUPLICATE-OPERATOR` | HIGH | illusion of redundancy (same signer repeated) |
| `MULTISIG-THRESHOLD-ONE` | HIGH | `1-of-N` multisig = single key |
| `ORACLE-SINGLE-FEED` | HIGH | single price feed = single point of failure |
| `NO-BACKSTOP-BUFFER` | HIGH | borrowing on, buffer zero |
| `ADMIN-NOT-A-MULTISIG` | HIGH | admin is an EOA |
| `ADMIN-NO-TIMELOCK` / oracle limits / `LOW-CONFIRMATIONS` | MEDIUM | |
| `NO-EMERGENCY-PAUSER` / `NO-LIVE-SENTINEL` | MEDIUM/LOW | no brake pedal |

Exit code `1` when the config is not shippable — gate it directly in CI.

### Ingestion — collateral whitelists + live TVL

```bash
# live (DeFiLlama public APIs, no key) — real lending markets with supply/borrow/LTV
python3 scripts/ingest_live.py --projects aave-v3 compound-v3 morpho-blue sparklend fluid

# or via the module
python -m blastradius.contagion ingest --source defillama --project aave-v3 --out graph.json

# deterministic (the protocol's own declared collateral listing)
python -m blastradius.contagion ingest --source whitelist --data listing.json --out graph.json

# then run the same graph
python -m blastradius.contagion map --token *** --data graph.json
```

`scripts/ingest_live.py` joins DeFiLlama's **`/pools` + `/lendBorrow`** on pool id —
which is why the graph carries real `token_supplied_usd`,
`debt_against_token_usd`, `ltv`, `borrowable`, and `debt_ceiling_usd`.
Snapshots land in `docs/data/blast-graph.json` **with a provenance block**
(source URLs, timestamp, and what was derived).

> **Known limitation (always disclosed):** no free API publishes safety-module /
> backstop balances. On live markets `backstop_buffer_usd = 0`, which makes
> `uncovered_loss_usd` an **upper bound**, not a forecast. Fill it in from
> on-chain reads via `backstop_buffers={...}`.

Data sources, attribution, and legal notes: [`DATA_ATTRIBUTION.md`](DATA_ATTRIBUTION.md).

### 🌐 Public site (GitHub Pages)

`docs/` is a static site — no build step, no framework, no third-party fonts/logos:

| Page | Contents |
|---|---|
| [`docs/index.html`](docs/index.html) | Landing page + KelpDAO case study |
| [`docs/calculator.html`](docs/calculator.html) | **Free blast-radius calculator** — all computation in-browser, same formulas as `scoring.py` |
| [`docs/deck.html`](docs/deck.html) | 8-slide pitch deck |

Deploy: repo **Settings → Pages → Source: GitHub Actions**. The
[`.github/workflows/pages.yml`](.github/workflows/pages.yml) workflow auto-deploys
on every `docs/` change to `main` (least-privilege permissions, no external requests).

Design notes and the reasoning behind every decision: [`research/04-DESIGN-DECISIONS.md`](research/04-DESIGN-DECISIONS.md).
Competitive research and market valuations: [`research/00-README.md`](research/00-README.md).

---

## Installation

### Prerequisites

| Requirement | Minimum | Notes |
|---|---|---|
| Python | 3.11+ | `python3 --version` |
| Git | Any | `git --version` |
| Docker | 20.10+ | Optional — needed for sandbox |
| gVisor (runsc) | Any | Optional — stronger sandbox isolation |

<details>
<summary>🐧 Kali Linux / Debian / Ubuntu</summary>

```bash
# 1. System dependencies
sudo apt update && sudo apt install -y \
  python3 python3-pip python3-venv \
  git docker.io docker-compose \
  libpq-dev gcc

# 2. Add your user to docker group (avoid sudo every time)
sudo usermod -aG docker $USER && newgrp docker

# 3. Clone the repo
git clone https://github.com/mysterious75/blastradius-agent
cd blastradius-agent

# 4. Create virtual environment (REQUIRED on Debian/Kali)
python3 -m venv venv
source venv/bin/activate

# 5. Install BlastRadius
# Core install (fast — AI agent is built-in, no heavy deps)
pip install -e "."

# Everything (dashboard/API/notifications extras)
pip install -e ".[all]"

# 6. Run setup wizard (configure API keys, notifications)
python -m blastradius.cli.wizard

# 7. Verify installation
# Sandbox proof tests reconstruct SSTI (jinja2) and XXE (lxml) PoCs and
# execute them, so those two libs are required to run the test suite.
# For REAL sandboxed proofs (not the unsandboxed fallback), build the
# sandbox image once — Docker Desktop works fine:
# docker build -t blastradius-sandbox sandbox/
pip install pytest jinja2 lxml
python -m pytest tests/ -q
# Expected: 1026 passed, 1 skipped

# 8. Run your first scan
# URL targets require a registered scope (fail-closed — register once):
python -m blastradius.scope add training --in https://github.com/WebGoat/WebGoat
python -m blastradius.hunter --target https://github.com/WebGoat/WebGoat --scope training
```

> **Kali Linux note:** If you see `externally-managed-environment` error,
> always use a virtual environment (step 4). Never use `--break-system-packages`
> on Kali — it can break system tools.

> **Note:** The AI agent (agent.py) is **built-in** — it runs on the core
> install and needs no extra dependencies (no cai-framework, no litellm).
> Just set one provider API key (see below) and it works.

</details>

<details>
<summary>gVisor Installation (Stronger Sandbox — Recommended)</summary>

```bash
# Install gVisor on Kali/Debian
curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" | sudo tee /etc/apt/sources.list.d/gvisor.list
sudo apt update && sudo apt install -y runsc

# Configure Docker to use gVisor
sudo runsc install
sudo systemctl restart docker

# Verify
docker run --runtime=runsc --rm hello-world
```

</details>

<details>
<summary>🍎 macOS</summary>

```bash
# 1. Install dependencies
brew install python@3.11 git docker

# 2. Clone + venv
git clone https://github.com/mysterious75/blastradius-agent
cd blastradius-agent
python3.11 -m venv venv && source venv/bin/activate

# 3. Install
# Core install (fast, no CAI)
pip install -e "."

# With AI agent support (slow, installs CAI+litellm)
pip install -e ".[agent]"

# Everything
pip install -e ".[all]"

# 4. Setup
python -m blastradius.cli.wizard
```

</details>

<details>
<summary>🪟 Windows (WSL2 recommended)</summary>

```powershell
# Option A: WSL2 (recommended)
wsl --install
# Then follow Kali/Debian steps inside WSL2

# Option B: Native Windows
git clone https://github.com/mysterious75/blastradius-agent
cd blastradius-agent
python -m venv venv && venv\Scripts\activate
# Core install (fast, no CAI)
pip install -e "."

# With AI agent support (slow, installs CAI+litellm)
pip install -e ".[agent]"

# Everything
pip install -e ".[all]"
python -m blastradius.cli.wizard
```

</details>

<details>
<summary>🐳 Docker (Zero-dependency install)</summary>

```bash
git clone https://github.com/mysterious75/blastradius-agent
cd blastradius-agent
cp .env.example .env   # add your API keys
docker-compose up

# Access:
# Dashboard  → http://localhost:8080
# REST API   → http://localhost:8001
# Neo4j      → http://localhost:7474
# Webhook    → http://localhost:8000
```

</details>

### Post-Install: Configure API Key

Minimum requirement — one LLM provider key:

```bash
# Recommended (free): OpenCode
export OPENCODE_API_KEY=your-key-here

# Or DeepSeek (cheap)
export DEEPSEEK_API_KEY=your-key-here

# Save permanently
echo "OPENCODE_API_KEY=your-key" >> ~/.bashrc
source ~/.bashrc
```

Or run the wizard: `python -m blastradius.cli.wizard`

### Verify Everything Works

```bash
# Check installation
blastradius version

# Check providers
blastradius providers list

# Run tests
python -m pytest tests/ -q

# First real scan (WebGoat = safe practice target)
blastradius scan --target https://github.com/WebGoat/WebGoat

# Start dashboard
blastradius dashboard
# Open http://localhost:8080
```

### Troubleshooting

| Error | Fix |
|---|---|
| `externally-managed-environment` | Use `python3 -m venv venv && source venv/bin/activate` first |
| `docker: permission denied` | `sudo usermod -aG docker $USER && newgrp docker` |
| `ModuleNotFoundError: rich` | `pip install rich` inside venv |
| `No module named pytest` | `pip install pytest` inside venv |
| `docker: Cannot connect to daemon` | `sudo systemctl start docker` |
| `runsc: unknown runtime` | Install gVisor (see above) — sandbox falls back to Docker automatically |
| `OPENCODE_API_KEY not set` | Rule-based patches still work; set key for AI patches |
| `No module named cai` | Not needed — the AI agent is built-in and works without CAI |

## Demo

```
╔══════════════════════════════════╗
║  🔴 BlastRadius Agent v1.0.0    ║
║  Autonomous Security Engineer   ║
╚══════════════════════════════════╝

[*] Cloning https://github.com/org/repo
[*] 12 candidate finding(s) with confidence >= 0.7

File                          Line  Type  Confidence  Severity  Status
src/app.py                      42  sqli    0.95     CRITICAL   CANDIDATE
src/views/user.rb               17  xss     0.85     HIGH       CANDIDATE

[+] report saved: reports/2026-08-09_sqli_repo_src_app-42.md
[*] Done: 1 report(s) saved to reports

┌ Stats ────────────────────────────────┐
│ 5 Total Scans  2 Confirmed CVEs       │
│ 3 Patches      80% Success Rate       │
└───────────────────────────────────────┘
```

## Supported Providers

BlastRadius auto-selects the best available provider (priority:
opencode_zen > deepseek > openai > anthropic > others) and falls back through
the chain when one fails. Any model ID a provider accepts works — unknown
models are passed through as-is.

| Provider | Base URL | Key env | Models (examples) |
|---|---|---|---|
| opencode_zen | https://opencode.ai/zen/go/v1 | `OPENCODE_API_KEY` | deepseek-v4-flash, gpt-5.4, claude-sonnet-4-6, kimi-k3 |
| opencode_go | https://opencode.ai/go/v1 | `OPENCODE_API_KEY` | deepseek-v4-flash, mimo-v2.5, grok-4.5, qwen3.8-max |
| deepseek | https://api.deepseek.com/v1 | `DEEPSEEK_API_KEY` | deepseek-chat, deepseek-reasoner, deepseek-v4-pro |
| openai | https://api.openai.com/v1 | `OPENAI_API_KEY` | gpt-4o, o3-mini, gpt-5.4 |
| anthropic | https://api.anthropic.com/v1 | `ANTHROPIC_API_KEY` | claude-sonnet-4-6, claude-opus-4-6, claude-haiku-4-5 |
| openrouter | https://openrouter.ai/api/v1 | `OPENROUTER_API_KEY` | openai/gpt-4o, deepseek/deepseek-chat, qwen/qwen3.8-max |
| qwen | https://dashscope.aliyuncs.com/compatible-mode/v1 | `QWEN_API_KEY` | qwen-max, qwen3.7-max, qwen2.5-coder-32b-instruct |
| kimi | https://api.moonshot.cn/v1 | `KIMI_API_KEY` | moonshot-v1-128k, kimi-k3 |
| groq | https://api.groq.com/openai/v1 | `GROQ_API_KEY` | llama-3.3-70b-versatile, groq/compound, gemma2-9b-it |
| together | https://api.together.xyz/v1 | `TOGETHER_API_KEY` | Qwen/Qwen3.7-Max, deepseek-ai/DeepSeek-V4-Pro |
| mistral | https://api.mistral.ai/v1 | `MISTRAL_API_KEY` | mistral-large-latest, codestral-2508 |
| google | https://generativelanguage.googleapis.com/v1beta/openai | `GOOGLE_API_KEY` | gemini-2.0-flash, gemini-2.5-pro |
| xai | https://api.x.ai/v1 | `XAI_API_KEY` | grok-4.5, grok-2 |
| ollama | http://localhost:11434/v1 | — (local) | llama3.1, qwen2.5, gemma2 |
| lmstudio | http://localhost:1234/v1 | — (local) | local-model |

## Architecture

```
┌────────────────────────────────────────────────────────────────────────────┐
│                     ENTRY POINTS                                           │
│   CLI (hunter / blast_radius / pipeline / recon / providers)               │
│   Web dashboard (:8080)     GitHub App webhook (:8000)     Scheduler       │
└──────────────┬───────────────────────────────┬─────────────────────────────┘
               ▼                                ▼
┌──────────────────────────────  FullPipeline (scan → prove → patch → verify) ─┐
│  CVEHunter (static scan, 19 vuln types, 12 languages, learned rules)          │
│  ─► sandbox exploit check ─► PatchLoop (generate → verify → retry ×3)       │
│  ─► DisclosureReport + SummaryReporter ─► reports/                           │
│  ─► BlastRadiusGraph (package → repo)  ─► SQLiteDB (findings, CVE tracking) │
└──────┬───────────────────────┬──────────────────────────┬──────────────────┘
       ▼                       ▼                          ▼
┌─────────────┐        ┌─────────────────┐        ┌──────────────────┐
│  Prometheus │        │ SandboxRunner    │        │ Notifier          │
│  scanners   │        │ docker --network │        │ slack/discord/    │
│  (56 total) │        │ none --read-only │        │ telegram/email/   │
│             │        │ --memory --runsc │        │ github issues     │
└─────────────┘        └─────────────────┘        └──────────────────┘
        ▲                       ▲
        └── LLM provider system (15 providers, auto-select, rate-limit, cost)
```

## All CLI Commands

| Command | What it does |
|---|---|
| `python -m blastradius.cli.wizard` | Interactive setup (providers, keys, notifications, schedule) |
| `python -m blastradius.hunter --target <url\|path>` | Scan a repo, sandbox-validate, save disclosure reports |
| `python -m blastradius.agents --target <url\|path>` | Multi-agent graph: recon → exploit (parallel) → patch, shared blackboard + chains |
| `python -m blastradius.web --target <url>` | Dynamic web testing: reflected XSS, open redirect, security headers, CORS, exposed files, directory listing |
| `python -m blastradius.net --target <host> --ports <preset\|list\|range>` | Network-service scan: bounded TCP connect + banner fingerprint + service-filtered detectors (cleartext FTP/Telnet, anonymous FTP, missing SMTP STARTTLS); `--scope` required for non-lab targets |
| `python -m blastradius.scope add\|check\|list\|rm` | Program scope registry (default-deny for URL targets) |
| `scripts/pr_scan.py --repo . --base origin/main` | PR diff-scoped scan (sandbox-verified, merge gate; auto-opens fix PRs — see `.github/workflows/pr-scan.yml`) |
| `python -m blastradius.pipeline_cli --target <url\|path>` | Full end-to-end pipeline |
| `python -m blastradius.auto_hunt --strategy github --max 20` | Autonomous hunt over discovered targets (`--scope` required; `--repo` hunts named repos without discovery) |
| `python -m blastradius.recon --strategy all` | Discover targets (GitHub code search / PyPI / Shodan) |
| `python -m blastradius.recon --shadow <org\|user>` | Shadow-repo recon: contributors → public repos/Gists/releases, bounded detection-only secret scoring |
| `python -m blastradius.blast_radius --repo ./path` | Map dependency blast radius |
| `python -m blastradius.providers list\|test\|set\|cost` | Provider status, connectivity, .env, cost report |
| `python -m blastradius.db stats\|clear` | SQLite stats / reset |
| `python -m blastradius.cve_tracker list\|update\|stats` | CVE disclosure tracking |
| `python -m blastradius.scheduler start\|status\|run-now` | Scheduled auto-hunts |
| `python -m blastradius.dashboard` | Web dashboard at :8080 |
| `uvicorn blastradius.github_app.webhook:app` | GitHub App webhook at :8000 |
| `python -m scripts.cve_hunt [--target …]` | Multi-target CVE hunt + disclosure templates |
| `python -m blastradius.db stats` | Persisted stats |

## Docker

```bash
docker-compose up
# dashboard http://localhost:8080 · REST API :8001 · sandbox (isolated)
```

## Multi-Agent Graph

Beyond the linear pipeline, BlastRadius can run as a **graph of specialized
agents** (`blastradius.agents`) that cooperate through a shared, thread-safe
blackboard:

```
ReconAgent (discover candidates)
  └─> ExploitAgent xN (prove in parallel in the sandbox, link chains)
        └─> PatchAgent (generate + verify fixes)
```

```bash
python -m blastradius.agents --target ./path-or-url
```

Every event (candidate → confirmed → patch → chain) is posted to the
blackboard and auditable; findings sharing a file are linked into chains so
related fixes are reviewed together. The graph is deterministic and
LLM-independent — the tools prove, nothing is asserted — and each role
carries a persona prompt ready for an LLM reasoning layer.

## Dynamic Web Testing

Beyond static source scanning, BlastRadius can test a **live target** with
behavioral checks (`blastradius.web` — stdlib only):

- Reflected XSS (payload injection into every query param and form input)
- Open redirects (via `url`/`next`/`return`-style params)
- Missing security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)
- Wildcard CORS with credentials
- Exposed files (`.git/config`, `.env`, `/admin`) and directory listing
- **Live IDOR/BOLA authz-diff** (opt-in) — replay object URLs under a second
  identity and flag cross-identity reads (`--attacker-cookie`, `--victim-cookie`,
  `--victim-marker`, `--idor-url`)
- **Live SSRF with OOB + redirect-follow oracle** — inject callback URLs into
  URL-bearing params; confirm server-side fetches and redirect following
- **Live JWT checks** — `alg:none`, RS256→HS256 confusion, weak HMAC secrets,
  `kid` traversal
- **Live SQL injection** (opt-in) — error-based, boolean-differential, and
  time-based probes; NoSQL operator probes for JSON endpoints
- **Mass-assignment probes** — smuggle privileged fields with sentinel values,
  distinguish reflection from persistence
- **Web cache poisoning** (opt-in) — unkeyed-header reflection with cache-buster
  discipline and a persistence proof; Web Cache Deception surfaces
- **Exploit-chain linking** — findings are linked into A→B→C chains
  (open-redirect→OAuth, IDOR→ATO, SSRF→metadata) with combined severity
- **Scope gating** — every URL-accepting command honors `--scope` against the
  scope registry (default deny); discovery commands filter to in-scope targets.
  URL targets without a registered program are BLOCKED (fail-closed — no
  silent opt-out); local paths and lab targets (loopback, `.invalid`, LAN)
  are exempt. Register once per program:
  `python -m blastradius.scope add myprogram --in app.example.com`
- HTTP interception proxy (records + replays traffic, builds sitemaps)

```bash
# basic dynamic scan
python -m blastradius.web --target http://localhost:8000

# + live IDOR/BOLA diff with two identities (attacker vs victim cookies)
python -m blastradius.web --target https://app.example \
  --attacker-cookie "session=ATTACKER" \
  --victim-cookie   "session=VICTIM" \
  --victim-marker "victim@example.com" \
  --idor-url https://app.example/api/users/1234
```

Dynamic findings are HTTP-response evidence and are reported as *candidates*
(no sandbox execution marker) — exactly like static candidates that fail
sandbox verification.

## PR Security Scan (GitHub Action)

`.github/workflows/pr-scan.yml` runs on every PR: diff-scoped scan → sandbox
verification → findings comment + SARIF upload → **merge gate** (confirmed
findings fail the check) → **autofix bot-PR** (`scripts/autofix_pr.py` applies
only parse-safe, exact-match patches on a fresh branch and opens a fix PR).
Patches that cannot be applied safely are left for manual review.

## Benchmark

[![CI](https://img.shields.io/github/actions/workflow/status/mysterious75/blastradius-agent/ci.yml?branch=main&label=CI%20%28benchmark%20gated%29)](https://github.com/mysterious75/blastradius-agent/actions)

Reproducible, offline detection benchmark — the real pipeline scored against a
ground-truth corpus (see [`benchmarks/`](benchmarks/README.md)). Every reported
finding either carries a sandbox-executed `[VULNERABLE]` proof or is honestly
labeled a candidate. Latest run (detection F1 / sandbox-proven):

| Target | Expected | Reported | F1 | Proven (--verify) |
|---|---|---|---|---|
| flask-auth-bypass | 1 | 1 | 1.000 | 1/1 |
| flask-cmd-injection | 1 | 1 | 1.000 | 1/1 |
| flask-crlf | 1 | 1 | 1.000 | 1/1 |
| flask-deserialization | 1 | 1 | 1.000 | 1/1 |
| flask-idor | 1 | 1 | 1.000 | 1/1 |
| flask-nosqli | 1 | 1 | 1.000 | 1/1 |
| flask-sqli | 1 | 1 | 1.000 | 1/1 |
| flask-traversal | 1 | 1 | 1.000 | 1/1 |
| flask-xss | 1 | 1 | 1.000 | 1/1 |
| requests-ssrf | 1 | 1 | 1.000 | 1/1 |
| jinja-ssti | 1 | 1 | 1.000 | 1/1 |
| lxml-xxe | 1 | 1 | 1.000 | 1/1 |
| hardcoded-secrets | 1 | 1 | 1.000 | 0/1* |
| flask-proto-pollution | 1 | 1 | 1.000 | 0/1* |
| ci-supply-chain | 1 | 1 | 1.000 | 0/1* |
| solidity-tx-origin | 1 | 1 | 1.000 | 0/1* |
| **Total** | **16** | **16** | **1.000** | **12/16** |

\* presence-based findings (hardcoded secrets, prototype pollution, CI config)
have no meaningful execution proof — reported as candidates, never silently "proven".

A second gate covers the live web checks (`benchmarks/run_dynamic.py`): IDOR
authz-diff, JWT acceptance, SSRF/OOB, SQLi, mass assignment, cache poisoning,
GraphQL (introspection, field suggestions, alias batching), request
smuggling (CL.TE / TE.CL desync probes), race conditions (gated bursts at
explicit single-use URLs), CSRF (passive token-field analysis + active
token harness on explicit URLs with a victim session), MFA (bounded OTP
rate probe, step-skip, OTP reuse on explicit config), and
network-service detectors against local stdlib targets — currently
**23 expected / 23 reported at F1 1.000**.

```bash
python benchmarks/run.py            # detection benchmark (offline)
python benchmarks/run.py --verify   # + sandbox PoC execution (proven count)
python benchmarks/run_dynamic.py --min-f1 1.0   # live local web checks
```

The benchmark runs on every push/PR in CI with an F1 gate.

## CVE Hall of Fame

| CVE ID | Project | Type | Severity | Bounty |
|--------|---------|------|----------|--------|
| — | — | — | — | — |

Found one with BlastRadius? Submit via the CVE Program / GitHub Security
Advisory (see [SECURITY.md](SECURITY.md)) and add it here.

## Trust & Safety

- **Authorized use only.** Every URL-accepting command supports `--scope`
  against a local scope registry that defaults to **deny** — and since this
  release the deny is fail-closed: a URL target with no registered program
  is BLOCKED, not silently scanned. Local paths and lab targets
  (loopback, `.invalid`, RFC-1918 LAN) stay frictionless for offline work.
  Discovery commands filter to in-scope targets. See
  `python -m blastradius.scope --help`.
- **Fail-closed verification.** No finding is ever reported as confirmed
  without execution evidence (`[VULNERABLE]` marker or HTTP-response proof);
  everything else stays labeled a *candidate*.
- **Responsible live testing.** Cache-poisoning probes use per-request cache
  busters so nothing can land in shared entries; OOB listeners are
  localhost-only by default; time-based and write-path probes are opt-in.
- **Exfiltration guard.** Agent actions that publish or export data
  (`visibility-change`, `gist-publish`, `package-publish`, and similar) are
  deny-by-default in `blastradius/security/exfil_guard.py`. Public hosts and
  public visibility are rejected unless a human explicitly overrides, every
  decision is written to the tamper-evident audit log, and an audit-write
  failure fails closed.
- **Shadow recon is detection-only.** `--shadow` inspects public repos, Gists
  and releases for secret-shaped material and scores it as a *candidate*. It
  never validates, authenticates with, or uses a discovered credential.
- **Disclosure.** Found a vulnerability with BlastRadius? Follow
  [SECURITY.md](SECURITY.md) — coordinated disclosure via the CVE Program
  or a GitHub Security Advisory.

## Contributing

PRs welcome. Ground rules:

- `python -m pytest tests/ -q` must stay green; add tests with every feature
- Keep new features dependency-light; mock all network calls in tests
- Every external integration must degrade gracefully when credentials are missing
- `ruff check` and `ruff format --check` must pass (`blastradius tests scripts`)
- Never commit secrets, corpora dumps, or large binaries — see `.gitignore`

## License

MIT — see [LICENSE](LICENSE).
