# 🔴 BlastRadius Agent

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

## What it does

BlastRadius clones repositories, statically scans them for vulnerabilities
across 8 types and 11 languages, proves exploitability in a sandboxed PoC,
auto-generates and verifies patches, and tracks the whole lifecycle — from
target discovery to CVE disclosure — in a local SQLite database with a web
dashboard, multi-channel notifications, and a self-improving scanner.

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
# Core install (fast, no CAI)
pip install -e "."

# With AI agent support (slow, installs CAI+litellm)
pip install -e ".[agent]"

# Everything
pip install -e ".[all]"

# 6. Run setup wizard (configure API keys, notifications)
python -m blastradius.cli.wizard

# 7. Verify installation (install pytest inside the venv if needed)
pip install pytest  # if running tests
python -m pytest tests/ -q
# Expected: 339 passed, 0 failed

# 8. Run your first scan
python -m blastradius.hunter --target https://github.com/WebGoat/WebGoat
```

> **Kali Linux note:** If you see `externally-managed-environment` error,
> always use a virtual environment (step 4). Never use `--break-system-packages`
> on Kali — it can break system tools.

> **Note:** `.[all]` installs cai-framework which is large (~500MB).
> For scanning only, use `pip install -e "."` (fast, <50MB).

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
| `litellm downloading forever` | Use `pip install -e "."` for core install without CAI |

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
| opencode_zen | https://opencode.ai/zen/go/v1 | `OPENCODE_API_KEY` | deepseek-v4-flash, gpt-5.6-sol, claude-sonnet-4-5, kimi-k3 |
| opencode_go | https://opencode.ai/go/v1 | `OPENCODE_API_KEY` | deepseek-v4-flash, mimo-v2.5, grok-4.5, qwen3.8-max |
| deepseek | https://api.deepseek.com/v1 | `DEEPSEEK_API_KEY` | deepseek-chat, deepseek-reasoner, deepseek-v4-pro |
| openai | https://api.openai.com/v1 | `OPENAI_API_KEY` | gpt-4o, o3-mini, gpt-5.6-terra |
| anthropic | https://api.anthropic.com/v1 | `ANTHROPIC_API_KEY` | claude-sonnet-4-6, claude-opus-5, claude-haiku-4-5 |
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
│  CVEHunter (static scan, 8 vuln types, 11 languages, learned rules)          │
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
| `python -m blastradius.pipeline_cli --target <url\|path>` | Full end-to-end pipeline |
| `python -m blastradius.auto_hunt --strategy github --max 20` | Autonomous hunt over discovered targets |
| `python -m blastradius.recon --strategy all` | Discover targets (GitHub code search / PyPI / Shodan) |
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
# dashboard http://localhost:8080 · webhook :8000 · Neo4j :7474/:7687
```

## CVE Hall of Fame

| CVE ID | Project | Type | Severity | Bounty |
|--------|---------|------|----------|--------|
| — | — | — | — | — |

Found one with BlastRadius? Submit via the CVE Program / GitHub Security
Advisory (see [SECURITY.md](SECURITY.md)) and add it here.

## Contributing

PRs welcome — tests run with `pytest tests/`. Keep new features dependency-
light, mock all network calls in tests, and make every integration graceful
when credentials are missing.

## License

MIT
