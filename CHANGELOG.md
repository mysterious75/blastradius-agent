# Changelog

All notable changes to BlastRadius Agent are documented here.

## [1.0.0] - 2026-08-09

### Added
- Complete 7-phase autonomous security pipeline (scan → prove → patch → verify → report → disclose)
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
