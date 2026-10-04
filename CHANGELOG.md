# Changelog

All notable changes to BlastRadius Agent are documented here.

## [Unreleased]

### Added
- Network-service scanner (`blastradius/net/`): Tsunami-style plugin foundation —
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
  (10 aliased `__typename` fields — the rate-limit-bypass primitive) checks,
  plus an offline sensitive-resolver review helper. Dynamic benchmark gains
  the `live-graphql` target (14/14 at F1 1.000).
- Live request-smuggling checks (`blastradius/web/smuggle.py`, opt-in
  `--smuggle-probe`): Kettle-ordered CL.TE timing probe then TE.CL
  differential probe over raw timeout-enforced sockets, our own connection
  only — no poisoning, no victim requests, no depth/DoS or H2 variants.
  Dynamic benchmark gains the `live-smuggle` target (16/16 at F1 1.000).
- Solidity smart-contract scanner (`blastradius/scanners/solidity.py`): Slither-aligned
  reentrancy (structural checks-effects-interactions analysis), tx.origin auth, controlled
  delegatecall, arbitrary send, weak randomness, unchecked low-level calls, unchecked ERC20
  transfers, divide-before-multiply, incorrect exponentiation, timestamp dependency,
  pre-0.8 integer overflow, unprotected upgrade, and hardcoded private keys.
- Registry: `solidity` vuln type (CWE-841) added, taking the static registry to
  **19 vuln types / 12 languages**.
- Dynamic benchmark extended to 6 live local targets (SQLi, mass assignment, cache
  poisoning added to IDOR/JWT/SSRF) — 7 expected / 7 reported, F1 1.000.
- Exfiltration guardrail (`blastradius/security/exfil_guard.py`): deny-by-default
  egress classification, public-host/visibility enforcement, command screening, audited
  and fail-closed.
- Shadow-repository recon (`--shadow`): contributors to public repos/Gists/releases with
  bounded, detection-only secret scoring.

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
