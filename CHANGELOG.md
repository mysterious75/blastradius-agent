# Changelog

All notable changes to BlastRadius Agent are documented here.

## [1.0.0] - 2026-08-09

### Added
- Complete 7-phase autonomous security pipeline (scan → prove → patch → verify → report → disclose)
- 10 vulnerability types (SQLi, XSS, SSRF, SSTI, XXE, IDOR, JWT, GraphQL, Path Traversal, Command Injection)
- 15 LLM provider support with auto-selection and fallback chain
- Docker sandbox with gVisor isolation
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
