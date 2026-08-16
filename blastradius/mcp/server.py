"""BlastRadius MCP server — expose BlastRadius as MCP tools.

Runs on stdio (works with Claude, Cursor, Windsurf, Continue and any
MCP-compatible client). Requires the optional ``mcp`` package
(``pip install "blastradius-agent[mcp]"``); without it, ``main()`` prints
install instructions and exits.
"""

import json
from typing import List

from blastradius.blast_radius.graph import BlastRadiusGraph
from blastradius.db.database import SQLiteDB
from blastradius.db.deduplicator import Deduplicator
from blastradius.hunter.scanner import CVEHunter, Finding
from blastradius.patcher.loop import PatchLoop
from blastradius.tools.sandbox_tool import run_exploit_sandbox

_graph = BlastRadiusGraph(backend="memory")


def _finding_json(finding) -> dict:
    return {
        "file": finding.file,
        "line": finding.line,
        "vuln_type": finding.vuln_type,
        "confidence": finding.confidence,
        "payload": finding.payload,
        "severity": finding.severity,
        "cwe": finding.cwe,
        "description": finding.description,
        "remediation": finding.remediation,
    }


# ---------------------------------------------------------------------------
# Tools (plain functions — usable without the mcp SDK)
# ---------------------------------------------------------------------------


def scan_repo(target: str) -> str:
    """Scan a GitHub repo URL or local path; returns findings as JSON."""
    hunter = CVEHunter()
    try:
        repo_path = (
            hunter.clone_repo(target) if target.startswith(("http://", "https://")) else target
        )
        findings = hunter.scan_repo(repo_path)
        return json.dumps([_finding_json(f) for f in findings], indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)})


def get_findings(scan_id: str) -> str:
    """Findings for a stored scan id (from SQLite)."""
    try:
        rows = SQLiteDB().get_findings(int(scan_id))
        return json.dumps(rows, indent=2, default=str)
    except Exception as exc:
        return json.dumps({"error": str(exc)})


def get_stats() -> str:
    """Persisted stats from SQLite."""
    try:
        return json.dumps(SQLiteDB().get_stats(), indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)})


def run_exploit(vuln_type: str, code: str) -> str:
    """Sandbox-validate a vulnerability: EXPLOITABLE or NOT_EXPLOITABLE."""
    try:
        result = run_exploit_sandbox(vuln_type, code)
        return result.splitlines()[0]
    except Exception as exc:
        return f"ERROR: {exc}"


def generate_patch(vuln_type: str, code: str) -> str:
    """Generate + verify a patch for vulnerable code; returns JSON with the diff."""
    try:
        first_line = code.splitlines()[0] if code.strip() else ""
        finding = Finding(
            file="mcp-input",
            line=0,
            vuln_type=vuln_type,
            payload=first_line,
            confidence=1.0,
            original_code=code,
        )
        result = PatchLoop().run(finding)
        patch = result.patch
        return json.dumps(
            {
                "needs_human": result.needs_human,
                "attempts": result.attempts,
                "diff": patch.diff,
                "explanation": patch.explanation,
            },
            indent=2,
        )
    except Exception as exc:
        return json.dumps({"error": str(exc)})


def blast_radius(package: str, version: str = "") -> str:
    """Repos affected by a package (from the in-memory blast-radius graph)."""
    _graph.add_package(package, version)
    return json.dumps(
        {
            "package": package,
            "version": version,
            "affected_repos": _graph.query_blast_radius(package),
        },
        indent=2,
    )


def list_cves() -> str:
    """Tracked CVE disclosures from SQLite."""
    try:
        rows = Deduplicator().get_tracking_rows()
        return json.dumps(rows, indent=2, default=str)
    except Exception as exc:
        return json.dumps({"error": str(exc)})


TOOLS: List = [
    scan_repo,
    get_findings,
    get_stats,
    run_exploit,
    generate_patch,
    blast_radius,
    list_cves,
]


def register(mcp) -> None:
    """Register every tool on a FastMCP instance."""
    for fn in TOOLS:
        mcp.tool()(fn)


def main(argv=None) -> int:
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        print("MCP SDK not installed. Install with: pip install 'blastradius-agent[mcp]'")
        return 1
    mcp = FastMCP("blastradius")
    register(mcp)
    mcp.run()  # stdio transport
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
