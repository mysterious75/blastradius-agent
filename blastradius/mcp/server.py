"""BlastRadius MCP server — expose BlastRadius as MCP tools.

Runs on stdio (works with Claude, Cursor, Windsurf, Continue and any
MCP-compatible client). Requires the optional ``mcp`` package
(``pip install "blastradius-agent[mcp]"``); without it, ``main()`` prints
install instructions and exits.

Security posture (per the official MCP security best practices; stdio-only):
- Every tool call passes through a typed guard: a 10k-char argument cap and a
  credential-like input check (``sk-``, ``AKIA``, ``ghp_``, ``Bearer <token>``)
  that rejects arguments that look like secrets.
- Scan targets are validated: URLs must use http(s) and must not resolve to
  private/loopback/link-local ranges (SSRF-safety; override with
  ``BLASTRADIUS_MCP_ALLOW_PRIVATE=1``); local paths must resolve inside the
  allowed roots (see ``blastradius.security.input_validator``).
- The exposed tool surface can be restricted with ``set_mcp_tools`` (default:
  everything in ``ALLOWED_TOOLS``); calls to blocked tools fail with a clear
  error.
- Every call is recorded — ``{tool, args_summary (truncated + redacted), ts}``
  — in an in-memory audit ring buffer (capped at ``AUDIT_MAX``) readable via
  the ``get_audit_log`` handler. No network/listen mode is added.
"""

import functools
import inspect
import ipaddress
import json
import os
import re
import urllib.parse
from datetime import datetime
from typing import Dict, List, Tuple

from blastradius.blast_radius.graph import BlastRadiusGraph
from blastradius.db.database import SQLiteDB
from blastradius.db.deduplicator import Deduplicator
from blastradius.hunter.scanner import CVEHunter, Finding
from blastradius.patcher.loop import PatchLoop
from blastradius.security.input_validator import (
    allowed_repo_roots,
    validate_repo_path,
    validate_target_code,
)
from blastradius.tools.sandbox_tool import run_exploit_sandbox

_graph = BlastRadiusGraph(backend="memory")

# ---------------------------------------------------------------------------
# Hardening constants
# ---------------------------------------------------------------------------

MAX_ARG_LEN = 10_000  # per-string argument cap (chars)
AUDIT_MAX = 500  # audit ring-buffer capacity
AUDIT_SUMMARY_LEN = 200  # per-argument truncation inside audit summaries

# Look-alike credentials that must never pass through tool arguments.
_CRED_RE = re.compile(
    r"(sk-[A-Za-z0-9]{16,}"
    r"|AKIA[0-9A-Z]{16}"
    r"|ghp_[A-Za-z0-9]{20,}"
    r"|Bearer\s+[A-Za-z0-9._~+/=-]{10,})"
)

_URL_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")

_PRIVATE_HOSTS = ("localhost", "0.0.0.0", "::1")


def _allow_private() -> bool:
    """Env override ``BLASTRADIUS_MCP_ALLOW_PRIVATE=1`` permits private targets."""
    return os.getenv("BLASTRADIUS_MCP_ALLOW_PRIVATE", "").lower() in ("1", "true", "yes")


def _host_is_private(host: str) -> bool:
    """True for loopback/private/link-local/reserved addresses or local names."""
    host = host.lower()
    if host in _PRIVATE_HOSTS or host.endswith((".local", ".internal", ".localhost")):
        return True
    try:
        ip = ipaddress.ip_address(host.split("%")[0])
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast


def _target_is_url(target: str) -> bool:
    """True when ``target`` carries an explicit ``scheme://`` prefix."""
    return bool(_URL_SCHEME_RE.match(target))


def _redact(text: str) -> str:
    """Replace look-alike credentials with ``[REDACTED]``."""
    return _CRED_RE.sub("[REDACTED]", text)


def _validate_target(target: str) -> str:
    """Validate a scan target. Returns it unchanged; raises ValueError."""
    if not isinstance(target, str) or not target.strip():
        raise ValueError("target must be a non-empty string")
    if len(target) > MAX_ARG_LEN:
        raise ValueError(f"target exceeds {MAX_ARG_LEN} char limit")
    if _target_is_url(target):
        parsed = urllib.parse.urlsplit(target)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"target scheme not allowed: {parsed.scheme!r}")
        host = (parsed.hostname or "").lower()
        if not host:
            raise ValueError(f"target URL has no host: {target!r}")
        if not _allow_private() and _host_is_private(host):
            raise ValueError(
                f"target URL {target!r} resolves to a private/loopback address; "
                "set BLASTRADIUS_MCP_ALLOW_PRIVATE=1 to allow"
            )
        return target
    # Local repo path — must exist inside an allowed root.
    try:
        return validate_repo_path(target)
    except ValueError as exc:
        roots = [str(r) for r in allowed_repo_roots()]
        raise ValueError(f"{exc} (allowed roots: {roots})") from exc


def _validate_code(code: str) -> str:
    """Validate exploit/patch target code (50KB cap + injection-pattern block)."""
    return validate_target_code(code)


# ---------------------------------------------------------------------------
# Audit ring buffer
# ---------------------------------------------------------------------------

_AUDIT_LOG: List[Dict] = []


def _record_audit(tool: str, args_summary: Dict) -> None:
    """Append ``{tool, args_summary, ts}`` to the ring buffer (capped)."""
    entry = {
        "tool": tool,
        "args_summary": {k: _redact(v) for k, v in args_summary.items()},
        "ts": datetime.now().isoformat(timespec="seconds"),
    }
    _AUDIT_LOG.append(entry)
    if len(_AUDIT_LOG) > AUDIT_MAX:
        del _AUDIT_LOG[: len(_AUDIT_LOG) - AUDIT_MAX]


def _summarize_args(fn, args, kwargs) -> Dict:
    """Positional/kwarg -> truncated, redacted string summary for auditing."""
    params = list(inspect.signature(fn).parameters.values())
    bound = {}
    for i, value in enumerate(args):
        key = params[i].name if i < len(params) else f"arg{i}"
        bound[key] = value
    bound.update(kwargs)
    summary = {}
    for key, value in bound.items():
        if isinstance(value, str):
            value = value[:AUDIT_SUMMARY_LEN]
        summary[key] = _redact(str(value))
    return summary


# ---------------------------------------------------------------------------
# Tool allowlist
# ---------------------------------------------------------------------------

ALLOWED_TOOLS: Tuple[str, ...] = (
    "scan_repo",
    "get_findings",
    "get_stats",
    "run_exploit",
    "generate_patch",
    "blast_radius",
    "list_cves",
    "get_audit_log",
)

_enabled: set = set(ALLOWED_TOOLS)


def set_mcp_tools(tools) -> None:
    """Restrict the exposed tool surface to ``tools`` (names or functions).

    The audit handler ``get_audit_log`` stays available so the operator can
    always inspect what ran. Pass ``ALLOWED_TOOLS`` to restore the full set.
    Raises ValueError for names outside ``ALLOWED_TOOLS``.
    """
    names = {t if isinstance(t, str) else getattr(t, "__name__", str(t)) for t in tools}
    unknown = names - set(ALLOWED_TOOLS)
    if unknown:
        raise ValueError(f"unknown MCP tools: {sorted(unknown)}")
    names.add("get_audit_log")
    _enabled.clear()
    _enabled.update(names)


def _error_response(tool: str, message: str) -> str:
    if tool == "run_exploit":
        return f"ERROR: {message}"
    return json.dumps({"error": message})


def _guarded(fn):
    """Decorator: audit + allowlist + generic arg guard around every tool."""

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        _record_audit(fn.__name__, _summarize_args(fn, args, kwargs))
        if fn.__name__ not in _enabled:
            return _error_response(
                fn.__name__,
                f"tool {fn.__name__!r} is not enabled (allowed: {sorted(_enabled)})",
            )
        try:
            for value in list(args) + list(kwargs.values()):
                if isinstance(value, str) and len(value) > MAX_ARG_LEN:
                    raise ValueError(f"argument exceeds {MAX_ARG_LEN} char limit")
                if isinstance(value, str) and _CRED_RE.search(value):
                    raise ValueError("credential-like input rejected")
        except ValueError as exc:
            return _error_response(fn.__name__, str(exc))
        return fn(*args, **kwargs)

    return wrapper


# ---------------------------------------------------------------------------
# Tools (plain functions — usable without the mcp SDK)
# ---------------------------------------------------------------------------


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


@_guarded
def scan_repo(target: str) -> str:
    """Scan a GitHub repo URL or local path; returns findings as JSON."""
    hunter = CVEHunter()
    try:
        target = _validate_target(target)
        repo_path = hunter.clone_repo(target) if _target_is_url(target) else target
        findings = hunter.scan_repo(repo_path)
        return json.dumps([_finding_json(f) for f in findings], indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)})


@_guarded
def get_findings(scan_id: str) -> str:
    """Findings for a stored scan id (from SQLite)."""
    try:
        rows = SQLiteDB().get_findings(int(scan_id))
        return json.dumps(rows, indent=2, default=str)
    except Exception as exc:
        return json.dumps({"error": str(exc)})


@_guarded
def get_stats() -> str:
    """Persisted stats from SQLite."""
    try:
        return json.dumps(SQLiteDB().get_stats(), indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)})


@_guarded
def run_exploit(vuln_type: str, code: str) -> str:
    """Sandbox-validate a vulnerability: EXPLOITABLE or NOT_EXPLOITABLE."""
    try:
        _validate_code(code)
        result = run_exploit_sandbox(vuln_type, code)
        return result.splitlines()[0]
    except Exception as exc:
        return f"ERROR: {exc}"


@_guarded
def generate_patch(vuln_type: str, code: str) -> str:
    """Generate + verify a patch for vulnerable code; returns JSON with the diff."""
    try:
        _validate_code(code)
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


@_guarded
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


@_guarded
def list_cves() -> str:
    """Tracked CVE disclosures from SQLite."""
    try:
        rows = Deduplicator().get_tracking_rows()
        return json.dumps(rows, indent=2, default=str)
    except Exception as exc:
        return json.dumps({"error": str(exc)})


@_guarded
def get_audit_log(n: int = 20) -> str:
    """Last ``n`` audit-log entries (args redacted). stdio-only handler."""
    try:
        count = max(0, int(n))
    except (TypeError, ValueError):
        count = 20
    entries = _AUDIT_LOG[-count:]
    redacted = [
        {
            "tool": e["tool"],
            "args_summary": {k: _redact(v) for k, v in e["args_summary"].items()},
            "ts": e["ts"],
        }
        for e in entries
    ]
    return json.dumps(redacted, indent=2)


TOOLS: List = [
    scan_repo,
    get_findings,
    get_stats,
    run_exploit,
    generate_patch,
    blast_radius,
    list_cves,
    get_audit_log,
]


def register(mcp) -> None:
    """Register the enabled tools on a FastMCP instance."""
    for fn in TOOLS:
        if fn.__name__ in _enabled:
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
