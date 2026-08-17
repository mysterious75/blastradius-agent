"""MCP server hardening tests — input validation, allowlist, credential guard,
audit log. Follows the direct-call style of tests/test_mcp.py."""

import json

import pytest

from blastradius.mcp.server import (
    ALLOWED_TOOLS,
    blast_radius,
    get_audit_log,
    run_exploit,
    scan_repo,
    set_mcp_tools,
)

META_DATA_URL = "http://169.254.169.254/latest/meta-data/"
TOKEN = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ"


@pytest.fixture(autouse=True)
def _reset_allowlist():
    """Restore the full tool surface after every test (module-global state)."""
    yield
    set_mcp_tools(ALLOWED_TOOLS)


def _error(result: str) -> str:
    try:
        return json.loads(result).get("error", "")
    except (ValueError, AttributeError):
        return result


def test_rejects_private_target():
    data = json.loads(scan_repo(META_DATA_URL))
    assert "error" in data
    assert "private/loopback" in data["error"]
    assert "169.254.169.254" in data["error"]


def test_private_target_allowed_with_env(monkeypatch):
    monkeypatch.setenv("BLASTRADIUS_MCP_ALLOW_PRIVATE", "1")
    data = json.loads(scan_repo(META_DATA_URL))
    # Validation is bypassed; a network failure (git clone) is not the SSRF block.
    assert "private/loopback" not in data.get("error", "")


def test_rejects_bad_scheme():
    for bad in ("file:///etc/passwd", "gopher://localhost/x", "dict://localhost:6379/x"):
        data = json.loads(scan_repo(bad))
        assert "error" in data
        assert "scheme not allowed" in data["error"]


def test_rejects_local_path_outside_roots():
    data = json.loads(scan_repo("/proc/self/mem"))
    assert "error" in data


def test_rejects_credential_arg():
    # Any tool with a look-alike credential argument is rejected.
    data = json.loads(blast_radius(TOKEN))
    assert data["error"] == "credential-like input rejected"

    data = json.loads(scan_repo(TOKEN))
    assert data["error"] == "credential-like input rejected"

    result = run_exploit("sqli", f'code = "{TOKEN}"')
    assert "credential-like input rejected" in result


def test_rejects_oversized_arg():
    data = json.loads(blast_radius("x" * 10_001))
    assert "limit" in data["error"]


def test_tool_allowlist():
    set_mcp_tools([t for t in ALLOWED_TOOLS if t != "scan_repo"])

    blocked = json.loads(scan_repo("anything"))
    assert "error" in blocked
    assert "not enabled" in blocked["error"]

    # Included tool still works.
    data = json.loads(blast_radius("flask"))
    assert data["package"] == "flask"


def test_set_mcp_tools_rejects_unknown():
    with pytest.raises(ValueError, match="unknown MCP tools"):
        set_mcp_tools(["not_a_tool"])


def test_audit_log_redacts():
    blast_radius(TOKEN)  # rejected, but still audited with redacted args
    entries = json.loads(get_audit_log(500))
    call = [e for e in entries if e["tool"] == "blast_radius"][-1]
    assert call["tool"] == "blast_radius"
    assert call["ts"]
    assert TOKEN not in json.dumps(call)
    assert "[REDACTED]" in json.dumps(call["args_summary"])


def test_audit_log_respects_limit_and_orders():
    entries = json.loads(get_audit_log(2))
    assert len(entries) <= 2
    if entries:
        assert set(entries[-1]) == {"tool", "args_summary", "ts"}
