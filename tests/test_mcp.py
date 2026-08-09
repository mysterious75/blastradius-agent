"""MCP server tests — tool functions exercised directly; SDK absence graceful."""

import json

import pytest

from blastradius.mcp import server as mcp_server
from blastradius.mcp.server import (
    TOOLS,
    blast_radius,
    generate_patch,
    get_findings,
    get_stats,
    list_cves,
    main,
    run_exploit,
    scan_repo,
)

VULN_CODE = 'def target(user_input):\n    return "SELECT * FROM users WHERE name = \'" + user_input + "\'"\n'


def test_seven_tools_registered():
    names = {fn.__name__ for fn in TOOLS}
    assert names == {
        "scan_repo", "get_findings", "get_stats", "run_exploit",
        "generate_patch", "blast_radius", "list_cves",
    }


def test_scan_repo_local_path(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text(
        "name = request.args.get('name')\n"
        "query = \"SELECT * FROM users WHERE name = '\" + name + \"'\"\n", encoding="utf-8"
    )
    data = json.loads(scan_repo(str(tmp_path)))
    assert isinstance(data, list)
    assert any(f["vuln_type"] == "sqli" for f in data)


def test_scan_repo_error_returns_json():
    data = json.loads(scan_repo("/nonexistent/nowhere"))
    assert "error" in data


def test_run_exploit():
    assert run_exploit("sqli", VULN_CODE) == "CONFIRMED_EXPLOITABLE"
    safe = 'def target(user_input):\n    return "SELECT 1"'
    assert run_exploit("sqli", safe) == "NOT_EXPLOITABLE"


def test_generate_patch():
    data = json.loads(generate_patch("sqli", VULN_CODE))
    assert data["diff"]
    assert data["patched_code"] if "patched_code" in data else True
    assert "explanation" in data


def test_blast_radius_tool():
    data = json.loads(blast_radius("flask", "2.3.2"))
    assert data["package"] == "flask"
    assert isinstance(data["affected_repos"], list)


def test_get_findings_and_stats_with_db(tmp_path, monkeypatch):
    from blastradius.db.database import SQLiteDB

    db = SQLiteDB(db_path=str(tmp_path / "m.db"))
    scan_id = db.save_scan("target")
    monkeypatch.setattr(mcp_server, "SQLiteDB", lambda: db)

    findings = json.loads(get_findings(str(scan_id)))
    assert findings == []

    stats = json.loads(get_stats())
    assert stats["total_scans"] == 1


def test_list_cves_with_db(tmp_path, monkeypatch):
    from blastradius.db.database import SQLiteDB

    db = SQLiteDB(db_path=str(tmp_path / "c.db"))
    monkeypatch.setattr(mcp_server, "SQLiteDB", lambda: db)
    rows = json.loads(list_cves())
    assert isinstance(rows, list)


def test_main_registers_and_runs(monkeypatch):
    import builtins
    import types

    real_import = builtins.__import__
    called = {}

    class FakeFastMCP:
        def __init__(self, *a, **k):
            pass

        def tool(self):
            def deco(fn):
                called.setdefault("tools", []).append(fn.__name__)
                return fn
            return deco

        def run(self, *a, **k):
            called["ran"] = True

    def fake_import(name, *a, **k):
        if name == "mcp.server.fastmcp":
            mod = types.ModuleType("mcp.server.fastmcp")
            mod.FastMCP = FakeFastMCP
            return mod
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    assert main() == 0
    assert called["ran"] is True
    assert len(called["tools"]) == 7


def test_main_missing_sdk_prints_instructions(monkeypatch, capsys):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name.startswith("mcp"):
            raise ModuleNotFoundError(f"No module named '{name}'")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    rc = main()
    assert rc == 1
    out = capsys.readouterr().out
    assert "MCP SDK not installed" in out
    assert "pip install" in out
