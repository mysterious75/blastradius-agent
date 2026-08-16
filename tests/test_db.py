"""SQLite DB tests — isolated tmp DB, no network."""

from datetime import datetime

import pytest

from blastradius.db.database import SQLiteDB
from blastradius.db.__main__ import main as db_main
from blastradius.hunter.scanner import Finding


@pytest.fixture
def db(tmp_path):
    return SQLiteDB(db_path=str(tmp_path / "test.db"))


def make_finding(vuln_type="sqli"):
    return Finding(
        file="app.py",
        line=5,
        vuln_type=vuln_type,
        payload="x",
        confidence=0.95,
        severity="CRITICAL",
        cwe="CWE-89",
        description="desc",
        remediation="fix",
    )


def test_save_and_get_scan(db):
    scan_id = db.save_scan("https://github.com/org/repo")
    assert scan_id > 0
    scan = db.get_scan(scan_id)
    assert scan["target"] == "https://github.com/org/repo"
    assert scan["status"] == "pending"

    db.update_scan(scan_id, status="done", files_scanned=42, finished_at=datetime.now().isoformat())
    scan = db.get_scan(scan_id)
    assert scan["status"] == "done"
    assert scan["files_scanned"] == 42


def test_findings_roundtrip(db):
    scan_id = db.save_scan("target")
    fid = db.save_finding(scan_id, make_finding())
    rows = db.get_findings(scan_id)
    assert len(rows) == 1 and rows[0]["id"] == fid
    assert rows[0]["vuln_type"] == "sqli"
    assert rows[0]["severity"] == "CRITICAL"

    db.save_finding(scan_id, make_finding(vuln_type="xss"))
    assert len(db.get_findings(scan_id)) == 2
    assert len(db.get_all_findings()) == 2


def test_patch_roundtrip(db):
    scan_id = db.save_scan("t")
    fid = db.save_finding(scan_id, make_finding())

    class Patch:
        original_code = "vuln"
        patched_code = "fixed"
        diff = "-vuln\n+fixed"

    db.save_patch(fid, Patch(), attempts=2, needs_human=True, confidence=66.67)
    patch = db.get_patch(fid)
    assert patch["patched"] == "fixed"
    assert patch["attempts"] == 2
    assert patch["needs_human"] == 1
    assert patch["confidence"] == 66.67


def test_reports_roundtrip(db):
    scan_id = db.save_scan("t")
    fid = db.save_finding(scan_id, make_finding())
    db.save_report(fid, "reports/x.md")
    reports = db.get_reports()
    assert len(reports) == 1
    assert reports[0]["path"] == "reports/x.md"
    assert reports[0]["finding_id"] == fid


def test_provider_usage_log(db):
    db.log_provider_usage("deepseek", "deepseek-chat", tokens=1500, cost=0.003)
    db.log_provider_usage("openai", "gpt-4o", tokens=200, cost=0.01)
    with db._connect() as conn:
        rows = conn.execute("SELECT * FROM providers_log ORDER BY id").fetchall()
    assert len(rows) == 2
    assert rows[0]["provider"] == "deepseek"
    assert rows[0]["tokens_used"] == 1500


def test_stats(db):
    s1 = db.save_scan("a")
    s2 = db.save_scan("b")
    db.update_scan(s1, status="done", files_scanned=10)
    db.update_scan(s2, status="running")
    fid = db.save_finding(s1, make_finding())

    class Patch:
        original_code = "o"
        patched_code = "p"
        diff = "-o\n+p"

    db.save_patch(fid, Patch(), attempts=1, needs_human=False, confidence=100.0)
    stats = db.get_stats()
    assert stats["total_scans"] == 2
    assert stats["confirmed"] == 1
    assert stats["patches"] == 1
    assert stats["findings"] == 1
    assert stats["success_rate"] == 50.0


def test_clear_removes_everything(db):
    s = db.save_scan("t")
    db.save_finding(s, make_finding())
    db.log_provider_usage("openai", "gpt-4o")
    db.clear()
    assert db.get_stats()["total_scans"] == 0
    assert db.get_all_findings() == []
    assert db.get_reports() == []


def test_cli_stats(capsys, tmp_path):
    db_path = tmp_path / "cli.db"
    db = SQLiteDB(db_path=str(db_path))
    db.save_scan("https://github.com/org/repo")
    rc = db_main(["stats", "--db", str(db_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Total scans" in out and "Success rate" in out
    assert "org/repo" in out


def test_cli_clear_requires_confirmation(tmp_path, monkeypatch, capsys):
    db_path = tmp_path / "cli.db"
    db = SQLiteDB(db_path=str(db_path))
    db.save_scan("t")
    monkeypatch.setattr("builtins.input", lambda prompt="": "yes")
    rc = db_main(["clear", "--db", str(db_path)])
    assert rc == 0
    assert db.get_stats()["total_scans"] == 0
    assert "Cleared all rows" in capsys.readouterr().out


def test_cli_clear_aborts_without_yes(tmp_path, monkeypatch, capsys):
    db_path = tmp_path / "cli.db"
    db = SQLiteDB(db_path=str(db_path))
    db.save_scan("t")
    monkeypatch.setattr("builtins.input", lambda prompt="": "nope")
    rc = db_main(["clear", "--db", str(db_path)])
    assert rc == 1
    assert db.get_stats()["total_scans"] == 1
