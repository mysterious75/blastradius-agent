"""Findings export tests — stdlib only, no network."""

import csv
import json

import pytest

from blastradius.export.cli import main as export_main
from blastradius.export.exporter import FindingsExporter

SAMPLE = [
    {"repo": "org/demo", "file": "src/app.py", "line": 42, "vuln_type": "sqli",
     "severity": "CRITICAL", "cvss": 9.8, "status": "open",
     "payload": "query = \"SELECT * FROM users WHERE name = '\" + name + \"'\"",
     "description": "SQL injection in search", "cwe": "CWE-89",
     "remediation": "parameterize", "patch_diff": "-a\n+b"},
    {"repo": "org/demo", "file": "views.js", "line": 7, "vuln_type": "xss",
     "severity": "HIGH", "cvss": 6.1, "status": "disclosed",
     "cve_id": "CVE-2026-0001", "bounty_usd": 500,
     "payload": "el.innerHTML = data;", "description": "DOM XSS", "cwe": "CWE-79",
     "remediation": "escape"},
]


@pytest.fixture
def exporter():
    return FindingsExporter(SAMPLE)


def test_export_csv(exporter, tmp_path):
    out = tmp_path / "f.csv"
    exporter.export_csv(str(out))
    with open(out, newline="", encoding="utf-8") as fh:
        rows = list(csv.reader(fh))
    assert rows[0] == ["ID", "Repo", "File", "Line", "Type", "Severity", "CVSS",
                       "Status", "Disclosed", "CVE_ID", "Bounty", "Description"]
    assert rows[1][1] == "org/demo" and rows[1][4] == "sqli" and rows[1][7] == "open"
    assert rows[2][9] == "CVE-2026-0001" and rows[2][10] == "500"


def test_export_json(exporter, tmp_path):
    out = tmp_path / "f.json"
    exporter.export_json(str(out))
    data = json.loads(out.read_text(encoding="utf-8"))
    assert len(data) == 2
    assert data[0]["patch_diff"] == "-a\n+b"
    assert data[1]["cve_id"] == "CVE-2026-0001"


def test_export_sarif(exporter, tmp_path):
    out = tmp_path / "f.sarif"
    exporter.export_sarif(str(out))
    sarif = json.loads(out.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "BlastRadius"
    assert len(run["results"]) == 2
    first = run["results"][0]
    assert first["level"] == "error"
    assert first["locations"][0]["physicalLocation"]["region"]["startLine"] == 42


def test_export_html(exporter, tmp_path):
    out = tmp_path / "f.html"
    exporter.export_html_report(str(out))
    html = out.read_text(encoding="utf-8")
    assert "BlastRadius Security Report" in html
    assert "chart.js" in html  # Chart.js via CDN
    assert "src/app.py" in html and "SQLI" in html


def test_export_markdown(exporter, tmp_path):
    out = tmp_path / "f.md"
    exporter.export_markdown(str(out))
    md = out.read_text(encoding="utf-8")
    assert "| # | File | Line | Type | Severity | Payload |" in md
    assert "`src/app.py`" in md and "CRITICAL" in md


def test_cli_with_input_file(tmp_path):
    src = tmp_path / "in.json"
    src.write_text(json.dumps(SAMPLE), encoding="utf-8")
    out = tmp_path / "out.sarif"
    rc = export_main(["--format", "sarif", "--output", str(out), "--input", str(src)])
    assert rc == 0
    assert json.loads(out.read_text(encoding="utf-8"))["version"] == "2.1.0"


def test_cli_from_db(tmp_path, monkeypatch, capsys):
    from blastradius.db.database import SQLiteDB

    db = SQLiteDB(db_path=str(tmp_path / "e.db"))
    from blastradius.hunter.scanner import Finding

    scan_id = db.save_scan("t")
    db.save_finding(scan_id, Finding(file="a.py", line=1, vuln_type="sqli", payload="p",
                                     confidence=0.9, severity="HIGH", cwe="CWE-89",
                                     description="d", remediation="r"))
    monkeypatch.setattr("blastradius.export.cli.SQLiteDB", lambda: db)
    out = tmp_path / "out.csv"
    rc = export_main(["--format", "csv", "--output", str(out)])
    assert rc == 0
    text = out.read_text(encoding="utf-8")
    assert "sqli" in text and "a.py" in text
    assert "exported 1 finding(s)" in capsys.readouterr().out
