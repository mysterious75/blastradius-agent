"""AutoHunt pipeline tests — discovery and clone mocked, sandbox runs locally."""

from pathlib import Path

import pytest

from blastradius.auto_hunt import main as auto_hunt_main
from blastradius.recon.auto_hunt import AutoHunt, _fp_filter
from blastradius.hunter.scanner import Finding

VULN_APP_PY = """\
from flask import request

def search():
    name = request.args.get("name")
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    return db.execute(query)
"""


@pytest.fixture
def vuln_repo(tmp_path):
    (tmp_path / "app.py").write_text(VULN_APP_PY)
    vendor = tmp_path / "vendor"
    vendor.mkdir()
    (vendor / "lib.js").write_text("el.innerHTML = payload;\n", encoding="utf-8")
    return tmp_path


def test_fp_filter_drops_vendored(tmp_path):
    findings = [
        Finding(
            file=str(tmp_path / "app.py"), line=5, vuln_type="sqli", payload="x", confidence=1.0
        ),
        Finding(
            file=str(tmp_path / "vendor" / "lib.js"),
            line=1,
            vuln_type="xss",
            payload="y",
            confidence=0.95,
        ),
        Finding(
            file=str(tmp_path / "static" / "js" / "bundle.min.js"),
            line=1,
            vuln_type="xss",
            payload="z",
            confidence=0.95,
        ),
    ]
    survivors = _fp_filter(findings)
    assert len(survivors) == 1
    assert survivors[0].vuln_type == "sqli"


def test_auto_hunt_runs_and_saves_reports(vuln_repo, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(
        "blastradius.recon.dorker.DorkEngine.find_targets",
        lambda self, strategy, min_stars=0, limit=200: [
            {
                "repo": "org/demo",
                "url": "https://github.com/org/demo",
                "stars": 500,
                "source": "github",
            },
        ],
    )
    monkeypatch.setattr(
        "blastradius.hunter.scanner.CVEHunter.clone_repo",
        lambda self, url: str(vuln_repo),
    )
    reports_dir = tmp_path / "reports"
    results = AutoHunt(reports_dir=str(reports_dir)).run("github", max_targets=5, min_stars=0)

    assert len(results) == 1
    row = results[0]
    assert row["repo"] == "org/demo"
    assert row["stars"] == 500
    assert row["files"] >= 1
    assert row["confirmed"] == 1
    assert row["severity"] == "CRITICAL"
    assert row["report"] != "-" and Path(row["report"]).exists()

    out = capsys.readouterr().out
    assert "Repo" in out and "Confirmed" in out and "Severity" in out

    # vendor findings were filtered out — only the sqli report is saved
    reports = list(Path(reports_dir).glob("*.md"))
    assert len(reports) == 1
    assert "sqli" in reports[0].name


def test_auto_hunt_cli(vuln_repo, tmp_path, monkeypatch):
    monkeypatch.setattr(
        "blastradius.recon.dorker.DorkEngine.find_targets",
        lambda self, strategy, min_stars=0, limit=200: [
            {
                "repo": "org/demo",
                "url": "https://github.com/org/demo",
                "stars": 500,
                "source": "github",
            },
        ],
    )
    monkeypatch.setattr(
        "blastradius.hunter.scanner.CVEHunter.clone_repo",
        lambda self, url: str(vuln_repo),
    )
    rc = auto_hunt_main(
        [
            "--strategy",
            "github",
            "--max",
            "5",
            "--min-stars",
            "0",
            "--reports-dir",
            str(tmp_path / "reports"),
        ]
    )
    assert rc == 0


def test_auto_hunt_handles_target_errors(vuln_repo, tmp_path, monkeypatch):
    monkeypatch.setattr(
        "blastradius.recon.dorker.DorkEngine.find_targets",
        lambda self, strategy, min_stars=0, limit=200: [
            {
                "repo": "org/demo",
                "url": "https://github.com/org/demo",
                "stars": 500,
                "source": "github",
            },
            {
                "repo": "org/bad",
                "url": "https://github.com/org/bad",
                "stars": 1,
                "source": "github",
            },
        ],
    )
    monkeypatch.setattr(
        "blastradius.hunter.scanner.CVEHunter.clone_repo",
        lambda self, url: (
            str(vuln_repo) if "demo" in url else (_ for _ in ()).throw(RuntimeError("clone failed"))
        ),
    )
    results = AutoHunt(reports_dir=str(tmp_path / "reports")).run(
        "github", max_targets=5, min_stars=0
    )
    by_repo = {r["repo"]: r for r in results}
    assert by_repo["org/demo"]["confirmed"] == 1
    assert by_repo["org/bad"]["confirmed"] == 0
    assert by_repo["org/bad"]["severity"] == "ERR"
