"""Release-readiness tests — CI config, SECURITY.md, console scripts,
cve_hunt runner, and the setup wizard. No network, no Docker, no API keys."""

import importlib
import tomllib
from pathlib import Path

import pytest
import yaml

from scripts.cve_hunt import main as hunt_main
from scripts.setup_github_app import main as setup_main

ROOT = Path(__file__).resolve().parents[1]

VULN_APP_PY = '''\
from flask import request

def search():
    name = request.args.get("name")
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    return db.execute(query)
'''


# --- CI workflow -------------------------------------------------------------


def test_ci_workflow_exists_and_valid_yaml():
    path = ROOT / ".github" / "workflows" / "ci.yml"
    assert path.exists(), "ci.yml missing"

    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert data["name"] == "CI"
    # pyyaml (YAML 1.1) parses the `on:` key as the boolean True — GitHub's
    # parser treats it as a string. Accept both.
    triggers = data.get("on") or data.get(True)
    assert "push" in triggers and "pull_request" in triggers
    assert "main" in triggers["push"]["branches"]

    job = data["jobs"]["test"]
    assert job["strategy"]["matrix"]["python-version"] == ["3.11", "3.12"]

    steps = " ".join(
        (step.get("name", "") + " " + step.get("run", "") + " " + step.get("uses", ""))
        for step in job["steps"]
    )
    assert 'pytest tests/ -v --tb=short' in steps
    assert "--cov=blastradius --cov-report=xml" in steps
    assert "upload-artifact" in steps or "actions/upload-artifact" in steps


# --- SECURITY.md -------------------------------------------------------------


def test_security_policy_sections():
    text = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    lowered = text.lower()
    for needle in (
        "security@blastradius.dev",
        "90-day",
        "hall of fame",
        "reporting a vulnerability",
        "disclosure policy",
    ):
        assert needle.lower() in lowered


# --- Console scripts ---------------------------------------------------------


def test_console_scripts_declared_and_importable():
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    scripts = pyproject["project"]["scripts"]
    assert set(scripts) == {
        "blastradius-scan",
        "blastradius-blast",
        "blastradius-server",
        "blastradius-hunt",
    }

    for name, target in scripts.items():
        module_name, _, attr = target.partition(":")
        module = importlib.import_module(module_name)
        assert callable(getattr(module, attr)), f"{name} -> {target}"


# --- cve_hunt ----------------------------------------------------------------


def test_cve_hunt_mocked_targets(tmp_path, capsys, monkeypatch):
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    (fixture / "app.py").write_text(VULN_APP_PY)

    def fake_clone(self, url):
        return str(fixture)

    monkeypatch.setattr("blastradius.hunter.scanner.CVEHunter.clone_repo", fake_clone)

    reports_dir = tmp_path / "cve_out"
    rc = hunt_main(["--reports-dir", str(reports_dir)])
    assert rc == 0

    out = capsys.readouterr().out
    # summary table headers + the 3 default repos
    for header in ("Repo", "Files", "Findings", "Confirmed", "Reports"):
        assert header in out
    for repo in ("WebGoat", "DVWA", "juice-shop"):
        assert repo in out
    # disclosure template printed per confirmed finding
    assert "RESPONSIBLE DISCLOSURE TEMPLATE" in out
    assert "To: security@" in out
    assert "Security Vulnerability Report" in out

    reports = list(reports_dir.glob("*.md"))
    assert len(reports) == 3, "expected one report per (mocked) target"


def test_cve_hunt_custom_target_local(tmp_path, capsys):
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    (fixture / "app.py").write_text(VULN_APP_PY)

    rc = hunt_main(["--target", str(fixture), "--reports-dir", str(tmp_path / "out")])
    assert rc == 0
    out = capsys.readouterr().out
    assert fixture.name in out
    assert "RESPONSIBLE DISCLOSURE TEMPLATE" in out


# --- setup wizard ------------------------------------------------------------


def test_setup_wizard_writes_env(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    # pre-existing .env must be preserved
    (tmp_path / ".env").write_text("AUTH_TOKEN=keepme\n", encoding="utf-8")

    answers = iter([
        "123456",                          # GITHUB_APP_ID
        "-----BEGIN RSA PRIVATE KEY-----\nline2",  # GITHUB_PRIVATE_KEY
        "whsec_test",                      # GITHUB_WEBHOOK_SECRET
        "sk-opencode",                     # OPENCODE_API_KEY
    ])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    monkeypatch.setattr("scripts.setup_github_app.test_webhook_connectivity", lambda: None)

    assert setup_main() == 0

    env = (tmp_path / ".env").read_text(encoding="utf-8")
    assert "GITHUB_APP_ID=123456" in env
    assert "BEGIN RSA PRIVATE KEY" in env
    assert "GITHUB_WEBHOOK_SECRET=whsec_test" in env
    assert "OPENCODE_API_KEY=sk-opencode" in env
    assert "AUTH_TOKEN=keepme" in env  # preserved


def test_setup_wizard_keeps_existing_defaults(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("GITHUB_APP_ID=999\n", encoding="utf-8")

    answers = iter(["", "key-content", "whsec_x", "sk_x"])  # blank = keep default
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    monkeypatch.setattr("scripts.setup_github_app.test_webhook_connectivity", lambda: None)

    assert setup_main() == 0
    env = (tmp_path / ".env").read_text(encoding="utf-8")
    assert "GITHUB_APP_ID=999" in env
