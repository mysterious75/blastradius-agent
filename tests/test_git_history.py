"""Git-history secret scanning tests (truffleHog-style) — real local git repos.

The fixture repo commits a secret in an OLD commit, removes it in a NEW
commit, and leaves the working tree CLEAN — so a secret finding can only
come from `scan_git_history`, never from `scan_repo`.
"""

import subprocess

import pytest

from blastradius.hunter.scanner import CVEHunter, VULN_META

SECRET = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


def _git(repo, *args):
    subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )


@pytest.fixture
def history_repo(tmp_path):
    """Repo whose OLD commit contains a secret and whose NEW commit removes it."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test")
    (repo / "config.py").write_text(f'API_KEY = "{SECRET}"\n', encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "add secret")
    (repo / "config.py").write_text('API_KEY = "clean"\n', encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "remove secret")
    return repo


def test_git_history_finds_committed_secret(history_repo):
    hunter = CVEHunter()
    findings = hunter.scan_git_history(str(history_repo))
    history = [f for f in findings if f.vuln_type == "secret_history"]
    assert history, "expected at least one secret_history finding"
    assert any("sk-" in f.payload for f in history)
    for f in history:
        assert "commit " in f.evidence
        assert f.confidence == 0.95
        assert f.severity == "HIGH"
        assert f.cwe == "CWE-798"
        assert "CWE-798" in f.remediation or f.remediation


def test_working_tree_clean_scan_repo_finds_no_secret(history_repo):
    hunter = CVEHunter()
    # the secret was removed from the working tree -> no 'secret' findings
    assert not any(f.vuln_type == "secret" for f in hunter.scan_repo(str(history_repo)))
    # but history still holds it (proves history-only detection)
    assert any(f.vuln_type == "secret_history" for f in hunter.scan_git_history(str(history_repo)))


def test_git_history_empty_for_non_repo(tmp_path):
    hunter = CVEHunter()
    assert hunter.scan_git_history(str(tmp_path)) == []


def test_secret_history_meta():
    meta = VULN_META["secret_history"]
    assert meta["severity"] == "HIGH"
    assert meta["cvss"] == 8.0
    assert meta["cwe"] == "CWE-798"
    assert "HISTORY" in meta["description"].upper()
