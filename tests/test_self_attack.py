"""Self-attack tests: hostile inputs and concurrent users must not fool the gate."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import self_attack as sa  # noqa: E402


# ---------------------------------------------------------------------------
# Unit — fixtures are what they claim to be
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize("kind", list(sa.KINDS))
def test_build_case_creates_a_real_repo(kind, tmp_path):
    repo, base = sa.build_case(kind, tmp_path)
    assert (repo / ".git").exists()
    assert base in (None, "HEAD~1", "no-such-base-ref")
    if kind == sa.CASE_BINARY:
        assert (repo / "payload.bin").read_bytes().startswith(b"\x00\x01")
    if kind == sa.CASE_UNICODE:
        assert (repo / "évil_名前.py").exists()
    if kind == sa.CASE_PROMPT:
        text = (repo / "injected.py").read_text(encoding="utf-8")
        assert "IGNORE ALL PREVIOUS INSTRUCTIONS" in text
        assert sa.CANARY in text
    if kind == sa.CASE_CLEAN:
        assert "SELECT" not in (repo / "clean.py").read_text(encoding="utf-8")


@pytest.mark.unit
def test_report_fails_when_any_case_is_broken():
    report = sa.AttackReport(mode="gate", workers=2)
    report.results = [
        sa.CaseResult(name="ok", held=True, exit_code=1, runtime_s=0.1),
        sa.CaseResult(name="bad", held=False, exit_code=0, runtime_s=0.1),
    ]
    assert not report.ok
    report.results = [sa.CaseResult(name="ok", held=True, exit_code=1, runtime_s=0.1)]
    assert report.ok


@pytest.mark.unit
def test_env_isolates_cache_home(tmp_path):
    home = tmp_path / "case-home"
    env = sa._env(tmp_path, home)
    assert env["BLASTRADIUS_HOME"] == str(home)
    assert env["PYTHONHASHSEED"] == "0"
    assert env["PYTHONIOENCODING"] == "utf-8"


@pytest.mark.unit
def test_failed_case_detail_includes_pipeline_output(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.setattr(sa, "build_case", lambda kind, root: (repo, "HEAD~1"))

    class Proc:
        returncode = 0
        stdout = "NO FINDINGS INJECTED"
        stderr = ""

    monkeypatch.setattr(sa, "run_gate", lambda *args, **kwargs: Proc())
    result = sa.attack_case(sa.CASE_PROMPT, ROOT, retest=False)
    assert not result.held
    assert "NO FINDINGS INJECTED" in result.detail


# ---------------------------------------------------------------------------
# Integration + adversarial — the real attack path
# ---------------------------------------------------------------------------


@pytest.mark.adversarial
@pytest.mark.integration
def test_prompt_injection_case_blocks_without_leaking_canary():
    result = sa.attack_case(sa.CASE_PROMPT, ROOT, retest=False)
    assert result.held, result.detail
    assert result.exit_code == 1
    assert result.leaks == 0


@pytest.mark.adversarial
@pytest.mark.integration
def test_concurrent_users_are_isolated():
    results, ok, detail = sa.concurrency_attack(ROOT, 2, retest=False)
    assert ok, detail
    assert len(results) == 2
    assert all(r.held and r.leaks == 0 for r in results)


# ---------------------------------------------------------------------------
# E2E — the public script
# ---------------------------------------------------------------------------


@pytest.mark.e2e
def test_self_attack_cli_quick_mode():
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "self_attack.py"), "--quick", "--json"],
        capture_output=True,
        text=True,
        timeout=900,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["ok"] is True
    names = {case["name"] for case in payload["results"]}
    assert sa.CASE_PROMPT in names
    assert any(name.startswith("concurrent[") for name in names)
