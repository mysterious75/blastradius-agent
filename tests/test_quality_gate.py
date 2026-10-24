"""Quality-gate tests: the rules must fail closed on their own meta-checks."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import quality_gate as qg  # noqa: E402


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=str(repo), check=True, capture_output=True)


def _repo_with_change(tmp_path: Path, *, with_tests: bool, tiers: str = "unit,integration"):
    repo = tmp_path / "repo"
    repo.mkdir(parents=True)
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "qg@local")
    _git(repo, "config", "user.name", "qg")
    (repo / "README.md").write_text("base\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "base")

    pkg = repo / "blastradius" / "pkg"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "mod.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    if with_tests:
        tests = repo / "tests"
        tests.mkdir()
        markers = "\n".join(f"@pytest.mark.{t}" for t in tiers.split(",") if t)
        tests.joinpath("test_mod.py").write_text(
            "import pytest\n\nfrom blastradius.pkg.mod import f\n\n"
            f"{markers}\ndef test_f():\n    assert f() == 1\n",
            encoding="utf-8",
        )
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "change")
    return repo


# ---------------------------------------------------------------------------
# Unit
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_required_tiers_for_security_surface():
    required = qg.required_tiers(["blastradius/verified_pr/replay.py"])
    assert required == {"unit", "integration", "e2e", "adversarial"}


@pytest.mark.unit
def test_required_tiers_for_internal_module_and_docs():
    assert qg.required_tiers(["blastradius/utils/helpers.py"]) == {
        "unit",
        "integration",
    }
    assert qg.required_tiers(["docs/verified-pr.md", "README.md"]) == set()


@pytest.mark.unit
def test_init_file_is_not_a_source_module():
    assert not qg.is_source("blastradius/verified_pr/__init__.py")
    assert qg.is_source("scripts/self_attack.py")


@pytest.mark.unit
def test_tier_markers_are_detected():
    text = (
        "import pytest\n"
        "pytestmark = pytest.mark.integration\n"
        "@pytest.mark.adversarial\n"
        "def test_x():\n    pass\n"
    )
    assert qg.test_tiers(text) == {"integration", "adversarial"}


@pytest.mark.unit
def test_secret_patterns_are_high_signal():
    names = {name for name, _ in qg.SECRET_PATTERNS}
    assert {"github-token", "private-key", "aws-access-key"} <= names
    joined = "\n".join(p.pattern for _, p in qg.SECRET_PATTERNS)
    assert "AKIA" in joined


@pytest.mark.unit
def test_checklist_renders_failure_detail():
    report = qg.Report(base="HEAD~1", changed=["x.py"], required=["unit"])
    report.checks = [
        qg.Check("test-tiers", False, "missing markers: e2e"),
        qg.Check("no-secrets", True),
    ]
    text = qg.render_checklist(report)
    assert "Gate: **FAIL**" in text
    assert "missing markers: e2e" in text
    assert "- [x] `no-secrets`" in text


# ---------------------------------------------------------------------------
# Integration
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_gate_passes_with_unit_and_integration_tests(tmp_path):
    repo = _repo_with_change(tmp_path, with_tests=True)
    report = qg.build_report(repo, "HEAD~1", lint=False, secrets=True)
    assert report.ok, [c for c in report.failed()]
    assert "test-reference" in {c.name for c in report.checks}
    assert "test-tiers" in {c.name for c in report.checks}


@pytest.mark.integration
def test_gate_fails_without_tests(tmp_path):
    repo = _repo_with_change(tmp_path, with_tests=False)
    report = qg.build_report(repo, "HEAD~1", lint=False, secrets=True)
    assert not report.ok
    names = {c.name for c in report.failed()}
    assert {"test-reference", "test-tiers"} <= names


@pytest.mark.integration
def test_gate_requires_e2e_and_adversarial_for_security_path(tmp_path):
    repo = _repo_with_change(tmp_path, with_tests=True, tiers="unit,integration")
    pkg = repo / "blastradius" / "verified_pr"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "gate.py").write_text("def gate():\n    return 'BLOCK'\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "security surface")
    report = qg.build_report(repo, "HEAD~2", lint=False, secrets=True)
    failed = {c.name: c.detail for c in report.failed()}
    assert "test-tiers" in failed
    assert "e2e" in failed["test-tiers"] and "adversarial" in failed["test-tiers"]


@pytest.mark.integration
def test_secret_scan_catches_canary_but_not_fixture_paths(tmp_path):
    repo = _repo_with_change(tmp_path, with_tests=True)
    (repo / "leak.py").write_text('KEY = "AKIA' + "A" * 16 + '"\n', encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "leak")
    hits = qg.secret_hits(repo, "HEAD~1")
    assert any(name == "aws-access-key" for _, name, _ in hits)


@pytest.mark.integration
def test_untracked_files_are_scanned_not_fail_open(tmp_path):
    repo = _repo_with_change(tmp_path, with_tests=True)
    (repo / "new_leak.py").write_text('KEY = "AKIA' + "A" * 16 + '"\n', encoding="utf-8")
    assert "new_leak.py" in qg.git_changed_files(repo, "HEAD~1")
    hits = qg.secret_hits(repo, "HEAD~1")
    assert any(f == "new_leak.py" and name == "aws-access-key" for f, name, _ in hits)


# ---------------------------------------------------------------------------
# E2E
# ---------------------------------------------------------------------------


@pytest.mark.e2e
def test_cli_gate_exit_codes_end_to_end(tmp_path):
    repo = _repo_with_change(tmp_path, with_tests=True)
    cmd = [
        sys.executable,
        str(ROOT / "scripts" / "quality_gate.py"),
        "--repo",
        str(repo),
        "--base",
        "HEAD~1",
        "--no-lint",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "Gate: **PASS**" in proc.stdout

    bad = _repo_with_change(tmp_path / "bad", with_tests=False)
    proc = subprocess.run(
        cmd[:2] + ["--repo", str(bad), "--base", "HEAD~1", "--no-lint"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 1
    assert "Gate: **FAIL**" in proc.stdout
