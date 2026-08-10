"""OSV dependency-check script tests — OSV queries mocked, no network."""

import pytest

from scripts.osv_check import check, project_deps


def test_project_deps_parsed():
    deps = project_deps()
    # cai-framework is optional (agent extra) — NOT a core dependency
    assert "cai-framework" not in deps
    assert "rich" in deps
    assert "fastapi" in deps
    assert all(">=" not in d for d in deps)


def test_cai_framework_is_optional():
    import tomllib
    from pathlib import Path

    data = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    extras = data["project"]["optional-dependencies"]
    # cai-framework lives ONLY in the agent extra — NOT in core deps nor in `all`
    assert "cai-framework>=0.5.0" in extras["agent"]
    assert "cai-framework>=0.5.0" not in extras["all"]
    deps = data["project"]["dependencies"]
    assert "cai-framework>=0.5.0" not in deps


def test_check_clean(monkeypatch):
    monkeypatch.setattr("scripts.osv_check.query_osv", lambda pkg, ecosystem="PyPI": [])
    assert check() == 0


def test_check_noncritical_vulns(monkeypatch):
    monkeypatch.setattr("scripts.osv_check.query_osv", lambda pkg, ecosystem="PyPI": [
        {"id": "GHSA-1", "summary": "low severity issue", "database_specific": {"severity": "MODERATE"}},
    ])
    assert check() == 0


def test_check_critical_fails(monkeypatch):
    monkeypatch.setattr("scripts.osv_check.query_osv", lambda pkg, ecosystem="PyPI": [
        {"id": "GHSA-2", "summary": "RCE", "database_specific": {"severity": "CRITICAL"}},
    ])
    assert check() == 1


def test_check_critical_no_fail_flag(monkeypatch):
    monkeypatch.setattr("scripts.osv_check.query_osv", lambda pkg, ecosystem="PyPI": [
        {"id": "GHSA-2", "summary": "RCE", "database_specific": {"severity": "CRITICAL"}},
    ])
    assert check(fail_on_critical=False) == 0


def test_check_osv_unreachable_skips(monkeypatch):
    def boom(pkg, ecosystem="PyPI"):
        raise RuntimeError("network down")

    monkeypatch.setattr("scripts.osv_check.query_osv", boom)
    assert check() == 0  # never fails on OSV unavailability
