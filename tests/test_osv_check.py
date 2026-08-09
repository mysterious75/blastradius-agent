"""OSV dependency-check script tests — OSV queries mocked, no network."""

import pytest

from scripts.osv_check import check, project_deps


def test_project_deps_parsed():
    deps = project_deps()
    assert "cai-framework" in deps
    assert "rich" in deps
    assert all(">=" not in d for d in deps)


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
