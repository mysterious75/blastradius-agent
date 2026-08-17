"""SCA lockfile + OSV tests — offline (network mocked, cache isolated to tmp)."""

import json

import pytest

from blastradius import sca
from blastradius.cli.main import main as cli_main

OSV_CANNED = {
    "results": [
        {
            "vulns": [
                {
                    "id": "GHSA-1234",
                    "aliases": ["CVE-2021-0001"],
                    "summary": "Bad thing in flask",
                    "database_specific": {"severity": "HIGH"},
                    "ranges": [
                        {
                            "type": "SEMVER",
                            "events": [{"introduced": "0"}, {"fixed": "3.0.1"}],
                        }
                    ],
                }
            ]
        }
    ]
}


@pytest.fixture
def cache_db(tmp_path, monkeypatch):
    """Point the SCA module's cache at an isolated tmp SQLite DB."""
    from blastradius.db.database import SQLiteDB

    db = SQLiteDB(db_path=str(tmp_path / "sca.db"))
    monkeypatch.setattr("blastradius.sca.SQLiteDB", lambda: db)
    return db


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self._payload


def fake_urlopen(payload):
    def _urlopen(req, timeout=30):
        return FakeResponse(json.dumps(payload).encode("utf-8"))

    return _urlopen


# ---------------------------------------------------------------------------
# Lockfile parsing
# ---------------------------------------------------------------------------


def test_parse_requirements(tmp_path):
    lock = tmp_path / "requirements.txt"
    lock.write_text("flask==3.0.0\n# comment\n-e .\n", encoding="utf-8")
    assert sca.parse_lockfiles(tmp_path) == [
        {"ecosystem": "PyPI", "name": "flask", "version": "3.0.0"}
    ]


def test_parse_package_lock(tmp_path):
    lock = tmp_path / "package-lock.json"
    lock.write_text(
        json.dumps(
            {
                "name": "app",
                "version": "1.0.0",
                "lockfileVersion": 2,
                "dependencies": {"lodash": {"version": "4.17.21"}},
            }
        ),
        encoding="utf-8",
    )
    pkgs = sca.parse_lockfiles(tmp_path)
    assert {"ecosystem": "npm", "name": "lodash", "version": "4.17.21"} in pkgs


def test_parse_poetry_lock(tmp_path):
    lock = tmp_path / "poetry.lock"
    lock.write_text(
        '[[package]]\nname = "requests"\nversion = "2.31.0"\n\n'
        '[[package]]\nname = "urllib3"\nversion = "2.0.0"\n',
        encoding="utf-8",
    )
    pkgs = sca.parse_lockfiles(tmp_path)
    assert {"ecosystem": "PyPI", "name": "requests", "version": "2.31.0"} in pkgs
    assert {"ecosystem": "PyPI", "name": "urllib3", "version": "2.0.0"} in pkgs


def test_parse_go_mod(tmp_path):
    lock = tmp_path / "go.mod"
    lock.write_text(
        "module example.com/app\n\ngo 1.21\n\nrequire (\n"
        "\tgithub.com/foo/bar v1.2.3 // indirect\n"
        "\tgolang.org/x/net v0.10.0\n)\n",
        encoding="utf-8",
    )
    pkgs = sca.parse_lockfiles(tmp_path)
    assert {"ecosystem": "Go", "name": "github.com/foo/bar", "version": "v1.2.3"} in pkgs
    assert {"ecosystem": "Go", "name": "golang.org/x/net", "version": "v0.10.0"} in pkgs


def test_parse_composer_lock(tmp_path):
    lock = tmp_path / "composer.lock"
    lock.write_text(
        json.dumps({"packages": [{"name": "symfony/console", "version": "v6.4.0"}]}),
        encoding="utf-8",
    )
    pkgs = sca.parse_lockfiles(tmp_path)
    assert {"ecosystem": "Packagist", "name": "symfony/console", "version": "6.4.0"} in pkgs


# ---------------------------------------------------------------------------
# OSV querying + cache
# ---------------------------------------------------------------------------


def test_query_osv_mock(cache_db, monkeypatch):
    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen(OSV_CANNED))
    results = sca.query_osv([{"ecosystem": "PyPI", "name": "flask", "version": "3.0.0"}])
    assert len(results) == 1
    assert results[0]["package"]["ecosystem"] == "PyPI"
    assert results[0]["package"]["name"] == "flask"
    advisories = results[0]["advisories"]
    assert len(advisories) == 1
    advisory = advisories[0]
    assert advisory["id"] == "GHSA-1234"
    assert advisory["aliases"] == ["CVE-2021-0001"]
    assert advisory["severity"] == "HIGH"
    assert advisory["fixed"] == "3.0.1"
    assert advisory["summary"] == "Bad thing in flask"


def test_offline_cache_fallback(cache_db, monkeypatch):
    def boom(req, timeout=30):
        raise OSError("network unreachable")

    monkeypatch.setattr("urllib.request.urlopen", boom)
    results = sca.query_osv([{"ecosystem": "PyPI", "name": "flask", "version": "3.0.0"}])
    assert results == []
    assert sca.network_available is False


def test_cache_used_when_network_down(cache_db, monkeypatch):
    pkg = {"ecosystem": "PyPI", "name": "flask", "version": "3.0.0"}
    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen(OSV_CANNED))
    first = sca.query_osv([pkg])
    assert first[0]["advisories"]

    def boom(req, timeout=30):
        raise OSError("network unreachable")

    monkeypatch.setattr("urllib.request.urlopen", boom)
    second = sca.query_osv([pkg])
    assert second[0]["advisories"][0]["id"] == "GHSA-1234"
    # cache hit serves the result without touching the network
    assert sca.network_available is True


# ---------------------------------------------------------------------------
# Summary + CLI
# ---------------------------------------------------------------------------


def test_summarize_counts():
    results = [
        {
            "package": {"ecosystem": "PyPI", "name": "a", "version": "1"},
            "advisories": [
                {"id": "1", "aliases": [], "severity": "CRITICAL", "summary": None, "fixed": "2"},
                {"id": "2", "aliases": [], "severity": "HIGH", "summary": None, "fixed": None},
                {"id": "3", "aliases": [], "severity": "bogus", "summary": None, "fixed": None},
            ],
        },
        {"package": {"ecosystem": "npm", "name": "b", "version": "1"}, "advisories": []},
    ]
    counts = sca.summarize(results)
    assert counts["CRITICAL"] == 1
    assert counts["HIGH"] == 1
    assert counts["UNKNOWN"] == 1
    assert counts["LOW"] == 0


def test_cli_no_lockfiles(tmp_path, capsys):
    rc = cli_main(["sca", "--repo", str(tmp_path)])
    assert rc == 0
    assert "lockfiles" in capsys.readouterr().out
