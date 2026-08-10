"""Scope registry tests — deterministic, tmp scopes dir, no network."""

import pytest

from blastradius.scope import (
    _matches,
    check_scope,
    list_programs,
    remove_scope,
    save_scope,
    scopes_dir,
)


@pytest.fixture
def scopes(tmp_path, monkeypatch):
    monkeypatch.setenv("BLASTRADIUS_SCOPES_DIR", str(tmp_path))
    return tmp_path


def test_save_and_load_roundtrip(scopes):
    save_scope("acme", ["acme.com"], ["*.acme.com", "internal.acme.com"])
    loaded = check_scope("https://acme.com", "acme")
    assert loaded["in_scope"] is True
    assert "acme" in list_programs()


def test_save_merges_entries(scopes):
    save_scope("acme", ["acme.com"], [])
    save_scope("acme", ["api.acme.com"], ["blocked.acme.com"])
    scope = check_scope("https://api.acme.com", "acme")
    assert scope["in_scope"] is True
    blocked = check_scope("https://blocked.acme.com", "acme")
    assert blocked["in_scope"] is False
    assert "explicitly out of scope" in blocked["reason"]


def test_subdomain_matches_domain_entry(scopes):
    save_scope("acme", ["acme.com"], [])
    assert check_scope("https://deep.sub.acme.com/x", "acme")["in_scope"] is True


def test_out_of_scope_wins(scopes):
    save_scope("acme", ["acme.com"], ["admin.acme.com"])
    assert check_scope("https://admin.acme.com", "acme")["in_scope"] is False


def test_repo_url_matching(scopes):
    save_scope("cf", ["https://github.com/cloudflare/workerd"], [])
    assert check_scope("https://github.com/cloudflare/workerd/src", "cf")["in_scope"] is True
    assert check_scope("https://github.com/cloudflare/cloudflared", "cf")["in_scope"] is False


def test_default_deny(scopes):
    save_scope("acme", ["acme.com"], [])
    result = check_scope("https://example.com")
    assert result["in_scope"] is False
    assert result["program"] is None
    assert "default deny" in result["reason"]


def test_unregistered_program_is_denied(scopes):
    result = check_scope("https://acme.com", "nope")
    assert result["in_scope"] is False
    assert "no scope registered" in result["reason"]


def test_remove_scope(scopes):
    save_scope("acme", ["acme.com"], [])
    assert remove_scope("acme") is True
    assert remove_scope("acme") is False
    assert list_programs() == []


def test_matches_edge_cases():
    assert _matches("example.com", "https://example.com/")
    assert _matches("example.com", "EXAMPLE.COM")
    assert _matches("https://github.com/a/b", "https://github.com/a/b/c")
    assert not _matches("example.com", "notexample.com")
