"""Scope-gate wiring tests — every URL-accepting CLI honors --scope (default deny).

Uses a tmp scopes dir (BLASTRADIUS_SCOPES_DIR) so no real registry is touched.
"""

import pytest

from blastradius.scope import require_scope, save_scope


@pytest.fixture
def scopes(tmp_path, monkeypatch):
    monkeypatch.setenv("BLASTRADIUS_SCOPES_DIR", str(tmp_path))
    save_scope("acme", ["acme.com"], ["evil.acme.com"])
    return tmp_path


# --- require_scope helper -------------------------------------------------


def test_require_scope_passes_local_path_without_program(scopes):
    assert require_scope("./local/path", None) is True
    assert require_scope("./local/path", "acme") is True


def test_require_scope_passes_in_scope_url(scopes, capsys):
    assert require_scope("https://acme.com/app", "acme") is True
    assert "BLOCKED" not in capsys.readouterr().out


def test_require_scope_blocks_out_of_scope_url(scopes, capsys):
    assert require_scope("https://evil.acme.com/x", "acme") is False
    assert "BLOCKED" in capsys.readouterr().out


def test_require_scope_blocks_unregistered_program(scopes, capsys):
    assert require_scope("https://acme.com/", "nosuch") is False
    assert "BLOCKED" in capsys.readouterr().out


# --- CLI wiring ------------------------------------------------------------


def test_web_cli_blocks_out_of_scope(scopes):
    from blastradius.web.cli import main

    rc = main(["--target", "https://evil.acme.com/", "--scope", "acme", "--max-urls", "1"])
    assert rc == 2


def test_hunter_cli_blocks_out_of_scope_repo(scopes):
    from blastradius.hunter.cli import main

    rc = main(["--target", "https://evil.acme.com/repo", "--scope", "acme"])
    assert rc == 2


def test_agents_cli_blocks_out_of_scope(scopes):
    from blastradius.agents.cli import main

    rc = main(["--target", "https://evil.acme.com/repo", "--scope", "acme"])
    assert rc == 2


def test_pipeline_cli_blocks_out_of_scope(scopes):
    from blastradius.pipeline_cli import main

    rc = main(["--target", "https://evil.acme.com/repo", "--scope", "acme"])
    assert rc == 2


def test_auto_hunt_filters_out_of_scope(scopes, monkeypatch):
    from blastradius.recon.auto_hunt import AutoHunt
    from blastradius.scope import save_scope

    # repo URLs need repo-prefix scope entries (host is github.com)
    save_scope("acme-repos", ["https://github.com/acme/ok"], [])

    seen = []

    class FakeDork:
        def find_targets(self, strategy, min_stars=0, limit=100):
            return [
                {"url": "https://github.com/acme/ok", "repo": "acme/ok", "stars": 5},
                {"url": "https://github.com/evil/bad", "repo": "evil/bad", "stars": 5},
            ]

    class FakeHunter:
        files_scanned = 1

        def clone_repo(self, url):
            seen.append(url)
            return "/tmp/x"

        def scan_repo(self, path):
            return []

    hunt = AutoHunt(dork_engine=FakeDork(), hunter=FakeHunter())
    rows = hunt.run("github", max_targets=10, scope="acme-repos")
    assert seen == ["https://github.com/acme/ok"]
    assert all("evil" not in r["repo"] for r in rows)


# --- net CLI: mandatory scope for non-lab targets -------------------------


def test_net_cli_blocks_external_without_scope(scopes, capsys):
    from blastradius.net.cli import main

    rc = main(["--target", "scanme.nmap.org", "--ports", "22"])
    assert rc == 2
    assert "BLOCKED" in capsys.readouterr().out


def test_net_cli_blocks_external_out_of_scope(scopes):
    from blastradius.net.cli import main

    rc = main(["--target", "evil.acme.com", "--ports", "22", "--scope", "acme"])
    assert rc == 2


def test_net_cli_lab_target_needs_no_scope(scopes, tmp_path):
    from blastradius.net.cli import main

    # Port 1 is closed in CI sandboxes: scan completes with 0 findings.
    rc = main(["--target", "127.0.0.1", "--ports", "1", "--reports-dir", str(tmp_path)])
    assert rc == 0


# --- enforce_scope: fail-closed (no silent opt-out) ----------------------


def test_enforce_scope_local_paths_always_pass(scopes, tmp_path):
    from blastradius.scope import enforce_scope

    assert enforce_scope("./local/path", None) is True
    assert enforce_scope(str(tmp_path), "acme") is True
    assert enforce_scope("myrepo", None) is True  # dotless name: a path, not a host


def test_enforce_scope_lab_targets_pass_without_program(scopes):
    from blastradius.scope import enforce_scope

    assert enforce_scope("http://127.0.0.1:8000/", None) is True
    assert enforce_scope("http://localhost:3000/", None) is True
    assert enforce_scope("http://lab.invalid/", None) is True
    assert enforce_scope("http://192.168.1.10/", None) is True


def test_enforce_scope_url_without_program_blocked(scopes, capsys):
    from blastradius.scope import enforce_scope

    assert enforce_scope("https://acme.com/app", None) is False
    assert "BLOCKED" in capsys.readouterr().out


def test_enforce_scope_bare_hostname_is_a_network_target(scopes, capsys):
    from blastradius.scope import enforce_scope

    assert enforce_scope("scanme.nmap.org", None) is False
    assert "BLOCKED" in capsys.readouterr().out


def test_enforce_scope_registered_program_still_checked(scopes, capsys):
    from blastradius.scope import enforce_scope

    assert enforce_scope("https://acme.com/app", "acme") is True
    assert enforce_scope("https://evil.acme.com/x", "acme") is False
    assert "BLOCKED" in capsys.readouterr().out


def test_web_cli_blocks_url_without_scope(scopes):
    from blastradius.web.cli import main

    assert main(["--target", "https://example.com/", "--max-urls", "1"]) == 2


def test_hunter_cli_blocks_url_without_scope(scopes):
    from blastradius.hunter.cli import main

    assert main(["--target", "https://github.com/acme/app"]) == 2


def test_agents_cli_blocks_url_without_scope(scopes):
    from blastradius.agents.cli import main

    assert main(["--target", "https://github.com/acme/app"]) == 2


def test_pipeline_cli_blocks_url_without_scope(scopes):
    from blastradius.pipeline_cli import main

    assert main(["--target", "https://github.com/acme/app"]) == 2


def test_hunter_cli_local_path_needs_no_scope(scopes, tmp_path):
    from blastradius.hunter.cli import main

    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    rc = main(["--target", str(tmp_path), "--reports-dir", str(tmp_path / "rep")])
    assert rc in (0, 1)  # scanned; never scope-blocked (2)
