"""Shadow-repository recon tests: fully offline, injected transports only."""

import pytest

from blastradius.recon.shadow_repo import (
    GITHUB_API,
    SENSITIVE_ASSET_LABELS,
    ShadowAsset,
    ShadowReconReport,
    ShadowRepoRecon,
    shadow_recon,
)

AWS_KEY = "AKIAQYLPMN5HHHFPZAM2"
AWS_PLACEHOLDER_KEY = "AKIAIOSFODNN7EXAMPLE"


def _api_fixture(contributors, repos=None, gists=None, releases=None):
    repos = repos or {}
    gists = gists or {}
    releases = releases or {}
    calls = []

    def http_json(url):
        calls.append(url)
        if url.endswith("/contributors?per_page=100"):
            return [{"login": c} for c in contributors]
        for login, data in repos.items():
            if url.startswith(f"{GITHUB_API}/users/{login}/repos"):
                return data
        for login, data in gists.items():
            if url.startswith(f"{GITHUB_API}/users/{login}/gists"):
                return data
        for key, data in releases.items():
            if url == f"{GITHUB_API}{key}":
                return data
        return []

    return http_json, calls


# ---------------------------------------------------------------------------
# Name classification
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name,label",
    [
        ("id_rsa", "private-key"),
        ("deploy.pem", "private-key"),
        ("server.key", "private-key"),
        ("release.asc", "private-key"),
        ("trezor-wallet.txt", "seed-phrase"),
        ("seed_phrase.md", "seed-phrase"),
        ("vault.kdbx", "seed-phrase"),
        ("prod-backup.sql", "database-dump"),
        ("users.sqlite3", "database-dump"),
        ("db.dump", "database-dump"),
        ("credentials.json", "cloud-credential"),
        ("secrets.yaml", "cloud-credential"),
        ("service_account.json", "cloud-credential"),
        (".env", "credential-file"),
        ("prod.env.local", "credential-file"),
        ("client.jks", "credential-file"),
    ],
)
def test_sensitive_names_classified(name, label):
    assert ShadowAsset("alice", "gist", name, "https://x").name_hit == label


@pytest.mark.parametrize("name", ["README.md", "index.html", "main.go", "package.json"])
def test_benign_names_not_classified(name):
    assert ShadowAsset("alice", "repo", name, "https://x").name_hit is None


def test_labels_exported():
    assert set(SENSITIVE_ASSET_LABELS) == {
        "private-key",
        "seed-phrase",
        "database-dump",
        "cloud-credential",
        "credential-file",
    }


# ---------------------------------------------------------------------------
# Sweep
# ---------------------------------------------------------------------------


def test_sweep_reports_contributor_gist_key():
    http_json, _ = _api_fixture(
        ["alice", "bob"],
        repos={
            "alice": [{"name": "website", "html_url": "https://github.com/alice/website"}],
            "bob": [],
        },
        gists={
            "alice": [
                {
                    "html_url": "https://gist.github.com/alice/1",
                    "files": {"id_rsa": {}, "notes.md": {}},
                }
            ],
            "bob": [],
        },
    )
    report = shadow_recon("acme/app", http_json=http_json, confirm_content=False)
    assert isinstance(report, ShadowReconReport)
    assert report.contributors == ["alice", "bob"]
    assert len(report.findings) == 1
    f = report.findings[0]
    assert f.vuln_type == "shadow-repo-exposure"
    assert f.payload == "private-key"
    assert f.severity == "CRITICAL"
    assert f.cwe == "CWE-200"
    assert "alice" in f.file
    assert f.line == 0
    assert "not validated or used" in f.description


def test_sweep_clean_when_nothing_sensitive():
    http_json, _ = _api_fixture(
        ["alice"],
        repos={"alice": [{"name": "website", "html_url": "u"}]},
        gists={"alice": [{"html_url": "g", "files": {"readme.md": {}}}]},
    )
    report = shadow_recon("acme/app", http_json=http_json, confirm_content=False)
    assert report.findings == []
    assert report.assets


def test_release_assets_included():
    http_json, _ = _api_fixture(
        ["alice"],
        repos={"alice": [{"name": "tool", "html_url": "u"}]},
        gists={"alice": []},
        releases={
            "/repos/alice/tool/releases?per_page=20": [
                {"assets": [{"name": "backup.sql", "browser_download_url": "b"}]}
            ]
        },
    )
    report = shadow_recon("acme/app", http_json=http_json, confirm_content=False)
    assert [f.payload for f in report.findings] == ["database-dump"]
    assert report.findings[0].severity == "HIGH"


def test_repos_endpoint_fetched_once_per_contributor():
    http_json, calls = _api_fixture(["alice"], repos={"alice": []}, gists={"alice": []})
    shadow_recon("acme/app", http_json=http_json, confirm_content=False)
    assert sum(1 for c in calls if "/users/alice/repos" in c) == 1


def test_max_contributors_respected():
    http_json, _ = _api_fixture(["a", "b", "c", "d"], repos={}, gists={})
    recon = ShadowRepoRecon(http_json=http_json, max_contributors=2, confirm_content=False)
    assert recon.run("acme/app").contributors == ["a", "b"]


# ---------------------------------------------------------------------------
# Content confirmation
# ---------------------------------------------------------------------------


def test_benign_name_with_live_secret_confirmed():
    http_json, _ = _api_fixture(
        ["alice"],
        repos={"alice": []},
        gists={"alice": [{"html_url": "https://gist.example/raw/config", "files": {"config": {}}}]},
    )

    def http_text(url):
        return f"AWS_ACCESS_KEY_ID={AWS_KEY}\nAWS_SECRET_ACCESS_KEY=abcd1234\n"

    report = shadow_recon(
        "acme/app", http_json=http_json, http_text=http_text, confirm_content=True
    )
    assert len(report.findings) == 1
    f = report.findings[0]
    assert f.payload == "cloud-credential"
    assert f.confidence == 0.9
    assert "confirmed" in f.evidence


def test_repository_page_is_never_fetched():
    http_json, _ = _api_fixture(
        ["alice"],
        repos={"alice": [{"name": "dotfiles", "html_url": "https://github.com/alice/dotfiles"}]},
        gists={"alice": []},
    )
    fetched = []

    def http_text(url):
        fetched.append(url)
        return AWS_KEY

    report = shadow_recon(
        "acme/app", http_json=http_json, http_text=http_text, confirm_content=True
    )
    assert fetched == []
    assert report.findings == []


def test_content_confirmation_off_skips_fetch():
    http_json, _ = _api_fixture(
        ["alice"],
        repos={"alice": []},
        gists={"alice": [{"html_url": "https://gist.example/raw/config", "files": {"config": {}}}]},
    )
    fetched = []

    def http_text(url):
        fetched.append(url)
        return AWS_KEY

    report = shadow_recon(
        "acme/app", http_json=http_json, http_text=http_text, confirm_content=False
    )
    assert report.findings == []
    assert fetched == []


def test_placeholder_content_not_confirmed():
    http_json, _ = _api_fixture(
        ["alice"],
        repos={"alice": []},
        gists={"alice": [{"html_url": "https://gist.example/raw/config", "files": {"config": {}}}]},
    )
    report = shadow_recon(
        "acme/app",
        http_json=http_json,
        http_text=lambda u: f"AWS_ACCESS_KEY_ID={AWS_PLACEHOLDER_KEY}  # example placeholder",
        confirm_content=True,
    )
    assert report.findings == []


def test_binary_asset_not_fetched():
    http_json, _ = _api_fixture(
        ["alice"],
        repos={"alice": []},
        gists={"alice": [{"html_url": "https://gist.example/raw/logo", "files": {"logo.png": {}}}]},
    )
    fetched = []

    def http_text(url):
        fetched.append(url)
        return AWS_KEY

    shadow_recon("acme/app", http_json=http_json, http_text=http_text, confirm_content=True)
    assert fetched == []


def test_content_fetch_cap_enforced():
    files = {f"r{i}.txt": {} for i in range(10)}
    http_json, _ = _api_fixture(
        ["alice"],
        repos={"alice": []},
        gists={"alice": [{"html_url": "https://g/raw", "files": files}]},
    )
    fetched = []

    def http_text(url):
        fetched.append(url)
        return "nothing here"

    ShadowRepoRecon(
        http_json=http_json, http_text=http_text, confirm_content=True, max_content_fetches=3
    ).run("acme/app")
    assert len(fetched) == 3


# ---------------------------------------------------------------------------
# Failure handling (fail closed, never a fabricated clean result)
# ---------------------------------------------------------------------------


def test_contributor_lookup_failure_returns_error_and_no_findings():
    def boom(url):
        raise OSError("api down")

    report = shadow_recon("acme/app", http_json=boom)
    assert report.contributors == []
    assert report.findings == []
    assert any("contributor lookup failed" in e for e in report.errors)


def test_asset_lookup_failure_recorded_but_sweep_completes():
    def http_json(url):
        if url.endswith("/contributors?per_page=100"):
            return [{"login": "alice"}]
        if "/users/alice/repos" in url:
            return [{"name": "site", "html_url": "u"}]
        if "/users/alice/gists" in url:
            raise OSError("403 rate limited")
        return []

    report = shadow_recon("acme/app", http_json=http_json, confirm_content=False)
    assert any("gists" in e for e in report.errors)
    assert isinstance(report, ShadowReconReport)


def test_content_fetch_failure_recorded():
    http_json, _ = _api_fixture(
        ["alice"],
        repos={"alice": []},
        gists={"alice": [{"html_url": "https://gist.example/raw/config", "files": {"config": {}}}]},
    )

    def http_text(url):
        raise OSError("404")

    report = shadow_recon(
        "acme/app", http_json=http_json, http_text=http_text, confirm_content=True
    )
    assert report.findings == []
    assert any("gist.example" in e for e in report.errors)


def test_non_list_response_tolerated():
    def http_json(url):
        if url.endswith("/contributors?per_page=100"):
            return [{"login": "alice"}]
        return {"message": "Not Found"}

    report = shadow_recon("acme/app", http_json=http_json, confirm_content=False)
    assert report.assets == []


def test_recon_instance_reusable_across_sweeps():
    http_json, _ = _api_fixture(["alice"], repos={"alice": []}, gists={"alice": []})
    recon = ShadowRepoRecon(http_json=http_json, confirm_content=False)
    first = recon.run("acme/one")
    second = recon.run("acme/two")
    assert first.errors == second.errors == []


# ---------------------------------------------------------------------------
# CLI wiring
# ---------------------------------------------------------------------------


def test_cli_shadow_path_runs_and_reports(capsys, monkeypatch):
    from blastradius.recon import cli

    http_json, _ = _api_fixture(
        ["alice"],
        repos={"alice": []},
        gists={"alice": [{"html_url": "https://gist.example/1", "files": {"id_rsa": {}}}]},
    )
    monkeypatch.setattr(
        "blastradius.recon.shadow_repo._default_http_json", lambda url, timeout=20: http_json(url)
    )
    rc = cli.main(["--shadow", "acme/app", "--no-content-confirm"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "1 contributor(s)" in out
    assert "1 exposure finding(s)" in out
    assert "no credential was validated or used" in out
