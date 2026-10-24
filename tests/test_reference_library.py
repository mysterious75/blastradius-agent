"""Reference-library fetcher — source-list invariants (offline)."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import fetch_reference_library as lib  # noqa: E402


@pytest.mark.unit
def test_sources_are_unique_https_and_expected():
    names = [name for name, _ in lib.SOURCES]
    urls = [url for _, url in lib.SOURCES]
    assert len(names) == len(set(names))
    assert all(url.startswith("https://") for url in urls)
    assert "nist-sp800-218.pdf" in names
    assert "owasp-asvs.zip" in names
    assert "scorecard-checks.md" in names
    assert "owasp-top10-2025.html" in names


@pytest.mark.integration
def test_fetch_skips_existing_file_without_network(tmp_path, monkeypatch):
    target = tmp_path / "already.html"
    target.write_text("cached", encoding="utf-8")
    monkeypatch.setattr(lib, "RAW", tmp_path)
    result = lib.fetch("already.html", "https://example.invalid/never", force=False)
    assert result.startswith("skip")
    assert target.read_text(encoding="utf-8") == "cached"


@pytest.mark.integration
def test_fetch_writes_file_from_local_url(tmp_path, monkeypatch):
    source = tmp_path / "source.txt"
    source.write_text("payload", encoding="utf-8")
    monkeypatch.setattr(lib, "RAW", tmp_path)
    result = lib.fetch("copy.txt", source.as_uri(), force=True)
    assert result.startswith("ok")
    assert (tmp_path / "copy.txt").read_text(encoding="utf-8") == "payload"


@pytest.mark.e2e
def test_cli_dry_run_lists_sources(tmp_path):
    import subprocess

    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "fetch_reference_library.py"), "--help"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )
    assert proc.returncode == 0
    assert "--force" in proc.stdout
