"""Recon layer tests — everything mocked, no network."""

import json

import pytest

from blastradius.recon.dorker import DorkEngine

SIMPLE_INDEX_HTML = """
<!DOCTYPE html><html><body>
<a href="/flask-awesome/">flask-awesome</a>
<a href="/flask-other/">flask-other</a>
<a href="/django-kit/">django-kit</a>
<a href="/fastapi-pro/">fastapi-pro</a>
<a href="/requests/">requests</a>
<a href="/starlette-min/">starlette-min</a>
</body></html>
"""


class FakeHttp:
    """Scripted HTTP responses keyed by URL substring."""

    def __init__(self, responses, json_calls=None, text_calls=None):
        self.responses = responses
        self.json_calls = json_calls if json_calls is not None else []
        self.text_calls = text_calls if text_calls is not None else []
        self.calls = []

    def json(self, url, headers=None):
        self.calls.append(url)
        self.json_calls.append(url)
        for key, value in self.responses.items():
            if key in url:
                return value
        raise AssertionError(f"unexpected URL: {url}")

    def text(self, url):
        self.calls.append(url)
        self.text_calls.append(url)
        if "pypi.org/simple" in url:
            return SIMPLE_INDEX_HTML
        raise AssertionError(f"unexpected text URL: {url}")


@pytest.fixture
def engine(tmp_path, monkeypatch):
    fake = FakeHttp({})
    e = DorkEngine(cache_dir=str(tmp_path / ".cache"), http=fake.json, http_text=fake.text)
    e.rate_sleep = 0
    return e, fake


# --- GitHub code search ------------------------------------------------------


def test_github_search_filters_and_prioritizes(engine, monkeypatch):
    dork, fake = engine
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
    fake.responses = {
        "search/code": {"items": [
            {"path": "a.py", "repository": {"full_name": "org/hot"}},
            {"path": "b.py", "repository": {"full_name": "org/cold"}},
            {"path": "c.py", "repository": {"full_name": "org/mid"}},
        ]},
        "repos/org/hot": {"stargazers_count": 500},
        "repos/org/cold": {"stargazers_count": 10},
        "repos/org/mid": {"stargazers_count": 120},
    }
    results = dork.github_code_search("render_template_string request", "python", min_stars=50)

    assert [r["repo"] for r in results] == ["org/hot", "org/mid"]  # stars >= 50, sorted desc
    assert results[0]["url"] == "https://github.com/org/hot"
    assert results[0]["file"] == "a.py"
    assert results[0]["source"] == "github"


def test_github_search_skips_without_token(engine, monkeypatch):
    dork, fake = engine
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    assert dork.github_code_search("x", "python") == []
    assert fake.calls == []


# --- PyPI --------------------------------------------------------------------


def test_pypi_filters_and_resolves_github_urls(engine):
    dork, fake = engine
    fake.responses = {
        "pypi.org/pypi/flask-awesome/json": {"info": {"home_page": "", "project_urls": {"Source": "https://github.com/org/flask-awesome"}}},
        "pypi.org/pypi/django-kit/json": {"info": {"home_page": "https://github.com/org/django-kit", "project_urls": {}}},
        "pypi.org/pypi/requests/json": {"info": {"home_page": "https://github.com/psf/requests", "project_urls": {}}},
    }
    results = dork.pypi_web_packages(limit=50)

    urls = {r["package"]: r["url"] for r in results}
    # only framework-filtered names are fetched; 'requests' is filtered out
    assert "flask-awesome" in urls and urls["flask-awesome"] == "https://github.com/org/flask-awesome"
    assert "django-kit" in urls
    assert "requests" not in urls
    # package without a GitHub URL is dropped
    assert not any(r["package"] == "flask-other" for r in results)


def test_pypi_cache_read_and_write(engine, tmp_path):
    dork, fake = engine
    fake.responses = {
        "pypi.org/pypi/flask-awesome/json": {"info": {"home_page": "", "project_urls": {"Source": "https://github.com/org/flask-awesome"}}},
    }
    dork.pypi_web_packages(limit=10)
    cache_file = tmp_path / ".cache" / "pypi_packages.json"
    assert cache_file.exists()
    first_calls = len(fake.calls)

    # second call must come from cache (no new HTTP calls)
    again = dork.pypi_web_packages(limit=10)
    assert len(fake.calls) == first_calls
    assert again == json.loads(cache_file.read_text(encoding="utf-8"))


# --- Shodan ------------------------------------------------------------------


def test_shodan_graceful_skip_without_key(engine, monkeypatch):
    dork, fake = engine
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    assert dork.shodan_search("flask port:5000") == []
    assert fake.calls == []


def test_shodan_parses_matches(engine, monkeypatch):
    dork, fake = engine
    monkeypatch.setenv("SHODAN_API_KEY", "shodan-test")
    fake.responses = {
        "shodan.io": {"matches": [
            {"ip_str": "1.2.3.4", "port": 5000, "hostnames": ["x.com"], "org": "ACME"},
            {"ip_str": "5.6.7.8", "port": 5000, "hostnames": [], "org": ""},
        ]}
    }
    results = dork.shodan_search("flask port:5000")
    assert results[0] == {"ip": "1.2.3.4", "port": 5000, "hostname": "x.com", "org": "ACME"}
    assert results[1]["hostname"] is None


# --- find_targets (dedup + prioritization + cache) ---------------------------


def test_find_targets_dedup_and_prioritize(engine, tmp_path, monkeypatch):
    dork, fake = engine
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    fake.responses = {
        "search/code": {"items": [
            {"path": "a.py", "repository": {"full_name": "org/hot"}},
        ]},
        "repos/org/hot": {"stargazers_count": 900},
        "pypi.org/pypi/starlette-min/json": {"info": {"home_page": "https://github.com/org/hot", "project_urls": {}}},
        "pypi.org/pypi/fastapi-pro/json": {"info": {"home_page": "https://github.com/org/fastapi-pro", "project_urls": {}}},
    }
    # starlette-min resolves to the SAME url as github -> deduped; fastapi-pro is distinct
    targets = dork.find_targets("all", min_stars=0, limit=10)

    urls = [t["url"] for t in targets]
    assert urls.count("https://github.com/org/hot") == 1  # deduped
    assert any(t["source"] == "github" for t in targets)
    assert any(t["source"] == "pypi" for t in targets)
    assert "https://github.com/org/fastapi-pro" in urls
    # github entry (900 stars) sorts before pypi entries (0 stars)
    assert targets[0]["source"] == "github"

    cache_file = tmp_path / ".cache" / "discovered_targets.json"
    assert cache_file.exists()
    assert json.loads(cache_file.read_text(encoding="utf-8")) == targets
