"""DorkEngine — discovers hunt targets from GitHub code search, PyPI, Shodan.

All network calls go through injectable ``http``/``http_text`` callables so
the engine is fully testable offline. Missing API keys degrade gracefully
(empty results, no exceptions).
"""

import json
import os
import re
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable, Dict, List, Optional

GITHUB_PATTERNS = [
    ("render_template_string request", "python"),
    ("innerHTML req.body", "javascript"),
    ("xml.etree.ElementTree.parse", "python"),
    ('.decode(algorithms=[\'none\'])', "python"),
]

PYPI_FILTERS = ("flask", "django", "fastapi", "starlette", "aiohttp")

DEFAULT_HEADERS = {"User-Agent": "blastradius-recon"}


def _default_http_json(url: str, headers: Optional[Dict] = None, timeout: int = 20) -> dict:
    req = urllib.request.Request(url, headers={**DEFAULT_HEADERS, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _default_http_text(url: str, timeout: int = 30) -> str:
    req = urllib.request.Request(url, headers=DEFAULT_HEADERS)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


class DorkEngine:
    """Target discovery across GitHub code search, PyPI metadata, and Shodan."""

    def __init__(
        self,
        cache_dir: str = ".cache",
        http: Optional[Callable] = None,
        http_text: Optional[Callable] = None,
    ):
        self.cache_dir = Path(cache_dir)
        self.http = http or _default_http_json
        self.http_text = http_text or _default_http_text
        self.rate_sleep = 2.0  # ~30 req/min on the GitHub API

    # ------------------------------------------------------------------
    # GitHub code search
    # ------------------------------------------------------------------

    def github_code_search(
        self, pattern: str, language: str, min_stars: int = 50, per_page: int = 20
    ) -> List[Dict]:
        """Search GitHub code via the Search API (requires GITHUB_TOKEN).

        Returns [{repo, file, url, stars, source}] with stars >= min_stars,
        highest stars first. Rate limit: one repo-detail call per unique repo
        with a built-in sleep.
        """
        token = os.getenv("GITHUB_TOKEN")
        if not token:
            return []
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            **DEFAULT_HEADERS,
        }
        q = urllib.parse.quote(f"{pattern} language:{language}")
        data = self.http(f"https://api.github.com/search/code?q={q}&per_page={per_page}", headers)
        repos: Dict[str, Dict] = {}
        for item in data.get("items", []):
            full = item["repository"]["full_name"]
            repos.setdefault(full, {
                "repo": full,
                "file": item.get("path"),
                "url": f"https://github.com/{full}",
                "stars": 0,
                "source": "github",
            })

        results: List[Dict] = []
        for full, rec in repos.items():
            try:
                detail = self.http(f"https://api.github.com/repos/{full}", headers)
                rec["stars"] = detail.get("stargazers_count", 0)
            except Exception:
                rec["stars"] = 0
            if rec["stars"] >= min_stars:
                results.append(rec)
            time.sleep(self.rate_sleep)

        results.sort(key=lambda r: r["stars"], reverse=True)
        return results

    # ------------------------------------------------------------------
    # PyPI
    # ------------------------------------------------------------------

    def pypi_web_packages(self, limit: int = 500, use_cache: bool = True) -> List[Dict]:
        """Discover web-framework PyPI packages and their GitHub URLs.

        Filters the PyPI simple index by framework keywords, then resolves
        each package's GitHub URL from its metadata. Cached to
        ``.cache/pypi_packages.json``.
        """
        cache_file = self.cache_dir / "pypi_packages.json"
        if use_cache and cache_file.exists():
            try:
                return json.loads(cache_file.read_text(encoding="utf-8"))
            except Exception:
                pass

        html = self.http_text("https://pypi.org/simple/")
        names = sorted(set(re.findall(r'href="[^"]*">([^<]+)</a>', html)))
        names = [n for n in names if any(f in n.lower() for f in PYPI_FILTERS)][:limit]

        out: List[Dict] = []
        for name in names:
            try:
                meta = self.http(f"https://pypi.org/pypi/{name}/json")
                info = meta.get("info", {})
                urls = [info.get("home_page")] + list((info.get("project_urls") or {}).values())
                github = next((u for u in urls if u and "github.com" in u), None)
                if github:
                    out.append({"package": name, "url": github})
            except Exception:
                continue

        self.cache_dir.mkdir(parents=True, exist_ok=True)
        cache_file.write_text(json.dumps(out, indent=2), encoding="utf-8")
        return out

    # ------------------------------------------------------------------
    # Shodan
    # ------------------------------------------------------------------

    def shodan_search(self, query: str, api_key: Optional[str] = None, limit: int = 20) -> List[Dict]:
        """Search Shodan for exposed services (requires SHODAN_API_KEY).

        Returns [{ip, port, hostname, org}] or [] when no key is configured.
        """
        key = api_key or os.getenv("SHODAN_API_KEY")
        if not key:
            return []
        url = (
            f"https://api.shodan.io/shodan/host/search"
            f"?key={key}&query={urllib.parse.quote(query)}&limit={limit}"
        )
        data = self.http(url)
        return [
            {
                "ip": m.get("ip_str"),
                "port": m.get("port"),
                "hostname": (m.get("hostnames") or [None])[0],
                "org": m.get("org"),
            }
            for m in data.get("matches", [])
        ]

    # ------------------------------------------------------------------
    # Aggregation
    # ------------------------------------------------------------------

    def find_targets(self, strategy: str = "all", min_stars: int = 0, limit: int = 200) -> List[Dict]:
        """Combine all sources, dedupe by URL, prioritize by stars, and cache."""
        found: List[Dict] = []
        if strategy in ("github", "all"):
            for pattern, language in GITHUB_PATTERNS:
                found.extend(self.github_code_search(pattern, language, min_stars=min_stars))
        if strategy in ("pypi", "all"):
            for pkg in self.pypi_web_packages(limit=limit):
                u = pkg["url"].rstrip("/")
                parts = u.split("/")
                repo = f"{parts[-2]}/{parts[-1]}" if len(parts) >= 2 else u
                found.append({"repo": repo, "file": None, "url": u, "stars": 0, "source": "pypi"})
        if strategy in ("shodan", "all"):
            for match in self.shodan_search("flask port:5000"):
                found.append({
                    "repo": None, "file": None,
                    "url": f"http://{match['ip']}:{match['port']}",
                    "stars": 0, "source": "shodan", **match,
                })

        seen, deduped = set(), []
        for target in found:
            key = target.get("url")
            if key in seen:
                continue
            seen.add(key)
            deduped.append(target)
        deduped.sort(key=lambda t: t.get("stars", 0), reverse=True)

        self.cache_dir.mkdir(parents=True, exist_ok=True)
        (self.cache_dir / "discovered_targets.json").write_text(
            json.dumps(deduped, indent=2), encoding="utf-8"
        )
        return deduped
