"""Shadow-repository recon: an org's own contributors as an exposure surface.

The premise is a supply-chain observation rather than a bug class: a project's
security posture includes what its contributors leak *outside* the project. A
maintainer who commits a private key, an ``.env``, a database dump or a signing
key to a personal repository, a Gist, or a release asset has published it
permanently, and the project inherits the blast radius through that person.

This module walks that surface read-only:

1. enumerate the target repository's contributors,
2. enumerate each contributor's own repositories, Gists and release assets,
3. flag assets whose *name* indicates a credential, key or dump,
4. optionally fetch the asset body and re-use the hunter's hardened secret
   scorer to confirm a live-looking token.

Safety properties, matching the rest of the product:

- **Read-only and public-API only.** No authentication, no writes, no pushes.
- **Detection only.** A discovered key is reported, never validated or used.
- **Injected transports.** Every HTTP call goes through a caller-supplied
  callable, so tests run fully offline.
- **Fail-closed on transport errors.** An unreachable API yields an empty
  surface plus a recorded error, never a fabricated clean result.
"""

import re
from typing import Callable, Iterable, List, NamedTuple, Optional

from ..hunter.scanner import Finding, _score_secret

GITHUB_API = "https://api.github.com"

# Filename/path fragments that indicate a credential, key or raw data dump,
# grouped by the label a finding reports. This is the single source of truth
# for name-based classification.
_NAME_CLASS_RULES = (
    (
        "private-key",
        (
            r"^id_(rsa|dsa|ecdsa|ed25519)",
            r"private[_-]?key",
            r"\.pem$",
            r"\.key$",
            r"\.asc$",
            r"\.gpg$",
        ),
    ),
    ("seed-phrase", (r"seed(phrase|_)?", r"mnemonic", r"wallet", r"\.kdbx$")),
    (
        "database-dump",
        (r"\.sql(\.|$)", r"\.sqlite3?$", r"\.dump$", r"^dump", r"^backup", r"\.bak$"),
    ),
    (
        "cloud-credential",
        (r"^creds?", r"^credentials?", r"^secrets?(\.|_|$)", r"service[_-]?account", r"password"),
    ),
    (
        "credential-file",
        (r"\.env(\.|$)", r"\.ovpn$", r"\.keystore$", r"\.p12$", r"\.pfx$", r"\.jks$"),
    ),
)

SENSITIVE_ASSET_LABELS = tuple(label for label, _ in _NAME_CLASS_RULES)

# Content confirmation only makes sense where the asset URL actually serves a
# file body: Gist files and release assets. A repository page is HTML, not
# source, so it is never fetched.
CONTENT_CONFIRM_KINDS = ("gist", "release-asset")

# Anything that is not plausibly text is skipped rather than fetched.
BINARY_EXTENSIONS = (
    ".7z",
    ".a",
    ".bin",
    ".bmp",
    ".bz2",
    ".class",
    ".dll",
    ".dmg",
    ".eot",
    ".exe",
    ".gif",
    ".gz",
    ".ico",
    ".iso",
    ".jar",
    ".jpeg",
    ".jpg",
    ".jks",
    ".mov",
    ".mp3",
    ".mp4",
    ".pdf",
    ".p12",
    ".pfx",
    ".png",
    ".pyc",
    ".rar",
    ".so",
    ".tar",
    ".tgz",
    ".ttf",
    ".wasm",
    ".webp",
    ".woff",
    ".woff2",
    ".zip",
)

SEVERITY_BY_HIT = {
    "private-key": "CRITICAL",
    "seed-phrase": "CRITICAL",
    "cloud-credential": "CRITICAL",
    "database-dump": "HIGH",
    "credential-file": "HIGH",
}


class ShadowAsset(NamedTuple):
    """One publicly reachable artifact owned by a contributor."""

    owner: str
    kind: str
    name: str
    url: str

    @property
    def name_hit(self) -> Optional[str]:
        """Name-based classification, or ``None`` when the name looks benign."""
        for label, patterns in _NAME_CLASS_RULES:
            if any(re.search(p, self.name, re.I) for p in patterns):
                return label
        return None


class ShadowReconReport(NamedTuple):
    """Result of one shadow-repository sweep."""

    repo: str
    contributors: List[str]
    assets: List[ShadowAsset]
    findings: List[Finding]
    errors: List[str]


def _default_http_json(url: str, timeout: int = 20) -> dict:
    import json
    import urllib.request

    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed API host
        return json.loads(resp.read().decode())


def _default_http_text(url: str, timeout: int = 20) -> str:
    import urllib.request

    req = urllib.request.Request(url, headers={"Accept": "text/plain"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - caller-supplied URL
        return resp.read().decode("utf-8", "replace")


class ShadowRepoRecon:
    """Contributor -> personal repo/Gist/release -> exposed-artifact sweep.

    Args:
        http_json: Callable ``(url) -> dict`` for the GitHub JSON API.
        http_text: Callable ``(url) -> str`` for raw asset bodies.
        max_contributors: Cap on contributors followed (rate-limit hygiene).
        confirm_content: Fetch small text assets to confirm a live-looking
            secret with the hunter's scorer instead of trusting the filename.
        max_content_fetches: Hard cap on content fetches per sweep.
    """

    def __init__(
        self,
        http_json: Optional[Callable[[str], dict]] = None,
        http_text: Optional[Callable[[str], str]] = None,
        max_contributors: int = 25,
        confirm_content: bool = True,
        max_content_fetches: int = 40,
    ):
        self.http_json = http_json or _default_http_json
        self.http_text = http_text or _default_http_text
        self.max_contributors = max_contributors
        self.confirm_content = confirm_content
        self.max_content_fetches = max_content_fetches
        self._errors: List[str] = []

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    def contributors(self, repo: str) -> List[str]:
        """Contributor logins for ``owner/name``, highest contribution first."""
        data = self.http_json(f"{GITHUB_API}/repos/{repo}/contributors?per_page=100")
        return [c["login"] for c in data if c.get("login")][: self.max_contributors]

    def assets(self, login: str) -> List[ShadowAsset]:
        """Public repos, Gists and release assets owned by ``login``."""
        found: List[ShadowAsset] = []
        repos = self._safe_list(f"/users/{login}/repos?per_page=100&sort=pushed")
        for repo in repos:
            name = repo.get("name", "")
            found.append(ShadowAsset(login, "repo", name, repo.get("html_url", "")))
        for gist in self._safe_list(f"/users/{login}/gists?per_page=100"):
            for fname in gist.get("files", {}):
                found.append(ShadowAsset(login, "gist", fname, gist.get("html_url", "")))
        for repo in repos:
            for release in self._safe_list(
                f"/repos/{login}/{repo.get('name', '')}/releases?per_page=20"
            ):
                for asset in release.get("assets", []):
                    found.append(
                        ShadowAsset(
                            login,
                            "release-asset",
                            asset.get("name", ""),
                            asset.get("browser_download_url", ""),
                        )
                    )
        return found

    def _safe_list(self, path: str) -> List[dict]:
        """GET a list endpoint; a transport error yields ``[]`` plus a note."""
        try:
            data = self.http_json(GITHUB_API + path)
        except Exception:  # noqa: BLE001 - recon must survive a dead API
            self._errors.append(f"GET {path} failed")
            return []
        return data if isinstance(data, list) else []

    # ------------------------------------------------------------------
    # Sweep
    # ------------------------------------------------------------------

    def run(self, repo: str) -> ShadowReconReport:
        """Sweep ``repo``'s contributors for publicly exposed sensitive assets."""
        self._errors = []
        try:
            logins = self.contributors(repo)
        except Exception as exc:  # noqa: BLE001 - fail closed, no fabricated clean
            return ShadowReconReport(repo, [], [], [], [f"contributor lookup failed: {exc}"])

        assets: List[ShadowAsset] = []
        for login in logins:
            assets.extend(self.assets(login))

        findings = self._to_findings(assets)
        return ShadowReconReport(repo, logins, assets, findings, list(self._errors))

    def _should_fetch(self, asset: ShadowAsset, fetches: int) -> bool:
        """Whether a benign-named asset is worth fetching for confirmation."""
        if not self.confirm_content or not asset.url or fetches >= self.max_content_fetches:
            return False
        if asset.kind not in CONTENT_CONFIRM_KINDS:
            return False
        return not asset.name.lower().endswith(BINARY_EXTENSIONS)

    def _to_findings(self, assets: Iterable[ShadowAsset]) -> List[Finding]:
        findings: List[Finding] = []
        fetches = 0
        for asset in assets:
            hit = asset.name_hit
            if hit is None:
                if not self._should_fetch(asset, fetches):
                    continue
                fetches += 1
                try:
                    body = self.http_text(asset.url)
                except Exception:  # noqa: BLE001 - unreachable asset is not a finding
                    self._errors.append(f"GET {asset.url} failed")
                    continue
                confirmed = any(
                    _score_secret(line, has_source=True) >= 0.95 for line in body.splitlines()
                )
                if not confirmed:
                    continue
                hit = "cloud-credential"
                evidence = "live-looking secret confirmed in public asset"
            else:
                evidence = f"sensitive filename exposed via {asset.kind}"

            findings.append(
                Finding(
                    file=f"{asset.owner}/{asset.name}",
                    line=0,
                    vuln_type="shadow-repo-exposure",
                    payload=hit,
                    confidence=0.8 if evidence.startswith("sensitive filename") else 0.9,
                    evidence=evidence,
                    context=asset.url,
                    severity=SEVERITY_BY_HIT.get(hit, "MEDIUM"),
                    cwe="CWE-200",
                    remediation=(
                        f"Rotate any credential in {asset.name}, purge it from history, and "
                        "move secrets to a managed vault; add a pre-commit secret scan for "
                        f"the {asset.owner} account."
                    ),
                    description=(
                        f"Contributor {asset.owner} publishes {hit} material in a public "
                        f"{asset.kind} ({asset.name}). Detection only - the credential was not "
                        "validated or used."
                    ),
                )
            )
        return findings


def shadow_recon(repo: str, **kwargs) -> ShadowReconReport:
    """Convenience wrapper: one shadow sweep for ``owner/name``."""
    return ShadowRepoRecon(**kwargs).run(repo)
