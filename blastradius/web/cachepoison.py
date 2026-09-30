"""Live web-cache-poisoning checks for the dynamic web scanner.

Methodology follows PortSwigger's practical cache-poisoning canon
(unkeyed inputs -> reflection -> cacheable -> persistence):

1. **CACHE-BUSTER** — every probe carries a unique random query param, so a
   poison can only ever land in our own throwaway cache entry, never a URL
   real users request (responsible-testing discipline).
2. **UNKEYED HEADER** — send each candidate header (``X-Forwarded-Host`` et
   al.) carrying a host-shaped ``.invalid`` marker; a reflection in the body
   or ``Location`` proves the header reaches response generation.
3. **CACHEABLE** — the response must look storable (``Cache-Control:
   public``/``max-age``, or cache-layer headers like ``Age``/``X-Cache``/
   ``CF-Cache-Status``).
4. **PERSISTENCE (the FP guard)** — re-request the SAME busted URL *without*
   the header; if the marker is still served, the cache keyed on the URL but
   not the header: confirmed poisoning. Otherwise it was mere reflection.

Severity tracks where the marker lands: a resource URL (script/link/base
``src``) is worst (attacker host -> loaded code), a redirect is high, plain
body text is medium. Web Cache Deception path extensions (``.css`` etc.) are
probed as a second vector.

Everything is dependency-injected (the HTTP session), so the logic is
unit-tested offline with fake sessions.
"""

import contextlib
import re
import secrets
import urllib.parse
from dataclasses import dataclass
from typing import Dict, List, Optional

from blastradius.web.browser import BrowserSession

#: Headers frequently excluded from cache keys yet reflected by apps.
UNKEYED_HEADERS = (
    "X-Forwarded-Host",
    "X-Forwarded-Scheme",
    "X-Forwarded-Proto",
    "X-Forwarded-Server",
    "X-Host",
    "X-Forwarded-Port",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-HTTP-Host-Override",
    "Forwarded",
)

#: Path suffixes that persuade caches a dynamic route is static (WCD).
WCD_SUFFIXES = (".css", ".js", ".jpg", ".ico", ".png", ".txt")

#: Response headers proving a cache layer (or a cached response) is present.
_CACHE_LAYER_RE = re.compile(
    r"(?i)(x-cache|cf-cache-status|age|x-varnish|x-served-by|via:.*(?:varnish|"
    r"cloudfront|fastly|akamai|squid|nginx))"
)

#: Resource-URL contexts: marker here means attacker-controlled code loading.
_RESOURCE_TEMPLATE = r"""(?i)(?:src|href)\s*=\s*["']?[^"'\s>]*{marker}"""


@dataclass
class CachePoisonFinding:
    """A live web-cache-poisoning finding."""

    url: str
    check: str  # always "cachepoison"
    severity: str
    cwe: str
    confidence: float
    evidence: str
    remediation: str
    description: str = ""


def _is_cacheable(headers: Dict[str, str], body: str) -> bool:
    cc = headers.get("Cache-Control", "") or headers.get("cache-control", "")
    if "no-store" in cc.lower() or "private" in cc.lower():
        return False
    if re.search(r"max-age\s*=\s*[1-9]", cc):
        return True
    if "public" in cc.lower():
        return True
    flat = "\n".join(f"{k}: {v}" for k, v in headers.items())
    return bool(_CACHE_LAYER_RE.search(flat))


def _reflection_context(body: str, marker: str) -> Optional[str]:
    """Where the marker lands: resource URL, redirect/Location, or plain body."""
    if marker not in body:
        return None
    if re.search(_RESOURCE_TEMPLATE.format(marker=re.escape(marker)), body):
        return "resource"
    return "body"


class CachePoisonChecker:
    """Probe unkeyed headers + WCD suffixes with cache-buster discipline."""

    def __init__(
        self,
        session: Optional[BrowserSession] = None,
        max_headers: int = 10,
        marker_domain: str = "invalid",
    ):
        self.session = session or BrowserSession()
        self.max_headers = max_headers
        self.marker_domain = marker_domain

    # ------------------------------------------------------------------
    def check(self, urls: List[str]) -> List[CachePoisonFinding]:
        findings: List[CachePoisonFinding] = []
        for url in urls:
            findings.extend(self._probe_url(url))
            findings.extend(self._probe_wcd(url))
        return findings

    # ------------------------------------------------------------------
    def _busted(self, url: str) -> str:
        sep = "&" if "?" in url else "?"
        return f"{url}{sep}cb={secrets.token_hex(4)}"

    def _probe_url(self, url: str) -> List[CachePoisonFinding]:
        findings: List[CachePoisonFinding] = []
        for header in UNKEYED_HEADERS[: self.max_headers]:
            marker = f"poison-{secrets.token_hex(3)}.{self.marker_domain}"
            probe_url = self._busted(url)
            page = self._get(probe_url, {header: marker})
            if page is None:
                continue
            where = _reflection_context(page.text or "", marker)
            if where is None or not _is_cacheable(dict(page.headers or {}), page.text or ""):
                continue
            # Persistence: same URL, no header — marker still served?
            clean = self._get(probe_url, None)
            if clean is None or marker not in (clean.text or ""):
                continue
            severity = "HIGH" if where == "resource" else "MEDIUM"
            findings.append(
                CachePoisonFinding(
                    url=url,
                    check="cachepoison",
                    severity=severity,
                    cwe="CWE-444",
                    confidence=0.85 if where == "resource" else 0.75,
                    evidence=(
                        f"unkeyed header `{header}` reflected into {where} context "
                        f"and persisted without the header: {marker}"
                    )[:500],
                    remediation="Include the header in the cache key (Vary:) or stop "
                    "reflecting it; never cache responses built from unkeyed input.",
                    description="Live web-cache-poisoning probe with persistence proof.",
                )
            )
            break  # one finding per URL is enough
        return findings

    def _get(self, url: str, headers):
        """GET that returns None instead of raising."""
        with contextlib.suppress(Exception):  # probe must never crash the scan
            return self.session._request("GET", url, headers=headers or {})
        return None

    def _probe_wcd(self, url: str) -> List[CachePoisonFinding]:
        """Web Cache Deception: dynamic route + static suffix, same session."""
        findings: List[CachePoisonFinding] = []
        parsed = urllib.parse.urlparse(url)
        if "." in parsed.path.rsplit("/", 1)[-1]:
            return findings  # already looks static
        for suffix in WCD_SUFFIXES[:3]:
            probe_url = self._busted(url.rstrip("/") + "/x" + suffix)
            page = self._get(probe_url, None)
            if page is None:
                continue
            body = page.text or ""
            ctype = (dict(page.headers or {}).get("Content-Type", "") or "").lower()
            # Dynamic content served under a static-looking, cacheable URL.
            if ("text/html" in ctype or "application/json" in ctype) and _is_cacheable(
                dict(page.headers or {}), body
            ):
                findings.append(
                    CachePoisonFinding(
                        url=url,
                        check="cachepoison",
                        severity="MEDIUM",
                        cwe="CWE-444",
                        confidence=0.6,
                        evidence=(
                            f"dynamic content ({ctype or 'unknown type'}) served at "
                            f"static-looking {probe_url[-40:]} with cacheable headers"
                        )[:500],
                        remediation="Do not serve authenticated/dynamic content under static "
                        "extensions; add authentication to the cache key.",
                        description="Possible Web Cache Deception surface (needs authed retest).",
                    )
                )
                break
        return findings
