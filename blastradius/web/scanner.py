"""DynamicWebScanner — black-box checks against a live target.

Crawls a target (same-origin links + forms) and runs behavioral checks that
static analysis cannot: reflected XSS, open redirects, missing security
headers, wildcard CORS, exposed files, and directory listing. Findings are
HTTP-response evidence — reported as candidates (no sandbox execution
marker), with the exact request/response snippet as proof.

Checks (vuln_type -> CWE):
    xss       CWE-79   payload reflected unescaped
    redirect  CWE-601  open redirect via url/next/return-like params
    headers   CWE-693  missing security headers
    cors      CWE-942  Access-Control-Allow-Origin: * + credentials
    exposure  CWE-200  /.git, /.env, /admin probes
    listing   CWE-538  directory listing

Usage:
    scanner = DynamicWebScanner()
    findings = scanner.scan("http://localhost:8000")
"""

import urllib.parse
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Dict, List, Optional

from blastradius.web.browser import BrowserSession

XSS_PAYLOADS = ("<script>alert(1)</script>", '"><img src=x onerror=alert(1)>')
REDIRECT_PARAMS = ("url", "redirect", "next", "return", "dest", "goto", "target")
REDIRECT_HOST = "https://blastradius-evil.invalid"
REQUIRED_HEADERS = {
    "x-frame-options": "X-Frame-Options",
    "content-security-policy": "Content-Security-Policy",
    "strict-transport-security": "Strict-Transport-Security",
    "x-content-type-options": "X-Content-Type-Options",
}
EXPOSED_PATHS = ("/.git/config", "/.git/HEAD", "/.env", "/admin", "/server-status", "/wp-admin/")
LISTING_MARKERS = ("Index of /", "Directory listing for", "Parent Directory</a>")


@dataclass
class DynamicFinding:
    """A black-box finding with HTTP-response evidence."""

    url: str
    check: str  # xss | redirect | headers | cors | exposure | listing
    severity: str
    cwe: str
    confidence: float
    evidence: str
    remediation: str
    description: str = ""


class _LinkParser(HTMLParser):
    """Collects href/action targets and form definitions from a page."""

    def __init__(self):
        super().__init__()
        self.links: List[str] = []
        self.forms: List[Dict] = []

    def handle_starttag(self, tag, attrs):
        attr_map = dict(attrs)
        if tag == "a" and attr_map.get("href"):
            self.links.append(attr_map["href"])
        if tag == "form":
            self.forms.append(
                {
                    "action": attr_map.get("action", ""),
                    "method": attr_map.get("method", "GET").upper(),
                    "inputs": [],
                }
            )
        if tag == "input":
            if self.forms:
                name = attr_map.get("name")
                if name:
                    self.forms[-1]["inputs"].append(name)


class DynamicWebScanner:
    """Crawl a target and run behavioral security checks."""

    def __init__(
        self,
        browser: Optional[BrowserSession] = None,
        max_urls: int = 20,
        depth: int = 1,
        probe_exposed: bool = True,
    ):
        self.browser = browser or BrowserSession()
        # Probe browser never follows redirects (so Location-based checks work).
        self._probe_browser = BrowserSession(follow_redirects=False)
        self.max_urls = max_urls
        self.depth = max(1, depth)
        self.probe_exposed = probe_exposed

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self, target: str) -> List[DynamicFinding]:
        """Scan a base URL and return candidate findings."""
        target = target.rstrip("/")
        findings: List[DynamicFinding] = []
        visited: List[str] = []
        queue = [target]

        while queue and len(visited) < self.max_urls:
            url = queue.pop(0)
            if url in visited:
                continue
            visited.append(url)
            try:
                page = self.browser.get(url)
            except Exception:
                continue
            findings.extend(self._check_response(url, page))
            for link in self._same_origin_links(url, page.text):
                if link not in visited and link not in queue:
                    queue.append(link)
            for form in self._parse_forms(page.text):
                findings.extend(self._check_form(target, form))

        if self.probe_exposed:
            findings.extend(self._probe_exposed(target))
        return findings

    # ------------------------------------------------------------------
    # Checks
    # ------------------------------------------------------------------

    def _check_response(self, url: str, page) -> List[DynamicFinding]:
        findings = []
        # Reflected XSS: inject each payload into every query param.
        parsed = urllib.parse.urlparse(url)
        if parsed.query:
            params = urllib.parse.parse_qs(parsed.query)
            for name, values in params.items():
                for payload in XSS_PAYLOADS:
                    probe = {**{k: v[0] for k, v in params.items()}, name: payload}
                    reflected = self._probe_browser.get(url.split("?")[0], params=probe)
                    if payload in reflected.text:
                        findings.append(
                            DynamicFinding(
                                url=url,
                                check="xss",
                                severity="HIGH",
                                cwe="CWE-79",
                                confidence=0.85,
                                evidence=f"param `{name}` reflected unescaped:\n{reflected.text[:500]}",
                                remediation="Encode all dynamic output with context-aware escaping; apply a strict CSP.",
                            )
                        )
                        break
        # Open redirect: probe redirect-ish params.
        for name in REDIRECT_PARAMS:
            probe_url = f"{url.split('?')[0]}?{name}={urllib.parse.quote(REDIRECT_HOST)}"
            try:
                page = self._probe_browser.get(probe_url)
            except Exception:
                continue
            location = page.headers.get("Location", "")
            if 300 <= page.status < 400 and location.startswith(REDIRECT_HOST):
                findings.append(
                    DynamicFinding(
                        url=probe_url,
                        check="redirect",
                        severity="MEDIUM",
                        cwe="CWE-601",
                        confidence=0.8,
                        evidence=f"302 -> {location}",
                        remediation="Only redirect to relative or allowlisted destinations.",
                    )
                )
                break
        # Missing security headers.
        missing = [
            REQUIRED_HEADERS[h]
            for h in REQUIRED_HEADERS
            if h not in {k.lower() for k in page.headers}
        ]
        if missing:
            findings.append(
                DynamicFinding(
                    url=url,
                    check="headers",
                    severity="LOW",
                    cwe="CWE-693",
                    confidence=0.95,
                    evidence="missing: " + ", ".join(missing),
                    remediation="Set X-Frame-Options, CSP, HSTS and X-Content-Type-Options.",
                )
            )
        # Wildcard CORS with credentials.
        acao = page.headers.get("Access-Control-Allow-Origin", "")
        acac = page.headers.get("Access-Control-Allow-Credentials", "").lower()
        if acao == "*" and acac == "true":
            findings.append(
                DynamicFinding(
                    url=url,
                    check="cors",
                    severity="MEDIUM",
                    cwe="CWE-942",
                    confidence=0.9,
                    evidence="Access-Control-Allow-Origin: * with credentials",
                    remediation="Restrict CORS to explicit origins; never pair '*' with credentials.",
                )
            )
        # Directory listing.
        if any(marker in page.text for marker in LISTING_MARKERS):
            findings.append(
                DynamicFinding(
                    url=url,
                    check="listing",
                    severity="MEDIUM",
                    cwe="CWE-538",
                    confidence=0.9,
                    evidence="directory listing marker found in response body",
                    remediation="Disable directory listings on the web server.",
                )
            )
        return findings

    def _check_form(self, base_url: str, form: Dict) -> List[DynamicFinding]:
        action = urllib.parse.urljoin(base_url, form.get("action", ""))
        inputs = form.get("inputs", [])
        if not inputs:
            return []
        findings = []
        for payload in XSS_PAYLOADS:
            data = {name: payload for name in inputs}
            try:
                page = self.browser.submit_form(action, data, form.get("method", "POST"))
            except Exception:
                continue
            if payload in page.text:
                findings.append(
                    DynamicFinding(
                        url=action,
                        check="xss",
                        severity="HIGH",
                        cwe="CWE-79",
                        confidence=0.8,
                        evidence=f"form payload reflected unescaped:\n{page.text[:500]}",
                        remediation="Encode all dynamic output with context-aware escaping.",
                    )
                )
                break
        return findings

    def _probe_exposed(self, base_url: str) -> List[DynamicFinding]:
        findings = []
        for path in EXPOSED_PATHS:
            try:
                page = self.browser.get(f"{base_url}{path}")
            except Exception:
                continue
            body = page.text.strip()
            if (
                page.status == 200
                and body
                and not body.startswith("<!DOCTYPE")
                and "404" not in body[:200]
            ):
                findings.append(
                    DynamicFinding(
                        url=f"{base_url}{path}",
                        check="exposure",
                        severity="HIGH",
                        cwe="CWE-200",
                        confidence=0.8,
                        evidence=f"HTTP 200, {len(body)} bytes:\n{body[:300]}",
                        remediation="Remove sensitive files from the web root; block access via the server config.",
                    )
                )
        return findings

    # ------------------------------------------------------------------
    # Crawl helpers
    # ------------------------------------------------------------------

    def _same_origin_links(self, url: str, html: str) -> List[str]:
        parser = _LinkParser()
        try:
            parser.feed(html)
        except Exception:
            return []
        base = urllib.parse.urlparse(url)
        result = []
        for href in parser.links:
            joined = urllib.parse.urljoin(url, href)
            parsed = urllib.parse.urlparse(joined)
            if parsed.netloc == base.netloc and joined not in result:
                result.append(joined)
        return result

    def _parse_forms(self, html: str) -> List[Dict]:
        parser = _LinkParser()
        try:
            parser.feed(html)
        except Exception:
            return []
        return parser.forms
