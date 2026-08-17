"""DynamicWebScanner — black-box checks against a live target.

Crawls a target (same-origin links + forms) and runs behavioral checks that
static analysis cannot: reflected XSS, open redirects, missing/weak
security headers, wildcard/reflected CORS, exposed files, directory
listing, and subdomain-takeover fingerprints. Findings are HTTP-response
evidence — reported as candidates (no sandbox execution marker), with the
exact request/response snippet as proof.

Checks (vuln_type -> CWE):
    xss       CWE-79   payload reflected unescaped
    redirect  CWE-601  open redirect via url/next/return-like params
    headers   CWE-693  missing/weak security headers (OWASP policy table)
    cors      CWE-942  Access-Control-Allow-Origin: * + credentials, or
                       ACAO reflecting the request Origin / null
    exposure  CWE-200  /.git, /.env, /admin probes
    listing   CWE-538  directory listing
    takeover  CWE-706  dangling third-party service fingerprint (candidate)

Usage:
    scanner = DynamicWebScanner()
    findings = scanner.scan("http://localhost:8000")
"""

import re
import urllib.parse
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Dict, List, Optional

from blastradius.payloads import xss_payloads
from blastradius.web import takeover
from blastradius.web.browser import BrowserSession

# Fallback defaults when the real HackerOne payload corpus is unavailable.
XSS_PAYLOADS = ("<script>alert(1)</script>", '"><img src=x onerror=alert(1)>')
REDIRECT_PARAMS = ("url", "redirect", "next", "return", "dest", "goto", "target")
REDIRECT_HOST = "https://blastradius-evil.invalid"
# OWASP security-header policy: per-header expected value + weak check.
# `weak` returns True when the header is present but does not meet the
# OWASP guidance; `None` means presence is sufficient.
HEADER_POLICY = {
    "strict-transport-security": {
        "name": "Strict-Transport-Security",
        "expected": "Strict-Transport-Security: max-age>=31536000; includeSubDomains (optionally preload)",
        "weak": lambda v: "includesubdomains" not in v.lower() and "preload" not in v.lower(),
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "expected": "X-Frame-Options: DENY (or SAMEORIGIN)",
        "weak": lambda v: v.strip().upper() not in ("DENY", "SAMEORIGIN"),
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "expected": "X-Content-Type-Options: nosniff",
        "weak": lambda v: v.strip().lower() != "nosniff",
    },
    "content-security-policy": {
        "name": "Content-Security-Policy",
        "expected": "Content-Security-Policy header present with a restrictive policy",
        "weak": None,
    },
}
# Origin sent by the CORS-reflection probe.
CORS_PROBE_ORIGIN = "https://evil.example"
EXPOSED_PATHS = ("/.git/config", "/.git/HEAD", "/.env", "/admin", "/server-status", "/wp-admin/")
LISTING_MARKERS = ("Index of /", "Directory listing for", "Parent Directory</a>")

# JS endpoint extraction: fetch/axios/XHR/WebSocket call sites with a quoted URL.
_JS_ENDPOINT_RE = re.compile(
    r"""(?:fetch\s*\(|axios\.(?:get|post|put|delete|patch|head|options)\s*\(|"""
    r"""\.(?:get|post|put|delete|patch)\s*\(|new\s+WebSocket\s*\(|"""
    r"""\.open\s*\(\s*['\"](?:GET|POST|PUT|DELETE|PATCH)['\"]\s*,)"""
    r"""\s*['\"]([^'\"]+)['\"]""",
    re.IGNORECASE,
)
# Fallback: string literals that look like API paths.
_JS_PATH_LITERAL_RE = re.compile(r"""['\"](/[A-Za-z0-9_./?=&:{}-]{3,})['\"]""")
_JS_PATH_MARKERS = ("/api", "/v1", "/user", "/admin", "/search", "/account", "/auth", "/payment")
_MAX_JS_SCRIPTS_PER_PAGE = 5
_MAX_JS_FETCHES_PER_SCAN = 20


@dataclass
class DynamicFinding:
    """A black-box finding with HTTP-response evidence."""

    url: str
    check: str  # xss | redirect | headers | cors | exposure | listing | takeover
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
        self.scripts: List[str] = []

    def handle_starttag(self, tag, attrs):
        attr_map = dict(attrs)
        if tag == "a" and attr_map.get("href"):
            self.links.append(attr_map["href"])
        if tag == "script" and attr_map.get("src"):
            self.scripts.append(attr_map["src"])
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
        check_takeover: bool = True,
    ):
        self.browser = browser or BrowserSession()
        # Probe browser never follows redirects (so Location-based checks work).
        self._probe_browser = BrowserSession(follow_redirects=False)
        self.max_urls = max_urls
        self.depth = max(1, depth)
        self.probe_exposed = probe_exposed
        self.check_takeover = check_takeover
        # Real HackerOne payloads (defaults always included) for reflected XSS.
        self.xss_payloads = xss_payloads()
        # Budget guard: total JS fetches allowed per scan() call.
        self._js_fetches = 0

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
            for link in self._collect_js_endpoints(url, page.text):
                if link not in visited and link not in queue and len(visited) < self.max_urls:
                    queue.append(link)
            for form in self._parse_forms(page.text):
                findings.extend(self._check_form(target, form))

        if self.probe_exposed:
            findings.extend(self._probe_exposed(target))
        if self.check_takeover:
            findings.extend(self._check_subdomain_takeover(target))
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
                for payload in self.xss_payloads:
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
        # Missing / weak security headers: one LOW finding per header that is
        # absent or does not meet the OWASP policy table, with the expected
        # value embedded in the evidence.
        header_map = {k.lower(): v for k, v in page.headers.items()}
        for name, policy in HEADER_POLICY.items():
            value = header_map.get(name)
            if value is None:
                findings.append(
                    DynamicFinding(
                        url=url,
                        check="headers",
                        severity="LOW",
                        cwe="CWE-693",
                        confidence=0.95,
                        evidence=f"missing: {policy['name']} (OWASP expected: {policy['expected']})",
                        remediation=f"Set {policy['name']} to the OWASP-recommended value.",
                    )
                )
            elif policy["weak"] is not None and policy["weak"](value):
                findings.append(
                    DynamicFinding(
                        url=url,
                        check="headers",
                        severity="LOW",
                        cwe="CWE-693",
                        confidence=0.9,
                        evidence=(
                            f"weak: {policy['name']}: {value.strip()} "
                            f"(OWASP expected: {policy['expected']})"
                        ),
                        remediation=f"Strengthen {policy['name']} to the OWASP-recommended value.",
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
        # CORS reflection: probe with an attacker Origin and flag ACAO echoing
        # it back (or the null origin), which lets any site read the response.
        try:
            probe = self._probe_browser._request("GET", url, headers={"Origin": CORS_PROBE_ORIGIN})
        except Exception:
            probe = None
        if probe is not None:
            acao_probe = probe.headers.get("Access-Control-Allow-Origin", "")
            if acao_probe == CORS_PROBE_ORIGIN or acao_probe == "null":
                findings.append(
                    DynamicFinding(
                        url=url,
                        check="cors",
                        severity="MEDIUM",
                        cwe="CWE-942",
                        confidence=0.9,
                        evidence=(
                            "reflected Origin: Access-Control-Allow-Origin echoes "
                            f"the request Origin ({acao_probe})"
                        ),
                        remediation="Restrict CORS to explicit allowlisted origins; never reflect arbitrary Origins.",
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
        for payload in self.xss_payloads:
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

    def _check_subdomain_takeover(self, base_url: str) -> List[DynamicFinding]:
        """Probe the base URL for dangling third-party service fingerprints.

        Candidate-only: a fingerprint match indicates the host serves an
        unclaimed provider error page (deregistered bucket, expired app,
        unused Pages site) that an attacker could claim.
        """
        findings = []
        for match in takeover.check_takeover(base_url, self.browser):
            findings.append(
                DynamicFinding(
                    url=base_url,
                    check="takeover",
                    severity="MEDIUM",
                    cwe="CWE-706",
                    confidence=0.5,
                    evidence=match["evidence"],
                    remediation=(
                        "Remove the dangling DNS record or reclaim the third-party "
                        "service account before an attacker registers it."
                    ),
                    description=(
                        f"Subdomain-takeover candidate: unclaimed {match['service']} "
                        "endpoint serves a provider error page."
                    ),
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

    def _collect_js_endpoints(self, url: str, html: str) -> List[str]:
        """Discover API endpoints referenced inside the page's JS files.

        Fetches same-origin ``<script src>`` files (max 5 per page, 20 total
        per scan) and extracts endpoint-like strings from fetch/axios/XHR/
        WebSocket call sites plus path literals. Network failures never raise
        — they just yield no endpoints for that script.
        """
        base = urllib.parse.urlparse(url)
        scripts: List[str] = []
        parser = _LinkParser()
        try:
            parser.feed(html)
        except Exception:
            return []
        for src in parser.scripts:
            if src not in scripts:
                scripts.append(src)
        endpoints: List[str] = []
        for src in scripts[:_MAX_JS_SCRIPTS_PER_PAGE]:
            script_url = urllib.parse.urljoin(url, src)
            if urllib.parse.urlparse(script_url).netloc != base.netloc:
                continue
            if self._js_fetches >= _MAX_JS_FETCHES_PER_SCAN:
                break
            self._js_fetches += 1
            try:
                js = self.browser.get(script_url).text
            except Exception:
                continue
            for raw in _JS_ENDPOINT_RE.findall(js):
                self._add_js_endpoint(endpoints, script_url, base.netloc, raw)
            for raw in _JS_PATH_LITERAL_RE.findall(js):
                if any(marker in raw for marker in _JS_PATH_MARKERS):
                    self._add_js_endpoint(endpoints, script_url, base.netloc, raw)
        return endpoints

    @staticmethod
    def _add_js_endpoint(endpoints: List[str], script_url: str, netloc: str, raw: str) -> None:
        """urljoin ``raw`` against the script URL; keep same-origin + dedupe."""
        joined = urllib.parse.urljoin(script_url, raw.strip())
        if urllib.parse.urlparse(joined).netloc == netloc and joined not in endpoints:
            endpoints.append(joined)
