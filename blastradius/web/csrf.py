"""Live CSRF checks for the dynamic web scanner.

Methodology follows the OWASP CSRF canon and the 2026 paid-pattern set
(token-presence/validation gaps, method-override SameSite-Lax bypass,
state-changing GETs). Two tiers:

1. **PASSIVE (zero-risk, runs inside the normal crawl)** — every discovered
   POST form is inspected for a synchronizer-token field (``csrf``,
   ``_token``, ``authenticity_token``, ``xsrf``, ``nonce``,
   ``__requestverificationtoken``). A state-changing form with no token
   field is a ``csrf-token-missing`` candidate (MEDIUM). No extra request
   beyond the crawl itself.
2. **ACTIVE (explicit URLs + victim session only)** — the token harness
   against analyst-named state-changing URLs, mirroring the ``--idor-url``
   / ``--race-url`` explicitness discipline (CSRF proofs fire real state
   changes, so the checker never invents targets):
   - no token at all          -> ``csrf-missing-token`` (HIGH)
   - garbage token            -> ``csrf-weak-validation`` (HIGH)
   - same action over GET      -> ``csrf-get-override`` (MEDIUM — also the
                                  classic GET-CSRF primitive)
   - GET + ``_method=POST``    -> ``csrf-method-override`` (MEDIUM — the
                                  SameSite-Lax bypass pattern: the browser
                                  sends cookies on a top-level GET while the
                                  server honors it as a POST)

   Success is strictly oracle-defined (caller-supplied markers present only
   when the state change happened). The "victim" is an injected session
   (cookie/bearer); without ambient authority a 200 proves nothing, so the
   active tier refuses to run sessionless.

Out of scope for a non-browser prober: cookie ``SameSite``/``Secure`` flag
audits that need Set-Cookie inspection are covered passively where the
crawl sees them; browser-navigation Lax-bypass confirmation needs a real
browser and stays analyst work.
"""

import contextlib
import re
import urllib.parse
from dataclasses import dataclass
from typing import Dict, List, Optional

from blastradius.web.browser import BrowserSession

#: Hidden-field names that carry synchronizer tokens across frameworks.
TOKEN_NAMES = (
    "csrf",
    "csrf_token",
    "csrftoken",
    "_token",
    "authenticity_token",
    "xsrf",
    "xsrf_token",
    "_xsrf",
    "nonce",
    "__requestverificationtoken",
    "csrfmiddlewaretoken",
)

_TOKEN_RE = re.compile(r'<input[^>]+name\s*=\s*["\']?([^"\'\s>]+)["\']?', re.IGNORECASE)
_FORM_RE = re.compile(
    r"<form[^>]*method\s*=\s*[\"']?post[\"']?[^>]*>(.*?)</form>",
    re.IGNORECASE | re.DOTALL,
)
_GARBAGE_TOKEN = "blast-radius-invalid-token"


@dataclass
class CsrfFinding:
    """A live CSRF candidate finding."""

    url: str
    check: str  # csrf-token-missing | csrf-missing-token | csrf-weak-validation
    #            | csrf-get-override | csrf-method-override
    severity: str
    cwe: str
    confidence: float
    evidence: str
    remediation: str
    description: str = ""


def form_has_token(form_html: str) -> bool:
    """Whether a POST form carries a synchronizer-token field (pure)."""
    for name in _TOKEN_RE.findall(form_html):
        lowered = name.lower()
        if any(token in lowered for token in TOKEN_NAMES):
            return True
    return False


def post_forms(page_html: str) -> List[str]:
    """Extract POST form bodies from a page (pure)."""
    return _FORM_RE.findall(page_html or "")


class CsrfChecker:
    """Passive form analysis + active token harness on explicit URLs."""

    def __init__(
        self,
        session: Optional[BrowserSession] = None,
        fields: Optional[List[str]] = None,
    ):
        self.session = session or BrowserSession()
        self.fields = dict(fields or {})

    # ------------------------------------------------------------------
    # Passive tier: zero extra requests, runs on crawled pages.
    # ------------------------------------------------------------------
    def check_forms(self, url: str, page_html: str) -> List[CsrfFinding]:
        """Flag POST forms without a synchronizer-token field."""
        findings: List[CsrfFinding] = []
        for form in post_forms(page_html):
            if not form_has_token(form):
                findings.append(
                    CsrfFinding(
                        url=url,
                        check="csrf-token-missing",
                        severity="MEDIUM",
                        cwe="CWE-352",
                        confidence=0.6,
                        evidence="POST form carries no synchronizer-token field"[:500],
                        remediation="Add a per-session synchronizer token to every "
                        "state-changing form and validate it server-side; never "
                        "rely on SameSite alone for state changes.",
                        description="Crawled POST form has no CSRF token field.",
                    )
                )
                break  # one finding per page is enough
        return findings

    # ------------------------------------------------------------------
    # Active tier: explicit URLs + victim session + success oracle.
    # ------------------------------------------------------------------
    def check(self, urls: List[str], success_markers: List[str]) -> List[CsrfFinding]:
        """Run the token harness against explicit state-changing URLs."""
        if not urls or not success_markers:
            return []  # no targets or no oracle: refuse to guess
        findings: List[CsrfFinding] = []
        for url in urls:
            findings.extend(self._harness(url, success_markers))
        return findings

    def _harness(self, url: str, markers: List[str]) -> List[CsrfFinding]:
        findings: List[CsrfFinding] = []

        def succeeded(page) -> bool:
            return page is not None and any(m in (page.text or "") for m in markers)

        # 1. No token at all.
        if succeeded(self._post(url, self._without_token())):
            findings.append(
                self._mk(
                    url,
                    "csrf-missing-token",
                    "HIGH",
                    0.85,
                    "state change accepted with no CSRF token",
                )
            )
            return findings  # weakest link found; deeper probes add nothing
        # 2. Garbage token.
        if succeeded(self._post(url, self._with_token(_GARBAGE_TOKEN))):
            findings.append(
                self._mk(
                    url,
                    "csrf-weak-validation",
                    "HIGH",
                    0.8,
                    "state change accepted with a garbage CSRF token",
                )
            )
            return findings
        # 3. Same action over GET.
        if succeeded(self._get(url)):
            findings.append(
                self._mk(
                    url,
                    "csrf-get-override",
                    "MEDIUM",
                    0.75,
                    "state change reachable over GET (GET-CSRF primitive)",
                )
            )
        # 4. GET + _method=POST (SameSite-Lax bypass shape).
        elif succeeded(self._get(url, {"_method": "POST"})):
            findings.append(
                self._mk(
                    url,
                    "csrf-method-override",
                    "MEDIUM",
                    0.75,
                    "GET + _method=POST honored (SameSite-Lax bypass shape)",
                )
            )
        return findings

    # ------------------------------------------------------------------
    def _without_token(self) -> Dict[str, str]:
        return {k: v for k, v in self.fields.items() if k.lower() not in TOKEN_NAMES}

    def _with_token(self, token: str) -> Dict[str, str]:
        body = self._without_token()
        body["csrf_token"] = token
        return body

    def _post(self, url: str, body: Dict[str, str]):
        with contextlib.suppress(Exception):  # probe must never crash the scan
            return self.session._request(
                "POST",
                url,
                data=_encode(body),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        return None

    def _get(self, url: str, params: Optional[Dict[str, str]] = None):
        with contextlib.suppress(Exception):  # probe must never crash the scan
            full = url
            if params:
                sep = "&" if "?" in url else "?"
                full = f"{url}{sep}{_encode(params).decode()}"
            return self.session._request("GET", full)
        return None

    @staticmethod
    def _mk(url, check, severity, confidence, evidence) -> CsrfFinding:
        return CsrfFinding(
            url=url,
            check=check,
            severity=severity,
            cwe="CWE-352",
            confidence=confidence,
            evidence=evidence[:500],
            remediation="Validate a per-session synchronizer token on every "
            "state-changing verb, reject tokenless/empty/garbage tokens, never "
            "honor state changes over GET or _method overrides, and set "
            "SameSite=Strict on session cookies.",
            description="Live CSRF token-harness probe accepted the state change.",
        )


def _encode(body: Dict[str, str]) -> bytes:
    return urllib.parse.urlencode(body).encode()
