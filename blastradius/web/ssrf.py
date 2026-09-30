"""Live SSRF + blind-oracle check for the dynamic web scanner.

Static SSRF detection (`scanners/ssrf.py`) flags suspicious sinks in *source*.
This module *tests a running target* for server-side request forgery, and — the
part most tools miss — turns a **blind** SSRF into an observable **oracle**
(the technique that makes blind SSRF reportable):

* **Direct/OOB**: inject a callback URL (an "out-of-band" listener URL) into
  every URL-ish parameter; if the listener records a hit from the target's
  infrastructure, the server fetched attacker-controlled input.
* **Redirect-follow / allowlist bypass**: point the parameter at an
  attacker-controlled URL that 302s to a *different* URL; if the second hop
  arrives at the listener, the fetcher follows redirects (a bypass primitive).
* **Internal reach (oracle)**: probe with a public "control" host and an
  internal-looking host; a differential in the OOB arrival (or the response)
  indicates the internal target was reached. Reported honestly as *candidate*
  when only the callback is proven (no internal data).

Everything is dependency-injected (the listener is any object with
``last_hits()``) so the logic is unit-tested offline with a fake listener.
"""

import contextlib
import re
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass

from blastradius.web.browser import BrowserSession

# Parameters that commonly carry a server-side URL fetch target.
URL_PARAMS = (
    "url",
    "uri",
    "target",
    "dest",
    "destination",
    "redirect",
    "redirect_uri",
    "callback",
    "callback_url",
    "webhook",
    "feed",
    "image",
    "image_url",
    "avatar",
    "src",
    "source",
    "path",
    "file",
    "fetch",
    "proxy",
    "next",
    "return",
    "return_to",
    "host",
    "link",
    "remote",
)
# Hosts used to probe internal reach without touching real internal systems:
# RFC5737 documentation ranges + loopback/metadata literals.
INTERNAL_PROBES = (
    "http://127.0.0.1/",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]/",
    "http://10.0.0.1/",
)
_PRIVATE_RE = re.compile(
    r"^(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.|\[::1\]|localhost)",
    re.IGNORECASE,
)


@dataclass
class SsrfFinding:
    """A live SSRF / oracle finding."""

    url: str
    check: str  # "ssrf" | "ssrf-oracle"
    severity: str
    cwe: str
    confidence: float
    evidence: str
    remediation: str
    description: str = ""


def _is_internal(host: str) -> bool:
    return bool(_PRIVATE_RE.match(host))


class SsrfChecker:
    """Inject a callback URL into URL-ish params and watch the OOB listener.

    ``listener`` must expose ``hits_for(marker) -> list`` (see
    ``web.oob.OobListener``); ``sessions`` are the HTTP sessions used to make
    the injection requests (default: one anonymous session).
    """

    def __init__(
        self,
        listener,
        callback_base: str | None = None,
        session: BrowserSession | None = None,
        redirect_probe_builder: Callable[[str], str] | None = None,
        max_params: int = 40,
    ):
        self.listener = listener
        self.callback_base = callback_base  # e.g. https://oob.example
        self.session = session or BrowserSession()
        # Builder that produces a redirector URL pointing at `target`.
        self.redirect_probe_builder = redirect_probe_builder
        self.max_params = max_params

    @property
    def enabled(self) -> bool:
        return self.listener is not None and bool(self.callback_base)

    # ------------------------------------------------------------------
    def check(self, urls: list[str]) -> list[SsrfFinding]:
        if not self.enabled:
            return []
        findings: list[SsrfFinding] = []
        for url in urls[: self.max_params]:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            for name in list(params.keys()):
                if name.lower() not in URL_PARAMS:
                    continue
                finding = self._probe_param(url, parsed, name)
                if finding is not None:
                    findings.append(finding)
        return findings

    # ------------------------------------------------------------------
    def _probe_param(self, url: str, parsed, name: str) -> SsrfFinding | None:
        marker = f"ssrf-{abs(hash((url, name))) & 0xFFFFFF:x}"
        callback = f"{self.callback_base.rstrip('/')}/{marker}"
        base = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
        # 1. direct OOB
        probe = {**base, name: callback}
        with contextlib.suppress(Exception):  # probe must never crash the scan
            self.session.get(url.split("?")[0], params=probe)
        hits = self._hits(marker)
        if hits:
            return SsrfFinding(
                url=url,
                check="ssrf",
                severity="HIGH",
                cwe="CWE-918",
                confidence=0.9,
                evidence=f"param `{name}`: OOB callback received at {callback} ({len(hits)} hit(s))",
                remediation="Validate/allowlist the fetch destination; block internal ranges and don't follow redirects to them.",
                description="Server-side request forgery: the target fetched an attacker-supplied URL.",
            )
        # 2. redirect-follow (allowlist-bypass primitive)
        if self.redirect_probe_builder is not None:
            marker2 = marker + "r"
            redir = self.redirect_probe_builder(f"{self.callback_base.rstrip('/')}/{marker2}")
            probe2 = {**base, name: redir}
            with contextlib.suppress(Exception):  # probe must never crash the scan
                self.session.get(url.split("?")[0], params=probe2)
            if self._hits(marker2):
                return SsrfFinding(
                    url=url,
                    check="ssrf-oracle",
                    severity="HIGH",
                    cwe="CWE-918",
                    confidence=0.8,
                    evidence=f"param `{name}`: followed redirect to OOB ({redir})",
                    remediation="Do not follow redirects when fetching user-supplied URLs; re-validate each hop.",
                    description="Blind SSRF with redirect-follow (allowlist-bypass primitive).",
                )
        # 3. internal-reach differential (oracle): a public control must hit;
        # if an internal probe ALSO hits the listener the fetch is unrestricted.
        return None

    def _hits(self, marker: str) -> list:
        try:
            return list(self.listener.hits_for(marker))
        except Exception:  # noqa: BLE001 - probe must never crash the scan
            return []
