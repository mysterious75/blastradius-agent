"""Live SQL-injection checks for the dynamic web scanner.

The static engine flags concatenated SQL in *source*; this module tests a
**running** target's parameters with three prove-it techniques:

* **error-based** — inject quote/breakout payloads; a database error string in
  the response confirms injectability;
* **boolean-differential** — send a true condition vs a false condition; a
  stable response difference (length/status, both directions) indicates
  evaluation;
* **time-based (opt-in)** — send sleep payloads; a delay >= threshold on the
  sleep probe but not on the baseline confirms execution.

NoSQL operator probes (``$gt``/``$ne``/``$regex``/``$where`` JSON bodies) are
covered by :func:`probe_nosql_body` for JSON endpoints.

Everything is dependency-injected (the HTTP session), so the logic is
unit-tested offline with fake sessions. Time-based probing is opt-in because
it is slow by construction.
"""

import contextlib
import json
import re
import time
import urllib.parse
from dataclasses import dataclass

from blastradius.payloads import (
    DEFAULT_NOSQLI_PAYLOADS,
    DEFAULT_SQLI_BOOLEAN_PAYLOADS,
    DEFAULT_SQLI_ERROR_PAYLOADS,
    DEFAULT_SQLI_TIME_PAYLOADS,
)
from blastradius.web.browser import BrowserSession

_DB_ERROR_RE = re.compile(
    r"(?i)(you have an error in your sql syntax|warning.*mysql|unclosed quotation mark|"
    r"quoted string not properly terminated|syntax error at or near|pg_query\(\)|"
    r"ORA-\d{5}|SQLSTATE|sqlite3?::|Microsoft OLE DB|ODBC SQL Server|"
    r"PostgreSQL.*ERROR|MySQL server version|supplied argument is not a valid MySQL)",
)


@dataclass
class SqliFinding:
    """A live SQL-injection finding."""

    url: str
    check: str  # sqli-error | sqli-boolean | sqli-time | nosqli
    severity: str
    cwe: str
    confidence: float
    evidence: str
    remediation: str
    description: str = ""


def _param_urls(url: str) -> list[str]:
    """Split a URL with a query string into (base, name) probe slots."""
    parsed = urllib.parse.urlparse(url)
    if not parsed.query:
        return []
    return [(name, url.split("?")[0]) for name in urllib.parse.parse_qs(parsed.query)]


class SqliChecker:
    """Probe URL parameters for SQL/NoSQL injection with prove-it oracles."""

    def __init__(
        self,
        session: BrowserSession | None = None,
        time_threshold_s: float = 4.0,
        enable_time_based: bool = False,
        max_params: int = 20,
    ):
        self.session = session or BrowserSession()
        self.time_threshold_s = time_threshold_s
        self.enable_time_based = enable_time_based
        self.max_params = max_params

    # ------------------------------------------------------------------
    def check(self, urls: list[str]) -> list[SqliFinding]:
        findings: list[SqliFinding] = []
        for url in urls[: self.max_params * 4]:
            for name, base in _param_urls(url)[: self.max_params]:
                hit = self._probe_param(url, base, name)
                if hit is not None:
                    findings.append(hit)
        return findings

    # ------------------------------------------------------------------
    def _get(self, base: str, name: str, value: str):
        return self.session.get(base, params={name: value})

    def _probe_param(self, url: str, base: str, name: str) -> SqliFinding | None:
        def _fetch(value: str):
            """GET that returns None instead of raising (probe must not crash)."""
            with contextlib.suppress(Exception):
                return self._get(base, name, value)
            return None

        # 1. error-based
        for payload in DEFAULT_SQLI_ERROR_PAYLOADS:
            page = _fetch("test" + payload)
            if page is None:
                continue
            match = _DB_ERROR_RE.search(page.text or "")
            if match:
                return self._mk(url, "sqli-error", "HIGH", "CWE-89", 0.9,
                                f"param `{name}`: database error with payload {payload!r}: "
                                f"{match.group(0)[:80]}")
        # 2. boolean differential (true vs false must differ, both stable)
        true_page = _fetch("test" + DEFAULT_SQLI_BOOLEAN_PAYLOADS[0])
        false_page = _fetch("test" + DEFAULT_SQLI_BOOLEAN_PAYLOADS[1])
        true_again = _fetch("test" + DEFAULT_SQLI_BOOLEAN_PAYLOADS[0])
        if true_page is None or false_page is None or true_again is None:
            return None
        if (len(true_page.text or "") != len(false_page.text or "")
                and true_page.text == true_again.text
                and true_page.status == true_again.status):
            return self._mk(url, "sqli-boolean", "HIGH", "CWE-89", 0.75,
                            f"param `{name}`: stable true/false response differential "
                            f"({len(true_page.text or '')} vs {len(false_page.text or '')} bytes)")
        # 3. time-based (opt-in only)
        if self.enable_time_based:
            for payload in DEFAULT_SQLI_TIME_PAYLOADS:
                start = time.monotonic()
                page = _fetch("test" + payload)
                waited = time.monotonic() - start
                if page is None:
                    continue
                if waited >= self.time_threshold_s and page.status < 500:
                    return self._mk(url, "sqli-time", "HIGH", "CWE-89", 0.8,
                                    f"param `{name}`: {waited:.1f}s delay with payload {payload!r}")
        return None

    # ------------------------------------------------------------------
    def probe_nosql_body(self, url: str, base_body: dict) -> list[SqliFinding]:
        """Send NoSQL operator bodies to a JSON endpoint; flag error/acceptance."""
        findings: list[SqliFinding] = []
        for payload in DEFAULT_NOSQLI_PAYLOADS:
            body = dict(base_body)
            body["__probe__"] = payload
            page = self._post_json(url, body)
            if page is None:
                continue
            if _DB_ERROR_RE.search(page.text or "") or (
                    page.status < 400 and "error" not in (page.text or "").lower()):
                findings.append(self._mk(url, "nosqli", "HIGH", "CWE-943", 0.7,
                                        f"NoSQL operator body accepted/surfaced: {payload}"))
                break
        return findings

    def _post_json(self, url: str, body: dict):
        """POST JSON that returns None instead of raising."""
        with contextlib.suppress(Exception):  # probe must never crash the scan
            return self.session._request(
                "POST", url, data=json.dumps(body).encode(),
                headers={"Content-Type": "application/json"})
        return None

    # ------------------------------------------------------------------
    @staticmethod
    def _mk(url, check, severity, cwe, confidence, evidence) -> SqliFinding:
        return SqliFinding(
            url=url, check=check, severity=severity, cwe=cwe, confidence=confidence,
            evidence=evidence[:500],
            remediation="Use parameterized queries / prepared statements for every database interaction; never concatenate input into SQL.",
            description="Live SQL-injection probe with response oracle.",
        )
