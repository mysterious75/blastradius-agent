"""Live race-condition (TOCTOU) checks for the dynamic web scanner.

Methodology follows the PortSwigger race canon (Turbo Intruder gated
requests, "Smashing the State Machine"): a burst of N requests released
simultaneously at the same single-use endpoint, then counting how many
"succeeded". More successes than the endpoint allows (usually 1) proves a
check-then-act window — the coupon double-redeem, the wallet double-spend
(CVE-2026-34368 pattern), the seat-limit bypass.

Responsible-testing constraints (this is what keeps the checker shippable):

* EXPLICIT TARGETS ONLY. The crawler never auto-races discovered forms —
  firing parallel state-changing bursts at every endpoint would itself be
  the attack. The caller names exact URLs (mirroring ``--idor-url``) plus
  the success markers that are only present on success.
* SMALL, SINGLE BURST. Default 10 requests, hard cap 25, released once via
  a thread barrier (the HTTP/1.1 gated-request equivalent). No retry loops,
  no hammering, no single-packet H2 machinery.
* READ THE RESULT, DON'T SPEND IT. The benchmark/lab endpoints credit
  obviously-fake sentinel value; on a real target the analyst picks an
  endpoint whose success is observable without harm (e.g. a coupon whose
  redemption they own and can void) — the checker cannot know that, so it
  refuses to guess targets.

A finding is a candidate with the success count as evidence
("10 parallel requests -> 7 successes, expected <= 1"); exploitability of
the window (what the extra successes buy) stays analyst work.
"""

import contextlib
import threading
from dataclasses import dataclass
from typing import Dict, List, Optional

from blastradius.web.browser import BrowserSession

DEFAULT_BURST = 10
MAX_BURST = 25


@dataclass
class RaceFinding:
    """A live race-condition candidate finding."""

    url: str
    check: str  # always "race-condition"
    severity: str
    cwe: str
    confidence: float
    evidence: str
    remediation: str
    description: str = ""


class RaceChecker:
    """Fire one gated burst at explicit URLs and count successes."""

    def __init__(
        self,
        session: Optional[BrowserSession] = None,
        burst: int = DEFAULT_BURST,
        method: str = "POST",
        body: Optional[Dict[str, str]] = None,
    ):
        self.session = session or BrowserSession()
        self.burst = max(2, min(burst, MAX_BURST))
        self.method = method.upper()
        self.body = dict(body or {})

    # ------------------------------------------------------------------
    def check(self, urls: List[str], success_markers: List[str]) -> List[RaceFinding]:
        """Burst each URL once; flag when successes exceed 1."""
        if not success_markers:
            return []  # without a success definition there is no oracle
        findings: List[RaceFinding] = []
        for url in urls:
            successes = self._burst(url, success_markers)
            if successes > 1:
                findings.append(
                    RaceFinding(
                        url=url,
                        check="race-condition",
                        severity="HIGH",
                        cwe="CWE-367",
                        confidence=0.85,
                        evidence=(
                            f"{self.burst} parallel requests -> {successes} "
                            f"successes containing {success_markers[0]!r} "
                            f"(expected at most 1)"
                        )[:500],
                        remediation="Make the check-and-act atomic: single "
                        "conditional UPDATE (… WHERE used = 0), row-level "
                        "locking, or a unique constraint — never separate "
                        "SELECT-then-UPDATE without a lock.",
                        description="Live TOCTOU probe: single-use action succeeded twice.",
                    )
                )
        return findings

    def _burst(self, url: str, success_markers: List[str]) -> int:
        """Release the burst through a barrier; return the success count.

        Success is strictly defined: the response arrived AND carries a
        caller-supplied success marker. Anything else (error, timeout,
        markerless 200) never counts — a burst that merely errors is not
        a race, it is noise.
        """
        barrier = threading.Barrier(self.burst)
        results: List[bool] = []

        def fire():
            with contextlib.suppress(Exception):
                barrier.wait(timeout=10)
            page = self._request(url)
            results.append(page is not None and any(m in page.text for m in success_markers))

        threads = [threading.Thread(target=fire, daemon=True) for _ in range(self.burst)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        return sum(results)

    def _request(self, url: str):
        """One raced request; None on transport failure (never counts)."""
        with contextlib.suppress(Exception):  # probe must never crash the scan
            if self.method == "POST":
                return self.session._request(
                    "POST",
                    url,
                    data=_encode(self.body),
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
            return self.session._request("GET", url)
        return None


def _encode(body: Dict[str, str]) -> bytes:
    import urllib.parse

    return urllib.parse.urlencode(body).encode()
