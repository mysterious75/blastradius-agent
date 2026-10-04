"""Live MFA checks for the dynamic web scanner.

Methodology follows the paid MFA-bypass pattern set (Oasis AuthQuake,
OpenBao/Vault CVE-2025-55003, Outline GHSA-cwhc-53hw-qqx6, the 2FA-lab
canon): rate-limit absence, step skip, and OTP reuse. Three bounded,
explicit, analyst-driven probes — never a 1M-code brute force:

1. **RATE-LIMIT probe** — submit K well-formed-but-wrong OTPs (``000000``…
   default K=8, hard cap 20). Two outcomes:
   - a wrong OTP is ACCEPTED (success marker) -> ``mfa-broken-verification``
     (HIGH): verification does not verify;
   - K attempts draw no throttle signal (no 429, no lockout language) ->
     ``mfa-no-rate-limit`` (MEDIUM, CWE-307): the gate brute force needs.
2. **STEP-SKIP probe** — request the explicit post-login URL with the
   analyst-supplied pre-MFA session. Success marker without MFA ->
   ``mfa-step-skip`` (HIGH): the bouncer can be walked around.
3. **OTP-REUSE probe** — submit the analyst-supplied once-valid OTP twice.
   Accepted twice -> ``mfa-otp-reuse`` (HIGH, CWE-613): codes are never
   invalidated (the Vault/OpenBao pattern).

Responsible-testing constraints:

* EXPLICIT CONFIG ONLY. There is no endpoint discovery and no crawling:
  the caller names the verify URL, the dashboard URL, the OTP field, and
  the success oracles (mirroring --idor-url/--race-url explicitness).
* ACCOUNTS YOU OWN. Wrong OTPs are structurally valid (``000000``…) so a
  collision with a stranger's live code is astronomically unlikely, but
  the probes still belong on test accounts with voidable effects.
* BOUNDED. K <= 20 wrong attempts per run; reuse is exactly 2 submissions.
  Full-space enumeration is out of scope by design.
* Without a success oracle no finding is possible: undifferentiated 200s
  are noise, not signal.
"""

import contextlib
import json
import urllib.error
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Dict, List, Optional

from blastradius.web.browser import BrowserSession

DEFAULT_PROBES = 8
MAX_PROBES = 20

#: Response signals that the server is throttling authentication attempts.
_THROTTLE_MARKERS = (
    "too many",
    "rate limit",
    "rate-limit",
    "ratelimit",
    "throttle",
    "locked",
    "lockout",
    "try again later",
    "slow down",
    "temporarily blocked",
)


@dataclass
class MfaFinding:
    """A live MFA candidate finding."""

    url: str
    check: str  # mfa-no-rate-limit | mfa-broken-verification
    #            | mfa-step-skip | mfa-otp-reuse
    severity: str
    cwe: str
    confidence: float
    evidence: str
    remediation: str
    description: str = ""


class MfaChecker:
    """Bounded MFA probes against explicit analyst-supplied configuration."""

    def __init__(
        self,
        session: Optional[BrowserSession] = None,
        otp_field: str = "otp",
        max_probes: int = DEFAULT_PROBES,
    ):
        self.session = session or BrowserSession()
        self.otp_field = otp_field
        self.max_probes = max(2, min(max_probes, MAX_PROBES))

    # ------------------------------------------------------------------
    def check(self, cfg: Dict) -> List[MfaFinding]:
        """Run the configured probes. Empty/missing config refuses to guess."""
        if not cfg:
            return []
        findings: List[MfaFinding] = []
        verify_url = cfg.get("verify_url")
        markers = list(cfg.get("success_markers", []))
        if verify_url and markers:
            findings.extend(self._check_rate_limit(verify_url, markers))
            reuse_otp = cfg.get("reuse_otp")
            if reuse_otp:
                findings.extend(self._check_reuse(verify_url, reuse_otp, markers))
        dashboard_url = cfg.get("dashboard_url")
        dashboard_markers = list(cfg.get("dashboard_markers", []))
        if dashboard_url and dashboard_markers:
            findings.extend(self._check_step_skip(dashboard_url, dashboard_markers))
        return findings

    # ------------------------------------------------------------------
    def _check_rate_limit(self, verify_url: str, markers: List[str]) -> List[MfaFinding]:
        throttled = False
        seen_response = False
        for i in range(self.max_probes):
            page = self._submit(verify_url, f"{i:06d}")
            if page is None:
                continue
            seen_response = True
            if self._succeeded(page.text, markers):
                return [
                    self._mk(
                        verify_url,
                        "mfa-broken-verification",
                        "HIGH",
                        "CWE-287",
                        0.9,
                        f"wrong OTP {i:06d} accepted (success marker present)",
                    )
                ]
            if self._throttled(page):
                throttled = True
                break
        # A target that never answered at all is unreachable, not unthrottled:
        # transport silence must never become a finding.
        if not seen_response:
            return []
        if not throttled:
            return [
                self._mk(
                    verify_url,
                    "mfa-no-rate-limit",
                    "MEDIUM",
                    "CWE-307",
                    0.75,
                    f"{self.max_probes} wrong OTPs drew no throttle signal "
                    "(no 429, no lockout language)",
                )
            ]
        return []

    def _check_step_skip(self, dashboard_url: str, markers: List[str]) -> List[MfaFinding]:
        page = self._get(dashboard_url)
        if page is not None and self._succeeded(page.text, markers):
            return [
                self._mk(
                    dashboard_url,
                    "mfa-step-skip",
                    "HIGH",
                    "CWE-287",
                    0.85,
                    "post-login content served to the pre-MFA session (no MFA)",
                )
            ]
        return []

    def _check_reuse(self, verify_url: str, otp: str, markers: List[str]) -> List[MfaFinding]:
        first = self._submit(verify_url, otp)
        if first is None or not self._succeeded(first.text, markers):
            return []  # supplied OTP not valid now: nothing to test
        second = self._submit(verify_url, otp)
        if second is not None and self._succeeded(second.text, markers):
            return [
                self._mk(
                    verify_url,
                    "mfa-otp-reuse",
                    "HIGH",
                    "CWE-613",
                    0.85,
                    "once-valid OTP accepted a second time (never invalidated)",
                )
            ]
        return []

    # ------------------------------------------------------------------
    @staticmethod
    def _succeeded(text: Optional[str], markers: List[str]) -> bool:
        return bool(text) and any(m in text for m in markers)

    @staticmethod
    def _throttled(page) -> bool:
        if page.status == 429:
            return True
        body = (page.text or "").lower()
        return any(m in body for m in _THROTTLE_MARKERS)

    def _submit(self, url: str, otp: str):
        """POST an OTP, surfacing HTTP error statuses as responses.

        BrowserSession raises HTTPError on 4xx/5xx — but a 429 IS the
        throttle signal this checker looks for, so error bodies are
        converted to lightweight pages instead of being swallowed.
        Transport failures (connection refused, timeout) stay None.
        """
        try:
            return self.session._request(
                "POST",
                url,
                data=json.dumps({self.otp_field: otp}).encode(),
                headers={"Content-Type": "application/json"},
            )
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read().decode("utf-8", errors="replace")
            except Exception:
                body = ""
            return SimpleNamespace(status=exc.code, text=body)
        except Exception:
            return None

    def _get(self, url: str):
        with contextlib.suppress(Exception):  # probe must never crash the scan
            return self.session._request("GET", url)
        return None

    @staticmethod
    def _mk(url, check, severity, cwe, confidence, evidence) -> MfaFinding:
        return MfaFinding(
            url=url,
            check=check,
            severity=severity,
            cwe=cwe,
            confidence=confidence,
            evidence=evidence[:500],
            remediation="Throttle OTP verification (per-account and per-session "
            "limits with lockout), invalidate every code on first use, bind "
            "the MFA result to the pre-auth session, and gate every "
            "post-login route on MFA completion — never on a client-side flag.",
            description="Live MFA probe exposed a verification gap.",
        )
