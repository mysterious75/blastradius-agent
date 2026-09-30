"""Live authorization-diff (IDOR/BOLA) check for the dynamic web scanner.

The static engine (`CVEHunter._scan_idor`) flags *suspicious source*. This module
*proves* object-level authorization bugs against a **running** target using two
identities — the same two-account methodology used in manual bug-bounty hunts:

    attacker session A  ──replays victim B's object URLs──►  does B's data return?

It never invents requests: it reuses the object URLs the crawler already found,
swaps the identity, and compares. A finding is emitted only when the victim's
response body (or a distinctive token from it) is returned to the attacker
session while the victim session also returns it — i.e. a real cross-identity
read, not a 200 status.

Safety:
    * opt-in — disabled unless two sessions are supplied;
    * read-only — GET replay only, never write methods;
    * bounded — one request per candidate URL per identity.
"""

import re
from dataclasses import dataclass

from blastradius.web.browser import BrowserSession

# URL shapes that usually carry an object identifier in the path.
_OBJECT_URL_RE = re.compile(
    r"/(?:\d+|[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}|[0-9a-fA-F]{16,})(?:[/?#]|$)"
)
# Query params that name an object identifier.
_ID_PARAMS = (
    "id",
    "user_id",
    "userid",
    "account_id",
    "account",
    "org_id",
    "order_id",
    "invoice",
    "file_id",
    "doc_id",
    "uid",
)
# Body tokens that indicate a purely negative / denial response.
_DENY_RE = re.compile(
    r"(?i)\b(access denied|forbidden|not authorized|unauthorized|permission denied|"
    r"not found|no permission|you do not have)\b"
)


@dataclass
class AuthzFinding:
    """A confirmed (or high-confidence) live authorization-diff hit."""

    url: str
    check: str  # "idor"
    severity: str
    cwe: str
    confidence: float
    evidence: str
    remediation: str
    description: str = ""


class AuthzDiffChecker:
    """Replay victim object URLs under an attacker identity and flag leaks."""

    def __init__(
        self,
        attacker: BrowserSession | None = None,
        victim: BrowserSession | None = None,
        victim_markers: list[str] | None = None,
        max_probes: int = 25,
    ):
        # Both sessions are required; the check is inert without them.
        self.attacker = attacker
        self.victim = victim
        self.victim_markers = [m.strip() for m in (victim_markers or []) if m and m.strip()]
        self.max_probes = max_probes

    @property
    def enabled(self) -> bool:
        return self.attacker is not None and self.victim is not None

    # ------------------------------------------------------------------
    # Candidate selection
    # ------------------------------------------------------------------

    @staticmethod
    def is_candidate_url(url: str) -> bool:
        """Whether a URL looks like it references an object by id."""
        if _OBJECT_URL_RE.search(url):
            return True
        query = url.split("?", 1)[1] if "?" in url else ""
        for part in query.split("&"):
            name = part.split("=", 1)[0].lower()
            if name in _ID_PARAMS:
                return True
        return False

    def candidate_urls(self, urls: list[str]) -> list[str]:
        seen = set()
        out = []
        for u in urls:
            if u in seen or not self.is_candidate_url(u):
                continue
            seen.add(u)
            out.append(u)
            if len(out) >= self.max_probes:
                break
        return out

    # ------------------------------------------------------------------
    # Check
    # ------------------------------------------------------------------

    def check(self, urls: list[str]) -> list[AuthzFinding]:
        """Run the authz diff over candidate URLs; returns confirmed leaks."""
        if not self.enabled:
            return []
        findings: list[AuthzFinding] = []
        for url in self.candidate_urls(urls):
            finding = self._probe(url)
            if finding is not None:
                findings.append(finding)
        return findings

    def _probe(self, url: str) -> AuthzFinding | None:
        try:
            victim_page = self.victim.get(url)
        except Exception:  # noqa: BLE001 - probe must never crash the scan
            return None
        # Victim must actually own the object (non-denial, 2xx, non-empty).
        victim_body = (victim_page.text or "").strip()
        if victim_page.status >= 400 or not victim_body or _DENY_RE.search(victim_body):
            return None
        try:
            attacker_page = self.attacker.get(url)
        except Exception:  # noqa: BLE001 - probe must never crash the scan
            return None
        if attacker_page.status >= 400:
            return None
        attacker_body = (attacker_page.text or "").strip()
        if not attacker_body or _DENY_RE.search(attacker_body):
            return None
        # Strong signature: a distinctive victim-owned token appears for the
        # attacker too. With no markers, fall back to byte-identical body.
        if self.victim_markers:
            leaked = [m for m in self.victim_markers if m in attacker_body and m in victim_body]
            if not leaked:
                return None
            evidence = (
                f"attacker session received victim marker(s) {leaked[:3]} from {url} "
                f"(victim status {victim_page.status}, attacker status {attacker_page.status})"
            )
            confidence = 0.95
        else:
            if attacker_body != victim_body:
                return None
            evidence = (
                f"attacker session received victim-identical body ({len(attacker_body)} bytes) "
                f"from {url}"
            )
            confidence = 0.75
        return AuthzFinding(
            url=url,
            check="idor",
            severity="HIGH",
            cwe="CWE-639",
            confidence=confidence,
            evidence=evidence[:500],
            remediation=(
                "Enforce object-level authorization on every request: verify the "
                "authenticated principal owns (or is authorized for) the referenced "
                "object before returning it."
            ),
            description="Live authorization diff: another identity read this object.",
        )
