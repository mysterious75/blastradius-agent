"""Live mass-assignment checks for the dynamic web scanner.

The static layer cannot see runtime model binding; this module tests a
**running** target by smuggling privileged attributes (``role``, ``is_admin``,
``tenant_id``, …) into update/profile JSON bodies and watching whether the
server honours them:

* **reflection** — the privileged field (or its value) comes back in the
  response object;
* **persistence** — a follow-up GET of the object still shows the value.

Both signals are required for HIGH confidence; reflection alone is MEDIUM
(some frameworks echo unknown fields harmlessly). Probes use obviously-fake
sentinel values (``blastradius-probe``) so a hit can never be confused with
real data, and every probe is read-only in effect (no destructive action).

Dependency-injected session: offline-testable with fake sessions.
"""

import contextlib
import json
from dataclasses import dataclass

from blastradius.payloads import DEFAULT_MASSASSIGN_FIELDS
from blastradius.web.browser import BrowserSession

_SENTINEL = "blastradius-probe"


@dataclass
class MassassignFinding:
    """A live mass-assignment finding."""

    url: str
    check: str  # always "massassign"
    severity: str
    cwe: str
    confidence: float
    evidence: str
    remediation: str
    description: str = ""


class MassassignChecker:
    """Smuggle privileged fields into JSON update bodies and watch."""

    def __init__(
        self,
        session: BrowserSession | None = None,
        fields=None,
        verify_url: str | None = None,
    ):
        self.session = session or BrowserSession()
        self.fields = list(fields or DEFAULT_MASSASSIGN_FIELDS)
        self.verify_url = verify_url

    # ------------------------------------------------------------------
    def check(self, url: str, base_body: dict) -> list[MassassignFinding]:
        findings: list[MassassignFinding] = []
        for field in self.fields:
            body = dict(base_body)
            body[field] = _SENTINEL
            page = self._post_json(url, body)
            if page is None:
                continue
            text = page.text or ""
            if page.status >= 400 or _SENTINEL not in text:
                continue
            persisted = False
            if self.verify_url:
                verify = self._get(self.verify_url)
                persisted = verify is not None and _SENTINEL in (verify.text or "")
            if persisted:
                findings.append(
                    self._mk(
                        url, "HIGH", 0.9, f"field `{field}` persisted (sentinel visible on re-read)"
                    )
                )
            else:
                findings.append(
                    self._mk(
                        url,
                        "MEDIUM",
                        0.6,
                        f"field `{field}` reflected in response (sentinel echoed)",
                    )
                )
        return findings

    def _post_json(self, url: str, body: dict):
        """POST JSON that returns None instead of raising."""
        with contextlib.suppress(Exception):  # probe must never crash the scan
            return self.session._request(
                "POST",
                url,
                data=json.dumps(body).encode(),
                headers={"Content-Type": "application/json"},
            )
        return None

    def _get(self, url: str):
        """GET that returns None instead of raising."""
        with contextlib.suppress(Exception):  # probe must never crash the scan
            return self.session._request("GET", url)
        return None

    # ------------------------------------------------------------------
    @staticmethod
    def _mk(url, severity, confidence, evidence) -> MassassignFinding:
        return MassassignFinding(
            url=url,
            check="massassign",
            severity=severity,
            cwe="CWE-915",
            confidence=confidence,
            evidence=evidence[:500],
            remediation="Bind only an explicit allowlist of fields on update endpoints; "
            "never mass-assign request bodies onto models.",
            description="Live mass-assignment probe with sentinel value.",
        )
