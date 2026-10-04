"""Live GraphQL checks for the dynamic web scanner.

Methodology follows the OWASP GraphQL testing canon (WSTG + cheat sheet)
and the paid-report pattern set (batching/alias rate-limit bypass,
introspection exposure, node-ID auth bypass):

1. **ENDPOINT DISCOVERY** — probe common GraphQL paths with a universal
   ``{__typename}`` query. ``__typename`` is valid on every GraphQL server,
   so a GraphQL-shaped answer confirms the endpoint without introspection.
2. **INTROSPECTION** — one read-only ``__schema`` query. A data-bearing
   answer exposes the full attack surface (CWE-200).
3. **FIELD SUGGESTIONS** — one deliberately misspelled field. A
   "Did you mean …?" error reconstructs schema without introspection
   (the Clairvoyance technique; CWE-209).
4. **ALIAS BATCHING** — one document with N aliased ``__typename`` fields.
   If the server executes all N aliases, per-operation rate limits and
   batch caps are absent: the primitive behind OTP/credential brute force
   and alias-amplification DoS (CVE-2026-11103 pattern; CWE-400). N is small
   (10) and the field is free, so the probe itself is non-disruptive.

What is deliberately NOT tested live: query-depth DoS (disruptive by
construction), node-ID IDOR (needs two authenticated identities — that is
the authz checker's job), and mutation abuse (state-changing).

Everything is dependency-injected (the HTTP session), so the logic is
unit-tested offline with fake sessions.
"""

import contextlib
import json
from dataclasses import dataclass
from typing import Dict, List, Optional

from blastradius.web.browser import BrowserSession

#: Paths where GraphQL endpoints conventionally live.
GRAPHQL_PATHS = (
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/query",
    "/gql",
    "/graph",
    "/graphql/console",
)

_INTROSPECTION_QUERY = "{__schema{queryType{name}mutationType{name}}}"
_SUGGESTION_QUERY = "{blast_radius_nonexistent_field_xyz{__typename}}"
_BATCH_ALIASES = 10


def _batch_query(n: int = _BATCH_ALIASES) -> str:
    return "{" + " ".join(f"blast_alias_{i}:__typename" for i in range(n)) + "}"


@dataclass
class GraphqlFinding:
    """A live GraphQL finding."""

    url: str
    check: str  # graphql-introspection | graphql-suggestions | graphql-batching
    severity: str
    cwe: str
    confidence: float
    evidence: str
    remediation: str
    description: str = ""


class GraphqlChecker:
    """Discover GraphQL endpoints and run the safe read-only check set."""

    def __init__(self, session: Optional[BrowserSession] = None):
        self.session = session or BrowserSession()

    # ------------------------------------------------------------------
    def check(self, base_url: str) -> List[GraphqlFinding]:
        findings: List[GraphqlFinding] = []
        endpoint = self._discover(base_url.rstrip("/"))
        if endpoint is None:
            return findings
        findings.extend(self._check_introspection(endpoint))
        findings.extend(self._check_suggestions(endpoint))
        findings.extend(self._check_batching(endpoint))
        return findings

    # ------------------------------------------------------------------
    def _discover(self, base: str) -> Optional[str]:
        """First path that answers a __typename probe with GraphQL JSON."""
        for path in GRAPHQL_PATHS:
            url = base + path
            body = self._post(url, "{__typename}")
            if body is None:
                continue
            if self._is_graphql(body):
                return url
        return None

    def _check_introspection(self, endpoint: str) -> List[GraphqlFinding]:
        body = self._post(endpoint, _INTROSPECTION_QUERY)
        if body is None:
            return []
        try:
            data = json.loads(body)
        except ValueError:
            return []
        schema = (data.get("data") or {}).get("__schema")
        if not schema:
            return []
        queries = (schema.get("queryType") or {}).get("name", "?")
        return [
            GraphqlFinding(
                url=endpoint,
                check="graphql-introspection",
                severity="MEDIUM",
                cwe="CWE-200",
                confidence=0.8,
                evidence=f"introspection enabled; query root `{queries}` disclosed"[:500],
                remediation="Disable introspection in production (and per-role "
                "where supported); it hands attackers the full schema.",
                description="Live GraphQL introspection probe returned schema data.",
            )
        ]

    def _check_suggestions(self, endpoint: str) -> List[GraphqlFinding]:
        body = self._post(endpoint, _SUGGESTION_QUERY)
        if body is None or "did you mean" not in body.lower():
            return []
        return [
            GraphqlFinding(
                url=endpoint,
                check="graphql-suggestions",
                severity="MEDIUM",
                cwe="CWE-209",
                confidence=0.75,
                evidence="misspelled field drew a 'Did you mean …?' hint"[:500],
                remediation="Disable field suggestions in production (Apollo: "
                "hideSchemaDetailsFromClientErrors; Yoga: maskedErrors).",
                description="Live GraphQL field-suggestion probe leaked a real field name.",
            )
        ]

    def _check_batching(self, endpoint: str) -> List[GraphqlFinding]:
        body = self._post(endpoint, _batch_query())
        if body is None:
            return []
        try:
            data = json.loads(body)
        except ValueError:
            return []
        executed = len(data.get("data") or {})
        if executed < _BATCH_ALIASES:
            return []
        return [
            GraphqlFinding(
                url=endpoint,
                check="graphql-batching",
                severity="MEDIUM",
                cwe="CWE-400",
                confidence=0.8,
                evidence=(
                    f"server executed all {_BATCH_ALIASES} aliased operations "
                    "in one document — no batch/alias cap"
                )[:500],
                remediation="Cap operations per document, throttle by query cost "
                "rather than HTTP requests, and forbid batching on sensitive "
                "fields (auth, OTP, password reset).",
                description="Live GraphQL alias-batching probe: all aliases executed.",
            )
        ]

    # ------------------------------------------------------------------
    @staticmethod
    def _is_graphql(body: str) -> bool:
        """GraphQL-shaped JSON: data with __typename, or a GraphQL errors array."""
        try:
            data = json.loads(body)
        except ValueError:
            return False
        if not isinstance(data, dict):
            return False
        if isinstance(data.get("data"), dict) and "__typename" in data["data"]:
            return True
        errors = data.get("errors")
        return bool(isinstance(errors, list) and errors and isinstance(errors[0], dict))

    def _post(self, url: str, query: str) -> Optional[str]:
        """POST a GraphQL query; None on any transport failure."""
        payload = json.dumps({"query": query}).encode()
        with contextlib.suppress(Exception):  # probe must never crash the scan
            page = self.session._request(
                "POST",
                url,
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            if page is not None and page.status < 500:
                return page.text or ""
        return None


def describe_resolver_risks(schema_names: Dict[str, List[str]]) -> List[str]:
    """Offline helper: flag risky resolver names recovered from a schema.

    Pure function over introspection output (no network) — maps the paid
    mutation/field patterns (auth, OTP, admin, transfer, export) to review
    priorities for the analyst. Returns human-readable review notes.
    """
    risky = ("auth", "login", "otp", "password", "admin", "role", "transfer", "export", "delete")
    notes = []
    for kind, names in schema_names.items():
        for name in names:
            lowered = name.lower()
            if any(token in lowered for token in risky):
                notes.append(
                    f"{kind}.{name}: sensitive resolver — verify authz on the "
                    "resolver itself, not just the edge (node-ID bypass pattern)"
                )
    return notes
