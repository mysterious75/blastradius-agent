"""Finding chains — express A -> B -> C exploit chains as first-class output.

Bug-bounty severity is usually about the *chain*, not the single finding: an
open redirect alone is informational, but open-redirect -> OAuth redirect_uri
theft is account takeover. This module links findings by known chain rules so a
report can state the end-to-end impact.

Input: a list of findings (any object with ``check`` / ``vuln_type`` and
``url``). Output: :class:`Chain` objects, each a named, ordered path with a
combined severity. Rules are declarative so they are easy to extend and test.
"""

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

# A chain rule: (required node types in order, chain name, bumped severity).
# `nodes` must appear in the finding set; order defines the reported path.
_CHAIN_RULES: Tuple[Tuple[Tuple[str, ...], str, str], ...] = (
    (("redirect", "oauth"), "Open redirect -> OAuth code theft", "CRITICAL"),
    (("redirect", "ssrf"), "Open redirect -> SSRF bypass", "HIGH"),
    (("idor", "ato"), "IDOR on auth object -> account takeover", "CRITICAL"),
    (("ssrf", "cloud-metadata"), "SSRF -> cloud metadata credential theft", "CRITICAL"),
    (("ssrf-oracle", "cloud-metadata"), "Blind SSRF -> internal metadata reach", "HIGH"),
    (("xss", "csrf"), "Stored XSS + CSRF -> victim action", "HIGH"),
    (("jwt-none", "idor"), "Forged JWT -> object-level access", "CRITICAL"),
    (("jwt-weak-secret", "idor"), "Weak JWT secret -> object-level access", "HIGH"),
    (("jwt-confusion", "idor"), "JWT confusion -> object-level access", "CRITICAL"),
    (("exposure", "secret"), "Exposed file -> leaked credential", "HIGH"),
    (("listing", "exposure"), "Directory listing -> exposed file", "MEDIUM"),
)

# Severity ordering for combining.
_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


@dataclass
class Chain:
    """One evidenced exploit chain."""

    name: str
    severity: str
    steps: List[str]  # node types in order
    finding_urls: List[str] = field(default_factory=list)

    def describe(self) -> str:
        return f"{self.name}: " + " -> ".join(self.steps)


def _kind_of(finding) -> str:
    return str(getattr(finding, "check", None) or getattr(finding, "vuln_type", "") or "").lower()


def build_chains(findings: Iterable[object]) -> List[Chain]:
    """Link findings into known exploit chains.

    A rule fires when every required node type is present. Only the first
    finding of each type is used (one proof per step).
    """
    by_kind: Dict[str, object] = {}
    for f in findings:
        k = _kind_of(f)
        if k and k not in by_kind:
            by_kind[k] = f

    chains: List[Chain] = []
    for nodes, name, severity in _CHAIN_RULES:
        if all(n in by_kind for n in nodes):
            chains.append(
                Chain(
                    name=name,
                    severity=severity,
                    steps=list(nodes),
                    finding_urls=[getattr(by_kind[n], "url", "") for n in nodes],
                )
            )
    return chains


def combined_severity(findings: Iterable[object]) -> str:
    """Highest severity among findings (info for empty)."""
    best = "INFO"
    for f in findings:
        sev = str(getattr(f, "severity", "INFO")).upper()
        if _SEV_RANK.get(sev, 0) > _SEV_RANK.get(best, 0):
            best = sev
    return best
