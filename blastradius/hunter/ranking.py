"""Finding ranking — composite score (confidence + severity + sandbox verdict).

Sorts candidate findings by expected value so the focused-task orchestrator
(hunter/agent_tasks.py) and humans alike spend effort on the findings most
likely to be real and impactful first.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from blastradius.hunter.scanner import Finding

SEVERITY_WEIGHT = {
    "CRITICAL": 1.0,
    "HIGH": 0.85,
    "MEDIUM": 0.65,
    "LOW": 0.4,
}

_CONFIRMED_BONUS = 0.25
_NOT_EXPLOITABLE_PENALTY = -0.25

FindingKey = Tuple[str, int, str]


def finding_key(f: Finding) -> FindingKey:
    """Stable identity for a finding: (file, line, vuln_type)."""
    return (f.file, f.line, f.vuln_type)


def classify_verdict(output: str) -> str:
    """Normalize a sandbox/task output into a verdict label."""
    upper = (output or "").upper()
    if upper.startswith("CONFIRMED_EXPLOITABLE"):
        return "exploitable"
    if upper.startswith("NOT_EXPLOITABLE"):
        return "not_exploitable"
    if upper.startswith("UNSUPPORTED") or "NO EXPLOIT TEMPLATE" in upper:
        return "unsupported"
    return "needs_manual_review"


def _verdict_score(verdict: str) -> float:
    if verdict == "exploitable":
        return _CONFIRMED_BONUS
    if verdict in ("not_exploitable", "unsupported"):
        return _NOT_EXPLOITABLE_PENALTY
    return 0.0


@dataclass
class RankedFinding:
    """A finding with its composite score and position."""

    finding: Finding
    score: float
    rank: int = 0
    sandbox_verdict: str = ""

    @property
    def file(self) -> str:
        return self.finding.file

    @property
    def line(self) -> int:
        return self.finding.line

    @property
    def vuln_type(self) -> str:
        return self.finding.vuln_type

    @property
    def confidence(self) -> float:
        return self.finding.confidence

    @property
    def severity(self) -> str:
        return self.finding.severity

    @property
    def payload(self) -> str:
        return self.finding.payload


def rank_findings(
    findings: List[Finding],
    sandbox_verdicts: Optional[Dict[FindingKey, str]] = None,
) -> List[RankedFinding]:
    """Rank findings by expected value; higher score = investigate first.

    Score = 0.55 * confidence + 0.30 * severity weight + sandbox verdict bonus.
    Verified-exploitable findings rise, ruled-out findings sink. Ties break by
    confidence, then file/line/type for determinism.
    """
    verdicts = sandbox_verdicts or {}
    ranked = []
    for f in findings:
        verdict = verdicts.get(finding_key(f), "")
        score = (
            0.55 * float(f.confidence)
            + 0.30 * SEVERITY_WEIGHT.get(f.severity or "", 0.5)
            + _verdict_score(verdict)
        )
        ranked.append(
            RankedFinding(
                finding=f,
                score=round(max(0.0, min(1.0, score)), 4),
                sandbox_verdict=verdict,
            )
        )
    ranked.sort(key=lambda r: (-r.score, -r.confidence, r.file, r.line, r.vuln_type))
    for i, r in enumerate(ranked, start=1):
        r.rank = i
    return ranked
