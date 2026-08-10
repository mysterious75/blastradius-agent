"""Finding ranking — composite score (confidence + severity + sandbox verdict).

Sorts candidate findings by expected value so the focused-task orchestrator
(hunter/agent_tasks.py) and humans alike spend effort on the findings most
likely to be real and impactful first. Weights are customizable via the
``weights`` argument or the BLASTRADIUS_RANK_WEIGHTS env var (JSON).
"""

import json
import os
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from blastradius.hunter.scanner import Finding

SEVERITY_WEIGHT = {
    "CRITICAL": 1.0,
    "HIGH": 0.85,
    "MEDIUM": 0.65,
    "LOW": 0.4,
}

DEFAULT_RANK_WEIGHTS = {
    "confidence": 0.55,
    "severity": 0.30,
    "confirmed": 0.25,
    "ruled_out": -0.25,
}

FindingKey = Tuple[str, int, str]


def rank_weights(weights: Optional[Dict[str, float]] = None) -> Dict[str, float]:
    """Effective rank weights: explicit argument > BLASTRADIUS_RANK_WEIGHTS
    env JSON > defaults. Partial dicts merge over the defaults."""
    merged = dict(DEFAULT_RANK_WEIGHTS)
    raw = os.getenv("BLASTRADIUS_RANK_WEIGHTS", "").strip()
    if raw:
        try:
            merged.update(json.loads(raw))
        except (ValueError, TypeError):
            pass
    if weights:
        merged.update(weights)
    return merged


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


def _verdict_score(verdict: str, w: Dict[str, float]) -> float:
    if verdict == "exploitable":
        return w["confirmed"]
    if verdict == "not_exploitable":
        return w["ruled_out"]
    # "unsupported" (no exploit template) is "can't validate", not "not vulnerable"
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
    weights: Optional[Dict[str, float]] = None,
) -> List[RankedFinding]:
    """Rank findings by expected value; higher score = investigate first.

    Score = w[confidence] * confidence + w[severity] * severity weight
            + sandbox verdict (w[confirmed] / w[ruled_out]).
    Verified-exploitable findings rise, ruled-out findings sink. Ties break by
    confidence, then file/line/type for determinism.
    """
    w = rank_weights(weights)
    verdicts = sandbox_verdicts or {}
    ranked = []
    for f in findings:
        verdict = verdicts.get(finding_key(f), "")
        score = (
            w["confidence"] * float(f.confidence)
            + w["severity"] * SEVERITY_WEIGHT.get(f.severity or "", 0.5)
            + _verdict_score(verdict, w)
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
