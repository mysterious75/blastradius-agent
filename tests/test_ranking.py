"""Ranking tests — deterministic, no network."""

from blastradius.hunter.ranking import (
    classify_verdict,
    finding_key,
    rank_findings,
)
from blastradius.hunter.scanner import Finding


def _f(file, line, vuln_type, confidence, severity="HIGH"):
    return Finding(
        file=file, line=line, vuln_type=vuln_type, payload="x",
        confidence=confidence, severity=severity,
    )


def test_rank_sorts_by_confidence_and_severity():
    low = _f("a.py", 1, "sqli", 0.7, "LOW")
    high = _f("a.py", 2, "xss", 0.95, "CRITICAL")
    ranked = rank_findings([low, high])
    assert [r.finding for r in ranked] == [high, low]
    assert ranked[0].rank == 1 and ranked[1].rank == 2
    assert ranked[0].score > ranked[1].score


def test_sandbox_verdict_moves_rankings():
    confirmed = _f("a.py", 1, "sqli", 0.7)
    unconfirmed = _f("a.py", 2, "xss", 0.75)
    verdicts = {
        finding_key(confirmed): "exploitable",
        finding_key(unconfirmed): "not_exploitable",
    }
    ranked = rank_findings([confirmed, unconfirmed], sandbox_verdicts=verdicts)
    # the verified one jumps above the higher-confidence ruled-out one
    assert ranked[0].finding is confirmed
    assert ranked[0].sandbox_verdict == "exploitable"


def test_rank_is_deterministic():
    findings = [
        _f("a.py", i, "sqli", 0.8, "HIGH") for i in range(3)
    ]
    a = rank_findings(findings)
    b = rank_findings(findings)
    assert [(r.file, r.line, r.score) for r in a] == [(r.file, r.line, r.score) for r in b]


def test_score_bounds():
    ranked = rank_findings([_f("a.py", 1, "sqli", 1.0, "CRITICAL")])
    assert 0.0 <= ranked[0].score <= 1.0


def test_classify_verdict_variants():
    assert classify_verdict("CONFIRMED_EXPLOITABLE\n[VULNERABLE]...") == "exploitable"
    assert classify_verdict("NOT_EXPLOITABLE\n...") == "not_exploitable"
    assert classify_verdict("UNSUPPORTED: no template") == "unsupported"
    assert classify_verdict("maybe?") == "needs_manual_review"
    assert classify_verdict("") == "needs_manual_review"
