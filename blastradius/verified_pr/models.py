"""Verified PR data models — re-test outcomes, dependency impact, gate verdict."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# Re-test outcomes for a single confirmed finding + generated patch.
RETEST_FIXED = "FIXED"  # patch applied on the real tree; scanners no longer flag it
RETEST_STILL_VULNERABLE = "STILL_VULNERABLE"  # patch applied but the finding persists
RETEST_UNVERIFIABLE = "UNVERIFIABLE"  # no patch, or the patch could not be applied safely

# Gate verdicts (mapped to process exit codes by the pipeline).
VERDICT_MERGE = "MERGE"  # exit 0 — safe to merge
VERDICT_BLOCK = "BLOCK"  # exit 1 — merge must be blocked
VERDICT_ERROR = "ERROR"  # exit 2 — tooling failure, fail-closed


@dataclass
class RetestOutcome:
    """Result of re-testing one confirmed finding's patch on a scratch tree."""

    file: str
    line: int
    vuln_type: str
    status: str = RETEST_UNVERIFIABLE
    detail: str = ""
    introduced: List[str] = field(default_factory=list)
    method: str = ""
    evidence: str = ""

    @property
    def key(self) -> Tuple[str, int, str]:
        return (self.file, self.line, self.vuln_type)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "vuln_type": self.vuln_type,
            "status": self.status,
            "detail": self.detail,
            "introduced": list(self.introduced),
            "method": self.method,
            "evidence": self.evidence,
        }


@dataclass
class DependencyChange:
    """One dependency-manifest change between base and head."""

    manifest: str
    name: str
    old_version: str = ""
    new_version: str = ""
    change: str = "changed"  # added | removed | upgraded | downgraded | changed

    def to_dict(self) -> Dict[str, Any]:
        return {
            "manifest": self.manifest,
            "name": self.name,
            "old_version": self.old_version,
            "new_version": self.new_version,
            "change": self.change,
        }


@dataclass
class VerifiedGate:
    """Fail-closed gate decision over the confirmed gate findings."""

    verdict: str = VERDICT_MERGE
    exit_code: int = 0
    fail_on: str = "high"
    gate_total: int = 0
    fixed_and_reverified: int = 0
    blocking: List[Dict[str, Any]] = field(default_factory=list)
    kev_blocked: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict,
            "exit_code": self.exit_code,
            "fail_on": self.fail_on,
            "gate_total": self.gate_total,
            "fixed_and_reverified": self.fixed_and_reverified,
            "blocking": list(self.blocking),
            "kev_blocked": self.kev_blocked,
        }


@dataclass
class VerifiedReport:
    """Full machine-readable result of one verified-PR run."""

    repo: str = ""
    base: str = ""
    baseline: bool = False
    fail_on: str = "high"
    diff_scoped: Optional[bool] = None
    changed_files: Optional[int] = None
    candidates: int = 0
    confirmed: int = 0
    new_findings: List[Dict[str, Any]] = field(default_factory=list)
    patches: List[Dict[str, Any]] = field(default_factory=list)
    retest: List[Dict[str, Any]] = field(default_factory=list)
    dependency_impact: List[Dict[str, Any]] = field(default_factory=list)
    kev_matched: int = 0
    gate: VerifiedGate = field(default_factory=VerifiedGate)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "repo": self.repo,
            "base": self.base,
            "baseline": self.baseline,
            "fail_on": self.fail_on,
            "diff_scoped": self.diff_scoped,
            "changed_files": self.changed_files,
            "candidates": self.candidates,
            "confirmed": self.confirmed,
            "new_findings": list(self.new_findings),
            "patches": list(self.patches),
            "retest": list(self.retest),
            "dependency_impact": list(self.dependency_impact),
            "kev_matched": self.kev_matched,
            "gate": self.gate.to_dict(),
        }
