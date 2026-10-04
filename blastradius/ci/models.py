"""Normalized schema for the CI security & quality gate.

Everything downstream (policy engine, reports, notifications) speaks only
this schema. AI output is validated into it; anything that does not fit is
rejected, never coerced into a passing result.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

# Process exit codes for the gate CLI.
PASS = 0
POLICY_FAILURE = 1
ANALYSIS_ERROR = 2


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(str, Enum):
    SECURITY = "security"
    QUALITY = "quality"


class Source(str, Enum):
    DETERMINISTIC = "deterministic"
    AI = "ai"


class Status(str, Enum):
    PASS = "PASS"
    POLICY_FAILURE = "POLICY_FAILURE"
    ANALYSIS_ERROR = "ANALYSIS_ERROR"


SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def normalize_severity(value: Any) -> Severity:
    """Map arbitrary severity input to the schema; unknown -> INFO.

    Unknown severities are demoted to INFO (report-only), never promoted:
    promotion would let a malformed model response escalate a gate decision.
    """
    if isinstance(value, Severity):
        return value
    try:
        return Severity(str(value).strip().lower())
    except ValueError:
        return Severity.INFO


@dataclass
class Hunk:
    """One unified-diff hunk with new-file line tracking."""

    old_start: int
    new_start: int
    lines: List[str] = field(default_factory=list)

    def added_lines(self) -> Dict[int, str]:
        """Map new-file line number -> added line content (no '+' prefix)."""
        out: Dict[int, str] = {}
        lineno = self.new_start
        for line in self.lines:
            if line.startswith("+") and not line.startswith("+++"):
                out[lineno] = line[1:]
                lineno += 1
            elif line.startswith("-") and not line.startswith("---"):
                continue
            else:
                lineno += 1
        return out


@dataclass
class FileChange:
    """One changed file with its hunks."""

    path: str
    old_path: Optional[str] = None
    is_new: bool = False
    is_deleted: bool = False
    is_binary: bool = False
    hunks: List[Hunk] = field(default_factory=list)

    def added_lines(self) -> Dict[int, str]:
        out: Dict[int, str] = {}
        for hunk in self.hunks:
            out.update(hunk.added_lines())
        return out

    def added_text(self) -> str:
        return "\n".join(self.added_lines().values())


@dataclass
class ChangeSet:
    """Provider-neutral representation of a PR/change set."""

    files: List[FileChange] = field(default_factory=list)
    base_ref: str = ""
    head_ref: str = ""
    truncated: bool = False
    truncation_reason: str = ""
    excluded: List[str] = field(default_factory=list)

    def added_line_count(self) -> int:
        return sum(len(f.added_lines()) for f in self.files)


@dataclass
class CiFinding:
    """One normalized gate finding (deterministic or AI-produced)."""

    id: str
    category: Category
    severity: Severity
    title: str
    description: str
    file: str = ""
    line: int = 0
    cwe: str = ""
    owasp: str = ""
    confidence: float = 0.0
    evidence: str = ""
    recommendation: str = ""
    source: Source = Source.DETERMINISTIC
    analyzer: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "file": self.file,
            "line": self.line,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "source": self.source.value,
            "analyzer": self.analyzer,
        }


@dataclass
class Policy:
    """Deterministic gate policy (validated on load)."""

    fail_on: List[Severity] = field(default_factory=lambda: [Severity.CRITICAL, Severity.HIGH])
    minimum_confidence: float = 0.80
    security_gate: bool = True
    quality_gate: bool = True
    # Fail-closed default: analysis errors (incl. unavailable/malformed AI
    # output and oversized diffs) fail the gate. Set "fail-open" explicitly
    # to downgrade them to reported warnings instead.
    on_error: str = "fail-closed"
    max_files: int = 100
    max_total_bytes: int = 200_000
    max_hunks_per_file: int = 50

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fail_on": [s.value for s in self.fail_on],
            "minimum_confidence": self.minimum_confidence,
            "security_gate": self.security_gate,
            "quality_gate": self.quality_gate,
            "on_error": self.on_error,
            "max_files": self.max_files,
            "max_total_bytes": self.max_total_bytes,
            "max_hunks_per_file": self.max_hunks_per_file,
        }


@dataclass
class GateResult:
    """Final deterministic verdict. Only the policy engine creates these."""

    status: Status
    exit_code: int
    failing: List[CiFinding] = field(default_factory=list)
    reported: List[CiFinding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    policy: Optional[Policy] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
