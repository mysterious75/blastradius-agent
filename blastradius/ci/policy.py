"""Deterministic policy engine — the ONLY decider of PASS/FAIL.

The LLM (or any analyzer) produces findings; this module evaluates them
against a validated policy. AI output can never flip a verdict by itself:
only severity/confidence/category thresholds configured here matter.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Tuple

from blastradius.ci.models import (
    ANALYSIS_ERROR,
    PASS,
    POLICY_FAILURE,
    Category,
    CiFinding,
    GateResult,
    Policy,
    Severity,
    Status,
    normalize_severity,
)

DEFAULT_POLICY = Policy()

_ON_ERROR_CHOICES = ("fail-closed", "fail-open")


def load_policy(path: str | None = None) -> Tuple[Policy, List[str]]:
    """Load + validate a YAML policy file; (policy, warnings).

    Missing path -> built-in safe defaults. Raises ValueError on invalid
    configuration (an invalid policy is itself an analysis error).
    """
    if not path:
        return Policy(), []
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - dev dep in practice
        raise ValueError("pyyaml is required to load a policy file") from exc
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except OSError as exc:
        raise ValueError(f"cannot read policy file {path}: {exc}") from exc
    except Exception as exc:
        raise ValueError(f"invalid YAML in policy file {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError(f"policy file {path} must contain a mapping")
    fail_on = raw.get("fail_on", ["critical", "high"])
    if not isinstance(fail_on, list) or not fail_on:
        raise ValueError("policy 'fail_on' must be a non-empty list")
    severities = []
    for item in fail_on:
        try:
            severities.append(Severity(str(item).strip().lower()))
        except ValueError:
            raise ValueError(f"policy 'fail_on' has unknown severity: {item!r}") from None
    try:
        minimum_confidence = float(raw.get("minimum_confidence", 0.80))
    except (TypeError, ValueError):
        raise ValueError("policy 'minimum_confidence' must be a number") from None
    if not 0.0 <= minimum_confidence <= 1.0:
        raise ValueError("policy 'minimum_confidence' must be within 0.0-1.0")
    on_error = str(raw.get("on_error", "fail-closed")).strip().lower()
    if on_error not in _ON_ERROR_CHOICES:
        raise ValueError(f"policy 'on_error' must be one of {_ON_ERROR_CHOICES}")
    warnings = []
    if on_error == "fail-open":
        warnings.append(
            "policy sets on_error=fail-open: analysis errors become warnings, "
            "weakening the gate — use only with explicit risk acceptance"
        )
    try:
        max_files = int(raw.get("max_files", 100))
        max_total_bytes = int(raw.get("max_total_bytes", 200_000))
        max_hunks = int(raw.get("max_hunks_per_file", 50))
    except (TypeError, ValueError):
        raise ValueError("policy limits must be integers") from None
    if min(max_files, max_total_bytes, max_hunks) <= 0:
        raise ValueError("policy limits must be positive")
    return (
        Policy(
            fail_on=severities,
            minimum_confidence=minimum_confidence,
            security_gate=bool(raw.get("security_gate", True)),
            quality_gate=bool(raw.get("quality_gate", True)),
            on_error=on_error,
            max_files=max_files,
            max_total_bytes=max_total_bytes,
            max_hunks_per_file=max_hunks,
        ),
        warnings,
    )


def _gated_out(finding: CiFinding, policy: Policy) -> bool:
    if finding.category == Category.SECURITY and not policy.security_gate:
        return True
    if finding.category == Category.QUALITY and not policy.quality_gate:
        return True
    return False


def evaluate(
    findings: List[CiFinding],
    policy: Policy,
    errors: List[str] | None = None,
    metadata: Dict[str, Any] | None = None,
) -> GateResult:
    """Evaluate normalized findings deterministically.

    - Finding counts toward FAIL iff: severity in fail_on AND
      confidence >= minimum_confidence AND its gate (security/quality)
      is enabled.
    - Any analysis error -> ANALYSIS_ERROR under fail-closed (default);
      under explicit fail-open they become warnings and evaluation proceeds.
    """
    errors = list(errors or [])
    warnings: List[str] = []
    if errors and policy.on_error == "fail-open":
        warnings.extend(f"analysis warning (fail-open): {e}" for e in errors)
        errors = []
    if errors:
        return GateResult(
            status=Status.ANALYSIS_ERROR,
            exit_code=ANALYSIS_ERROR,
            errors=errors,
            warnings=warnings,
            policy=policy,
            metadata=dict(metadata or {}),
        )
    failing: List[CiFinding] = []
    reported: List[CiFinding] = []
    for finding in findings:
        finding.severity = normalize_severity(finding.severity)
        try:
            confidence = float(finding.confidence)
        except (TypeError, ValueError):
            confidence = 0.0
        finding.confidence = max(0.0, min(1.0, confidence))
        if _gated_out(finding, policy):
            reported.append(finding)
            continue
        if finding.severity in policy.fail_on and finding.confidence >= policy.minimum_confidence:
            failing.append(finding)
        else:
            reported.append(finding)
    if failing:
        return GateResult(
            status=Status.POLICY_FAILURE,
            exit_code=POLICY_FAILURE,
            failing=failing,
            reported=reported,
            warnings=warnings,
            policy=policy,
            metadata=dict(metadata or {}),
        )
    return GateResult(
        status=Status.PASS,
        exit_code=PASS,
        reported=reported,
        warnings=warnings,
        policy=policy,
        metadata=dict(metadata or {}),
    )
