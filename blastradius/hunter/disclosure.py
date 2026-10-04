"""DisclosureReport — markdown responsible-disclosure report for a finding.

The report includes the vulnerability description, affected file + line, a
PoC, the sandbox validation result, a suggested patch, and a CVSS estimate.

The staging helpers below build a local HackerOne-style submission package
without submitting anything: impact-first title, summary, numbered
reproduction steps, severity metadata, sanitized evidence manifest, and a
pre-submit checklist. Staging is local-only by design.
"""

import datetime
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from blastradius.hunter.scanner import Finding, VULN_META, reconstruct_target_code
from blastradius.tools.sandbox_tool import run_exploit_sandbox

_BANNED_THEORETICAL_PHRASES = (
    "could potentially",
    "could be used to",
    "may allow",
    "might allow",
)
_PLACEHOLDER_MARKERS = ("TODO", "TBD", "XXX", "[INSERT", "[insert", "<insert")
_SENSITIVE_PATTERNS = (
    ("cookie", re.compile(r"(?i)\b(cookie\s*[:=]\s*)([^\s;,\n}]+)")),
    ("bearer-token", re.compile(r"(?i)\b(authorization\s*:\s*bearer\s+)([^\s\"',}]+)")),
    ("email", re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")),
)
_REQUIRED_CONTEXT_FIELDS = (
    "program",
    "asset",
    "asset_type",
    "bug_class",
    "attacker",
    "impact",
    "summary",
    "steps",
    "severity",
)


class DisclosureReport:
    """Generate and persist markdown disclosure reports for findings."""

    def generate_report(
        self,
        finding: Finding,
        repo_name: str = "unknown",
        sandbox_result: Optional[str] = None,
    ) -> str:
        """Return the markdown report for ``finding``.

        Args:
            finding: The Finding to report.
            repo_name: Repo name used in the title (and report filename).
            sandbox_result: Pre-computed sandbox output; when None it is
                computed by running the reconstructed PoC in the sandbox.
        """
        if sandbox_result is None:
            sandbox_result = self._run_sandbox(finding)

        date = datetime.date.today().isoformat()
        f = finding
        verdict = sandbox_result.splitlines()[0] if sandbox_result else "NOT RUN"

        return f"""# Vulnerability Disclosure: {f.vuln_type.upper()} in {repo_name}

- **Date:** {date}
- **Severity:** {f.severity} | **CVSS estimate:** {VULN_META.get(f.vuln_type, {}).get("cvss", "n/a")} | **CWE:** {f.cwe}
- **Affected file:** `{f.file}` line {f.line}
- **Confidence:** {f.confidence}

## Vulnerability description

{f.description}

## Proof of Concept

```text
{f.payload}
```

Code context:

```text
{f.context}
```

## Sandbox validation

{verdict}

```
{sandbox_result}
```

> Note: the PoC is reconstructed from the static finding. It proves the
> pattern is exploitable; a live exploit against the real deployment must be
> confirmed manually before any disclosure.

## Suggested patch

{f.remediation}

## Responsible disclosure

Coordinate with the maintainers (security contact / GitHub Security Advisory)
and wait for the fix before public disclosure.
"""

    def save_report(
        self,
        finding: Finding,
        repo_name: str,
        reports_dir: str = "reports",
        sandbox_result: Optional[str] = None,
    ) -> Path:
        """Save the report to ``reports_dir/YYYY-MM-DD_<type>_<repo>_<file>-<line>.md``.

        The file stem + line suffix keeps reports from multiple findings of
        the same type+repo from overwriting each other. Returns the path.
        """
        content = self.generate_report(finding, repo_name, sandbox_result)
        date = datetime.date.today().isoformat()
        stem = Path(finding.file).stem
        path = (
            Path(reports_dir) / f"{date}_{finding.vuln_type}_{repo_name}_{stem}-{finding.line}.md"
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    @staticmethod
    def _run_sandbox(finding: Finding) -> str:
        try:
            return run_exploit_sandbox(finding.vuln_type, reconstruct_target_code(finding))
        except Exception as exc:
            return f"SANDBOX_ERROR: {exc}"


def _finding_value(finding: Any, name: str, default: Any = "") -> Any:
    """Read a field from a Finding, dynamic finding, or plain dict."""
    if isinstance(finding, dict):
        return finding.get(name, default)
    return getattr(finding, name, default)


def _finding_location(finding: Any) -> str:
    """Human-readable source location for static or live findings."""
    url = _finding_value(finding, "url", "")
    if url:
        return str(url)
    filename = _finding_value(finding, "file", "unknown location")
    line = _finding_value(finding, "line", "")
    return f"`{filename}` line {line}" if line not in ("", 0, None) else f"`{filename}`"


def _finding_evidence(finding: Any) -> str:
    """Prefer explicit evidence, then payload, then description."""
    for name in ("evidence", "payload", "description"):
        value = _finding_value(finding, name, "")
        if value:
            return str(value)
    return ""


def _redact_match(match: re.Match) -> str:
    """Preserve a captured label/prefix, otherwise replace the whole match."""
    if match.lastindex:
        return f"{match.group(1)}[REDACTED]"
    return "[REDACTED]"


def redact_evidence(text: str) -> Tuple[str, List[str]]:
    """Redact auth material and direct-contact PII from staged evidence.

    Returns the redacted text plus a list of redaction warning labels. The
    package is local-only, but staged evidence must still avoid live cookies,
    bearer tokens, and email addresses: rotate credentials after testing and
    use throwaway test accounts.
    """
    findings: List[str] = []
    redacted = text or ""
    for label, pattern in _SENSITIVE_PATTERNS:
        redacted, count = pattern.subn(_redact_match, redacted)
        if count:
            findings.append(label)
    return redacted, findings


def build_disclosure_title(context: Dict[str, Any]) -> str:
    """Impact-first title: class + asset + actor + demonstrated impact."""
    return (
        f"{context['bug_class']} in {context['asset']} allows "
        f"{context['attacker']} to {context['impact']}"
    )


def validate_disclosure_package(
    title: str, context: Dict[str, Any], redaction_warnings: List[str]
) -> Dict[str, Any]:
    """Validate a staged report against HackerOne submission requirements."""
    blockers: List[str] = []
    warnings: List[str] = []

    for field in _REQUIRED_CONTEXT_FIELDS:
        value = context.get(field)
        if value is None or value == "" or value == []:
            blockers.append(f"missing required field: {field}")
    steps = context.get("steps", [])
    if steps is not None and not isinstance(steps, list):
        blockers.append("reproduction steps must be a list")
    elif isinstance(steps, list) and len(steps) < 2:
        blockers.append("provide at least two numbered reproduction steps")

    checked_text = f"{title}\n{context.get('summary', '')}\n{context.get('impact', '')}".lower()
    for phrase in _BANNED_THEORETICAL_PHRASES:
        if phrase in checked_text:
            blockers.append(f"remove theoretical language: {phrase!r}")
    draft_text = f"{title}\n{context.get('summary', '')}\n{context.get('impact', '')}"
    for marker in _PLACEHOLDER_MARKERS:
        if marker in draft_text:
            blockers.append(f"replace unfinished placeholder: {marker}")

    if not context.get("cvss"):
        warnings.append("add a CVSS vector/score; severity alone slows triage")
    if not context.get("weakness") and not _finding_value(context.get("finding", {}), "cwe", ""):
        warnings.append("add the CWE/weakness used by the target program")
    for warning in redaction_warnings:
        warnings.append(
            f"staged evidence contained {warning} material; it was redacted. "
            "Rotate the credential and use throwaway test accounts."
        )

    return {"ok": not blockers, "blockers": blockers, "warnings": warnings}


def stage_disclosure_package(
    finding: Any,
    context: Dict[str, Any],
    out_dir: str = "reports/staged",
    status: str = "draft",
) -> Dict[str, Any]:
    """Stage a local submission package for one finding.

    This never submits a report. It writes ``report.md`` (impact-first
    HackerOne-style draft), ``evidence.json`` (sanitized evidence plus
    validation metadata), ``checklist.md`` (pre-submit blockers/warnings),
    and ``status.json`` (local workflow status only).
    """
    missing = [field for field in _REQUIRED_CONTEXT_FIELDS if not context.get(field)]
    if missing:
        raise ValueError(f"incomplete disclosure context: {', '.join(missing)}")

    title = build_disclosure_title(context)
    steps = [str(step) for step in context["steps"]]
    raw_evidence = "\n\n".join(
        [str(item) for item in [context.get("proof"), _finding_evidence(finding)] if item]
    )
    redacted_evidence, redaction_warnings = redact_evidence(raw_evidence)
    validation = validate_disclosure_package(title, context, redaction_warnings)
    package_status = "ready-for-review" if validation["ok"] else "draft"
    if status not in ("draft", "ready-for-review"):
        raise ValueError("status must be 'draft' or 'ready-for-review'")

    date = datetime.date.today().isoformat()
    slug = re.sub(r"[^a-z0-9]+", "-", f"{context['program']}-{title}".lower()).strip("-")
    package_dir = Path(out_dir) / f"{date}-{slug[:96]}"
    package_dir.mkdir(parents=True, exist_ok=True)

    report = f"""# {title}

## Summary

{context["summary"]}

**Program:** {context["program"]}
**Asset:** {context["asset"]} ({context["asset_type"]})
**Severity:** {context["severity"]}
**CVSS:** {context.get("cvss", "not supplied")}
**Weakness:** {context.get("weakness", _finding_value(finding, "cwe", "not supplied"))}
**Location:** {_finding_location(finding)}

## Steps to reproduce

{chr(10).join(f"{index}. {step}" for index, step in enumerate(steps, 1))}

## Impact

{context["impact"]}

## Evidence

```text
{redacted_evidence}
```

## Recommended fix

{context.get("remediation", _finding_value(finding, "remediation", ""))}

## Submission notes

Stage locally, verify every step from a fresh test-account state, attach
only redacted artifacts, then submit manually through the program's
official HackerOne workflow. This tool never submits a report.
"""
    (package_dir / "report.md").write_text(report, encoding="utf-8")
    evidence = {
        "title": title,
        "program": context["program"],
        "asset": context["asset"],
        "asset_type": context["asset_type"],
        "location": _finding_location(finding),
        "redacted_evidence": redacted_evidence,
        "redaction_warnings": redaction_warnings,
        "validation": validation,
    }
    (package_dir / "evidence.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    checklist = [
        "# Pre-submit checklist",
        "",
        f"- [ ] Title states class, asset, actor, and demonstrated impact: {title}",
        "- [ ] Summary states the exact impact in the first sentence",
        "- [ ] Steps reproduce the issue from a fresh test-account state",
        "- [ ] Response or proof artifact demonstrates the claimed impact",
        "- [ ] Severity matches the demonstrated impact, with CVSS supplied",
        "- [ ] Credentials rotated; evidence contains no live cookies, tokens, or PII",
    ]
    for blocker in validation["blockers"]:
        checklist.append(f"- [ ] BLOCKER: {blocker}")
    for warning in validation["warnings"]:
        checklist.append(f"- [ ] Review: {warning}")
    (package_dir / "checklist.md").write_text("\n".join(checklist) + "\n", encoding="utf-8")
    status_payload = {
        "status": package_status if status == "ready-for-review" and validation["ok"] else "draft",
        "submitted": False,
        "platform": None,
        "report": "report.md",
        "evidence": "evidence.json",
        "checklist": "checklist.md",
    }
    (package_dir / "status.json").write_text(json.dumps(status_payload, indent=2), encoding="utf-8")
    return {"directory": str(package_dir), **status_payload, "validation": validation}
