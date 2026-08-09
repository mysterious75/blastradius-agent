"""BlastRadius scanner tools wrapped as CAI function_tools.

Self-contained: detection runs on the built-in ``blastradius.scanners``
package — NO prometheus dependency, no PROMETHEUS_ROOT, no sys.path hack.

Tools:
    prometheus_sqli_scan / prometheus_xss_scan / prometheus_ssrf_scan
        → scan a repo path or GitHub URL with the built-in scanner
    prometheus_adversarial_validate
        → Prometheus AdversarialValidator when available, else a local
          heuristic verdict

Each scan tool returns a JSON string of findings. CAI registration is lazy:
``function_tool`` when cai-framework is installed, plain callables otherwise.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from blastradius.hunter.scanner import FILE_EXTENSIONS, CVEHunter
from blastradius.scanners import get_scanner
from blastradius.tools.cai_utils import cai_tool

_SCAN_VULN_TYPES = {"sqli": "sqli", "xss": "xss", "ssrf": "ssrf"}

_TITLES = {
    "sqli": "SQL Injection",
    "xss": "Cross-Site Scripting",
    "ssrf": "Server-Side Request Forgery",
}


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _params_from_json(params_json: Optional[str]) -> Optional[Dict[str, str]]:
    """Parse a JSON object of parameter name -> test value (kept for tool schema)."""
    if not params_json:
        return None
    try:
        data = json.loads(params_json)
    except json.JSONDecodeError as exc:
        raise ValueError(f"params_json is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("params_json must be a JSON object of parameter name -> value")
    return {str(k): str(v) for k, v in data.items()}


def _finding_dict(finding) -> Dict[str, Any]:
    return {
        "id": 0,
        "vuln_type": _TITLES.get(finding.vuln_type, finding.vuln_type),
        "title": f"{finding.vuln_type.upper()} in {finding.file}:{finding.line}",
        "severity": finding.severity,
        "url": f"file://{finding.file}",
        "parameter": "",
        "method": "STATIC",
        "payload": finding.payload,
        "evidence": finding.evidence,
        "description": finding.description,
        "remediation": finding.remediation,
        "cvss": 0.0,
        "cwe": finding.cwe,
        "tool": "blastradius-scanners",
        "verified": False,
        "confidence": finding.confidence,
        "request": "",
        "timestamp": datetime.now().isoformat(timespec="seconds"),
    }


def _scan_target(target: str, vuln_type: str) -> List:
    """Scan a repo path or GitHub URL with the built-in scanner."""
    hunter = CVEHunter()
    repo_path = hunter.clone_repo(target) if target.startswith(("http://", "https://")) else target
    scanner = get_scanner(vuln_type)
    if scanner is None:
        return []
    findings = []
    for ext in FILE_EXTENSIONS:
        for path in Path(repo_path).rglob(ext):
            if "min." in path.name or any(part in path.parts for part in
                                          (".git", "node_modules", "vendor", "dist", "__pycache__")):
                continue
            try:
                code = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            findings.extend(scanner.detect(code, path=str(path)))
    return findings


def _findings_json(findings: List) -> str:
    return json.dumps([_finding_dict(f) for f in findings], indent=2)


# ---------------------------------------------------------------------------
# CAI function_tools
# ---------------------------------------------------------------------------


@cai_tool
def prometheus_sqli_scan(
    target: str,
    params_json: Optional[str] = None,
    rps: float = 5.0,
    timeout: float = 15.0,
) -> str:
    """Scan a repo (GitHub URL or local path) for SQL injection.

    Args:
        target: GitHub repo URL or a local path to scan.
        params_json: Reserved for tool-schema compatibility (validated if given).
        rps: Reserved (rate limit hint).
        timeout: Reserved.

    Returns:
        JSON string of findings, or "[]" if none found.
    """
    _params_from_json(params_json)  # validate for schema compatibility
    return _findings_json(_scan_target(target, "sqli"))


@cai_tool
def prometheus_xss_scan(
    target: str,
    params_json: Optional[str] = None,
    rps: float = 5.0,
    timeout: float = 10.0,
) -> str:
    """Scan a repo (GitHub URL or local path) for cross-site scripting."""
    _params_from_json(params_json)
    return _findings_json(_scan_target(target, "xss"))


@cai_tool
def prometheus_ssrf_scan(
    target: str,
    params_json: Optional[str] = None,
    rps: float = 3.0,
    timeout: float = 8.0,
) -> str:
    """Scan a repo (GitHub URL or local path) for server-side request forgery."""
    _params_from_json(params_json)
    return _findings_json(_scan_target(target, "ssrf"))


def _local_verdict(finding) -> Dict[str, Any]:
    """Heuristic verdict used when prometheus is not installed."""
    return {
        "finding_id": getattr(finding, "finding_id", 0),
        "vuln_type": getattr(finding, "vuln_type", ""),
        "url": getattr(finding, "url", ""),
        "verdict": "needs_manual_review",
        "confidence": getattr(finding, "confidence", 0.0),
        "evidence_strength": "moderate" if getattr(finding, "evidence", "") else "none",
        "hunter_notes": "prometheus unavailable — local heuristic verdict",
        "skeptic_notes": "",
        "referee_reasoning": "Prometheus not installed; manual review recommended.",
    }


@cai_tool
def prometheus_adversarial_validate(findings_json: str, strict_mode: bool = False) -> str:
    """Run adversarial validation on findings to kill false positives.

    Uses Prometheus's AdversarialValidator when available; falls back to a
    local heuristic verdict otherwise.
    """
    try:
        data = json.loads(findings_json)
    except json.JSONDecodeError as exc:
        raise ValueError(f"findings_json is not valid JSON: {exc}") from exc
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list) or not all(isinstance(i, dict) for i in data):
        raise ValueError("findings_json must be a JSON object or a list of objects")

    try:
        from blastradius.prometheus_bootstrap import ensure_prometheus_importable

        ensure_prometheus_importable()
        from src.scanner.adversarial import AdversarialValidator  # noqa: E402
        from src.scanner.findings import Finding as PrometheusFinding  # noqa: E402

        validator = AdversarialValidator(strict_mode=strict_mode)
        findings = []
        for item in data:
            d = dict(item)
            if "id" in d and "finding_id" not in d:
                d["finding_id"] = d.pop("id")
            fields = {k: v for k, v in d.items() if k in PrometheusFinding.__dataclass_fields__}
            findings.append(PrometheusFinding(**fields))
        results = [validator.validate(f).to_dict() for f in findings]
        return json.dumps(results, indent=2)
    except ImportError:
        return json.dumps([_local_verdict(item) for item in data], indent=2)
