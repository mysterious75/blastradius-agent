"""Prometheus scanners wrapped as CAI function_tools.

Wraps four Prometheus scanners WITHOUT modifying them — pure import + thin
adapter layer so a CAI agent can drive the detection engine:

    prometheus_sqli_scan            -> src.scanner.sqli.SQLiScanner
    prometheus_xss_scan             -> src.scanner.xss.XSSScanner
    prometheus_ssrf_scan            -> src.scanner.ssrf.SSRFScanner
    prometheus_adversarial_validate -> src.scanner.adversarial.AdversarialValidator

Each scan tool returns a JSON string of findings (Finding.to_dict()), which is
what the LLM consumes. The adversarial tool is a post-processing step: it
validates findings from the scan tools to eliminate false positives.

CAI integration: when cai-framework is installed, every function here is
registered via CAI's ``function_tool`` decorator (``cai.sdk.agents``). When it
is not installed (e.g. local testing), the same functions remain plain
callables, so the scanner wiring can be exercised without CAI.

Prometheus path bootstrap: prometheus is a ``src``-layout package (import root
``src``) and is not pip-installed. Set ``PROMETHEUS_ROOT`` to the prometheus
repo root (the directory that contains its ``src/`` package); it defaults to
``../prometheus`` relative to this project.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

from blastradius.prometheus_bootstrap import ensure_prometheus_importable

# ---------------------------------------------------------------------------
# Prometheus bootstrap
# ---------------------------------------------------------------------------

ensure_prometheus_importable()

from src.core.auth_context import set_auth_token  # noqa: E402
from src.scanner.adversarial import AdversarialValidator  # noqa: E402
from src.scanner.sqli import SQLiScanner  # noqa: E402
from src.scanner.ssrf import SSRFScanner  # noqa: E402
from src.scanner.xss import XSSScanner  # noqa: E402

# ---------------------------------------------------------------------------
# CAI registration
# ---------------------------------------------------------------------------

from blastradius.tools.cai_utils import cai_tool  # noqa: E402


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _auth() -> None:
    """Pass prometheus's auth token through so its auth gate allows scanning.

    No-op when AUTH_TOKEN is unset (prometheus's check_auth() then allows).
    """
    set_auth_token(os.getenv("AUTH_TOKEN"))


def _params_from_json(params_json: Optional[str]) -> Optional[Dict[str, str]]:
    """Parse a JSON object of parameter name -> test value."""
    if not params_json:
        return None
    try:
        data = json.loads(params_json)
    except json.JSONDecodeError as exc:
        raise ValueError(f"params_json is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("params_json must be a JSON object of parameter name -> value")
    return {str(k): str(v) for k, v in data.items()}


def _findings_to_json(findings: List[Any]) -> str:
    """Serialize Finding objects to a JSON string for LLM consumption."""
    return json.dumps([f.to_dict() for f in findings], indent=2)


def _finding_from_dict(item: Dict[str, Any]) -> Any:
    """Reconstruct a Finding from a dict (accepts Finding.to_dict() shape)."""
    from src.scanner.findings import Finding

    d = dict(item)
    if "id" in d and "finding_id" not in d:
        d["finding_id"] = d.pop("id")
    fields = {k: v for k, v in d.items() if k in Finding.__dataclass_fields__}
    return Finding(**fields)


# ---------------------------------------------------------------------------
# CAI function_tools
# ---------------------------------------------------------------------------


@cai_tool
def prometheus_sqli_scan(
    target_url: str,
    params_json: Optional[str] = None,
    rps: float = 5.0,
    timeout: float = 15.0,
) -> str:
    """Scan a URL for SQL injection using Prometheus's SQLiScanner.

    Tests every query parameter with error-based, time-based blind,
    boolean-based blind, UNION-based, stacked-query and second-order
    techniques, then returns confirmed findings as JSON.

    Args:
        target_url: Full URL to scan, e.g. "https://example.com/page?id=1".
        params_json: Optional JSON object of parameter name -> value to test,
            e.g. '{"id": "1", "q": "test"}'. Defaults to the URL's query params.
        rps: Max requests per second to the target.
        timeout: Per-request timeout in seconds.

    Returns:
        JSON string of findings, or "[]" if none found.
    """
    _auth()
    scanner = SQLiScanner(rps=rps, timeout=timeout)
    findings = scanner.scan_url(target_url, params=_params_from_json(params_json))
    return _findings_to_json(findings)


@cai_tool
def prometheus_xss_scan(
    target_url: str,
    params_json: Optional[str] = None,
    rps: float = 5.0,
    timeout: float = 10.0,
) -> str:
    """Scan a URL for cross-site scripting using Prometheus's XSSScanner.

    Detects reflected, stored and DOM-based XSS across HTML, attribute,
    script and URL contexts, then returns confirmed findings as JSON.

    Args:
        target_url: Full URL to scan, e.g. "https://example.com/search?q=test".
        params_json: Optional JSON object of parameter name -> value to test.
            Defaults to the URL's query params.
        rps: Max requests per second to the target.
        timeout: Per-request timeout in seconds.

    Returns:
        JSON string of findings, or "[]" if none found.
    """
    _auth()
    scanner = XSSScanner(rps=rps, timeout=timeout)
    findings = scanner.scan_url(target_url, params=_params_from_json(params_json))
    return _findings_to_json(findings)


@cai_tool
def prometheus_ssrf_scan(
    target_url: str,
    params_json: Optional[str] = None,
    rps: float = 3.0,
    timeout: float = 8.0,
) -> str:
    """Scan a URL for server-side request forgery using Prometheus's SSRFScanner.

    Tests URL-like parameters against cloud metadata endpoints, internal
    networks, protocol smuggling and IP bypasses, then returns confirmed
    findings as JSON.

    Args:
        target_url: Full URL to scan, e.g. "https://example.com/fetch?url=http://x".
        params_json: Optional JSON object of parameter name -> value to test.
            Defaults to the URL's query params.
        rps: Max requests per second to the target.
        timeout: Per-request timeout in seconds.

    Returns:
        JSON string of findings, or "[]" if none found.
    """
    _auth()
    scanner = SSRFScanner(rps=rps, timeout=timeout)
    findings = scanner.scan_url(target_url, params=_params_from_json(params_json))
    return _findings_to_json(findings)


@cai_tool
def prometheus_adversarial_validate(findings_json: str, strict_mode: bool = False) -> str:
    """Run Prometheus's AdversarialValidator on scan findings to kill false positives.

    Each finding is passed through a hunter -> skeptic -> referee pipeline that
    confirms the evidence is real, tries to disprove it, and returns a verdict:
    confirmed | likely_false_positive | false_positive | needs_manual_review.

    Args:
        findings_json: JSON string of findings, either a single object or a
            list of objects in Finding.to_dict() shape (as returned by the
            prometheus_*_scan tools).
        strict_mode: When True, demands stronger evidence before confirming.

    Returns:
        JSON string of validation results (one per input finding).
    """
    try:
        data = json.loads(findings_json)
    except json.JSONDecodeError as exc:
        raise ValueError(f"findings_json is not valid JSON: {exc}") from exc
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list) or not all(isinstance(i, dict) for i in data):
        raise ValueError("findings_json must be a JSON object or a list of objects")

    findings = [_finding_from_dict(item) for item in data]
    results = AdversarialValidator(strict_mode=strict_mode).validate_batch(findings)
    return json.dumps([r.to_dict() for r in results], indent=2)
