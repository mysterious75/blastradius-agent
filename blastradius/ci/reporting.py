"""Gate reporting: machine-readable JSON + human-readable Markdown.

Reports contain status, severity counts, findings with source attribution,
evidence (redacted, truncated), remediation, policy used, and run metadata.
Secrets are redacted before writing; source snippets stay short.
"""

from __future__ import annotations

import datetime
import json
import os
from pathlib import Path
from typing import Dict, List

from blastradius.ci.models import CiFinding, GateResult, Severity
from blastradius.ci.redact import redact_secrets
from blastradius.version import __version__


def counts_by_severity(findings: List[CiFinding]) -> Dict[str, int]:
    counts = {s.value: 0 for s in Severity}
    for finding in findings:
        counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
    return counts


def gate_payload(result: GateResult, metadata: dict | None = None) -> dict:
    meta = dict(result.metadata or {})
    if metadata:
        meta.update(metadata)
    meta.setdefault("tool", f"blastradius-ci/{__version__}")
    meta.setdefault("generated_at", datetime.datetime.now(datetime.timezone.utc).isoformat())
    return {
        "status": result.status.value,
        "exit_code": result.exit_code,
        "counts": counts_by_severity(result.failing + result.reported),
        "failing": [f.to_dict() for f in result.failing],
        "reported": [f.to_dict() for f in result.reported],
        "errors": [redact_secrets(e) for e in result.errors],
        "warnings": [redact_secrets(w) for w in result.warnings],
        "policy": result.policy.to_dict() if result.policy else None,
        "metadata": meta,
    }


def write_json(result: GateResult, path: str, metadata: dict | None = None) -> str:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(gate_payload(result, metadata), indent=2), encoding="utf-8")
    return path


def render_markdown(result: GateResult, metadata: dict | None = None) -> str:
    payload = gate_payload(result, metadata)
    lines = [
        "# BlastRadius CI Gate",
        "",
        f"**Status:** {payload['status']}  ",
        "**Counts:** " + ", ".join(f"{k}={v}" for k, v in payload["counts"].items() if v),
        "",
        "## Failing findings",
        "",
    ]
    if payload["failing"]:
        lines += [
            "| Severity | Finding | Location | Source | Confidence |",
            "|---|---|---|---|---|",
        ]
        for f in payload["failing"]:
            loc = f"{f['file']}:{f['line']}" if f["file"] else "—"
            lines.append(
                f"| {f['severity']} | {f['title']} | {loc} | {f['source']} | {f['confidence']:.2f} |"
            )
    else:
        lines.append("None — no finding met the failing thresholds.")
    lines += ["", "## Reported (below threshold / gate disabled)", ""]
    if payload["reported"]:
        for f in payload["reported"]:
            loc = f"{f['file']}:{f['line']}" if f["file"] else "—"
            lines.append(f"- [{f['severity']}] {f['title']} ({loc}, {f['source']})")
            if f["recommendation"]:
                lines.append(f"  - Fix: {f['recommendation'][:300]}")
    else:
        lines.append("None.")
    if payload["errors"]:
        lines += ["", "## Errors", ""]
        lines += [f"- {e}" for e in payload["errors"]]
    if payload["warnings"]:
        lines += ["", "## Warnings", ""]
        lines += [f"- {w}" for w in payload["warnings"]]
    lines += (
        [
            "",
            f"_Policy: fail_on={','.join(payload['policy']['fail_on'])} "
            f"min_confidence={payload['policy']['minimum_confidence']} "
            f"on_error={payload['policy']['on_error']}_",
        ]
        if payload["policy"]
        else []
    )
    return "\n".join(lines) + "\n"


def write_markdown(result: GateResult, path: str, metadata: dict | None = None) -> str:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(render_markdown(result, metadata), encoding="utf-8")
    return path


def append_github_summary(markdown: str) -> bool:
    """Append the report to the GitHub Actions job summary when available."""
    summary_file = os.getenv("GITHUB_STEP_SUMMARY", "")
    if not summary_file:
        return False
    try:
        with open(summary_file, "a", encoding="utf-8") as fh:
            fh.write(markdown)
        return True
    except OSError:
        return False
