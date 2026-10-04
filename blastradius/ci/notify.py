"""Gate notifications: concise, secret-free, failure-isolated.

Reuses the existing :class:`blastradius.notify.notifier.Notifier` via its
plain-text API. A notification failure never changes the gate result —
errors are returned for the report only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from blastradius.ci.models import GateResult
from blastradius.ci.redact import redact_secrets


@dataclass
class GateNotification:
    channels: List[str]
    errors: List[str]
    sent: bool


def gate_summary_text(result: GateResult, run_ref: str = "") -> str:
    failing = "; ".join(
        f"[{f.severity.value}] {f.title} ({f.file}:{f.line or '?'} via {f.source.value})"
        for f in result.failing[:5]
    )
    text = f"BlastRadius CI gate: {result.status.value}"
    if run_ref:
        text += f" ({run_ref})"
    if failing:
        text += f" — failing: {failing}"
    if result.errors:
        text += f" — errors: {len(result.errors)} (see CI report)"
    return redact_secrets(text)


def notify_gate(
    result: GateResult,
    report_path: str = "",
    run_ref: str = "",
    notifier: Optional[object] = None,
) -> GateNotification:
    """Send the gate summary to configured channels; never raises."""
    try:
        from blastradius.notify.notifier import Notifier

        active = notifier or Notifier()
        channels = active.configured_channels()
        if not channels:
            return GateNotification(channels=[], errors=[], sent=False)
        text = gate_summary_text(result, run_ref)
        if report_path:
            text += f" — report: {report_path}"
        errors = active.notify_text(redact_secrets(text))
        return GateNotification(channels=channels, errors=errors, sent=not errors)
    except Exception as exc:
        return GateNotification(channels=[], errors=[redact_secrets(str(exc))], sent=False)
