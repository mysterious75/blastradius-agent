"""SummaryReporter — markdown summary of a full pipeline run."""

import datetime
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from blastradius.pipeline import PipelineResult

from blastradius.reporting.attack_map import attack_for

_VULN_LABELS = {"sqli": "SQLi", "xss": "XSS", "ssrf": "SSRF"}


class SummaryReporter:
    """Generate and persist the end-of-run markdown summary."""

    def generate_summary(self, result: "PipelineResult") -> str:
        """Build the summary markdown for a PipelineResult."""
        by_type: dict = {}
        for finding in result.findings:
            by_type[finding.vuln_type] = by_type.get(finding.vuln_type, 0) + 1
        type_lines = (
            "\n".join(
                f"- {_VULN_LABELS.get(t, t.upper())}: {n}" for t, n in sorted(by_type.items())
            )
            or "- none"
        )

        patch_rows = []
        human_files = []
        for finding, patch_result in result.patches:
            confidence = patch_result.verification.confidence if patch_result.verification else 0.0
            patch_rows.append(
                f"| `{finding.file}:{finding.line}` | {_VULN_LABELS.get(finding.vuln_type, finding.vuln_type.upper())} "
                f"| {confidence}% | {'YES' if patch_result.needs_human else 'no'} |"
            )
            if patch_result.needs_human:
                human_files.append(finding.file)
        patch_table = (
            (
                "| File | Type | Confidence | Needs human |\n"
                "|---|---|---|---|\n" + "\n".join(patch_rows)
            )
            if patch_rows
            else "- none"
        )

        human_lines = "\n".join(f"- `{f}`" for f in sorted(set(human_files))) or "- none"

        blast_lines = []
        graph = result.blast_radius
        if graph is not None:
            for name, version in result.dependencies:
                affected = graph.query_blast_radius(name)
                blast_lines.append(f"- `{name}` v{version} → {len(affected)} repo(s): {affected}")
        blast_section = "\n".join(blast_lines) or "- none"

        attack_lines = []
        for finding in result.confirmed:
            techniques = attack_for(finding)
            if not techniques:
                continue
            label = _VULN_LABELS.get(finding.vuln_type, finding.vuln_type.upper())
            for technique in techniques:
                attack_lines.append(
                    f"- {finding.cwe or ''} ({label}) -> {technique['id']} {technique['name']}".rstrip()
                )
        attack_section = "\n".join(attack_lines) or "- none"

        date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        return f"""# BlastRadius Summary

- **Target:** {result.target}
- **Date:** {date}
- **Files scanned:** {result.files_scanned}
- **Findings:** {len(result.findings)} | **Confirmed exploitable:** {len(result.confirmed)}
- **Patches generated:** {len(result.patches)} | **Reports saved:** {len(result.reports)}

## Findings by type

{type_lines}

## Confirmed exploitable

{len(result.confirmed)} finding(s) were confirmed exploitable in the sandbox
and went through the patch loop.

## Patches

{patch_table}

## Files needing human review

{human_lines}

## Blast radius

Dependency packages and the repos that use them:

{blast_section}

## ATT&CK Techniques

MITRE ATT&CK techniques for confirmed exploitable findings:

{attack_section}
"""

    def save_summary(self, result: "PipelineResult", reports_dir: str = "reports") -> Path:
        """Save to ``reports_dir/summary_YYYY-MM-DD_HH-MM.md``; returns the path."""
        content = self.generate_summary(result)
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M")
        path = Path(reports_dir) / f"summary_{timestamp}.md"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path
