"""FindingsExporter — CSV / JSON / SARIF 2.1.0 / CycloneDX SBOM / HTML / Markdown export (stdlib only)."""

import csv
import hashlib
import html as _html
import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from blastradius.reporting.attack_map import attack_for
from blastradius.version import __version__

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)
_SEVERITY_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}
_SEVERITY_SCORE = {
    "CRITICAL": 9.0,
    "HIGH": 7.5,
    "MEDIUM": 5.0,
    "LOW": 2.0,
}

_CSV_COLUMNS = [
    "ID",
    "Repo",
    "File",
    "Line",
    "Type",
    "Severity",
    "CVSS",
    "Status",
    "Disclosed",
    "CVE_ID",
    "Bounty",
    "Description",
]


def _get(obj, name, default=""):
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


class FindingsExporter:
    """Export findings in multiple formats."""

    def __init__(self, findings: List):
        self.findings = findings

    # ------------------------------------------------------------------
    # CSV
    # ------------------------------------------------------------------

    def export_csv(self, path: str) -> None:
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(_CSV_COLUMNS)
            for idx, f in enumerate(self.findings, 1):
                writer.writerow(
                    [
                        idx,
                        _get(f, "repo", ""),
                        _get(f, "file"),
                        _get(f, "line"),
                        _get(f, "vuln_type"),
                        _get(f, "severity"),
                        _get(f, "cvss", 0.0),
                        _get(f, "status", "open"),
                        _get(f, "disclosed_at", ""),
                        _get(f, "cve_id", ""),
                        _get(f, "bounty_usd", 0),
                        _get(f, "description"),
                    ]
                )

    # ------------------------------------------------------------------
    # JSON
    # ------------------------------------------------------------------

    def export_json(self, path: str) -> None:
        data = []
        for f in self.findings:
            entry = (
                dict(f)
                if isinstance(f, dict)
                else {
                    k: getattr(f, k)
                    for k in (
                        "file",
                        "line",
                        "vuln_type",
                        "payload",
                        "confidence",
                        "evidence",
                        "severity",
                        "cwe",
                        "description",
                        "remediation",
                    )
                    if hasattr(f, k)
                }
            )
            entry["patch_diff"] = _get(f, "patch_diff", "")
            data.append(entry)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)

    # ------------------------------------------------------------------
    # SARIF 2.1.0
    # ------------------------------------------------------------------

    @staticmethod
    def _location_line_hash(f) -> str:
        """Stable SARIF primaryLocationLineHash: sha256(file+line+vuln_type+payload), first 32 hex chars."""
        raw = "{}{}{}{}".format(
            _get(f, "file", ""),
            _get(f, "line", ""),
            _get(f, "vuln_type", ""),
            _get(f, "payload", ""),
        )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]

    def export_sarif(self, path: str) -> None:
        """Export findings as SARIF 2.1.0.

        GitHub code-scanning ingestion limits (not enforced here — see
        https://docs.github.com/en/code-security/code-scanning/managing-your-code-scanning-results):
        a single upload supports at most 25,000 results and 25,000 rules.
        """
        rules = {}
        results = []
        for f in self.findings:
            vuln_type = str(_get(f, "vuln_type", "X"))
            rule_id = f"BR-{vuln_type.upper()}"
            description = str(_get(f, "description", ""))
            severity = str(_get(f, "severity")).upper()
            if rule_id not in rules:
                remediation = str(_get(f, "remediation", ""))
                help_md = description
                if remediation:
                    help_md = f"{description}\n\n**Remediation:** {remediation}"
                try:
                    confidence = float(_get(f, "confidence", 0.0) or 0.0)
                except (TypeError, ValueError):
                    confidence = 0.0
                rules[rule_id] = {
                    "id": rule_id,
                    "name": vuln_type,
                    "shortDescription": {"text": description[:200]},
                    "fullDescription": {"text": description},
                    "help": {"text": help_md, "markdown": help_md},
                    "properties": {
                        "security-severity": _SEVERITY_SCORE.get(severity, 0.0),
                        "precision": "high" if confidence >= 0.85 else "medium",
                        "tags": [vuln_type],
                    },
                }
                techniques = [t["id"] for t in attack_for(f)]
                if techniques:
                    rules[rule_id]["properties"]["techniques"] = techniques
            line = int(_get(f, "line", 1) or 1)
            result = {
                "ruleId": rule_id,
                "level": _SEVERITY_LEVEL.get(severity, "warning"),
                "message": {"text": description},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": str(_get(f, "file", "unknown"))},
                            "region": {"startLine": line},
                        }
                    }
                ],
                "partialFingerprints": {"primaryLocationLineHash": self._location_line_hash(f)},
            }
            patch_diff = _get(f, "patch_diff")
            if patch_diff:
                result["fixes"] = [
                    {
                        "artifactChanges": [
                            {
                                "artifactLocation": {"uri": str(_get(f, "file", "unknown"))},
                                "replacements": [
                                    {
                                        "deletedRegion": {
                                            "startLine": line,
                                            "endLine": line,
                                        },
                                        "insertedContent": {"text": str(patch_diff)},
                                    }
                                ],
                            }
                        ]
                    }
                ]
            results.append(result)
        sarif = {
            "$schema": _SARIF_SCHEMA,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "BlastRadius",
                            "version": __version__,
                            "semanticVersion": __version__,
                            "informationUri": "https://github.com/mysterious75/blastradius-agent",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(sarif, fh, indent=2)

    # ------------------------------------------------------------------
    # CycloneDX 1.5 SBOM
    # ------------------------------------------------------------------

    def export_sbom_cyclonedx(self, path: str, deps: Optional[list] = None) -> None:
        """Export a CycloneDX 1.5 software bill of materials (JSON).

        deps is an optional iterable of (name, version, purl) tuples; when
        empty/None the BOM carries metadata only (no components list).
        """
        bom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "tools": [{"name": "BlastRadius", "version": __version__}],
                "component": {
                    "type": "application",
                    "name": "blastradius-agent",
                    "version": __version__,
                },
            },
        }
        if deps:
            bom["components"] = [
                {
                    "type": "library",
                    "name": str(name),
                    "version": str(version),
                    "purl": str(purl),
                }
                for name, version, purl in deps
            ]
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(bom, fh, indent=2)

    # ------------------------------------------------------------------
    # HTML report
    # ------------------------------------------------------------------

    def export_html_report(self, path: str) -> None:
        rows = []
        for idx, f in enumerate(self.findings, 1):
            rows.append(
                f"<tr><td>{idx}</td><td>{_html.escape(str(_get(f, 'file')))}</td>"
                f"<td>{_html.escape(str(_get(f, 'line')))}</td>"
                f"<td>{_html.escape(str(_get(f, 'vuln_type'))).upper()}</td>"
                f"<td>{_html.escape(str(_get(f, 'severity')))}</td>"
                f"<td><pre>{_html.escape(str(_get(f, 'payload')))}</pre></td></tr>"
            )
        total = len(self.findings)
        by_sev = {}
        for f in self.findings:
            sev = str(_get(f, "severity", "INFO")).upper()
            by_sev[sev] = by_sev.get(sev, 0) + 1
        labels = ",".join(json.dumps(k) for k in by_sev)
        values = ",".join(str(v) for v in by_sev.values())
        html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>BlastRadius Pentest Report</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
 body {{ background:#0d1117; color:#c9d1d9; font-family:sans-serif; padding:2rem; max-width:1100px; margin:auto; }}
 h1 {{ color:#ff4444; }} table {{ width:100%; border-collapse:collapse; background:#161b22; }}
 th,td {{ border:1px solid #30363d; padding:.5rem; text-align:left; font-size:.85rem; }}
 pre {{ white-space:pre-wrap; margin:0; }} .card {{ display:inline-block; background:#161b22; border:1px solid #30363d; padding:1rem; margin:.5rem; border-radius:8px; }}
 @media print {{ body {{ background:#fff; color:#000; }} table {{ background:#fff; }} .card {{ border:1px solid #ccc; }} }}
</style></head><body>
<h1>🔴 BlastRadius Security Report</h1>
<p>Generated {datetime.now().isoformat(timespec="seconds")} · {total} finding(s)</p>
<div class="card"><b>{total}</b> total findings</div>
<div class="card"><b>{by_sev.get("CRITICAL", 0)}</b> critical</div>
<div class="card"><b>{by_sev.get("HIGH", 0)}</b> high</div>
<canvas id="sev" style="max-width:400px;max-height:300px"></canvas>
<h2>Findings</h2>
<table><thead><tr><th>#</th><th>File</th><th>Line</th><th>Type</th><th>Severity</th><th>Payload</th></tr></thead>
<tbody>{"".join(rows)}</tbody></table>
<script>
new Chart(document.getElementById('sev'), {{ type:'doughnut',
 data: {{ labels: [{labels}], datasets: [{{ data: [{values}], backgroundColor: ['#ff4444','#f0883e','#d29922','#58a6ff'] }}] }} }});
</script></body></html>"""
        Path(path).write_text(html, encoding="utf-8")

    # ------------------------------------------------------------------
    # Markdown
    # ------------------------------------------------------------------

    def export_markdown(self, path: str) -> None:
        lines = [
            "# BlastRadius Findings",
            "",
            f"**{len(self.findings)}** finding(s) — generated {datetime.now().isoformat(timespec='seconds')}",
            "",
            "| # | File | Line | Type | Severity | Payload |",
            "|---|------|------|------|----------|---------|",
        ]
        for idx, f in enumerate(self.findings, 1):
            lines.append(
                f"| {idx} | `{_get(f, 'file')}` | {_get(f, 'line')} | "
                f"{str(_get(f, 'vuln_type')).upper()} | {_get(f, 'severity')} | "
                f"`{_get(f, 'payload')}` |"
            )
        Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")
