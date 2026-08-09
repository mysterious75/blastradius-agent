"""CSV export plugin — writes findings to CSV on scan complete.

Output: $CSV_EXPORT_DIR/findings.csv (default ~/.blastradius/findings.csv).
"""

import csv
import os
from pathlib import Path

from blastradius.plugins.base import BasePlugin


class CsvExportPlugin(BasePlugin):
    name = "csv_export"
    version = "1.0.0"

    def __init__(self):
        self.findings = []

    def on_finding(self, finding) -> None:
        self.findings.append(finding)

    def on_scan_complete(self, results) -> None:
        if not self.findings:
            return
        base = Path(os.getenv("BLASTRADIUS_HOME", str(Path.home()))) / ".blastradius"
        out = Path(os.getenv("CSV_EXPORT_DIR", str(base))) / "findings.csv"
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["file", "line", "vuln_type", "severity", "confidence", "payload"])
            for finding in self.findings:
                writer.writerow([
                    finding.file, finding.line, finding.vuln_type, finding.severity,
                    finding.confidence, finding.payload,
                ])
