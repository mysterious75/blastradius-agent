"""python -m blastradius.web — dynamic web testing CLI.

Scans a live target with behavioral checks (reflected XSS, open redirect,
security headers, CORS, exposed files, directory listing) and saves the
candidate findings as JSON.

Usage:
    python -m blastradius.web --target http://localhost:8000
"""

import argparse
import json
import time
from pathlib import Path

from blastradius.cli.display import RichDisplay
from blastradius.hunter.scanner import Finding
from blastradius.web.scanner import DynamicWebScanner


def _to_finding(f: "object") -> Finding:
    return Finding(
        file=f.url,
        line=0,
        vuln_type=f.check,
        payload=f.url,
        confidence=f.confidence,
        severity=f.severity,
        cwe=f.cwe,
        description=f.description or f"{f.check.upper()} detected dynamically",
        evidence=f.evidence,
        remediation=f.remediation,
    )


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="BlastRadius dynamic web testing")
    ap.add_argument("--target", required=True, help="base URL to scan (e.g. http://localhost:8000)")
    ap.add_argument("--max-urls", type=int, default=20)
    ap.add_argument("--depth", type=int, default=1)
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("--no-exposed-probe", action="store_true", help="skip /.git, /.env probes")
    ap.add_argument("--reports-dir", default="reports")
    args = ap.parse_args(argv)

    scanner = DynamicWebScanner(
        max_urls=args.max_urls, depth=args.depth, probe_exposed=not args.no_exposed_probe
    )
    scanner.browser.timeout = args.timeout

    print(f"[*] Dynamic scan of {args.target}")
    findings = scanner.scan(args.target)
    rows = [_to_finding(f) for f in findings]
    rows.sort(key=lambda f: (f.severity, f.file))

    display = RichDisplay()
    if rows:
        display.print_findings_table(rows)
    print(f"[*] {len(rows)} dynamic candidate finding(s)")

    out_dir = Path(args.reports_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime())
    path = out_dir / f"web_scan_{stamp}.json"
    path.write_text(
        json.dumps(
            [
                {
                    "url": f.url,
                    "check": f.check,
                    "severity": f.severity,
                    "cwe": f.cwe,
                    "confidence": f.confidence,
                    "evidence": f.evidence,
                }
                for f in findings
            ],
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"[*] saved: {path}")
    return 1 if rows else 0


if __name__ == "__main__":
    raise SystemExit(main())
