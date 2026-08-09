"""Automated CVE hunt runner.

Scans the default targets (WebGoat, DVWA, Juice Shop) — plus any number of
``--target`` repos — saves disclosure reports for confirmed-exploitable
findings to ``reports/cve_hunt_YYYY-MM-DD/``, prints a summary table, and
prints a responsible-disclosure email template per confirmed finding.

Usage:
    python -m scripts.cve_hunt
    python -m scripts.cve_hunt --target https://github.com/org/repo --target ./local
    python -m scripts.cve_hunt --reports-dir /tmp/out
"""

import argparse
import datetime
from pathlib import Path

from blastradius.hunter.cli import _repo_name
from blastradius.hunter.disclosure import DisclosureReport
from blastradius.hunter.scanner import CVEHunter, Finding, VULN_META, reconstruct_target_code
from blastradius.hunter.targets import DEFAULT_TARGETS
from blastradius.tools.sandbox_tool import run_exploit_sandbox

TABLE_HEADER = f"{'Repo':<18} | {'Files':>6} | {'Findings':>9} | {'Confirmed':>10} | {'Reports':>8}"


def hunt(hunter: CVEHunter, target: str, reports_dir: Path) -> dict:
    """Scan one target and save reports for confirmed-exploitable findings."""
    if target.startswith(("http://", "https://")):
        repo_path = hunter.clone_repo(target)
    else:
        repo_path = target
    repo_name = _repo_name(target)

    findings = hunter.scan_repo(repo_path)
    report_paths = []
    confirmed = 0
    for finding in findings:
        sandbox_result = run_exploit_sandbox(
            finding.vuln_type, reconstruct_target_code(finding)
        )
        if not sandbox_result.startswith("CONFIRMED_EXPLOITABLE"):
            continue
        confirmed += 1
        report = DisclosureReport()
        path = report.save_report(finding, repo_name, str(reports_dir), sandbox_result)
        report_paths.append(path)
        print_disclosure_template(finding, repo_name, path)

    return {
        "repo": repo_name,
        "files": hunter.files_scanned,
        "findings": len(findings),
        "confirmed": confirmed,
        "reports": len(report_paths),
    }


def print_disclosure_template(finding: Finding, repo_name: str, report_path: Path) -> None:
    """Print a responsible-disclosure email template for a confirmed finding."""
    domain = f"{repo_name.lower()}.com"  # placeholder — verify the real contact
    print("\n" + "=" * 72)
    print("RESPONSIBLE DISCLOSURE TEMPLATE")
    print("=" * 72)
    print(f"To: security@{domain}")
    print(f"Subject: Security Vulnerability Report — {finding.vuln_type.upper()} in {repo_name}")
    print()
    print("Body:")
    print()
    print(f"Hi {repo_name} maintainers,")
    print()
    print("I am a security researcher using the BlastRadius automated scanner")
    print("and found the following vulnerability in your project.")
    print()
    print(f"  Vulnerability: {finding.description}")
    print(f"  Affected file: {finding.file}:{finding.line}")
    print(f"  Payload / evidence: {finding.evidence[:200]}")
    print(f"  Severity: {finding.severity} | CVSS estimate: {VULN_META[finding.vuln_type]['cvss']} | CWE: {finding.cwe}")
    print("  Sandbox validation: CONFIRMED_EXPLOITABLE (reproduced in isolation)")
    print(f"  Suggested patch: {finding.remediation}")
    print(f"  Full disclosure report: {report_path}")
    print()
    print("I am happy to coordinate a fix and will wait for a patch before any")
    print("public disclosure. Please let me know if you need more details.")
    print("=" * 72)


def _print_table(rows: list) -> None:
    from blastradius.cli.display import RichDisplay

    print()
    RichDisplay().print_table(
        ["Repo", "Files", "Findings", "Confirmed", "Reports"],
        [[r["repo"], r["files"], r["findings"], r["confirmed"], r["reports"]] for r in rows],
        title="CVE Hunt Summary",
    )
    print()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="blastradius-hunt",
        description="Automated CVE hunt over the default targets (and any custom repos)",
    )
    parser.add_argument(
        "--target", action="append", default=None,
        help="Custom repo URL or local path (repeatable). Default: the 3 blueprint targets.",
    )
    parser.add_argument(
        "--reports-dir", default=None,
        help="Where to save reports (default: reports/cve_hunt_YYYY-MM-DD)",
    )
    args = parser.parse_args(argv)

    targets = args.target or list(DEFAULT_TARGETS)
    reports_dir = Path(
        args.reports_dir or f"reports/cve_hunt_{datetime.date.today().isoformat()}"
    )
    reports_dir.mkdir(parents=True, exist_ok=True)

    hunter = CVEHunter()
    rows = []
    for target in targets:
        try:
            rows.append(hunt(hunter, target, reports_dir))
        except Exception as exc:
            rows.append({
                "repo": _repo_name(target), "files": 0, "findings": 0,
                "confirmed": 0, "reports": 0,
            })
            print(f"[!] failed on {target}: {exc}")

    _print_table(rows)
    print(f"[*] Reports saved under {reports_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
