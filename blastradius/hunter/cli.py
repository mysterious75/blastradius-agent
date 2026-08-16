"""BlastRadius CVE hunter CLI (Phase 3).

Usage:
    python -m blastradius.hunter --target https://github.com/user/repo
    python -m blastradius.hunter --target ./local/path

Prints a findings table, adversarially validates each candidate, sandbox-
validates the survivors, and saves a disclosure report for findings that are
confirmed exploitable.
"""

import argparse

from pathlib import Path

from blastradius.cli.display import RichDisplay
from blastradius.hunter.disclosure import DisclosureReport
from blastradius.hunter.scanner import CVEHunter, reconstruct_target_code
from blastradius.hunter.targets import DEFAULT_TARGETS
from blastradius.tools.sandbox_tool import run_exploit_sandbox


def _repo_name(target: str) -> str:
    if target.startswith(("http://", "https://")):
        return target.rstrip("/").split("/")[-1]
    return Path(target).name or "unknown"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="blastradius-hunter",
        description="BlastRadius CVE hunter — scan a repo and write disclosure reports",
    )
    parser.add_argument(
        "--target",
        help="GitHub repo URL or local path (default: first target in targets.py)",
    )
    parser.add_argument("--min-confidence", type=float, default=0.7)
    parser.add_argument("--reports-dir", default="reports")
    parser.add_argument(
        "--scope",
        default=None,
        help="program name in the scope registry — blocks out-of-scope URL targets (default deny)",
    )
    args = parser.parse_args(argv)

    display = RichDisplay()
    display.print_banner()

    hunter = CVEHunter(min_confidence=args.min_confidence)
    target = args.target or DEFAULT_TARGETS[0]

    if args.scope and target.startswith(("http://", "https://")):
        from blastradius.scope import check_scope

        result = check_scope(target, args.scope)
        if not result["in_scope"]:
            print(f"[!] BLOCKED: {result['reason']} (program={args.scope})")
            return 2

    if target.startswith(("http://", "https://")):
        print(f"[*] Cloning {target}")
        repo_path = hunter.clone_repo(target)
        repo_name = _repo_name(target)
    else:
        repo_path = target
        repo_name = _repo_name(target)
        print(f"[*] Scanning local path {target}")

    findings = hunter.scan_repo(repo_path)
    print(f"[*] {len(findings)} candidate finding(s) with confidence >= {args.min_confidence}")
    if findings:
        display.print_findings_table(findings)

    reports = DisclosureReport()
    saved = 0
    for finding in findings:
        sandbox_result = run_exploit_sandbox(finding.vuln_type, reconstruct_target_code(finding))
        if sandbox_result.startswith("CONFIRMED_EXPLOITABLE"):
            path = reports.save_report(finding, repo_name, args.reports_dir, sandbox_result)
            saved += 1
            print(f"[+] report saved: {path}")
        else:
            print(
                f"[-] not exploitable in sandbox: {finding.vuln_type}@{finding.file}:{finding.line}"
            )

    print(f"[*] Done: {saved} report(s) saved to {args.reports_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
