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
        "--git-history",
        action="store_true",
        help="also scan git history (truffleHog-style) for secrets committed in any commit",
    )
    parser.add_argument(
        "--scope",
        default=None,
        help="program name in the scope registry — blocks out-of-scope URL targets (default deny)",
    )
    parser.add_argument(
        "--real-repo",
        action="store_true",
        default=False,
        help="also run the PoC against the actual repo file (local path targets only)",
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

    # truffleHog-style git-history scan: candidates only, no sandbox PoC
    if args.git_history:
        history = hunter.scan_git_history(repo_path)
        print(
            f"[*] {len(history)} secret(s) found in git history "
            "(candidates — rotated or not, they are recoverable; no sandbox PoC)"
        )
        if history:
            display.print_findings_table(history)

    reports = DisclosureReport()
    saved = 0
    is_local = not target.startswith(("http://", "https://"))
    for finding in findings:
        sandbox_result = run_exploit_sandbox(finding.vuln_type, reconstruct_target_code(finding))
        if sandbox_result.startswith("CONFIRMED_EXPLOITABLE"):
            if args.real_repo and is_local:
                # pattern-check passed — now prove it against the actual file
                from blastradius.sandbox.real_repo import run_real_poc

                real = run_real_poc(finding, repo_path)
                if real.get("vulnerable"):
                    print(f"[real-repo] confirmed in actual file: {finding.file}:{finding.line}")
                else:
                    print(
                        f"[real-repo] pattern-only (real code not PoC-able): "
                        f"{finding.file}:{finding.line}"
                    )
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
