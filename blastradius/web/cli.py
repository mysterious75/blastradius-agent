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
import urllib.error
from pathlib import Path

from blastradius.cli.display import RichDisplay
from blastradius.hunter.scanner import Finding
from blastradius.web.authz import AuthzDiffChecker
from blastradius.web.browser import BrowserSession
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
    ap.add_argument(
        "--attacker-cookie",
        help="session cookie for identity A (attacker) — enables the live IDOR authz-diff check",
    )
    ap.add_argument(
        "--victim-cookie",
        help="session cookie for identity B (victim) — enables the live IDOR authz-diff check",
    )
    ap.add_argument(
        "--victim-marker",
        action="append",
        default=[],
        help="distinctive string only the victim should see (repeatable); strengthens IDOR confidence",
    )
    ap.add_argument(
        "--idor-url",
        action="append",
        default=[],
        help="explicit object URL to test for IDOR (repeatable); crawler URLs are also used",
    )
    ap.add_argument(
        "--sqli-probe",
        action="store_true",
        help="probe crawled URLs for SQL injection (error + boolean differential)",
    )
    ap.add_argument(
        "--sqli-time-probe",
        action="store_true",
        help="also run slow time-based SQLi probes (implies --sqli-probe)",
    )
    ap.add_argument(
        "--cachepoison-probe",
        action="store_true",
        help="probe crawled URLs for web cache poisoning (unkeyed headers + WCD)",
    )
    ap.add_argument(
        "--graphql-probe",
        action="store_true",
        help="discover a GraphQL endpoint and run read-only checks "
        "(introspection, field suggestions, alias batching)",
    )
    ap.add_argument(
        "--scope",
        default=None,
        help="program name in the scope registry — blocks out-of-scope URL targets (default deny)",
    )
    ap.add_argument("--reports-dir", default="reports")
    args = ap.parse_args(argv)

    from blastradius.scope import require_scope

    if not require_scope(args.target, args.scope):
        return 2

    authz = None
    if args.attacker_cookie and args.victim_cookie:
        attacker = BrowserSession(default_headers={"Cookie": args.attacker_cookie})
        victim = BrowserSession(default_headers={"Cookie": args.victim_cookie})
        authz = AuthzDiffChecker(
            attacker=attacker, victim=victim, victim_markers=args.victim_marker
        )

    scanner = DynamicWebScanner(
        max_urls=args.max_urls,
        depth=args.depth,
        probe_exposed=not args.no_exposed_probe,
        authz=authz,
        authz_urls=args.idor_url,
        sqli_probe=args.sqli_probe or args.sqli_time_probe,
        sqli_time_probe=args.sqli_time_probe,
        cachepoison_probe=args.cachepoison_probe,
        graphql_probe=args.graphql_probe,
    )
    scanner.browser.timeout = args.timeout

    print(f"[*] Dynamic scan of {args.target}")
    # Reachability probe: a dead target must fail loudly instead of reporting
    # a clean "0 findings" scan (HTTP error answers mean the host IS reachable).
    try:
        scanner.browser.get(args.target)
    except urllib.error.HTTPError:
        pass
    except Exception as exc:
        print(f"[!] target unreachable: {args.target} ({exc.__class__.__name__}: {exc})")
        return 2
    findings = scanner.scan(args.target)
    rows = [_to_finding(f) for f in findings]
    rows.sort(key=lambda f: (f.severity, f.file))

    # Exploit-chain linking: report end-to-end impact, not just single findings.
    from blastradius.web.chains import build_chains

    chains = build_chains(findings)
    if chains:
        print("[*] exploit chain(s) detected:")
        for c in chains:
            print(f"    [{c.severity}] {c.describe()}")

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
            {
                "findings": [
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
                "chains": [
                    {"name": c.name, "severity": c.severity, "steps": c.steps} for c in chains
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"[*] saved: {path}")
    return 1 if rows else 0


if __name__ == "__main__":
    raise SystemExit(main())
