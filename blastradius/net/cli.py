"""python -m blastradius.net — network-service scanning CLI.

Scans TCP ports on an explicitly named host, fingerprints services from
banners, and runs service-filtered detectors (cleartext FTP/Telnet,
anonymous FTP, missing SMTP STARTTLS). Saves candidate findings as JSON.

Scope discipline (stricter than the web CLI): loopback and `.invalid` lab
targets scan freely, but any other host REQUIRES `--scope` with a registered
program — there is no silent opt-out for network probing.

Usage:
    python -m blastradius.net --target 127.0.0.1 --ports common
    python -m blastradius.net --target example.com --ports 21,23,25 --scope myprogram
"""

import argparse
import json
import time
from pathlib import Path

from blastradius.cli.display import RichDisplay
from blastradius.hunter.scanner import Finding
from blastradius.net.scanner import NetworkServiceScanner

_LAB_SUFFIXES = (".invalid", ".example", ".test", ".localhost")


def _is_lab_target(target: str) -> bool:
    host = target.strip().lower().split("/")[0].split(":")[0]
    return (
        host in ("localhost", "127.0.0.1", "::1")
        or host.startswith("127.")
        or host.endswith(_LAB_SUFFIXES)
    )


def _to_finding(f: "object") -> Finding:
    return Finding(
        file=f.url,
        line=0,
        vuln_type=f.check,
        payload=f.url,
        confidence=f.confidence,
        severity=f.severity,
        cwe=f.cwe,
        description=f.description or f"{f.check} detected on the wire",
        evidence=f.evidence,
        remediation=f.remediation,
    )


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="BlastRadius network-service scanner")
    ap.add_argument("--target", required=True, help="host to scan (IP or hostname)")
    ap.add_argument(
        "--ports",
        default="common",
        help="preset (common|web|mail|db|remote), list (22,80) or range (1-1024)",
    )
    ap.add_argument("--connect-timeout", type=float, default=3.0)
    ap.add_argument("--read-timeout", type=float, default=5.0)
    ap.add_argument("--workers", type=int, default=20)
    ap.add_argument(
        "--scope",
        default=None,
        help="program name in the scope registry — REQUIRED for non-lab targets",
    )
    ap.add_argument("--reports-dir", default="reports")
    args = ap.parse_args(argv)

    from blastradius.scope import require_scope

    if not _is_lab_target(args.target):
        if not args.scope:
            print(
                "[!] BLOCKED: network scans of non-lab targets require --scope "
                "with a registered program (no silent opt-out)"
            )
            return 2
        # Bare hostnames never match the URL-gated require_scope, so present
        # the target as a URL for the scope check only (scan still uses TCP).
        scope_target = args.target if "://" in args.target else f"http://{args.target}"
        if not require_scope(scope_target, args.scope):
            return 2

    ports = args.ports
    from blastradius.net.scanner import parse_ports

    try:
        parse_ports(ports)
    except ValueError as exc:
        print(f"[!] unknown port spec: {ports} ({exc})")
        return 2

    scanner = NetworkServiceScanner(
        connect_timeout=args.connect_timeout,
        read_timeout=args.read_timeout,
        workers=args.workers,
    )
    print(f"[*] Network-service scan of {args.target} (ports={args.ports})")
    try:
        findings = scanner.scan(args.target, ports=args.ports)
    except ValueError as exc:
        print(f"[!] {exc}")
        return 2
    rows = [_to_finding(f) for f in findings]
    rows.sort(key=lambda f: (f.severity, f.file))

    display = RichDisplay()
    if rows:
        display.print_findings_table(rows)
    print(f"[*] {len(rows)} network candidate finding(s)")

    out_dir = Path(args.reports_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime())
    path = out_dir / f"net_scan_{stamp}.json"
    path.write_text(
        json.dumps(
            {
                "target": args.target,
                "findings": [
                    {
                        "host": f.host,
                        "port": f.port,
                        "check": f.check,
                        "severity": f.severity,
                        "cwe": f.cwe,
                        "confidence": f.confidence,
                        "evidence": f.evidence,
                    }
                    for f in findings
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
