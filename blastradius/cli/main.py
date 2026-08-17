"""Unified BlastRadius CLI (``blastradius`` after pip install).

Usage:
    blastradius scan --target <url|path>
    blastradius hunt --strategy github --max 10
    blastradius blast --repo ./path
    blastradius dashboard
    blastradius api [--port 8001]
    blastradius providers list|test
    blastradius cve list
    blastradius export --format <csv|json|sarif|html|markdown> --output <file>
    blastradius sca --repo . [--online]
    blastradius cvehunt [--repo .] [--kev-file <saved KEV JSON>]
    blastradius setup
    blastradius version
"""

import argparse
from pathlib import Path

from blastradius.version import __version__


def cmd_version(_args) -> int:
    print(f"BlastRadius Agent v{__version__}")
    return 0


def cmd_setup(_args) -> int:
    from blastradius.cli.wizard import main as wizard_main

    return wizard_main()


def cmd_dashboard(_args) -> int:
    from blastradius.dashboard.__main__ import main as dashboard_main

    return dashboard_main()


def cmd_api(args) -> int:
    import os

    import uvicorn

    from blastradius.api.server import app

    host = os.getenv("BLASTRADIUS_HOST", "127.0.0.1")
    uvicorn.run(app, host=host, port=args.port, reload=args.reload)
    return 0


def cmd_scan(args) -> int:
    from blastradius.hunter.cli import main as hunter_main

    return hunter_main(["--target", args.target, "--reports-dir", args.reports_dir])


def cmd_hunt(args) -> int:
    from blastradius.auto_hunt import main as auto_hunt_main

    return auto_hunt_main(
        [
            "--strategy",
            args.strategy,
            "--max",
            str(args.max),
            "--min-stars",
            str(args.min_stars),
            "--reports-dir",
            args.reports_dir,
        ]
    )


def cmd_blast(args) -> int:
    from blastradius.blast_radius.cli import main as blast_main

    return blast_main(["--repo", args.repo])


def cmd_providers(args) -> int:
    from blastradius.providers.cli import main as providers_main

    return providers_main([args.action] + list(args.rest))


def cmd_cve(args) -> int:
    from blastradius.cli.cve_tracker import main as cve_main

    return cve_main([args.action] + list(args.rest))


def cmd_scope(args) -> int:
    from blastradius.scope import _main as scope_main

    return scope_main(list(args.arguments))


def cmd_graph(args) -> int:
    from blastradius.agents.cli import main as graph_main

    return graph_main(
        [
            "--target",
            args.target,
            "--exploit-workers",
            str(args.exploit_workers),
            "--reports-dir",
            args.reports_dir,
        ]
    )


def cmd_web(args) -> int:
    from blastradius.web.cli import main as web_main

    return web_main(
        [
            "--target",
            args.target,
            "--max-urls",
            str(args.max_urls),
            "--reports-dir",
            args.reports_dir,
        ]
    )


def cmd_export(args) -> int:
    from blastradius.export.cli import main as export_main

    return export_main(["--format", args.format, "--output", args.output])


def cmd_sca(args) -> int:
    import json as _json
    from datetime import datetime

    from blastradius import sca as sca_mod
    from blastradius.sca import parse_lockfiles, query_osv, summarize

    packages = parse_lockfiles(args.repo)
    if not packages:
        print(f"No supported lockfiles found under {args.repo!r} — nothing to check.")
        return 0

    print(f"Found {len(packages)} dependency record(s) under {args.repo!r}.")
    if not args.online:
        print("Offline mode: using cached OSV results only (pass --online to query the API).")

    results = query_osv(packages, online=args.online)
    if not sca_mod.network_available:
        print("WARNING: OSV API unreachable — results limited to cached data.")

    total = sum(len(entry["advisories"]) for entry in results)
    if total:
        header = f"{'package':<32} {'id':<24} {'severity':<9} {'fixed'}"
        print(header)
        print("-" * len(header))
        for entry in results:
            for advisory in entry["advisories"]:
                pkg = entry["package"]
                print(
                    f"{str(pkg.get('name')):<32} {str(advisory.get('id')):<24} "
                    f"{str(advisory.get('severity')):<9} {advisory.get('fixed') or '-'}"
                )
    else:
        print("No known vulnerabilities found in the dependency set.")

    summary = summarize(results)
    print("Summary: " + ", ".join(f"{k}={v}" for k, v in summary.items()))

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    reports_dir = Path(args.reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_path = reports_dir / f"{ts}_sca.json"
    report = {
        "tool": "blastradius-sca",
        "repo": str(args.repo),
        "packages_checked": len(packages),
        "packages": packages,
        "results": results,
        "summary": summary,
        "network_available": sca_mod.network_available,
    }
    with report_path.open("w", encoding="utf-8") as fh:
        _json.dump(report, fh, indent=2)
    print(f"Report written to {report_path}")

    if summary.get("CRITICAL", 0) or summary.get("HIGH", 0):
        return 1
    return 0


def cmd_cvehunt(args) -> int:
    """Cross-reference scan findings with known-exploited CVEs (KEV + EPSS).

    Enrichment only — never a gate: returns 0 even when the KEV feed or EPSS
    API is unreachable. Matched CVEs are candidate signals; the sandbox still
    owns the ``[VULNERABLE]`` verdict.
    """
    import json as _json
    from datetime import datetime

    from blastradius import cve_hunt
    from blastradius.hunter.scanner import CVEHunter

    if args.kev_file:
        try:
            kev = cve_hunt.load_kev_file(args.kev_file)
            kev_source = args.kev_file
        except OSError:
            print(f"[!] Could not read KEV file {args.kev_file!r} — no enrichment.")
            return 0
    else:
        kev = cve_hunt.fetch_kev()
        kev_source = cve_hunt.KEV_FEED_URL
    if not kev:
        print("[!] KEV catalog empty/unreachable — no enrichment possible.")
        return 0

    print(f"[*] Scanning {args.repo!r}")
    hunter = CVEHunter()
    findings = hunter.scan_repo(args.repo)
    print(f"[*] {len(findings)} candidate finding(s)")

    matches = cve_hunt.match_findings_to_kev(findings, kev=kev)
    print(f"[*] {len(matches)} finding(s) cross-referenced to {len(kev)} KEV entries")

    cve_ids = sorted({entry["cveID"] for m in matches for entry in m["kev_cves"]})
    epss = cve_hunt.fetch_epss(cve_ids)

    if matches:
        header = f"{'vuln':<18} {'cwe':<10} {'KEV cves':<24} {'EPSS'}"
        print(header)
        print("-" * len(header))
        for m in matches:
            f = m["finding"]
            ids = sorted({entry["cveID"] for entry in m["kev_cves"]})
            epss_str = (
                ", ".join(f"{cve}={epss[cve]['epss']:.3f}" for cve in ids if cve in epss) or "-"
            )
            print(f"{f.vuln_type:<18} {f.cwe:<10} {','.join(ids):<24} {epss_str}")
    else:
        print("No findings matched the KEV catalog (candidate-only enrichment).")

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    reports_dir = Path(args.reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_path = reports_dir / f"{ts}_cvehunt.json"
    report = {
        "tool": "blastradius-cvehunt",
        "repo": str(args.repo),
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "kev_source": kev_source,
        "kev_entries": len(kev),
        "network_available": cve_hunt.network_available,
        "findings_scanned": len(findings),
        "enrichments": [
            {
                "file": m["finding"].file,
                "line": m["finding"].line,
                "vuln_type": m["finding"].vuln_type,
                "cwe": m["finding"].cwe,
                "kev_cves": [entry["cveID"] for entry in m["kev_cves"]],
                "kev_details": m["kev_cves"],
                "epss": {entry["cveID"]: epss.get(entry["cveID"]) for entry in m["kev_cves"]},
            }
            for m in matches
        ],
    }
    with report_path.open("w", encoding="utf-8") as fh:
        _json.dump(report, fh, indent=2)
    print(f"Report written to {report_path}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="blastradius",
        description="Autonomous security engineer — scan, prove, patch, verify",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("version", help="show version")

    sub.add_parser("setup", help="interactive setup wizard")

    sub.add_parser("dashboard", help="start the web dashboard on :8080")

    api_p = sub.add_parser("api", help="start the REST API on :8001")
    api_p.add_argument("--port", type=int, default=8001)
    api_p.add_argument("--reload", action="store_true")

    scan_p = sub.add_parser("scan", help="scan a repo and save disclosure reports")
    scan_p.add_argument("--target", required=True)
    scan_p.add_argument("--reports-dir", default="reports")

    hunt_p = sub.add_parser("hunt", help="autonomous hunt over discovered targets")
    hunt_p.add_argument("--strategy", default="github", choices=["github", "pypi", "shodan", "all"])
    hunt_p.add_argument("--max", type=int, default=10)
    hunt_p.add_argument("--min-stars", type=int, default=0)
    hunt_p.add_argument("--reports-dir", default="reports/auto_hunt")

    blast_p = sub.add_parser("blast", help="map dependency blast radius")
    blast_p.add_argument("--repo", required=True)

    providers_p = sub.add_parser("providers", help="provider status (list|test|set|cost)")
    providers_p.add_argument("action", choices=["list", "test", "set", "cost"])
    providers_p.add_argument("rest", nargs=argparse.REMAINDER)

    cve_p = sub.add_parser("cve", help="CVE tracking (list|update|stats)")
    cve_p.add_argument("action", choices=["list", "update", "stats"])
    cve_p.add_argument("rest", nargs=argparse.REMAINDER)

    scope_p = sub.add_parser("scope", help="scope registry (default-deny for URL targets)")
    scope_p.add_argument("arguments", nargs=argparse.REMAINDER)

    graph_p = sub.add_parser("graph", help="multi-agent graph scan")
    graph_p.add_argument("--target", required=True)
    graph_p.add_argument("--exploit-workers", type=int, default=4)
    graph_p.add_argument("--reports-dir", default="reports")

    web_p = sub.add_parser("web", help="dynamic web testing (XSS/redirect/headers/CORS)")
    web_p.add_argument("--target", required=True)
    web_p.add_argument("--max-urls", type=int, default=20)
    web_p.add_argument("--reports-dir", default="reports")

    export_p = sub.add_parser("export", help="export findings")
    export_p.add_argument(
        "--format", choices=["csv", "json", "sarif", "html", "markdown"], default="markdown"
    )
    export_p.add_argument("--output", required=True)

    sca_p = sub.add_parser("sca", help="dependency/SCA scan via OSV (lockfiles)")
    sca_p.add_argument("--repo", default=".", help="path to the project to scan")
    sca_p.add_argument("--online", action="store_true", help="allow network queries to OSV")
    sca_p.add_argument("--reports-dir", default="reports")

    cvehunt_p = sub.add_parser(
        "cvehunt",
        help="cross-reference findings with known-exploited CVEs (KEV + EPSS enrichment)",
    )
    cvehunt_p.add_argument("--repo", default=".", help="path to the project to scan")
    cvehunt_p.add_argument(
        "--kev-file",
        default=None,
        help="path to a saved KEV JSON snapshot (skips the network fetch)",
    )
    cvehunt_p.add_argument("--reports-dir", default="reports")

    args = parser.parse_args(argv)
    if args.command == "version":
        return cmd_version(args)
    if args.command == "setup":
        return cmd_setup(args)
    if args.command == "dashboard":
        return cmd_dashboard(args)
    if args.command == "api":
        return cmd_api(args)
    if args.command == "scan":
        return cmd_scan(args)
    if args.command == "hunt":
        return cmd_hunt(args)
    if args.command == "blast":
        return cmd_blast(args)
    if args.command == "providers":
        return cmd_providers(args)
    if args.command == "cve":
        return cmd_cve(args)
    if args.command == "scope":
        return cmd_scope(args)
    if args.command == "graph":
        return cmd_graph(args)
    if args.command == "web":
        return cmd_web(args)
    if args.command == "export":
        return cmd_export(args)
    if args.command == "sca":
        return cmd_sca(args)
    if args.command == "cvehunt":
        return cmd_cvehunt(args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
