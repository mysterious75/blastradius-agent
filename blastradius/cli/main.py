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
    blastradius setup
    blastradius version
"""

import argparse

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
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
