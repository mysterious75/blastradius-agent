"""BlastRadius recon CLI — discover hunt targets.

Usage:
    python -m blastradius.recon --strategy github
    python -m blastradius.recon --strategy pypi --limit 100
    python -m blastradius.recon --strategy all
    python -m blastradius.recon --shadow acme/protocol
"""

import argparse

from blastradius.cli.display import RichDisplay
from blastradius.recon.dorker import DorkEngine


def _run_shadow(args, display) -> int:
    """Shadow-repository sweep: contributors -> public repos/Gists/releases."""
    from blastradius.recon.shadow_repo import ShadowRepoRecon

    recon = ShadowRepoRecon(
        max_contributors=args.max_contributors,
        confirm_content=not args.no_content_confirm,
        max_content_fetches=args.max_content_fetches,
    )
    report = recon.run(args.shadow)
    print(
        f"[*] shadow sweep {report.repo}: {len(report.contributors)} contributor(s), "
        f"{len(report.assets)} public asset(s)"
    )
    rows = [[f.severity, f.payload, f.file, f.context] for f in report.findings[:30]]
    if rows:
        display.print_table(["Severity", "Class", "Asset", "URL"], rows, title="Shadow Exposures")
    print(
        f"[*] {len(report.findings)} exposure finding(s); detection only - "
        "no credential was validated or used"
    )
    for err in report.errors[:10]:
        print(f"[!] {err}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="blastradius-recon",
        description="Discover CVE-hunt targets (GitHub code search / PyPI / Shodan)",
    )
    parser.add_argument("--strategy", choices=["github", "pypi", "shodan", "all"], default="all")
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--min-stars", type=int, default=0)
    parser.add_argument(
        "--scope",
        default=None,
        help="program name in the scope registry — filters discovered targets to in-scope ones",
    )
    parser.add_argument(
        "--shadow",
        default=None,
        metavar="OWNER/REPO",
        help="sweep a repo's contributors for publicly exposed keys/dumps instead of target discovery",
    )
    parser.add_argument("--max-contributors", type=int, default=25)
    parser.add_argument("--max-content-fetches", type=int, default=40)
    parser.add_argument(
        "--no-content-confirm",
        action="store_true",
        help="classify by asset name only; never fetch asset bodies",
    )
    args = parser.parse_args(argv)

    display = RichDisplay()
    display.print_banner()

    if args.shadow:
        return _run_shadow(args, display)

    engine = DorkEngine()
    targets = engine.find_targets(args.strategy, min_stars=args.min_stars, limit=args.limit)
    if args.scope:
        from blastradius.scope import check_scope

        before = len(targets)
        targets = [t for t in targets if check_scope(t.get("url", ""), args.scope)["in_scope"]]
        print(f"[*] scope filter ({args.scope}): {before} -> {len(targets)} target(s)")

    print(f"[*] {len(targets)} target(s) discovered (strategy={args.strategy})")
    rows = [[t.get("source", "?"), t["url"], t.get("stars", 0)] for t in targets[:30]]
    if rows:
        display.print_table(["Source", "URL", "Stars"], rows, title="Discovered Targets")
    print("[*] Full list saved to .cache/discovered_targets.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
