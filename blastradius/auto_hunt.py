"""AutoHunt CLI — python -m blastradius.auto_hunt.

Usage:
    python -m blastradius.auto_hunt --strategy github --max 20
"""

import argparse

from blastradius.recon.auto_hunt import AutoHunt


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="blastradius-auto-hunt",
        description="Autonomous CVE hunt over discovered targets",
    )
    parser.add_argument("--strategy", choices=["github", "pypi", "shodan", "all"], default="github")
    parser.add_argument("--max", type=int, default=20, dest="max_targets")
    parser.add_argument("--min-stars", type=int, default=100)
    parser.add_argument("--reports-dir", default="reports/auto_hunt")
    parser.add_argument(
        "--scope",
        default=None,
        help="program name in the scope registry — hunts only in-scope discovered targets",
    )
    args = parser.parse_args(argv)

    AutoHunt(reports_dir=args.reports_dir).run(
        args.strategy, max_targets=args.max_targets, min_stars=args.min_stars, scope=args.scope
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
