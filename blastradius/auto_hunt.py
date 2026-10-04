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
        help="program name in the scope registry — REQUIRED: the autonomous hunt "
        "clones and scans discovered repos, so unguided runs are blocked "
        "(default deny)",
    )
    parser.add_argument(
        "--repo",
        action="append",
        default=[],
        help="explicit repo URL to hunt (repeatable); skips discovery entirely. "
        "Each repo must be in scope — out-of-scope repos are BLOCKED.",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=1,
        help="repeat the hunt N times with a fixed seed; confirmations aggregate k-of-N",
    )
    parser.add_argument("--seed", type=int, default=0, help="fixed seed for iterated runs")
    args = parser.parse_args(argv)

    # Fail-closed: an autonomous hunt clones and scans whatever discovery
    # returns — running it with no registered scope is never allowed.
    if not args.scope:
        print(
            "[!] BLOCKED: autonomous hunts require --scope with a registered "
            "program (default deny — no silent opt-out). Register one with:\n"
            "      python -m blastradius.scope add <program> --in <host-or-url>"
        )
        return 2

    # Explicit repos skip discovery but never skip the gate: each named repo
    # must be in scope, otherwise the whole run is blocked.
    if args.repo:
        from blastradius.scope import enforce_scope

        for repo in args.repo:
            if not enforce_scope(repo, args.scope):
                return 2

    AutoHunt(reports_dir=args.reports_dir).run(
        args.strategy,
        max_targets=args.max_targets,
        min_stars=args.min_stars,
        scope=args.scope,
        iterations=args.iterations,
        seed=args.seed,
        repos=args.repo or None,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
