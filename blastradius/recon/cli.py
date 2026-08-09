"""BlastRadius recon CLI — discover hunt targets.

Usage:
    python -m blastradius.recon --strategy github
    python -m blastradius.recon --strategy pypi --limit 100
    python -m blastradius.recon --strategy all
"""

import argparse

from blastradius.recon.dorker import DorkEngine


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="blastradius-recon",
        description="Discover CVE-hunt targets (GitHub code search / PyPI / Shodan)",
    )
    parser.add_argument(
        "--strategy", choices=["github", "pypi", "shodan", "all"], default="all"
    )
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--min-stars", type=int, default=0)
    args = parser.parse_args(argv)

    engine = DorkEngine()
    targets = engine.find_targets(args.strategy, min_stars=args.min_stars, limit=args.limit)

    print(f"[*] {len(targets)} target(s) discovered (strategy={args.strategy})")
    for target in targets[:30]:
        print(
            f"  [{target.get('source', '?')}] {target['url']} "
            f"(stars={target.get('stars', 0)})"
        )
    print("[*] Full list saved to .cache/discovered_targets.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
