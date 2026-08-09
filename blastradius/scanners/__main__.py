"""python -m blastradius.scanners — cache stats | clear."""

import argparse

from blastradius.scanners.cache import ScanCache


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="blastradius-scanners")
    sub = parser.add_subparsers(dest="command", required=True)
    cache_p = sub.add_parser("cache", help="scan cache management")
    cache_sub = cache_p.add_subparsers(dest="cache_command", required=True)
    cache_sub.add_parser("stats", help="show cache stats")
    cache_sub.add_parser("clear", help="clear the scan cache")
    args = parser.parse_args(argv)

    cache = ScanCache()
    if args.cache_command == "stats":
        stats = cache.stats()
        print(f"Cached files: {stats['cached_files']}")
        print(f"DB: {stats['db']}")
    elif args.cache_command == "clear":
        cache.clear()
        print("[+] Scan cache cleared.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
