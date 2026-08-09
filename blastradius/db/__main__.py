"""BlastRadius DB CLI.

Usage:
    python -m blastradius.db stats   → print stats table
    python -m blastradius.db clear   → confirm, then delete all rows
"""

import argparse
import sys

from blastradius.db.database import SQLiteDB


def cmd_stats(db: SQLiteDB) -> int:
    stats = db.get_stats()
    print(f"{'Total scans':<22} {stats['total_scans']}")
    print(f"{'Confirmed findings':<22} {stats['confirmed']}")
    print(f"{'Patches generated':<22} {stats['patches']}")
    print(f"{'Total findings':<22} {stats['findings']}")
    print(f"{'Success rate':<22} {stats['success_rate']}%")
    print()
    print("Latest scans:")
    for scan in db.get_scans(limit=10):
        print(f"  #{scan['id']} [{scan['status']}] {scan['target']} "
              f"({scan['files_scanned']} files)")
    return 0


def cmd_clear(db: SQLiteDB, confirm: str = "") -> int:
    if confirm != "yes":
        confirm = input(f"Delete ALL data in {db.db_path}? type 'yes': ").strip()
    if confirm != "yes":
        print("Aborted.")
        return 1
    db.clear()
    print("Cleared all rows.")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="blastradius-db")
    sub = parser.add_subparsers(dest="command", required=True)
    stats_p = sub.add_parser("stats", help="print stats table")
    stats_p.add_argument("--db", default=None, help="override DB path")
    clear_p = sub.add_parser("clear", help="delete all rows (with confirmation)")
    clear_p.add_argument("--db", default=None, help="override DB path")
    clear_p.add_argument("--yes", action="store_true", help="skip confirmation")
    args = parser.parse_args(argv)

    db = SQLiteDB(db_path=args.db)
    if args.command == "stats":
        return cmd_stats(db)
    if args.command == "clear":
        return cmd_clear(db, confirm="yes" if args.yes else "")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
