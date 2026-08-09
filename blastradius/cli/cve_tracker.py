"""CVE tracker CLI.

Usage:
    python -m blastradius.cve_tracker list
    python -m blastradius.cve_tracker update --id 1 --cve CVE-2026-XXXXX --bounty 500
    python -m blastradius.cve_tracker stats
"""

import argparse
from datetime import datetime

from blastradius.cli.display import RichDisplay
from blastradius.db.deduplicator import Deduplicator


def _days_open(disclosed_at: str) -> int:
    try:
        return max(0, (datetime.now() - datetime.fromisoformat(disclosed_at)).days)
    except ValueError:
        return 0


def cmd_list(_args) -> int:
    rows = Deduplicator().get_tracking_rows()
    display = RichDisplay()
    table = []
    for r in rows:
        status = Deduplicator().get_disclosure_status(r["finding_id"])
        table.append([
            f"{r.get('vuln_type', '?').upper()} @ {r.get('file', '?')}:{r.get('line', '?')}",
            r.get("cve_id") or "—",
            status,
            r.get("bounty_usd") or 0,
            _days_open(r.get("disclosed_at") or ""),
        ])
    display.print_table(["Finding", "CVE ID", "Status", "Bounty", "Days Open"], table,
                        title="CVE Tracker")
    return 0


def cmd_update(args) -> int:
    dedup = Deduplicator()
    dedup.mark_disclosed(args.id, cve_id=args.cve or "", bounty=args.bounty or 0)
    status = dedup.get_disclosure_status(args.id)
    print(f"[+] finding {args.id} → status: {status} (cve={args.cve or '—'}, bounty=${args.bounty or 0})")
    return 0


def cmd_stats(_args) -> int:
    stats = Deduplicator().get_stats()
    print(f"{'Total disclosed':<20} {stats['total_disclosed']}")
    print(f"{'Assigned CVEs':<20} {stats['assigned_cves']}")
    print(f"{'Total bounty':<20} ${stats['total_bounty_usd']}")
    print(f"{'Avg fix time':<20} {stats['avg_fix_days']} days" if stats['avg_fix_days'] is not None
          else f"{'Avg fix time':<20} —")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="blastradius-cve-tracker")
    sub = parser.add_subparsers(dest="command", required=True)
    list_p = sub.add_parser("list", help="list tracked findings")
    list_p.add_argument("--db", default=None, help="override DB path")
    update_p = sub.add_parser("update", help="update CVE/bounty for a finding")
    update_p.add_argument("--db", default=None, help="override DB path")
    update_p.add_argument("--id", type=int, required=True)
    update_p.add_argument("--cve", default="")
    update_p.add_argument("--bounty", type=float, default=0)
    stats_p = sub.add_parser("stats", help="disclosure statistics")
    stats_p.add_argument("--db", default=None, help="override DB path")
    args = parser.parse_args(argv)

    if args.command == "update":
        return cmd_update(args)
    if args.command == "list":
        return cmd_list(args)
    if args.command == "stats":
        return cmd_stats(args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
