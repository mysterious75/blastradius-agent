"""BlastRadius scheduler CLI.

Usage:
    python -m blastradius.scheduler start     → starts scheduler daemon
    python -m blastradius.scheduler status    → shows next run times
    python -m blastradius.scheduler run-now   → immediate hunt
"""

import argparse
import time

from blastradius.scheduler.cron import HuntScheduler


def cmd_start(args) -> int:
    scheduler = HuntScheduler()
    if not scheduler.start():
        print("[*] HUNT_SCHEDULE=disabled — nothing scheduled (set daily/weekly).")
        return 0
    print("[*] Scheduler started:")
    for name, next_run in scheduler.status().items():
        print(f"    {name:<16} next: {next_run}")
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        scheduler.stop()
        print("\n[*] Scheduler stopped.")
    return 0


def cmd_status(_args) -> int:
    scheduler = HuntScheduler()
    scheduler.schedule()
    if not scheduler._jobs:
        print("[*] HUNT_SCHEDULE=disabled — no jobs configured.")
        return 0
    print("Scheduled jobs:")
    for name, job in scheduler._jobs.items():
        print(f"    {name:<16} every {int(job['interval'].total_seconds() / 3600)}h")
    return 0


def cmd_run_now(args) -> int:
    scheduler = HuntScheduler()
    scheduler.run_now(args.strategy, args.max_targets)
    print("[*] Hunt complete.")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="blastradius-scheduler")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("start", help="start the scheduler daemon")
    sub.add_parser("status", help="show scheduled jobs")
    run_p = sub.add_parser("run-now", help="run a hunt immediately")
    run_p.add_argument("--strategy", default="github", choices=["github", "pypi", "shodan", "all"])
    run_p.add_argument("--max-targets", type=int, default=None)
    args = parser.parse_args(argv)

    if args.command == "start":
        return cmd_start(args)
    if args.command == "status":
        return cmd_status(args)
    if args.command == "run-now":
        return cmd_run_now(args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
