"""Security CLI.

Usage:
    python -m blastradius.security audit [--verify]
"""

import argparse

from blastradius.security.audit_log import AuditLogger


def cmd_audit(args) -> int:
    logger = AuditLogger()
    entries = logger.read()
    if args.verify:
        ok, message = logger.verify()
        print(f"[{'OK' if ok else 'TAMPERED'}] {message}")
    for entry in entries[-args.lines:]:
        print(f"{entry.get('ts', '?')} {entry.get('event', '?')} {entry.get('hash', '')[:8]}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="blastradius-security")
    sub = parser.add_subparsers(dest="command", required=True)
    audit_p = sub.add_parser("audit", help="print the audit log")
    audit_p.add_argument("--lines", type=int, default=20)
    audit_p.add_argument("--verify", action="store_true", help="verify the tamper chain")
    args = parser.parse_args(argv)
    if args.command == "audit":
        return cmd_audit(args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
