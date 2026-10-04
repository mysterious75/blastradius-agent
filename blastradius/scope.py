"""Program scope registry — the lab101-style discipline: only scan what a
program explicitly allows.

Scopes live in ``BLASTRADIUS_SCOPES_DIR`` (default ``~/.blastradius/scopes/``)
as ``<program>.json``:

    {"program": "...", "in_scope": [...], "out_of_scope": [...], "notes": ""}

The default is DENY: a target that matches no registered scope is out of
scope. Out-of-scope entries always win over in-scope entries.

Two gates are offered:

* ``require_scope`` — the historical opt-in gate: only URL targets WITH an
  explicit program are checked (kept for backward compatibility);
* ``enforce_scope`` — the fail-closed gate every network CLI must use:
  URL targets (and bare hostnames) without a registered program are
  BLOCKED; only local paths and lab targets (loopback, RFC-2606 names,
  RFC-1918 LAN) pass ungated.

Entries can be domains (``example.com`` matches the host and any subdomain)
or URLs/repos (``https://github.com/org/repo`` matches that repo prefix).

Run:  python -m blastradius.scope add|check|list|rm
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse

ScopesResult = Dict[str, object]


def scopes_dir() -> Path:
    env = os.getenv("BLASTRADIUS_SCOPES_DIR", "").strip()
    return Path(env) if env else Path.home() / ".blastradius" / "scopes"


def _scope_path(program: str) -> Path:
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in program)
    return scopes_dir() / f"{safe}.json"


def load_scope(program: str) -> Optional[dict]:
    path = _scope_path(program)
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def list_programs() -> List[str]:
    d = scopes_dir()
    if not d.exists():
        return []
    return sorted(p.stem for p in d.glob("*.json"))


def _unique(items: List[str]) -> List[str]:
    seen, out = set(), []
    for item in items:
        norm = item.strip().lower()
        if norm and norm not in seen:
            seen.add(norm)
            out.append(item.strip())
    return out


def save_scope(
    program: str,
    in_scope: List[str],
    out_of_scope: List[str],
    notes: str = "",
) -> dict:
    d = scopes_dir()
    d.mkdir(parents=True, exist_ok=True)
    existing = load_scope(program) or {}
    payload = {
        "program": program,
        "in_scope": _unique(existing.get("in_scope", []) + in_scope),
        "out_of_scope": _unique(existing.get("out_of_scope", []) + out_of_scope),
        "notes": notes or existing.get("notes", ""),
    }
    _scope_path(program).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload


def remove_scope(program: str) -> bool:
    path = _scope_path(program)
    if not path.exists():
        return False
    path.unlink()
    return True


def _host(url: str) -> str:
    candidate = url if "://" in url else "//" + url
    parsed = urlparse(candidate)
    return (parsed.hostname or url.split("/")[0]).lower().rstrip(".")


def _normalize(url: str) -> str:
    if "://" not in url:
        url = "http://" + url
    parsed = urlparse(url)
    return f"{parsed.hostname.lower()}{parsed.path.rstrip('/')}"


def _matches(entry: str, target: str) -> bool:
    entry = entry.strip().lower()
    target = target.strip()
    is_url_entry = "://" in entry or ("/" in entry and "." in entry.split("/")[0])
    if is_url_entry:
        norm = _normalize(entry).rstrip("/")
        t_norm = _normalize(target).rstrip("/")
        return t_norm == norm or t_norm.startswith(norm + "/")
    ehost = _host(entry)
    thost = _host(target)
    return thost == ehost or thost.endswith("." + ehost)


def check_scope(target: str, program: Optional[str] = None) -> ScopesResult:
    """Default-deny scope check: a target matching no registered scope is out.

    Returns {"in_scope": bool, "program": str|None, "reason": str}.
    """
    if program:
        scope = load_scope(program)
        if not scope:
            return {
                "in_scope": False,
                "program": program,
                "reason": f"no scope registered for '{program}'",
            }
        if any(_matches(e, target) for e in scope.get("out_of_scope", [])):
            return {
                "in_scope": False,
                "program": program,
                "reason": "explicitly out of scope",
            }
        if any(_matches(e, target) for e in scope.get("in_scope", [])):
            return {"in_scope": True, "program": program, "reason": "in scope"}
        return {
            "in_scope": False,
            "program": program,
            "reason": "target not listed in scope",
        }
    for prog in list_programs():
        result = check_scope(target, prog)
        if result["in_scope"]:
            return result
    return {
        "in_scope": False,
        "program": None,
        "reason": "no matching registered scope (default deny)",
    }


def require_scope(target: str, program: Optional[str] = None) -> bool:
    """Enforce scope for a URL target; print BLOCKED and return False if denied.

    Shared by every CLI that touches URL targets (hunter, web, recon,
    auto_hunt, agents, pipeline). Local paths and empty programs always pass —
    only URL targets with an explicit ``--scope`` program are gated, matching
    the hunter convention.
    """
    if not program or not target.startswith(("http://", "https://")):
        return True
    result = check_scope(target, program)
    if not result["in_scope"]:
        print(f"[!] BLOCKED: {result['reason']} (program={program})")
        return False
    return True


#: Host suffixes reserved for documentation and lab use (RFC 2606 + localhost).
_LAB_SUFFIXES = (".invalid", ".example", ".test", ".localhost")


def is_lab_target(target: str) -> bool:
    """Whether a target is a local lab that needs no registered scope.

    Loopback addresses and RFC-2606 documentation names can never leave the
    machine (or never resolve), so gating them would only add friction to
    offline testing. Everything else is a real network target.
    """
    text = target.strip().lower()
    if "://" in text:
        text = text.split("://", 1)[1]  # strip scheme: host lives after it
    host = text.split("/")[0].split(":")[0].split("@")[-1].strip("[]")
    return (
        host in ("localhost", "127.0.0.1", "::1")
        or host.startswith("127.")
        or host.startswith("10.")
        or host.startswith("192.168.")
        or host.endswith(_LAB_SUFFIXES)
    )


def enforce_scope(target: str, program: Optional[str] = None) -> bool:
    """Fail-closed scope gate for every CLI that touches the network.

    This closes the opt-in gap in ``require_scope`` (URL target + omitted
    ``--scope`` used to sail through silently):

    * local paths ................. always pass (no network involved);
    * lab targets (loopback, RFC-2606 names, RFC-1918 LAN) ... pass;
    * URL target + registered program matching ... pass;
    * URL target + wrong/missing program ... BLOCKED (guidance printed).

    Returns True when the scan may proceed, False when it must not.
    """
    if not target.startswith(("http://", "https://")):
        if "://" in target:
            return True  # non-HTTP scheme: this tool cannot use it anyway
        if (
            Path(target).exists()
            or "/" in target
            or "\\" in target
            or target in (".", "..")
            or "." not in target
        ):
            return True  # local path (dotless names are paths, not hosts)
        # Dotted bare hostname (scanme.nmap.org, 10.0.0.5): a network
        # target — present it as a URL for the checks below.
        target = f"http://{target}"
    if is_lab_target(target):
        return True
    if not program:
        print(
            "[!] BLOCKED: URL targets require --scope with a registered program "
            "(default deny — no silent opt-out). Register one with:\n"
            "      python -m blastradius.scope add <program> --in <host-or-url>"
        )
        return False
    result = check_scope(target, program)
    if not result["in_scope"]:
        print(f"[!] BLOCKED: {result['reason']} (program={program})")
        return False
    return True


def _main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="blastradius-scope",
        description="Program scope registry (default deny).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_add = sub.add_parser("add", help="register/merge a program scope")
    p_add.add_argument("program")
    p_add.add_argument(
        "--in", dest="in_scope", action="append", default=[], help="in-scope target (repeatable)"
    )
    p_add.add_argument(
        "--out",
        dest="out_scope",
        action="append",
        default=[],
        help="out-of-scope target (repeatable)",
    )
    p_add.add_argument("--notes", default="")

    p_check = sub.add_parser("check", help="check a target against registered scopes")
    p_check.add_argument("target")
    p_check.add_argument("--program", default=None)

    sub.add_parser("list", help="list registered programs")
    p_rm = sub.add_parser("rm", help="remove a program scope")
    p_rm.add_argument("program")

    args = parser.parse_args(argv)
    if args.command == "add":
        payload = save_scope(args.program, args.in_scope, args.out_scope, args.notes)
        print(f"scope saved: {_scope_path(args.program)}")
        print(f"  in_scope:  {payload['in_scope']}")
        print(f"  out_scope: {payload['out_of_scope']}")
        return 0
    if args.command == "check":
        result = check_scope(args.target, args.program)
        status = "IN SCOPE" if result["in_scope"] else "OUT OF SCOPE"
        print(f"{status} ({result['reason']})")
        return 0 if result["in_scope"] else 2
    if args.command == "list":
        for prog in list_programs():
            print(prog)
        return 0
    if args.command == "rm":
        removed = remove_scope(args.program)
        print(f"removed: {args.program}" if removed else f"not found: {args.program}")
        return 0 if removed else 1
    return 1


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:] if len(sys.argv) > 1 else None))
