"""Program scope registry — the lab101-style discipline: only scan what a
program explicitly allows.

Scopes live in ``BLASTRADIUS_SCOPES_DIR`` (default ``~/.blastradius/scopes/``)
as ``<program>.json``:

    {"program": "...", "in_scope": [...], "out_of_scope": [...], "notes": ""}

The default is DENY: a target that matches no registered scope is out of
scope. Out-of-scope entries always win over in-scope entries.

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


def _main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="blastradius-scope",
        description="Program scope registry (default deny).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_add = sub.add_parser("add", help="register/merge a program scope")
    p_add.add_argument("program")
    p_add.add_argument("--in", dest="in_scope", action="append", default=[], help="in-scope target (repeatable)")
    p_add.add_argument("--out", dest="out_scope", action="append", default=[], help="out-of-scope target (repeatable)")
    p_add.add_argument("--notes", default="")

    p_check = sub.add_parser("check", help="check a target against registered scopes")
    p_check.add_argument("target")
    p_check.add_argument("--program", default=None)

    p_list = sub.add_parser("list", help="list registered programs")
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
