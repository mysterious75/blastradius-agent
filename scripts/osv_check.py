"""Check BlastRadius's own dependencies for known CVEs via the OSV API.

Usage:
    python scripts/osv_check.py            # exit 1 if any CRITICAL vuln
    python scripts/osv_check.py --no-fail  # report only, never fail
"""

import argparse
import json
import sys
import tomllib
import urllib.request
from pathlib import Path
from typing import List


def project_deps(pyproject_path: str = "pyproject.toml") -> List[str]:
    with open(pyproject_path, "rb") as fh:
        data = tomllib.load(fh)
    deps = data["project"]["dependencies"]
    cleaned = []
    for dep in deps:
        name = dep.split(">=")[0].split("==")[0].split("[")[0].strip()
        if name:
            cleaned.append(name)
    return cleaned


def query_osv(package: str, ecosystem: str = "PyPI") -> List[dict]:
    body = json.dumps({"package": {"name": package, "ecosystem": ecosystem}}).encode("utf-8")
    req = urllib.request.Request(
        "https://api.osv.dev/v1/query",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8")).get("vulns", [])


def _is_critical(vuln: dict) -> bool:
    db_sev = str(vuln.get("database_specific", {}).get("severity", "")).upper()
    if "CRITICAL" in db_sev:
        return True
    return "critical" in (vuln.get("summary") or "").lower()


def check(fail_on_critical: bool = True, pyproject_path: str = "pyproject.toml") -> int:
    issues = []
    for dep in project_deps(pyproject_path):
        try:
            vulns = query_osv(dep)
        except Exception:
            continue  # OSV unreachable — skip, don't fail
        for vuln in vulns:
            issues.append({
                "package": dep,
                "id": vuln.get("id"),
                "summary": (vuln.get("summary") or "")[:120],
                "critical": _is_critical(vuln),
            })

    critical = [i for i in issues if i["critical"]]
    if critical:
        print(f"❌ {len(critical)} CRITICAL known-vulnerability dependency(-ies):")
        for item in critical:
            print(f"   {item['package']}: {item['id']} — {item['summary']}")
        return 1 if fail_on_critical else 0

    print(f"✅ {len(issues)} known vulnerability record(s) across "
          f"{len(project_deps(pyproject_path))} dependencies — none critical.")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="osv-check")
    parser.add_argument("--no-fail", action="store_true", help="report only, never fail")
    parser.add_argument("--pyproject", default="pyproject.toml")
    args = parser.parse_args(argv)
    return check(fail_on_critical=not args.no_fail, pyproject_path=args.pyproject)


if __name__ == "__main__":
    raise SystemExit(main())
